//! # Winexe Container Module
//!
//! This module provides functionality for managing and interacting with Windows machines
//! through a containerized Winexe implementation. It handles SMB protocol negotiation,
//! container management, and command execution over SMB.

use crate::client::{Command, CommandOutput, Config, Session};
use crate::cmd;
use crate::smb::negotiate_session;
use crate::stateful_process::{Message, StatefulProcess};
use crate::Result;
use byteorder::{BigEndian, WriteBytesExt};
use download_embed_macro::download_and_embed;
use flate2::read::GzDecoder;
use serde_json::Value;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tar::Archive;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command as TokioCommand};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::Duration;

/// Signature byte for SMB version 3 protocol
const SMB_3_SIGNATURE: u8 = 0xFE;

/// Standard ports used for SMB communication
static PORTS: &[u16] = &[445, 139];

/// Embedded binary data for the Winexe container
static WINEXE_CONTAINER: &[u8] = include_bytes!("../img/winexe-static.tar.gz");

/// Embedded binary data for the runc container runtime
static RUNC: &[u8] = download_and_embed!(
    "https://github.com/opencontainers/runc/releases/download/v1.2.0-rc.3/runc.386"
);

/// Temporary directory for storing Winexe container files
const TMP_DIR: &str = "/tmp/winexe_container";

/// Path to the Winexe executable within the container
const WINEXE_PATH: &str = "/tmp/winexe_container/winexe";

/// Path to the runc executable
const RUNC_PATH: &str = "/tmp/winexe_container/runc";

/// Common system paths where runc might be installed
const RUNC_COMMON_PATHS: &[&str] = &[
    "/usr/bin/runc",
    "/usr/local/bin/runc",
    "/usr/sbin/runc",
    "/usr/local/sbin/runc",
];

impl std::fmt::Debug for WinexeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WinexeConfig::NoPassword {
                username,
                ip,
                inactivity_timeout,
            } => f
                .debug_struct("WinexeConfig")
                .field("username", username)
                .field("ip", ip)
                .field("inactivity_timeout", inactivity_timeout)
                .finish(),
            WinexeConfig::Password {
                username,
                ip,
                password,
                inactivity_timeout,
            } => f
                .debug_struct("WinexeConfig")
                .field("username", username)
                .field("ip", ip)
                .field("password", password)
                .field("inactivity_timeout", inactivity_timeout)
                .finish(),
        }
    }
}

/// Enum representing different SMB protocol versions
pub enum SMBVersion {
    V1,
    V3,
}

/// Configuration options for Winexe connections
#[derive(Clone)]
pub enum WinexeConfig {
    NoPassword {
        username: String,
        ip: IpAddr,
        inactivity_timeout: Duration,
    },
    Password {
        username: String,
        ip: IpAddr,
        password: String,
        inactivity_timeout: Duration,
    },
}

impl WinexeConfig {
    /// Creates a new WinexeConfig with password authentication
    ///
    /// # Arguments
    ///
    /// * `username` - The username for the connection
    /// * `ip_input` - The IP address of the target machine
    /// * `password` - The password for the connection
    /// * `inactivity_timeout` - The duration after which an inactive connection is terminated
    ///
    /// # Returns
    ///
    /// Returns a Result containing the WinexeConfig if successful, or an error if the IP address is invalid
    pub async fn password<U: Into<String>, I: crate::TryIntoIpAddr, P: Into<String>>(
        username: U,
        password: P,
        ip_input: I,
        inactivity_timeout: Duration,
    ) -> Result<Self> {
        let ip = ip_input
            .try_into_ip_addr()
            .map_err(|e| crate::Error::ConnectionError(format!("Invalid IP address: {}", e)))?;

        Ok(Self::Password {
            username: username.into(),
            ip,
            password: password.into(),
            inactivity_timeout,
        })
    }

    fn ip(&self) -> &IpAddr {
        match self {
            Self::NoPassword { ip, .. } => ip,
            Self::Password { ip, .. } => ip,
        }
    }

    fn inactivity_timeout(&self) -> Duration {
        match self {
            Self::NoPassword {
                inactivity_timeout, ..
            } => *inactivity_timeout,
            Self::Password {
                inactivity_timeout, ..
            } => *inactivity_timeout,
        }
    }
}

impl Config for WinexeConfig {
    type SessionType = WinexeContainer;

    async fn create_session(&self) -> Result<Self::SessionType> {
        WinexeContainer::new(self.clone()).await
    }
}

/// Struct representing a Winexe container instance
pub struct WinexeContainer {
    /// Configuration for the Winexe connection
    config: WinexeConfig,
    /// Path to the runc executable
    runc_path: String,
}

impl WinexeContainer {
    /// Creates a new WinexeContainer instance
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the Winexe connection
    ///
    /// # Returns
    ///
    /// Returns a Result containing the WinexeContainer if successful, or an error if setup fails
    pub async fn new(config: WinexeConfig) -> Result<Self> {
        let runc_path = Self::ensure_runc_available().await?;
        Self::ensure_winexe_installed().await?;

        let container = Self { config, runc_path };

        if !container.is_container_running().await? {
            let _ = container.start_container().await?;

            // Wait for the container to start
            loop {
                if container.is_container_running().await? {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        container.write_transfer_helper().await?;

        Ok(container)
    }

    /// Ensures that runc is available, installing it if not found
    ///
    /// # Returns
    ///
    /// Returns a Result containing the path to runc if successful, or an error if installation fails
    async fn ensure_runc_available() -> Result<String> {
        if let Some(path) = Self::find_existing_runc().await {
            return Ok(path);
        }

        fs::create_dir_all(TMP_DIR).await?;
        fs::write(RUNC_PATH, RUNC).await?;
        fs::set_permissions(RUNC_PATH, std::fs::Permissions::from_mode(0o755)).await?;

        Ok(RUNC_PATH.to_string())
    }

    /// Searches for an existing runc installation in common system paths
    ///
    /// # Returns
    ///
    /// Returns Some(path) if a valid runc installation is found, or None otherwise
    async fn find_existing_runc() -> Option<String> {
        for path in RUNC_COMMON_PATHS {
            if Path::new(path).exists() && Self::is_valid_runc(path).await {
                return Some(path.to_string());
            }
        }
        None
    }

    fn ip(&self) -> &IpAddr {
        self.config.ip()
    }

    /// Checks if the runc at the given path is valid
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the runc executable
    ///
    /// # Returns
    ///
    /// Returns true if runc is valid, false otherwise
    async fn is_valid_runc(path: &str) -> bool {
        TokioCommand::new(path)
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Ensures that Winexe is installed in the container
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if installation is successful, or an error if it fails
    async fn ensure_winexe_installed() -> Result<()> {
        let winexe_path = Path::new(TMP_DIR).join("winexe");
        if !winexe_path.exists() {
            fs::create_dir_all(TMP_DIR).await?;

            let mut decoder = GzDecoder::new(WINEXE_CONTAINER);
            let mut decompressed_data = Vec::new();
            decoder.read_to_end(&mut decompressed_data)?;

            let mut archive = Archive::new(&decompressed_data[..]);
            archive.unpack(TMP_DIR)?;
        }
        Ok(())
    }

    /// Checks if the container is currently running
    ///
    /// # Returns
    ///
    /// Returns a Result containing a boolean indicating whether the container is running
    async fn is_container_running(&self) -> Result<bool> {
        let output = TokioCommand::new(&self.runc_path)
            .arg("state")
            .arg("winexe-container")
            .output()
            .await?;

        if !output.status.success() {
            return Ok(false);
        }

        let json: Value = serde_json::from_slice(&output.stdout)?;

        if let Some(status) = json.get("status") {
            let is_running = status == "running";
            Ok(is_running)
        } else {
            Ok(false)
        }
    }


    async fn fetch_file(addr: &SocketAddr, local_path: &str) -> crate::Result<()> {
        // Try connection with retries
        let mut stream = {
            let mut stream = None;
            let mut last_error = None;

            for attempt in 1..=5 {
                match TcpStream::connect(&addr).await {
                    Ok(s) => {
                        stream = Some(s);
                        break;
                    }
                    Err(e) => {
                        last_error = Some(e);
                        if attempt < 5 {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    }
                }
            }

            match stream {
                Some(s) => s,
                None => {
                    return Err(crate::Error::ConnectionError(format!(
                        "Failed to connect after 5 attempts: {}",
                        last_error.unwrap()
                    )))
                }
            }
        };

        // Read 8-byte size header
        let mut size_buf = [0u8; 8];
        stream.read_exact(&mut size_buf).await.map_err(|e| {
            crate::Error::FileTransferError(format!("Failed to read size header: {}", e))
        })?;

        let file_size = size_buf.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);

        // Create output file
        let mut file = tokio::fs::File::create(local_path).await.map_err(|e| {
            crate::Error::FileTransferError(format!("Failed to create output file: {}", e))
        })?;

        let mut received = 0u64;
        let mut buffer = [0u8; 8192];

        while received < file_size {
            let to_read = std::cmp::min(8192, file_size - received) as usize;
            let bytes_read = stream.read(&mut buffer[..to_read]).await.map_err(|e| {
                crate::Error::FileTransferError(format!("Failed to read from stream: {}", e))
            })?;

            if bytes_read == 0 {
                return Err(crate::Error::FileTransferError(
                    "Connection closed before transfer completed".to_string(),
                ));
            }

            file.write_all(&buffer[..bytes_read]).await.map_err(|e| {
                crate::Error::FileTransferError(format!("Failed to write to file: {}", e))
            })?;

            received += bytes_read as u64;
        }

        Ok(())
    }

    /// Starts the container
    ///
    /// # Returns
    ///
    /// Returns a Result containing the Child process of the started container
    async fn start_container(&self) -> Result<Child> {
        Ok(TokioCommand::new(&self.runc_path)
            .arg("run")
            .arg("-d")
            .arg("--bundle")
            .arg(WINEXE_PATH)
            .arg("winexe-container")
            .spawn()?)
    }

    /// Opens a new channel to the container
    ///
    /// # Returns
    ///
    /// Returns a Result containing a WinexeChannel if successful, or an error if opening fails
    pub async fn open_channel(&self) -> Result<WinexeChannel> {
        let ip = self.config.ip();

        let smb_ver = match Self::get_smb_version(ip).await {
            Ok(SMBVersion::V1) => "./winexe-static",
            Ok(SMBVersion::V3) => "./winexe-static-2",
            Err(_) => {
                return Err(crate::Error::ConnectionError(
                    "Error Getting SMB Version".to_string(),
                ))
            }
        };

        let mut cmd_args = vec!["exec", "winexe-container", smb_ver];

        cmd_args.push("-U");

        let user_auth = match &self.config {
            WinexeConfig::NoPassword { username, .. } => username.clone(),
            WinexeConfig::Password {
                username, password, ..
            } => format!("{}%{}", username, password),
        };

        let connection_str = format!("//{}", ip);

        cmd_args.push(&user_auth);
        cmd_args.push(&connection_str);
        cmd_args.push("cmd.exe");

        let (tx, rx) = mpsc::unbounded_channel();
        let process = StatefulProcess::new(&self.runc_path, cmd_args, tx).await?;

        Ok(WinexeChannel {
            process,
            receiver: rx,
            inactivity_timeout: self.config.inactivity_timeout(),
        })
    }

    /// Determines the SMB version of the target server
    ///
    /// # Arguments
    ///
    /// * `server` - The IP address of the target server
    ///
    /// # Returns
    ///
    /// Returns a Result containing the detected SMBVersion, or an error if detection fails
    async fn get_smb_version(server: &IpAddr) -> Result<SMBVersion> {
        for port in PORTS.iter() {
            match negotiate_session(server, *port, Duration::from_secs(2), true).await {
                Ok(Some(dialect)) => {
                    if !dialect.is_empty() && dialect[0] == SMB_3_SIGNATURE {
                        return Ok(SMBVersion::V3);
                    } else if !dialect.is_empty() {
                        return Ok(SMBVersion::V1);
                    }
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }

        Ok(SMBVersion::V1)
    }

    async fn write_transfer_helper(&self) -> Result<()> {
        // Check if file exists
        let check = self
            .exec(&cmd!("if exist C:\\Temp\\transfer_file.bat echo TRUE"))
            .await?;

        let check_stdout = String::from_utf8_lossy(&check.stdout);

        // Check if TRUE shows up twice in the output
        if check_stdout.matches("TRUE").count() > 1 {
            println!("Transfer helper already exists");
            return Ok(());
        }

        let check = self
            .exec(&cmd!("if not exist C:\\Temp\\ echo TRUE"))
            .await?;

        let check_stdout = String::from_utf8_lossy(&check.stdout);

        if check_stdout.matches("TRUE").count() > 1 {
            self.exec(&cmd!("mkdir C:\\Temp")).await?;
        }

        // Write the entire content in one echo command
        let transfer_helper = include_str!("../resources/transfer_file.bat");
        let base64_content = base64::encode(transfer_helper);


        // First write the base64 string
        let echo_command = format!("echo {}> C:\\Temp\\transfer_file.b64", base64_content);
        println!("echo command: {}", echo_command);
        let echo_out =  self.exec(&cmd!(echo_command)).await?;
        println!("cmd out{}", String::from_utf8_lossy(&echo_out.stdout));

        // Then decode it into the batch file using certutil
        self.exec(&cmd!(
            "certutil -decode C:\\Temp\\transfer_file.b64 C:\\Temp\\transfer_file.bat"
        ))
        .await?;

        // Clean up the temporary b64 file
        self.exec(&cmd!("del C:\\Temp\\transfer_file.b64")).await?;

        Ok(())
    }
}

/// Struct representing a channel to a Winexe container
pub struct WinexeChannel {
    /// The underlying stateful process
    process: StatefulProcess,
    /// Receiver for messages from the process
    receiver: mpsc::UnboundedReceiver<Message>,
    /// Timeout duration for inactivity
    inactivity_timeout: Duration,
}

impl WinexeChannel {
    /// Waits for a message from the channel
    ///
    /// # Returns
    ///
    /// Returns Some(Message) if a message is received before the timeout, or None if a timeout occurs
    pub async fn wait(&mut self) -> Option<Message> {
        match tokio::time::timeout(self.inactivity_timeout, self.receiver.recv()).await {
            Ok(message) => message,
            Err(_) => None, // Timeout occurred
        }
    }

    /// Executes a command on the channel
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if the command is successfully sent, or an error if sending fails
    pub async fn exec(&mut self, command: &Command) -> Result<()> {
        let exit_bytes = b" && exit\n";
        let mut command: Vec<u8> = command.into();
        command.extend_from_slice(exit_bytes);
        self.process.exec(command).await
    }

    /// Closes the channel
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if the channel is successfully closed
    pub async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Session for WinexeContainer {
    /// Disconnects from the session
    ///
    /// # Note
    ///
    /// This method might not be directly applicable for WinexeContainer.
    /// It could be used to close all open channels if implemented.
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if the disconnection is successful
    async fn disconnect(&mut self) -> Result<()> {
        // This method might not be directly applicable for WinexeContainer
        // You might want to close all open channels here
        Ok(())
    }

    /// Executes a command on the session
    ///
    /// # Arguments
    ///
    /// * `command` - The command to execute
    ///
    /// # Returns
    ///
    /// Returns a Result containing the CommandOutput if successful, or an error if execution fails
    async fn exec(&self, command: &Command) -> Result<CommandOutput> {
        // Open a new channel for command execution
        let mut channel = self.open_channel().await?;

        // Execute the command
        channel.exec(command).await?;

        // Initialize variables for command output
        let status_code = None;
        let mut stdout = vec![];
        let stderr = vec![];

        // Collect output from the channel
        loop {
            let Some(msg) = channel.wait().await else {
                channel.close().await?;
                break;
            };

            match msg {
                Message::Data(data) => {
                    stdout.extend_from_slice(&data);
                }
                _ => {}
            }
        }

        // Return the collected output
        Ok(CommandOutput {
            stdout,
            stderr,
            status_code,
        })
    }

    async fn download_file(&self, remote_path: &str, local_path: &str) -> crate::Result<()> {
        let port_number = 49152 + rand::random::<u16>() % 16384;
        let rule = format!(
            "cmd.exe /c netsh advfirewall firewall add rule name=\"Allow Port {}\" dir=in action=allow protocol=TCP localport={}",
            port_number, port_number
        );
        let rule_output = self.exec(&cmd!(rule)).await?;

        let start_helper = format!(
            "cmd.exe /c wmic process call create 'C:\\Temp\\transfer_file.bat {} 0.0.0.0 {} serve'",
            port_number, remote_path
        );
        let helper = self.exec(&cmd!(start_helper)).await?;

        match format!("{}:{}", self.ip(), port_number).parse() {
            Ok(socket) => Self::fetch_file(&socket, local_path).await,
            Err(_) => {
                self.exec(&crate::cmd!(format!(
                    "cmd.exe /c netsh advfirewall firewall delete rule name=\"Allow Port {}\"",
                    port_number
                ))).await;
                Err(crate::Error::ConnectionError("Invalid socket address".to_string()))
            },
        }
    }

    async fn transfer_file(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_destination: &str,
    ) -> Result<()> {
        let port_number = 49152 + rand::random::<u16>() % 16384;
        let rule = format!(
            "cmd.exe /c netsh advfirewall firewall add rule name=\"Allow Port {}\" dir=in action=allow protocol=TCP localport={}",
            port_number, port_number
        );
        let rule_output = self.exec(&cmd!(rule)).await?;

        let start_helper = format!(
            "cmd.exe /c wmic process call create 'C:\\Temp\\transfer_file.bat {} 0.0.0.0 {} receive'",
            port_number, remote_destination
        );
        let helper = self.exec(&cmd!(start_helper)).await?;
        let helper_stdout = String::from_utf8_lossy(&helper.stdout);

        let socket = format!("{}:{}", self.ip(), port_number);

        // Try to connect with retries
        let mut stream = None;
        for attempt in 0..5 {
            match TcpStream::connect(&socket).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    if attempt < 4 {
                        // Don't sleep on last attempt
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }

        match stream {
            Some(mut stream) => {
                let file_size = file_contents.len() as u64;
                let mut size_buffer = vec![];
                WriteBytesExt::write_u64::<BigEndian>(&mut size_buffer, file_size)?;

                stream.write_all(&size_buffer).await?;
                Ok(stream.write_all(&file_contents).await?)
            }
            None => {
                self.exec(&crate::cmd!(format!(
                    "cmd.exe /c netsh advfirewall firewall delete rule name=\"Allow Port {}\"",
                    port_number
                )))
                .await?;
                return Err(crate::Error::FileTransferError(
                    "Failed to connect after 5 attempts".to_string(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Config;
    use crate::cmd;
    use std::time::Duration;

    #[tokio::test]
    async fn test_winexe_container() {
        let config = WinexeConfig::Password {
            username: "Administrator".to_string(),
            password: "Cheesed2MeetU!".to_string(),
            ip: "10.100.136.241".parse().unwrap(),
            inactivity_timeout: Duration::from_secs(10),
        };

        let mut session = config.create_session().await.unwrap();
        let file_bytes = b"Hello, World!".to_vec();

        session
            .transfer_file(Arc::new(file_bytes), "C:\\Temp\\chimera")
            .await
            .unwrap();
        
        session.download_file("C:\\Temp\\transfer_file.bat", "./transfer_file.bat").await.unwrap();

        let output = session.exec(&cmd!("dir C:\\Temp")).await.unwrap();

        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
}
