//! # Winexe Container Module
//!
//! This module provides functionality for managing and interacting with Windows machines
//! through a containerized Winexe implementation. It handles SMB protocol negotiation,
//! container management, and command execution over SMB.

use crate::client::*;
use crate::client::{Command, CommandOutput, Config, Session};
use crate::smb::negotiate_session;
use crate::stateful_process::{Message, StatefulProcess};
use download_embed_macro::download_and_embed;
use flate2::read::GzDecoder;
use serde_json::Value;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tar::Archive;
use tokio::fs;
use tokio::process::{Child, Command as TokioCommand};
use tokio::sync::mpsc;
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
        ip_input: I,
        password: P,
        inactivity_timeout: Duration,
    ) -> crate::Result<Self> {
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

    async fn create_session(&self) -> crate::Result<Self::SessionType> {
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
    pub async fn new(config: WinexeConfig) -> crate::Result<Self> {
        let runc_path = Self::ensure_runc_available().await?;
        Self::ensure_winexe_installed().await?;

        let container = Self { config, runc_path };

        if !container.is_container_running().await? {
            println!("Starting Container");
            let _ = container.start_container().await?;
            println!("Container Started");

            // Wait for the container to start
            loop {
                println!("Checking if container is running");
                if container.is_container_running().await? {
                    break;
                }
                println!("Waiting for container to start");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }

            println!("Container Started");
        }

        Ok(container)
    }

    /// Ensures that runc is available, installing it if not found
    ///
    /// # Returns
    ///
    /// Returns a Result containing the path to runc if successful, or an error if installation fails
    async fn ensure_runc_available() -> crate::Result<String> {
        if let Some(path) = Self::find_existing_runc().await {
            println!("Found existing runc at: {}", path);
            return Ok(path);
        }

        println!("Installing runc to {}", RUNC_PATH);
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
    async fn ensure_winexe_installed() -> crate::Result<()> {
        let winexe_path = Path::new(TMP_DIR).join("winexe");
        if !winexe_path.exists() {
            println!("Installing winexe to {}", TMP_DIR);
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
    async fn is_container_running(&self) -> crate::Result<bool> {
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

    /// Starts the container
    ///
    /// # Returns
    ///
    /// Returns a Result containing the Child process of the started container
    async fn start_container(&self) -> crate::Result<Child> {
        println!("Starting Container");
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
    pub async fn open_channel(&self) -> crate::Result<WinexeChannel> {
        let ip = self.config.ip();

        println!("Getting SMB Version");
        let smb_ver = match Self::get_smb_version(ip).await {
            Ok(SMBVersion::V1) => "./winexe-static",
            Ok(SMBVersion::V3) => "./winexe-static-2",
            Err(_) => {
                return Err(crate::Error::ConnectionError(
                    "Error Getting SMB Version".to_string(),
                ))
            }
        };
        println!("SMB Version: {}", smb_ver);

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
    async fn get_smb_version(server: &IpAddr) -> crate::Result<SMBVersion> {
        for port in PORTS.iter() {
            match negotiate_session(server, *port, Duration::from_secs(2), true).await {
                Ok(Some(dialect)) => {
                    if !dialect.is_empty() && dialect[0] == SMB_3_SIGNATURE {
                        println!("SMB Version 3");
                        return Ok(SMBVersion::V3);
                    } else if !dialect.is_empty() {
                        println!("SMB Version 1");
                        return Ok(SMBVersion::V1);
                    }
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }

        println!("SMB Version DEFAULTING");
        Ok(SMBVersion::V1)
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
    pub async fn exec(&mut self, command: &Command) -> crate::Result<()> {
        let exit_bytes = b"&& exit\n";
        let mut command: Vec<u8> = command.into();
        command.extend_from_slice(exit_bytes);
        self.process.exec(command).await
    }

    /// Closes the channel
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if the channel is successfully closed
    pub async fn close(&mut self) -> crate::Result<()> {
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
    async fn disconnect(&mut self) -> crate::Result<()> {
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
    async fn exec(&self, command: &Command) -> crate::Result<CommandOutput> {
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
}

// End of the module
#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::cmd;
    use std::time::Duration;

    #[tokio::test]
    async fn test_winexe_container() {
        let socket = "139.182.180.178";
        let config =
            WinexeConfig::password("", socket, "", Duration::from_secs(10))
                .await
                .unwrap();

        let client = Client::connect(config).await.unwrap();

        let output = client.exec(&cmd!("echo", "TESTING")).await.unwrap();

        let str_output = String::from_utf8_lossy(&output.stdout);

        dbg!(str_output);
    }
}
