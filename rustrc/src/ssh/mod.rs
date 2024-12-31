use crate::client::{Command, CommandOutput, Config, Session};

use async_trait::async_trait;
use byteorder::{BigEndian, WriteBytesExt};
use russh::client;
use russh_keys::key::PrivateKeyWithHashAlg;
use russh_keys::load_secret_key;
use russh_keys::ssh_key::public::PublicKey;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::{
    io::AsyncWriteExt,
    net::{lookup_host, ToSocketAddrs},
    time::Duration,
};

pub struct Connected;
pub struct Disconnected;

#[allow(unused)]
pub struct SSHSession {
    session: client::Handle<Handler>,
    config: SSHConfig,
}

#[derive(Debug, Clone)]
pub enum SSHConfig {
    Key {
        username: String,
        socket: SocketAddr,
        key_path: PathBuf,
        inactivity_timeout: Duration,
    },
    Password {
        username: String,
        socket: SocketAddr,
        password: String,
        inactivity_timeout: Duration,
    },
}

impl SSHConfig {
    fn ip(&self) -> IpAddr {
        match self {
            Self::Key { socket, .. } => socket.ip(),
            Self::Password { socket, .. } => socket.ip(),
        }
    }

    async fn resolve_socket<S: ToSocketAddrs>(socket: S) -> crate::Result<SocketAddr> {
        lookup_host(&socket)
            .await?
            .next()
            .ok_or_else(|| crate::Error::ConnectionError("Error Parsing Socket".to_string()))
    }

    pub async fn key<U: Into<String>, S: ToSocketAddrs, P: Into<PathBuf>>(
        username: U,
        socket: S,
        key_path: P,
        inactivity_timeout: Duration,
    ) -> crate::Result<Self> {
        Ok(SSHConfig::Key {
            username: username.into(),
            socket: Self::resolve_socket(socket).await?,
            key_path: key_path.into(),
            inactivity_timeout,
        })
    }

    pub async fn password<U: Into<String>, S: ToSocketAddrs, P: Into<String>>(
        username: U,
        password: P,
        socket: S,
        inactivity_timeout: Duration,
    ) -> crate::Result<Self> {
        Ok(SSHConfig::Password {
            username: username.into(),
            socket: Self::resolve_socket(socket).await?,
            password: password.into(),
            inactivity_timeout,
        })
    }
}

impl Session for SSHSession {
    async fn disconnect(&mut self) -> crate::Result<()> {
        self.session
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }

    async fn exec(&self, cmd: &Command) -> crate::Result<CommandOutput> {
        let mut channel = self.session.channel_open_session().await?;
        let command: Vec<u8> = cmd.into();
        channel.exec(true, command).await?;

        self.process_channel_output(&mut channel).await
    }

    async fn download_file(&self, remote_path: &str, local_path: &str) -> crate::Result<()> {
        let sftp = self.create_sftp_session().await?;
        let mut remote_file = sftp.open(remote_path).await?;

        let mut local_file = tokio::fs::File::create(local_path).await?;
        tokio::io::copy(&mut remote_file, &mut local_file).await?;

        Ok(())
    }

    async fn transfer_file(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> crate::Result<()> {
        let sftp = self.create_sftp_session().await?;

        match self
            .try_direct_file_transfer(&sftp, &file_contents, remote_dest)
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = sftp.remove_file(remote_dest).await;

                self.ensure_transfer_helper(&sftp).await?;
                self.batch_transfer_file(file_contents, remote_dest).await
            }
        }
    }
}

impl SSHSession {
    async fn process_channel_output(
        &self,
        channel: &mut russh::Channel<russh::client::Msg>,
    ) -> crate::Result<CommandOutput> {
        let mut code = None;
        let mut stdout = vec![];
        let stderr = vec![];

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    stdout.extend_from_slice(data);
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                }
                _ => {}
            }
        }

        Ok(CommandOutput {
            stdout,
            stderr,
            status_code: code,
        })
    }

    async fn create_sftp_session(&self) -> crate::Result<russh_sftp::client::SftpSession> {
        let channel = self.session.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;

        russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|_| crate::Error::FileTransferError("Failed to create SFTP session".into()))
    }

    async fn try_direct_file_transfer(
        &self,
        sftp: &russh_sftp::client::SftpSession,
        file_contents: &[u8],
        remote_dest: &str,
    ) -> crate::Result<()> {
        // Try direct file creation first
        let mut remote_file = match sftp.create(remote_dest).await {
            Ok(file) => file,
            Err(_) => {
                self.create_parent_directories(sftp, remote_dest).await?;
                sftp.create(remote_dest).await?
            }
        };

        match remote_file.write_all(file_contents).await{
            Ok(_) => {},
            Err(e) => {
                let _ = remote_file.shutdown().await;
                return Err(crate::Error::FileTransferError("Failed to write file contents".to_string()));
            }
        };

        remote_file.shutdown().await?;

        Ok(())
    }

    async fn create_parent_directories(
        &self,
        sftp: &russh_sftp::client::SftpSession,
        remote_dest: &str,
    ) -> crate::Result<()> {
        let path = Path::new(remote_dest);
        if let Some(parent) = path.parent() {
            let mut current = String::with_capacity(remote_dest.len());

            // Handle Windows-style root if present
            if let Some(Component::Prefix(p)) = parent.components().next() {
                current.push_str(p.as_os_str().to_str().ok_or_else(|| {
                    crate::Error::FileTransferError("Invalid UTF-8 in path prefix".to_string())
                })?);
            }

            for comp in parent.components() {
                match comp {
                    Component::Normal(dir) => {
                        if !current.is_empty() {
                            current.push(std::path::MAIN_SEPARATOR);
                        }
                        current.push_str(dir.to_str().ok_or_else(|| {
                            crate::Error::FileTransferError("Invalid UTF-8 in path".to_string())
                        })?);

                        if !sftp.try_exists(&current).await.unwrap_or(false) {
                            sftp.create_dir(&current).await?;
                        }
                    }
                    Component::RootDir => current.push(std::path::MAIN_SEPARATOR),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    async fn ensure_transfer_helper(
        &self,
        sftp: &russh_sftp::client::SftpSession,
    ) -> crate::Result<()> {
        if !sftp
            .try_exists("C:\\Temp\\transfer_file.bat")
            .await
            .unwrap_or(false)
        {
            let mut helper = sftp.create("C:\\Temp\\transfer_file.bat").await?;
            helper.write_all(crate::TRANSFER_HELPER.as_bytes()).await?;
        }
        Ok(())
    }

   pub async fn batch_transfer_file(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_destination: &str,
    ) -> crate::Result<()> {
        let port_number = 49152 + rand::random::<u16>() % 16384;

        let rule = format!(
            "cmd.exe /c netsh advfirewall firewall add rule name=\"Allow Port {}\" dir=in action=allow protocol=TCP localport={}",
            port_number, port_number
        );

        let rule_output = self.exec(&crate::cmd!(rule)).await?;
        let start_helper = format!(
            "cmd.exe /c wmic process call create 'C:\\Temp\\transfer_file.bat {} 0.0.0.0 {} receive'",
            port_number, remote_destination
        );
        let helper = self.exec(&crate::cmd!(start_helper)).await?;
        let helper_output = String::from_utf8_lossy(&helper.stdout);


        match self.connect_with_retry(port_number).await {
            Ok(stream) => {
                self.send_file_data(stream, &file_contents).await
            }
            Err(e) => {
                self.exec(&crate::cmd!(format!("cmd.exe /c netsh advfirewall firewall delete rule name=\"Allow Port {}\"", port_number))).await?;
                return Err(e);
            }
        }
    }

    async fn connect_with_retry(&self, port_number: u16) -> crate::Result<TcpStream> {
        let socket = format!("{}:{}", self.config.ip(), port_number);

        for attempt in 0..5 {
            match TcpStream::connect(&socket).await {
                Ok(stream) => return Ok(stream),
                Err(_) if attempt < 4 => {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(_) => break,
            }
        }

        Err(crate::Error::FileTransferError(
            "Failed to connect after 5 attempts".to_string(),
        ))
    }

    async fn send_file_data(
        &self,
        mut stream: TcpStream,
        file_contents: &[u8],
    ) -> crate::Result<()> {
        let file_size = file_contents.len() as u64;
        let mut size_buffer = vec![];
        WriteBytesExt::write_u64::<BigEndian>(&mut size_buffer, file_size)?;

        stream.write_all(&size_buffer).await?;
        stream.write_all(file_contents).await?;

        Ok(())
    }
}

impl Config for SSHConfig {
    type SessionType = SSHSession;

    async fn create_session(&self) -> crate::Result<Self::SessionType> {
        match self {
            SSHConfig::Key {
                key_path,
                inactivity_timeout,
                username,
                socket,
            } => {
                let mut session = get_handle(*socket, *inactivity_timeout).await?;

                let key_pair = load_secret_key(key_path, None)?;
                let auth_res = session
                    .authenticate_publickey(
                        username,
                        PrivateKeyWithHashAlg::new(Arc::new(key_pair), None)?,
                    )
                    .await?;

                if !auth_res {
                    return Err(crate::Error::AuthenticationError(
                        "Failed to authenticate with public key".to_string(),
                    ));
                }

                Ok(SSHSession {
                    session,
                    config: self.clone(),
                })
            }
            SSHConfig::Password {
                username,
                socket,
                password,
                inactivity_timeout,
            } => {
                let mut session = get_handle(*socket, *inactivity_timeout).await?;
                let auth_res = session.authenticate_password(username, password).await?;

                if !auth_res {
                    return Err(crate::Error::AuthenticationError(
                        "Failed to authenticate with password".to_string(),
                    ));
                }

                Ok(SSHSession {
                    session,
                    config: self.clone(),
                })
            }
        }
    }
}

async fn get_handle<S: ToSocketAddrs>(
    socket: S,
    timeout: Duration,
) -> crate::Result<russh::client::Handle<Handler>> {
    let config = client::Config {
        inactivity_timeout: Some(timeout),
        ..Default::default()
    };

    let config = Arc::new(config);
    let sh = Handler {};
    Ok(client::connect(config, socket, sh).await?)
}

struct Handler {}

#[async_trait]
impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_ssh_config_key() {
        let config = SSHConfig::password(
            "Administrator",
            "Cheesed2MeetU!",
            "10.100.136.132:22",
            Duration::from_secs(60),
        )
        .await
        .unwrap();

        let session = config.create_session().await.unwrap();

        let chimera = include_bytes!("../../chimera.exe");

        session
            .transfer_file(Arc::new(chimera.into()), "C:\\Temp\\womp.exe")
            .await
            .unwrap();
        let output = session.exec(&Command::new("dir C:\\Temp")).await.unwrap();

        session.download_file("C:\\Temp\\womp.exe", "womp.exe")
            .await
            .unwrap();
        println!("{:?}", output);
    }
}
