use crate::client::{Command, CommandOutput, Config, Session};

use async_trait::async_trait;
use russh::client;
use russh_keys::key::PrivateKeyWithHashAlg;
use russh_keys::load_secret_key;
use russh_keys::ssh_key::public::PublicKey;
use std::{
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
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
}

/// Configuration for an SSH session
///
/// SSHConfig::Key is used to authenticate with a private key
/// SSHConfig::Password is used to authenticate with a password
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
    pub async fn key<U: Into<String>, S: ToSocketAddrs, P: Into<PathBuf>>(
        username: U,
        socket: S,
        key_path: P,
        inactivity_timeout: Duration,
    ) -> crate::Result<Self> {
        Ok(SSHConfig::Key {
            username: username.into(),
            socket: lookup_host(&socket)
                .await?
                .next()
                .ok_or_else(|| crate::Error::ConnectionError("Error Parsing Socket".to_string()))?,
            key_path: key_path.into(),
            inactivity_timeout,
        })
    }

    pub async fn password<U: Into<String>, S: ToSocketAddrs, P: Into<String> + Clone>(
        username: U,
        password: P,
        socket: S,
        inactivity_timeout: Duration,
    ) -> crate::Result<Self> {
        // Convert username first and store it
        let username_str = username.into();

        // Handle socket
        let socket_addr = lookup_host(&socket)
            .await?
            .next()
            .ok_or_else(|| crate::Error::ConnectionError("Error Parsing Socket".to_string()))?;

        // Convert password
        let password_str = password.into();

        let config = SSHConfig::Password {
            username: username_str,
            socket: socket_addr,
            password: password_str,
            inactivity_timeout,
        };

        Ok(config)
    }
}

impl Session for SSHSession {
    async fn disconnect(&mut self) -> crate::Result<()> {
        self.session
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }

    /// Execute a command on the remote host
    async fn exec(&self, cmd: &Command) -> crate::Result<CommandOutput> {
        // Look into this -------------> let mut channel = self.session.channel_open_direct_tcpip().await?;
        let mut channel = self.session.channel_open_session().await?;

        let command: Vec<u8> = cmd.into();

        channel.exec(true, command).await?;

        let mut code = None;

        let mut stdout = vec![];
        let stderr = vec![];

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
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

    async fn transfer_file(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> crate::Result<()> {
        let channel = self.session.channel_open_session().await?;

        // Request SFTP subsystem
        channel.request_subsystem(true, "sftp").await?;

        // Create new SFTP session from the channel
        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|_| crate::Error::FileTransferError("Failed to create SFTP session".into()))?;

        // Create the remote file
        let mut remote_file = match sftp.create(remote_dest).await {
            Ok(file) => file,
            Err(_) => {
                let path = Path::new(remote_dest);
                let parent = path.parent().ok_or_else(|| {
                    crate::Error::FileTransferError("Invalid remote path".to_string())
                })?;

                // Track the path as we build it
                let mut current_path = String::new();

                // Process each component of the parent path
                for component in parent.components() {
                    match component {
                        Component::Prefix(prefix) => {
                            current_path = prefix
                                .as_os_str()
                                .to_str()
                                .ok_or_else(|| {
                                    crate::Error::FileTransferError(
                                        "Invalid UTF-8 in path prefix".to_string(),
                                    )
                                })?
                                .to_string();
                        }
                        Component::RootDir => {
                            current_path.push(std::path::MAIN_SEPARATOR);
                        }
                        Component::Normal(dir) => {
                            if !current_path.is_empty() {
                                current_path.push(std::path::MAIN_SEPARATOR);
                            }
                            current_path.push_str(dir.to_str().ok_or_else(|| {
                                crate::Error::FileTransferError("Invalid UTF-8 in path".to_string())
                            })?);

                            if let Err(e) = sftp.create_dir(&current_path).await {
                                if !e.to_string().contains("already exists") {
                                    return Err(crate::Error::FileTransferError(format!(
                                        "Failed to create directory {}: {}",
                                        current_path, e
                                    )));
                                }
                            }
                        }
                        _ => {} // Skip CurDir and ParentDir components
                    }
                }

                sftp.create(remote_dest).await.map_err(|e| {
                    crate::Error::FileTransferError(format!("Failed to create remote file: {}", e))
                })?
            }
        };

        // Write the contents to the remote file
        remote_file.write_all(&file_contents).await.map_err(|e| {
            crate::Error::FileTransferError(format!("Failed to write to remote file: {}", e))
        })?;

        // Shutdown the file handle
        remote_file.shutdown().await.map_err(|e| {
            crate::Error::FileTransferError(format!("Failed to close remote file: {}", e))
        })?;

        Ok(())
    }
}

impl Config for SSHConfig {
    type SessionType = SSHSession;

    /// Create a new SSH session
    async fn create_session(&self) -> crate::Result<Self::SessionType> {
        // Match on the SSHConfig variant to build the session
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

                Ok(SSHSession { session })
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

                Ok(SSHSession { session })
            }
        }
    }
}

/// Get a handle to the SSH session
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

    let handle = client::connect(config, socket, sh).await?;

    Ok(handle)
}

struct Handler {}

#[async_trait]
impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Config;
    use std::time::Duration;

    #[tokio::test]
    async fn test_ssh_config_key() {
        let config = SSHConfig::password(
            "Administrator",
            "Cheesed2MeetU!",
            "10.100.136.43:22",
            Duration::from_secs(60),
        )
        .await
        .unwrap();

        let session = config.create_session().await.unwrap();

        session
            .transfer_file(Arc::new(b"Hello world".into()), "C:\\Temp\\chimera")
            .await
            .unwrap();
        let output = session.exec(&Command::new("dir C:\\Temp")).await.unwrap();
        println!("{:?}", output);
    }
}
