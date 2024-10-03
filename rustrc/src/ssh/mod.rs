use crate::client::{Command, CommandOutput, Config, Session};

use async_trait::async_trait;
use russh::client;
use russh_keys::{key::PublicKey, load_secret_key};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
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

    pub async fn password<U: Into<String>, S: ToSocketAddrs, P: Into<String>>(
        username: U,
        password: P,
        socket: S,
        inactivity_timeout: Duration,
    ) -> crate::Result<Self> {
        Ok(SSHConfig::Password {
            username: username.into(),
            socket: lookup_host(&socket)
                .await?
                .next()
                .ok_or_else(|| crate::Error::ConnectionError("Error Parsing Socket".to_string()))?,
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

    fn transfer_file(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> impl std::future::Future<Output = crate::Result<()>> + Send {
        async move { Ok(()) }
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
                    .authenticate_publickey(username, Arc::new(key_pair))
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
                password,
                inactivity_timeout,
                socket,
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
