use futures::future::{join_all, BoxFuture};
use rustrc::client::{Client, Command, CommandOutput, Config};
use rustrc::ssh::SSHConfig;
use rustrc::winexe::WinexeConfig;
use std::pin::Pin;
use std::time::Duration;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OS {
    Windows,
    Unix,
    Unknown,
}

pub enum OSConfig {
    Windows(WinexeConfig),
    Unix(SSHConfig),
    Unknown(SSHConfig),
}

impl OSConfig {
    pub fn os_type(&self) -> OS {
        match self {
            OSConfig::Windows(_) => OS::Windows,
            OSConfig::Unix(_) => OS::Unix,
            OSConfig::Unknown(_) => OS::Unknown,
        }
    }

    pub async fn connect(self) -> Result<(OS, Box<dyn ClientWrapper>)> {
        match self {
            OSConfig::Windows(config) => {
                let client = Client::connect(config).await?;
                Ok((
                    OS::Windows,
                    Box::new(WindowsClientWrapper(client)) as Box<dyn ClientWrapper>,
                ))
            }
            OSConfig::Unix(config) => {
                let client = Client::connect(config).await?;
                Ok((
                    OS::Unix,
                    Box::new(UnixClientWrapper(client)) as Box<dyn ClientWrapper>,
                ))
            }
            OSConfig::Unknown(config) => {
                let client = Client::connect(config).await?;
                Ok((
                    OS::Unknown,
                    Box::new(UnknownClientWrapper(client)) as Box<dyn ClientWrapper>,
                ))
            }
        }
    }
}

pub trait ClientWrapper: Send + Sync {
    fn exec<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>>;
    fn disconnect<'a>(&'a mut self) -> BoxFuture<'a, Result<()>>;
}

macro_rules! impl_client_wrapper {
    ($name:ident, $config:ty) => {
        struct $name(Client<$config>);

        impl ClientWrapper for $name {
            fn exec<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>> {
                Box::pin(async move { self.0.exec(cmd).await.map_err(Into::into) })
            }

            fn disconnect<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
                Box::pin(async move { self.0.disconnect().await.map_err(Into::into) })
            }
        }
    };
}

impl_client_wrapper!(WindowsClientWrapper, WinexeConfig);
impl_client_wrapper!(UnixClientWrapper, SSHConfig);
impl_client_wrapper!(UnknownClientWrapper, SSHConfig);

pub struct Communicator {
    clients: Vec<(OS, Box<dyn ClientWrapper>)>,
}

impl Communicator {
    pub async fn new(configs: Vec<OSConfig>) -> Result<Self> {
        let clients = join_all(configs.into_iter().map(OSConfig::connect))
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        Ok(Communicator { clients })
    }

    pub async fn disconnect_all(&mut self) -> Result<()> {
        let futures: Vec<_> = self
            .clients
            .iter_mut()
            .map(|(_, client)| client.disconnect())
            .collect();
        join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        Ok(())
    }

    pub async fn exec_by_os(&self, cmd: &Command, os_type: OS) -> Vec<Result<CommandOutput>> {
        let futures: Vec<_> = self
            .clients
            .iter()
            .filter(|(client_os, _)| *client_os == os_type)
            .map(|(_, client)| client.exec(cmd))
            .collect();
        join_all(futures).await
    }

    pub async fn exec_all(&self, cmd: &Command) -> Vec<Result<CommandOutput>> {
        let futures: Vec<_> = self
            .clients
            .iter()
            .map(|(_, client)| client.exec(cmd))
            .collect();
        join_all(futures).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustrc::cmd;

    #[tokio::test]
    async fn test_communicator() {
        let configs = vec![
            OSConfig::Unix(
                SSHConfig::password(
                    "m00nl1g7",
                    "139.182.180.243:22",
                    "",
                    Duration::from_secs(30),
                )
                .await
                .unwrap(),
            ),
            OSConfig::Windows(
                WinexeConfig::password(
                    "",
                    "139.182.180.178",
                    "",
                    Duration::from_secs(30),
                )
                .await
                .unwrap(),
            ),
        ];

        let communicator = Communicator::new(configs).await.unwrap();

        let unix_cmd = cmd!("ls", "-l");
        let unix_results = communicator.exec_by_os(&unix_cmd, OS::Unix).await;

        let win_cmd = cmd!("dir");
        let win_results = communicator.exec_by_os(&win_cmd, OS::Windows).await;

        let all_cmd = cmd!("echo", "Hello, World!");
        let all_results = communicator.exec_all(&all_cmd).await;
    }
}
