use crate::{Result, OS};
use futures::future::{join_all, BoxFuture};
use rustrc::client::{Client, Command, CommandOutput, Config};
use rustrc::ssh::SSHConfig;
use rustrc::winexe::WinexeConfig;
use std::sync::Arc;

pub enum Either<L, R> {
    Left(L),
    Right(R),
}

pub type WindowsConfig = Either<WinexeConfig, SSHConfig>;

pub enum OSConfig {
    Windows(WindowsConfig),
    Unix(SSHConfig),
    Unknown(SSHConfig),
}

pub trait ClientWrapper: Send + Sync {
    fn exec<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>>;
    fn disconnect(&self) -> BoxFuture<'_, Result<()>>;
    fn transfer_file(&self, file: Arc<Vec<u8>>, destination: String) -> BoxFuture<'_, Result<()>>;
}

impl<C: Config + Send + Sync + 'static> ClientWrapper for Client<C>
where
    C::SessionType: Send + Sync + 'static,
{
    fn exec<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>> {
        Box::pin(async move { self.exec(cmd).await.map_err(Into::into) })
    }

    fn disconnect(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { self.disconnect().await.map_err(Into::into) })
    }

    fn transfer_file(&self, file: Arc<Vec<u8>>, destination: String) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { 
            self.transfer_file(file, &destination).await.map_err(Into::into)
        })
    }
}

impl OSConfig {
    pub fn os_type(&self) -> OS {
        match self {
            OSConfig::Windows(_) => OS::Windows,
            OSConfig::Unix(_) => OS::Unix,
            OSConfig::Unknown(_) => OS::Unknown,
        }
    }

    pub async fn connect(self) -> Result<(OS, Arc<dyn ClientWrapper>)> {
        match self {
            OSConfig::Windows(config) => {
                match config {
                    Either::Left(winexe_config) => {
                        let client = Client::connect(winexe_config).await?;
                        Ok((OS::Windows, Arc::new(client) as Arc<dyn ClientWrapper>))
                    }
                    Either::Right(ssh_config) => {
                        let client = Client::connect(ssh_config).await?;
                        Ok((OS::Windows, Arc::new(client) as Arc<dyn ClientWrapper>))
                    }
                }
            }
            OSConfig::Unix(config) => {
                let client = Client::connect(config).await?;
                Ok((OS::Unix, Arc::new(client) as Arc<dyn ClientWrapper>))
            }
            OSConfig::Unknown(config) => {
                let client = Client::connect(config).await?;
                Ok((OS::Unknown, Arc::new(client) as Arc<dyn ClientWrapper>))
            }
        }
    }
}

pub struct Communicator {
    clients: Vec<(OS, Arc<dyn ClientWrapper>)>,
}

impl Communicator {
    pub async fn new(configs: Vec<OSConfig>) -> Result<Self> {
        let clients = join_all(configs.into_iter().map(OSConfig::connect))
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        Ok(Communicator { clients })
    }

    pub async fn disconnect_all(&self) -> Result<()> {
        let futures: Vec<_> = self
            .clients
            .iter()
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

    pub async fn mass_file_transfer_by_os(&self, file: Arc<Vec<u8>>, destination: String, os_type: OS) -> Vec<Result<()>> {
        let futures: Vec<_> = self
            .clients
            .iter()
            .filter(|(client_os, _)| *client_os == os_type)
            .map(|(_, client)| {
                let file_clone = Arc::clone(&file);
                let dest_clone = destination.clone();
                client.transfer_file(file_clone, dest_clone)
            })
            .collect();
        join_all(futures).await
    }

    pub async fn mass_file_transfer_all(&self, file: Arc<Vec<u8>>, destination: String) -> Vec<Result<()>> {
        let futures: Vec<_> = self
            .clients
            .iter()
            .map(|(_, client)| {
                let file_clone = Arc::clone(&file);
                let dest_clone = destination.clone();
                client.transfer_file(file_clone, dest_clone)
            })
            .collect();
        join_all(futures).await
    }
}

pub fn windows_config<T: Config + 'static>(config: T) -> OSConfig {
    if std::any::TypeId::of::<T>() == std::any::TypeId::of::<WinexeConfig>() {
        OSConfig::Windows(Either::Left(unsafe { std::mem::transmute_copy(&config) }))
    } else if std::any::TypeId::of::<T>() == std::any::TypeId::of::<SSHConfig>() {
        OSConfig::Windows(Either::Right(unsafe { std::mem::transmute_copy(&config) }))
    } else {
        panic!("Unsupported config type for Windows")
    }
}

pub fn unix_config(config: SSHConfig) -> OSConfig {
    OSConfig::Unix(config)
}

pub fn unknown_config(config: SSHConfig) -> OSConfig {
    OSConfig::Unknown(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustrc::cmd;

    #[tokio::test]
    async fn test_communicator() {
        let configs = vec![
            unix_config(
                SSHConfig::password(
                    "",
                    "139.182.180.243:22",
                    "",
                    std::time::Duration::from_secs(30),
                )
                .await
                .unwrap(),
            ),
            windows_config(
                WinexeConfig::password(
                    "",
                    "",
                    "139.182.180.178",
                    std::time::Duration::from_secs(30),
                )
                .await
                .unwrap(),
            ),
            windows_config(
                SSHConfig::password(
                    "",
                    "139.182.180.179:22",
                    "",
                    std::time::Duration::from_secs(30),
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

        // Test file transfer
        let file_contents = Arc::new(b"Hello, World!".to_vec());
        let destination = "/tmp/test_file.txt".to_string();
        
        let unix_transfer_results = communicator.mass_file_transfer_by_os(Arc::clone(&file_contents), destination.clone(), OS::Unix).await;
        let windows_transfer_results = communicator.mass_file_transfer_by_os(Arc::clone(&file_contents), destination.clone(), OS::Windows).await;
        let all_transfer_results = communicator.mass_file_transfer_all(file_contents, destination).await;

        // Add assertions here to check the results

        communicator.disconnect_all().await.unwrap();
    }
}
