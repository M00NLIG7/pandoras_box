use crate::{Error, Result, OS};
use futures::future::{join_all, BoxFuture};
use rustrc::client::{Client, Command, CommandOutput, Config};
use rustrc::ssh::SSHConfig;
use rustrc::winexe::WinexeConfig;
use std::net::IpAddr;
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

// Generic result type for operations that need to track which host they're associated with
#[derive(Debug)]
pub struct HostOperationResult<T> {
    pub ip: String,
    pub os: OS,
    pub result: Result<T>,
}

pub trait ClientWrapper: Send + Sync {
    fn exec<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>>;
    fn disconnect(&self) -> BoxFuture<'_, Result<()>>;
    fn transfer_file(&self, file: Arc<Vec<u8>>, destination: String) -> BoxFuture<'_, Result<()>>;
    fn download_file(&self, remote_path: String, local_path: String) -> BoxFuture<'_, Result<()>>;
    fn get_ip(&self) -> IpAddr;
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
            self.transfer_file(file, &destination)
                .await
                .map_err(Into::into)
        })
    }

    fn download_file(&self, remote_path: String, local_path: String) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.download_file(&remote_path, &local_path)
                .await
                .map_err(Into::into)
        })
    }

    fn get_ip(&self) -> IpAddr {
        unimplemented!("Implementation would depend on Client struct")
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

    pub async fn connect(self, ip: IpAddr) -> Result<(OS, IpAddr, Arc<dyn ClientWrapper>)> {
        match self {
            OSConfig::Windows(config) => match config {
                Either::Left(winexe_config) => match Client::connect(winexe_config).await {
                    Ok(client) => Ok((OS::Windows, ip, Arc::new(client) as Arc<dyn ClientWrapper>)),
                    Err(e) => Err(Error::CommunicatorError(format!(
                        "Winexe connection failed for {}: {}",
                        ip, e
                    ))),
                },
                Either::Right(ssh_config) => {
                    match Client::connect(ssh_config.clone()).await {
                        Ok(client) => {
                            Ok((OS::Windows, ip, Arc::new(client) as Arc<dyn ClientWrapper>))
                        }
                        Err(_) => {
                            // SSH failed, try Winexe fallback
                            match ssh_to_winexe(ssh_config, ip).await {
                                Ok(winexe_config) => match Client::connect(winexe_config).await {
                                    Ok(client) => Ok((
                                        OS::Windows,
                                        ip,
                                        Arc::new(client) as Arc<dyn ClientWrapper>,
                                    )),
                                    Err(e) => Err(Error::CommunicatorError(format!(
                                        "Both SSH and Winexe failed for {}: {}",
                                        ip, e
                                    ))),
                                },
                                Err(e) => Err(e),
                            }
                        }
                    }
                }
            },
            OSConfig::Unix(config) => match Client::connect(config).await {
                Ok(client) => Ok((OS::Unix, ip, Arc::new(client) as Arc<dyn ClientWrapper>)),
                Err(e) => Err(Error::CommunicatorError(format!(
                    "SSH connection failed for {}: {}",
                    ip, e
                ))),
            },
            OSConfig::Unknown(config) => match Client::connect(config).await {
                Ok(client) => Ok((OS::Unknown, ip, Arc::new(client) as Arc<dyn ClientWrapper>)),
                Err(e) => Err(Error::CommunicatorError(format!(
                    "Connection failed for unknown OS at {}: {}",
                    ip, e
                ))),
            },
        }
    }
}

pub struct Communicator {
    clients: Vec<(OS, IpAddr, Arc<dyn ClientWrapper>)>,
}

impl Communicator {
    pub async fn new(configs: Vec<(IpAddr, OSConfig)>) -> Result<Self> {
        let connection_results = join_all(configs.into_iter().map(|(ip, config)| async move {
            HostOperationResult {
                ip: ip.to_string(),
                os: config.os_type(),
                result: config.connect(ip).await,
            }
        }))
        .await;

        let mut clients = Vec::new();
        let mut errors = Vec::new();

        for result in connection_results {
            match result.result {
                Ok((os, ip, client)) => clients.push((os, ip, client)),
                Err(e) => errors.push(format!("{}:{:?} - {}", result.ip, result.os, e)),
            }
        }

        if clients.is_empty() {
            Err(Error::CommunicatorError(format!(
                "No successful connections established. Errors: {}",
                errors.join("; ")
            )))
        } else {
            Ok(Communicator { clients })
        }
    }

    pub async fn disconnect_all(&self) -> Vec<HostOperationResult<()>> {
        join_all(self.clients.iter().map(|(os, ip, client)| async move {
            HostOperationResult {
                ip: ip.to_string(),
                os: *os,
                result: client.disconnect().await,
            }
        }))
        .await
    }

    pub async fn exec_by_os(
        &self,
        cmd: &Command,
        os_type: OS,
    ) -> Vec<HostOperationResult<CommandOutput>> {
        join_all(
            self.clients
                .iter()
                .filter(|(client_os, _, _)| *client_os == os_type)
                .map(|(os, ip, client)| async move {
                    HostOperationResult {
                        ip: ip.to_string(),
                        os: *os,
                        result: client.exec(cmd).await,
                    }
                }),
        )
        .await
    }

    pub async fn exec_all(&self, cmd: &Command) -> Vec<HostOperationResult<CommandOutput>> {
        join_all(self.clients.iter().map(|(os, ip, client)| async move {
            HostOperationResult {
                ip: ip.to_string(),
                os: *os,
                result: client.exec(cmd).await,
            }
        }))
        .await
    }

    pub async fn mass_file_download_by_os(
        &self,
        destination_path: String,
        local_path: String,
        os_type: OS,
    ) -> Vec<HostOperationResult<()>> {
        join_all(
            self.clients
                .iter()
                .filter(|(client_os, _, _)| *client_os == os_type)
                .map(|(os, ip, client)| {
                    let dest_clone = destination_path.clone();
                    let local_dir = local_path.clone();
                    async move {
                        let local_path = format!("{}{}", local_dir, ip);
                        println!("Downloading from {} to {}", dest_clone, local_path);
                        HostOperationResult {
                            ip: ip.to_string(),
                            os: *os,
                            result: client.download_file(dest_clone, local_path).await,
                        }
                    }
                }),
        )
        .await
    }

    pub async fn mass_file_transfer_by_os(
        &self,
        file: Arc<Vec<u8>>,
        destination: String,
        os_type: OS,
    ) -> Vec<HostOperationResult<()>> {
        join_all(
            self.clients
                .iter()
                .filter(|(client_os, _, _)| *client_os == os_type)
                .map(|(os, ip, client)| {
                    let file_clone = Arc::clone(&file);
                    let dest_clone = destination.clone();
                    async move {
                        HostOperationResult {
                            ip: ip.to_string(),
                            os: *os,
                            result: client.transfer_file(file_clone, dest_clone).await,
                        }
                    }
                }),
        )
        .await
    }

    pub async fn mass_file_transfer_all(
        &self,
        file: Arc<Vec<u8>>,
        destination: String,
    ) -> Vec<HostOperationResult<()>> {
        join_all(self.clients.iter().map(|(os, ip, client)| {
            let file_clone = Arc::clone(&file);
            let dest_clone = destination.clone();
            async move {
                HostOperationResult {
                    ip: ip.to_string(),
                    os: *os,
                    result: client.transfer_file(file_clone, dest_clone).await,
                }
            }
        }))
        .await
    }
}

// Helper functions
pub fn windows_config(config: impl Into<WindowsConfig>) -> OSConfig {
    OSConfig::Windows(config.into())
}

impl From<WinexeConfig> for WindowsConfig {
    fn from(config: WinexeConfig) -> Self {
        WindowsConfig::Left(config)
    }
}

impl From<SSHConfig> for WindowsConfig {
    fn from(config: SSHConfig) -> Self {
        WindowsConfig::Right(config)
    }
}

async fn ssh_to_winexe(ssh_config: SSHConfig, ip: IpAddr) -> Result<WinexeConfig> {
    match ssh_config {
        SSHConfig::Password {
            username,
            password,
            inactivity_timeout,
            ..
        } => WinexeConfig::password(&username, &password, &ip.to_string(), inactivity_timeout)
            .await
            .map_err(|e| {
                Error::CommunicatorError(format!("Failed to create Winexe config: {}", e))
            }),
        SSHConfig::Key { .. } => Err(Error::CommunicatorError(
            "Cannot convert key-based SSH config to Winexe".into(),
        )),
    }
}

pub fn unix_config(config: SSHConfig) -> OSConfig {
    OSConfig::Unix(config)
}

pub fn unknown_config(config: SSHConfig) -> OSConfig {
    OSConfig::Unknown(config)
}

#[tokio::test]
async fn test_communicator() {
    use rustrc::client::Command;
    use rustrc::ssh::SSHConfig;
    use std::net::IpAddr;

    let ip1 = IpAddr::from([10, 100, 136, 7]);
    let ip2 = IpAddr::from([10, 100, 136, 241]);

    let socket_1 = format!("{}:{}", ip1, 22);
    let socket_2 = format!("{}:{}", ip2, 22);

    let config_1 = SSHConfig::password("Administrator", "Cheesed2MeetU!", socket_1, std::time::Duration::from_secs(60)).await.unwrap();
    let config_2 = SSHConfig::password("Administrator", "Cheesed2MeetU!", socket_2, std::time::Duration::from_secs(60)).await.unwrap();

    let communicator = Communicator::new(vec![
        (ip1, windows_config(config_1.clone())),
        (ip2, windows_config(config_2.clone())),
    ])
    .await
    .unwrap();

    let chimera_exe = include_bytes!("../../../../../chimera.exe");
    let results = communicator.mass_file_transfer_by_os(Arc::new(chimera_exe.to_vec()), "C:\\temp\\chimera.exe".into(), OS::Windows).await;
    for result in results {
        println!("{:?}", result);
    }

    let results = communicator.exec_by_os(&rustrc::cmd!("C:\\temp\\chimera.exe inventory > C:\\temp\\inventory.json"), OS::Windows).await;
    for result in results {
        println!("{:?}", result);
    }

    let results = communicator.mass_file_download_by_os("C:\\temp\\inventory.json".into(), "./inventory".into(), OS::Windows).await;

    for result in results {
        println!("{:?}", result);
    }
}
