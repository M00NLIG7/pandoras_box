use crate::{Error, Result, OS};
use futures::future::{join_all, BoxFuture};
use futures::StreamExt;
use log::{debug, error, info};
use rustrc::client::{Client, Command, CommandOutput, Config};
use rustrc::ssh::SSHConfig;
use rustrc::winexe::WinexeConfig;
use rustrc::cmd;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

    pub fn get_clients_by_os(&self, os_type: OS) -> Vec<(OS, &IpAddr, &Arc<dyn ClientWrapper>)> {
        self.clients
            .iter()
            .filter(|(client_os, _, _)| *client_os == os_type)
            .map(|(os, ip, client)| (*os, ip, client))
            .collect()
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
        tokio::time::sleep(Duration::from_secs(1)).await;

        join_all(
            self.clients
                .iter()
                .filter(|(client_os, _, _)| *client_os == os_type)
                .map(|(os, ip, client)| async move {
                    let result = client.exec(cmd).await;
                    if let Err(e) = &result {
                        if *os == OS::Unix {
                            error!("Retrying with sudo");
                            let sudo_cmd = format!("sudo {}", cmd.to_string());

                            let cmd = &cmd!(sudo_cmd);

                            return HostOperationResult {
                                ip: ip.to_string(),
                                os: *os,
                                result: client.exec(cmd).await,
                            };
                        }
                    }
                    HostOperationResult {
                        ip: ip.to_string(),
                        os: *os,
                        result
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
        tokio::time::sleep(Duration::from_secs(1)).await;

        join_all(
            self.clients
                .iter()
                .filter(|(client_os, _, _)| *client_os == os_type)
                .map(|(os, ip, client)| {
                    let dest_clone = destination_path.clone();
                    let local_dir = local_path.clone();
                    async move {
                        let local_path = format!("{}{}", local_dir, ip);

                        // First verify the remote file
                        let verify_cmd = match os {
                            OS::Windows => format!("cmd.exe /c dir \"{}\"", dest_clone),
                            OS::Unix => format!("ls -l \"{}\"", dest_clone),
                            OS::Unknown => {
                                return HostOperationResult {
                                    ip: ip.to_string(),
                                    os: *os,
                                    result: Err(Error::UnknownOS),
                                }
                            }
                        };

                        match client.exec(&rustrc::cmd!(verify_cmd)).await {
                            Ok(output) => {
                                let output_str = String::from_utf8_lossy(&output.stdout);
                                debug!("File verification output for {}: {}", ip, output_str);

                                if output_str.contains("not found")
                                    || output_str.contains("No such file")
                                {
                                    error!("Remote file not found on {}: {}", ip, dest_clone);
                                    return HostOperationResult {
                                        ip: ip.to_string(),
                                        os: *os,
                                        result: Err(Error::FileTransferError(format!(
                                            "Remote file not found on {}",
                                            ip
                                        ))),
                                    };
                                }
                            }
                            Err(e) => {
                                error!("Failed to verify file on {}: {}", ip, e);
                                return HostOperationResult {
                                    ip: ip.to_string(),
                                    os: *os,
                                    result: Err(e),
                                };
                            }
                        }

                        info!("Downloading from {} to {}", dest_clone, local_path);

                        // Try the download with detailed error logging
                        let result = match client
                            .download_file(dest_clone.clone(), local_path.clone())
                            .await
                        {
                            Ok(_) => {
                                // Verify the downloaded file
                                match tokio::fs::metadata(&local_path).await {
                                    Ok(metadata) => {
                                        if metadata.len() == 0 {
                                            error!("Downloaded empty file for {}", ip);
                                            Err(Error::FileTransferError(format!(
                                                "Downloaded empty file from {}",
                                                ip
                                            )))
                                        } else {
                                            info!(
                                                "Successfully downloaded {}B from {}",
                                                metadata.len(),
                                                ip
                                            );
                                            Ok(())
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to verify downloaded file for {}: {}",
                                            ip, e
                                        );
                                        Err(Error::FileTransferError(format!(
                                            "Failed to verify downloaded file: {}",
                                            e
                                        )))
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Download failed for {}: {}", ip, e);
                                Err(e)
                            }
                        };

                        HostOperationResult {
                            ip: ip.to_string(),
                            os: *os,
                            result,
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
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Use join_all like exec_by_os for sequential processing
        join_all(
            self.clients
                .iter()
                .filter(|(client_os, _, _)| *client_os == os_type)
                .map(|(os, ip, client)| {
                    let file_clone = Arc::clone(&file);
                    let dest_clone = destination.clone();
                    async move {
                        debug!("Starting transfer for {}", ip);
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

