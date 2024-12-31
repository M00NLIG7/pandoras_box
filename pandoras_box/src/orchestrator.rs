use crate::communicator::{
    unix_config, windows_config, Communicator, HostOperationResult, OSConfig,
};
use crate::enumerator::{Enumerator, Subnet};
use crate::types::{Host, OS};
use crate::{Error, Result};
use rustrc::client::CommandOutput;
use rustrc::cmd;
use rustrc::ssh::SSHConfig;
use rustrc::winexe::WinexeConfig;

use futures::stream;
use futures::stream::StreamExt;

use futures::future::join_all;
use log::{error, info, warn};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::{log_failure, log_output, log_results, log_skipped, log_success};

// Constants for Chimera binaries (placeholder)
static CHIMERA_UNIX: &[u8] = include_bytes!("../resources/chimera");
static CHIMERA_WIN: &[u8] = include_bytes!("../resources/chimera.exe");

pub struct NetworkManager {
    enumerator: Enumerator,
    communicator: Option<Communicator>,
}

impl NetworkManager {
    pub fn new(subnet: Subnet) -> Self {
        let enumerator = Enumerator::new(subnet);
        Self {
            enumerator,
            communicator: None,
        }
    }

    pub async fn enumerate(&self) -> Result<Vec<Arc<Host>>> {
        info!("Starting network enumeration");
        let hosts = self.enumerator.sweep().await?;
        for host in &hosts {
            info!(
                "Enumerated host: {} (OS: {:?}, Open ports: {:?})",
                host.ip, host.os, host.open_ports
            );
        }
        Ok(hosts)
    }
    pub fn get_communicator(&self) -> Option<&Communicator> {
        self.communicator.as_ref()
    }
    async fn create_single_config(
        &self,
        host: &Arc<Host>,
        password: &str,
    ) -> Result<(OSConfig, Option<Arc<Host>>)> {
        // Changed return type
        info!(
            "Creating config for host {} (OS: {:?}, Open ports: {:?})",
            host.ip, host.os, host.open_ports
        );

        let socket_addr = (host.ip.clone(), 22)
            .to_socket_addrs()
            .map_err(|e| Error::InvalidIP(e.to_string()))?
            .find(|addr| addr.is_ipv4())
            .ok_or_else(|| Error::InvalidIP("No valid IPv4 address found".into()))?;

        match host.os {
            OS::Unix | OS::Unknown => self.create_unix_config(host, password, socket_addr).await,
            OS::Windows => {
                // Windows config doesn't return updated host
                self.create_windows_config(host, password, socket_addr)
                    .await
                    .map(|config| (config, None))
            }
        }
    }

    async fn create_os_configs(
        &self,
        hosts: &[Arc<Host>],
        password: &str,
    ) -> Result<Vec<(Arc<Host>, Result<OSConfig>)>> {
        // Changed return type to match what we need
        Ok(stream::iter(hosts)
            .map(|host| async move {
                match self.create_single_config(host, password).await {
                    Ok((config, maybe_updated_host)) => (
                        maybe_updated_host.unwrap_or_else(|| Arc::clone(host)),
                        Ok(config),
                    ),
                    Err(e) => (Arc::clone(host), Err(e)),
                }
            })
            .buffer_unordered(32)
            .collect()
            .await)
    }

    pub async fn initialize_communication(
        &mut self,
        hosts: &[Arc<Host>],
        network_password: &str,
    ) -> Result<Vec<Arc<Host>>> {
        info!(
            "Starting communication initialization for {} hosts",
            hosts.len()
        );

        let config_results = self.create_os_configs(hosts, network_password).await?;

        let (successful_configs, successful_hosts): (Vec<_>, Vec<_>) = config_results
            .into_iter()
            .filter_map(|(host, config_result)| match config_result {
                Ok(config) => Some(((host.ip.parse().expect("Invalid IP"), config), host)), // Now includes IP in the tuple
                Err(e) => {
                    warn!("Failed to create config for {}: {}", host.ip, e);
                    None
                }
            })
            .unzip();

        if successful_configs.is_empty() {
            error!("No successful configurations created");
            return Err(Error::CommunicatorError(
                "No successful configurations".into(),
            ));
        }

        match Communicator::new(successful_configs).await {
            Ok(comm) => {
                self.communicator = Some(comm);
                info!(
                    "Successfully initialized communicator with {}/{} hosts",
                    successful_hosts.len(),
                    hosts.len()
                );
                Ok(successful_hosts)
            }
            Err(e) => {
                error!("Failed to initialize communicator: {}", e);
                Err(e)
            }
        }
    }

    async fn create_unix_config(
        &self,
        host: &Arc<Host>,
        password: &str,
        socket_addr: SocketAddr,
    ) -> Result<(OSConfig, Option<Arc<Host>>)> {
        // Now returns potential new host
        if !host.open_ports.contains(&22) {
            warn!("Skipping Unix/Unknown host without SSH: {}", host.ip);
            return Err(Error::NoSSHPort);
        }

        match SSHConfig::password("root", password, socket_addr, Duration::from_secs(30)).await {
            Ok(config) => {
                let updated_host = if host.os == OS::Unknown {
                    // Create new Host with Unix OS
                    let mut new_host = (**host).clone();
                    new_host.os = OS::Unix;
                    Some(Arc::new(new_host))
                } else {
                    None
                };
                Ok((unix_config(config), updated_host))
            }
            Err(e) => {
                warn!("Failed to create SSH config for {}: {}", host.ip, e);
                Err(e.into())
            }
        }
    }

    async fn create_windows_config(
        &self,
        host: &Arc<Host>,
        password: &str,
        socket_addr: SocketAddr,
    ) -> Result<OSConfig> {
        if host.open_ports.contains(&22) {
            match self.try_windows_ssh(password, socket_addr).await {
                Ok(config) => return Ok(config),
                Err(e) => warn!(
                    "SSH failed for Windows host {}: {}, trying WinExe",
                    host.ip, e
                ),
            }
        }

        self.try_windows_winexe(host, password).await
    }

    async fn try_windows_ssh(&self, password: &str, socket_addr: SocketAddr) -> Result<OSConfig> {
        SSHConfig::password(
            "Administrator",
            password,
            socket_addr,
            Duration::from_secs(30),
        )
        .await
        .map(windows_config)
        .map_err(Into::into)
    }

    async fn try_windows_winexe(&self, host: &Arc<Host>, password: &str) -> Result<OSConfig> {
        WinexeConfig::password("Administrator", password, &host.ip, Duration::from_secs(30))
            .await
            .map(windows_config)
            .map_err(|e| {
                warn!("Failed to create WinExe config for {}: {}", host.ip, e);
                e.into()
            })
    }
}

pub struct Orchestrator {
    network_manager: NetworkManager,
}

impl Orchestrator {
    pub fn new(subnet: Subnet) -> Self {
        info!("Initializing Orchestrator for subnet {}", subnet);
        let network_manager = NetworkManager::new(subnet);
        Self { network_manager }
    }

    pub async fn run(&mut self, network_password: &str) -> Result<()> {
        info!("Starting Orchestrator run");

        // Step 1: Enumerate hosts
        let hosts = match self.network_manager.enumerate().await {
            Ok(hosts) => {
                info!("Successfully enumerated {} hosts", hosts.len());
                hosts
            }
            Err(e) => {
                error!("Enumeration failed: {}", e);
                return Err(e);
            }
        };

        // Step 2: Initialize communication
        let connected_hosts = match self
            .network_manager
            .initialize_communication(&hosts, network_password)
            .await
        {
            Ok(connected) => {
                info!(
                    "Communication initialized successfully for {}/{} hosts",
                    connected.len(),
                    hosts.len()
                );
                connected
            }
            Err(e) => {
                error!("All communication initialization attempts failed: {}", e);
                return Err(e);
            }
        };

        if connected_hosts.is_empty() {
            error!("No hosts successfully connected");
            return Err(Error::CommandError("No hosts available".into()));
        }

        // Step 3: Deploy Chimera to successfully connected hosts
        let deployment_results = self.deploy_chimera(&connected_hosts).await;
        let deployed_hosts: Vec<Arc<Host>> = deployment_results
            .iter()
            .filter_map(|(host, result)| match result {
                Ok(_) => Some(host.clone()),
                Err(e) => {
                    error!("Failed to deploy to {}: {}", host.ip, e);
                    None
                }
            })
            .collect();

        if deployed_hosts.is_empty() {
            error!("No hosts successfully deployed");
            return Err(Error::CommandError("No successful deployments".into()));
        }

        // Step 4: Execute Chimera modes on successfully deployed hosts
        let execution_results = self.execute_chimera_modes(&deployed_hosts).await;
        for result in &execution_results {
            match &result.result {
                Ok(_) => info!("Successfully executed Chimera on {}", result.ip),
                Err(e) => error!("Failed to execute Chimera on {}: {}", result.ip, e),
            }
        }

        info!(
            "Orchestrator run completed. Summary:\n\
             Total hosts: {}\n\
             Successfully connected: {}\n\
             Successfully deployed: {}",
            hosts.len(),
            connected_hosts.len(),
            deployed_hosts.len()
        );
        Ok(())
    }

    async fn deploy_for_os(
        &self,
        communicator: &Communicator,
        hosts: &[Arc<Host>],
        os: OS,
        binary: &[u8],
        path: &str,
        extra_setup: Option<&rustrc::client::Command>,
    ) -> Vec<(Arc<Host>, Result<()>)> {
        // Run any extra setup if needed
        if let Some(setup_cmd) = extra_setup {
            let setup_results = communicator.exec_by_os(setup_cmd, os).await;
            for result in &setup_results {
                if let Err(e) = &result.result {
                    warn!(
                        "Setup command failed for {} ({}): {}",
                        result.ip, result.os, e
                    );
                }
            }
        }

        // Do the transfer
        let transfer_results = communicator
            .mass_file_transfer_by_os(Arc::new(binary.to_vec()), path.to_string(), os)
            .await;

        // Map results back to hosts
        let host_map: std::collections::HashMap<String, Arc<Host>> = hosts
            .iter()
            .map(|h| (h.ip.clone(), Arc::clone(h)))
            .collect();

        // For Unix, we need to handle chmod on a per-host basis
        if matches!(os, OS::Unix) {
            let chmod_cmd = format!("chmod +x {}", path);

            let chmod_results = communicator
                .exec_by_os(&rustrc::cmd!(chmod_cmd), os)
                .await;

            // Create a map of chmod results by IP
            let chmod_map: std::collections::HashMap<String, Result<()>> = chmod_results
                .into_iter()
                .map(|r| (r.ip, r.result.map(|_| ())))
                .collect();

            // Process transfer results with chmod results
            transfer_results
                .into_iter()
                .filter_map(|tr| {
                    let host = host_map.get(&tr.ip)?;
                    let chmod_result = chmod_map.get(&tr.ip)?;

                    match (tr.result, chmod_result) {
                        (Ok(_), Ok(_)) => {
                            log_success("Deployment complete", &tr.ip.to_string());
                            Some((Arc::clone(host), Ok(())))
                        }
                        (Err(e), _) => {
                            log_failure("file transfer", &tr.ip.to_string(), &e);
                            Some((Arc::clone(host), Err(e)))
                        }
                        (Ok(_), Err(e)) => {
                            log_failure("chmod", &tr.ip.to_string(), e);
                            Some((
                                Arc::clone(host),
                                Err(Error::DeploymentError("Chmod failed".into())),
                            ))
                        }
                    }
                })
                .collect()
        } else {
            // For non-Unix, just handle transfer results
            transfer_results
                .into_iter()
                .filter_map(|tr| {
                    let host = host_map.get(&tr.ip)?;
                    match tr.result {
                        Ok(_) => {
                            log_success("Deployment complete", &tr.ip.to_string());
                            Some((Arc::clone(host), Ok(())))
                        }
                        Err(e) => {
                            log_failure("file transfer", &tr.ip.to_string(), &e);
                            Some((Arc::clone(host), Err(e)))
                        }
                    }
                })
                .collect()
        }
    }

    async fn deploy_chimera(&self, hosts: &[Arc<Host>]) -> Vec<(Arc<Host>, Result<()>)> {
        let communicator = match self.network_manager.get_communicator() {
            Some(comm) => comm,
            None => return self.handle_missing_communicator(hosts),
        };

        let mut all_results = Vec::new();

        // Deploy to Unix hosts
        all_results.extend(
            self.deploy_for_os(
                communicator,
                hosts,
                OS::Unix,
                CHIMERA_UNIX,
                "/tmp/chimera",
                None,
            )
            .await,
        );

        // Deploy to Windows hosts
        all_results.extend(
            self.deploy_for_os(
                communicator,
                hosts,
                OS::Windows,
                CHIMERA_WIN,
                "C:\\Temp\\chimera.exe",
                Some(&rustrc::cmd!("md C:\\Temp")),
            )
            .await,
        );

        // Handle unknown OS hosts
        all_results.extend(
            hosts
                .iter()
                .filter(|h| matches!(h.os, OS::Unknown))
                .map(|host| {
                    warn!("Skipping deployment to unknown OS host: {}", host.ip);
                    log_skipped("deploy", &host.ip.to_string(), "unknown OS");
                    (Arc::clone(host), Err(Error::UnknownOS))
                }),
        );

        all_results
    }

    fn handle_missing_communicator(&self, hosts: &[Arc<Host>]) -> Vec<(Arc<Host>, Result<()>)> {
        hosts
            .iter()
            .map(|host| {
                (
                    Arc::clone(host),
                    Err(Error::CommandError("Communicator not initialized".into())),
                )
            })
            .collect()
    }

    async fn execute_chimera_modes(
        &self,
        hosts: &[Arc<Host>],
    ) -> Vec<HostOperationResult<CommandOutput>> {
        info!("Executing Chimera modes on {} hosts", hosts.len());

        let communicator = match self.network_manager.get_communicator() {
            Some(comm) => comm,
            None => {
                return hosts
                    .iter()
                    .map(|host| HostOperationResult {
                        ip: host.ip.to_string(),
                        os: host.os,
                        result: Err(Error::CommandError("Communicator not initialized".into())),
                    })
                    .collect();
            }
        };

        // Execute inventory mode for each host
        join_all(hosts.iter().map(|host| async {
            self.execute_chimera_mode(host, communicator, "inventory")
                .await
        }))
        .await
        .into_iter()
        .map(|result| result)
        .collect()
    }

    async fn execute_chimera_mode(
        &self,
        host: &Arc<Host>,
        communicator: &Communicator,
        mode: &str,
    ) -> HostOperationResult<CommandOutput> {
        info!(
            "Executing {} mode on host: {} (OS: {:?})",
            mode, host.ip, host.os
        );

        let unix_cmd = format!("/tmp/chimera {} > chimera_inv.json", mode);
        let win_cmd = format!("C:\\Temp\\chimera.exe {} > chimera_inv.json", mode);

        let command = match host.os {
            OS::Unix => cmd!(unix_cmd),
            OS::Windows => cmd!(win_cmd),
            OS::Unknown => {
                warn!("Skipping unknown OS host: {}", host.ip);
                log_skipped("execute Chimera", &host.ip, "unknown OS");
                return HostOperationResult {
                    ip: host.ip.clone(),
                    os: host.os,
                    result: Err(Error::UnknownOS),
                };
            }
        };

        let results = communicator.exec_by_os(&command, host.os).await;
        for result in &results {
            match &result.result {
                Ok(output) => {
                    info!("Successfully executed {} mode on {}", mode, result.ip);
                    log_success(
                        &format!("execute Chimera in {} mode", mode),
                        &result.ip.to_string(),
                    );
                    log_output(&output.stdout, &output.stderr);
                }
                Err(e) => {
                    error!("Failed to execute {} mode on {}: {}", mode, result.ip, e);
                    log_failure(
                        &format!("execute Chimera in {} mode", mode),
                        &result.ip.to_string(),
                        e,
                    );
                }
            }
        }

        // Return the result for this specific host
        results
            .into_iter()
            .find(|r| r.ip == host.ip)
            .unwrap_or_else(|| HostOperationResult {
                ip: host.ip.clone(),
                os: host.os,
                result: Err(Error::CommandError("No result found for host".into())),
            })
    }
}

#[tokio::test]
async fn test_main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let subnet = Subnet::try_from("10.100.136.0/24")?;
    let mut orchestrator = Orchestrator::new(subnet);

    orchestrator.run("Cheesed2MeetU!").await

}
