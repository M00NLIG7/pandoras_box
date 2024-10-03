use crate::communicator::{unix_config, windows_config, Communicator, OSConfig};
use crate::enumerator::{Enumerator, Subnet};
use crate::types::{Host, OS};
use crate::Result;
use rustrc::cmd;
use rustrc::ssh::SSHConfig;
use rustrc::winexe::WinexeConfig;

use futures::future::join_all;
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::{log_failure, log_output, log_results, log_skipped, log_success};

// Constants for Chimera binaries (placeholder)
static CHIMERA_UNIX: &[u8] = include_bytes!("/etc/passwd");
static CHIMERA_WIN: &[u8] = include_bytes!("/etc/passwd");

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
        self.enumerator.sweep().await
    }

    pub async fn initialize_communication(
        &mut self,
        hosts: &[Arc<Host>],
        network_password: &str,
    ) -> Result<()> {
        let configs = self.create_os_configs(hosts, network_password).await?;
        self.communicator = Some(Communicator::new(configs).await?);
        Ok(())
    }

    pub fn get_communicator(&self) -> Option<&Communicator> {
        self.communicator.as_ref()
    }

    async fn create_os_configs(
        &self,
        hosts: &[Arc<Host>],
        password: &str,
    ) -> Result<Vec<OSConfig>> {
        let mut configs = Vec::new();

        for host in hosts {
            let config = match host.os {
                OS::Unix => unix_config(
                    SSHConfig::password("root", &host.ip, password, Duration::from_secs(30))
                        .await?,
                ),
                OS::Windows => {
                    if host.open_ports.contains(&22) {
                        windows_config(
                            SSHConfig::password(
                                "Administrator",
                                &host.ip,
                                password,
                                Duration::from_secs(30),
                            )
                            .await?,
                        )
                    } else {
                        windows_config(
                            WinexeConfig::password(
                                "Administrator",
                                password,
                                &host.ip,
                                Duration::from_secs(30),
                            )
                            .await?,
                        )
                    }
                }
                OS::Unknown => {
                    warn!(
                        "Skipping config creation for host with unknown OS: {}",
                        host.ip
                    );
                    continue;
                }
            };
            configs.push(config);
        }

        Ok(configs)
    }
}

pub struct Orchestrator {
    network_manager: NetworkManager,
}

impl Orchestrator {
    pub fn new(subnet: Subnet) -> Self {
        info!("Initializing Orchestrator");
        let network_manager = NetworkManager::new(subnet);
        Self { network_manager }
    }

    pub async fn run(&mut self, network_password: &str) -> Result<()> {
        info!("Starting Orchestrator run");

        // Step 1: Enumerate hosts
        let hosts = self.network_manager.enumerate().await?;
        info!("Enumerated {} hosts", hosts.len());

        // Step 2: Initialize communication
        self.network_manager
            .initialize_communication(&hosts, network_password)
            .await?;

        // Step 3: Deploy Chimera
        self.deploy_chimera(&hosts).await?;

        // Step 4: Execute Chimera in different modes
        self.execute_chimera_modes(&hosts).await?;

        log_success("Orchestrator run", "completed successfully");
        Ok(())
    }

    async fn deploy_chimera(&self, hosts: &[Arc<Host>]) -> Result<()> {
        info!("Deploying Chimera to prepared hosts");

        let communicator = self
            .network_manager
            .get_communicator()
            .ok_or_else(|| crate::Error::CommandError("Communicator not initialized".into()))?;

        let deployment_futures = hosts
            .iter()
            .map(|host| self.deploy_to_host(host.clone(), communicator));
        let results = join_all(deployment_futures).await;

        for result in results {
            if let Err(e) = result {
                error!("Failed to deploy Chimera: {}", e);
            }
        }

        Ok(())
    }

    async fn deploy_to_host(&self, host: Arc<Host>, communicator: &Communicator) -> Result<()> {
        match host.os {
            OS::Unix => {
                info!("Deploying Chimera to Unix host: {}", host.ip);
                let transfer_results = communicator
                    .mass_file_transfer_by_os(
                        Arc::new(CHIMERA_UNIX.to_vec()),
                        "/tmp/chimera".to_string(),
                        OS::Unix,
                    )
                    .await;

                log_results(transfer_results, "transfer Chimera", &host.ip.to_string());

                // Set execute permissions
                let chmod_results = communicator
                    .exec_by_os(&cmd!("chmod", "+x", "/tmp/chimera"), OS::Unix)
                    .await;
                log_results(
                    chmod_results,
                    "set execute permissions",
                    &host.ip.to_string(),
                );
            }
            OS::Windows => {
                info!("Deploying Chimera to Windows host: {}", host.ip);
                let transfer_results = communicator
                    .mass_file_transfer_by_os(
                        Arc::new(CHIMERA_WIN.to_vec()),
                        "C:\\Temp\\chimera.exe".to_string(),
                        OS::Windows,
                    )
                    .await;

                log_results(transfer_results, "transfer Chimera", &host.ip.to_string());
            }
            OS::Unknown => log_skipped("deploy", &host.ip, "unknown OS"),
        }
        Ok(())
    }

    async fn execute_chimera_modes(&self, hosts: &[Arc<Host>]) -> Result<()> {
        info!("Executing Chimera in different modes");

        let communicator = self
            .network_manager
            .get_communicator()
            .ok_or_else(|| crate::Error::CommandError("Communicator not initialized".into()))?;

        // Example modes - adjust based on your actual Chimera functionality
        self.execute_chimera_mode(hosts, communicator, "recon")
            .await?;
        self.execute_chimera_mode(hosts, communicator, "persist")
            .await?;
        self.execute_chimera_mode(hosts, communicator, "exfil")
            .await?;

        Ok(())
    }

    async fn execute_chimera_mode(
        &self,
        hosts: &[Arc<Host>],
        communicator: &Communicator,
        mode: &str,
    ) -> Result<()> {
        info!("Executing Chimera in {} mode", mode);
        for host in hosts {
            let command = match host.os {
                OS::Unix => cmd!("/tmp/chimera", "--mode", mode),
                OS::Windows => cmd!("C:\\Temp\\chimera.exe", "--mode", mode),
                OS::Unknown => {
                    log_skipped("execute Chimera", &host.ip, "unknown OS");
                    continue;
                }
            };

            let results = communicator.exec_by_os(&command, host.os).await;
            for (index, result) in results.into_iter().enumerate() {
                match result {
                    Ok(output) => {
                        log_success(
                            format!("execute Chimera in {} mode (execution {})", mode, index),
                            &host.ip,
                        );
                        log_output(&output.stdout, &output.stderr);
                    }
                    Err(e) => log_failure(
                        format!("execute Chimera in {} mode (execution {})", mode, index),
                        &host.ip,
                        e,
                    ),
                }
            }
        }
        Ok(())
    }
}

/*
// Example usage
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();

    let subnet = Subnet::try_from("192.168.1.0/24")?;
    let mut orchestrator = Orchestrator::new(subnet);

    orchestrator.run("network_password").await
}
*/
