mod platform;

use super::ModeExecutor;
use crate::error::{Error, Result};
use crate::types::{
    Container, ContainerNetwork, ContainerVolume, Disk, ExecutionMode, ExecutionResult, Host, User,
    UserInfo,
};
use crate::utils::CommandExecutor;
use platform::conn_info;

use futures::future::join_all;
use local_ip_address::local_ip;
use log::{debug, error};
use serde_json::{Map, Value};
use sysinfo::{CpuExt, DiskExt, System, SystemExt, UserExt};

pub struct InventoryMode {
    system: System,
}

impl ModeExecutor for InventoryMode {
    type Args = ();
    type ArgRequirement = super::Optional;

    async fn execute(&self, _args: Option<Self::Args>) -> ExecutionResult {
        match self.fetch_inventory().await {
            Ok(host) => ExecutionResult::new(
                ExecutionMode::Inventory,
                true,
                serde_json::to_string(&host).unwrap(),
            ),
            Err(e) => {
                error!("Failed to collect inventory: {}", e);
                ExecutionResult::new(
                    ExecutionMode::Inventory,
                    false,
                    format!("Inventory collection failed: {}", e),
                )
            }
        }
    }
}

impl InventoryMode {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        Self { system }
    }

    async fn fetch_inventory(&self) -> Result<Host> {
        let (connections, open_ports) = conn_info().await;

        Ok(Host {
            hostname: self.system.host_name().unwrap_or_default(),
            ip: local_ip().unwrap_or("0.0.0.0".parse().unwrap()).to_string(),
            os: self.system.long_os_version().unwrap_or_default(),
            cpu: self.system.cpus().first().unwrap().brand().into(),
            cores: self.system.cpus().len() as u8,
            memory: self.system.total_memory() / 1024 / 1024,
            disks: self.get_disks(),
            network_adapters: String::from(""),
            ports: open_ports,
            connections,
            services: platform::services().await,
            users: self.get_users(),
            shares: platform::shares(),
            containers: self.get_containers().await,
        })
    }

    fn get_disks(&self) -> Vec<Disk> {
        self.system
            .disks()
            .iter()
            .map(|disk| Disk {
                name: disk.name().to_str().unwrap().into(),
                mount_point: disk.mount_point().to_str().unwrap().into(),
                filesystem: String::from_utf8(disk.file_system().to_vec())
                    .unwrap()
                    .into(),
                total_space: disk.total_space() / 1024 / 1024,
                available_space: disk.available_space() / 1024 / 1024,
            })
            .collect()
    }

    fn get_users(&self) -> Vec<User> {
        self.system
            .users()
            .iter()
            .map(|user| User {
                name: user.name().into(),
                uid: user.id().to_string().into(),
                gid: user.group_id().to_string().into(),
                groups: user.groups().iter().cloned().collect(),
                is_admin: user.is_admin(),
                is_local: user.is_local(),
                shell: None,
            })
            .collect()
    }

    async fn get_containers(&self) -> Vec<Container> {
        if cfg!(target_os = "windows") {
            match self.get_generic_containers("docker.exe").await {
                Ok(containers) => containers,
                Err(e) => {
                    error!("Failed to get Windows containers: {}", e);
                    Vec::new()
                }
            }
        } else {
            let commands = vec!["docker", "podman"];
            let mut containers = Vec::new();

            let kubes = self.get_kubernetes_containers().await;

            containers.extend(match kubes {
                Ok(kubes) => kubes,
                Err(e) => {
                    error!("Failed to get Kubernetes containers: {}", e);
                    Vec::new()
                }
            });

            for command in commands {
                match self.get_generic_containers(command).await {
                    Ok(generic_containers) => containers.extend(generic_containers),
                    Err(e) => error!("Failed to get containers using {}: {}", command, e),
                }
            }
            containers
        }
    }

    async fn get_container_ids(&self, command: &str) -> Result<Vec<String>> {
        let output =
            match CommandExecutor::execute_command(command, Some(&["ps", "-q"]), None).await {
                Ok(output) => output,
                Err(e) => {
                    let err = Error::Execution(format!("Failed to get container IDs: {}", e));
                    error!("{}", err);
                    return Err(err);
                }
            };

        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    async fn get_generic_containers(&self, command: &str) -> Result<Vec<Container>> {
        let container_ids = self.get_container_ids(command).await?;
        debug!("Found {} containers for {}", container_ids.len(), command);

        let inspect_futures: Vec<_> = container_ids
            .iter()
            .map(|id| async move {
                let inspect_result =
                    CommandExecutor::execute_command(command, Some(&["inspect", id]), None).await;

                match inspect_result {
                    Ok(output) => {
                        let inspect_str = String::from_utf8_lossy(&output.stdout);
                        self.generic_container(&inspect_str)
                    }
                    Err(e) => {
                        let err =
                            Error::Execution(format!("Failed to inspect container {}: {}", id, e));
                        error!("{}", err);
                        Err(err)
                    }
                }
            })
            .collect();

        let results = join_all(inspect_futures).await;

        Ok(results
            .into_iter()
            .filter_map(|result| match result {
                Ok(container) => Some(container),
                Err(e) => {
                    error!("{}", e);
                    None
                }
            })
            .collect())
    }

    fn volumes_from_inspect(&self, mounts: &Option<&Vec<Value>>) -> Vec<ContainerVolume> {
        mounts.map_or(Vec::new(), |mounts| {
            mounts
                .iter()
                .filter_map(|mount| {
                    let source = mount["Source"].as_str()?;
                    let host_path = if cfg!(target_os = "windows") {
                        source.replace('/', "\\")
                    } else {
                        source.to_string()
                    };

                    Some(ContainerVolume {
                        host_path: host_path.into(),
                        container_path: mount["Destination"].as_str()?.into(),
                        mode: mount["Mode"].as_str()?.into(),
                        volume_name: mount["Name"].as_str()?.into(),
                        rw: mount["RW"].as_bool()?,
                        v_type: mount["Type"].as_str()?.into(),
                    })
                })
                .collect()
        })
    }

    fn networks_from_inspect(
        &self,
        networks: &Option<&Map<String, Value>>,
    ) -> Vec<ContainerNetwork> {
        networks.map_or(Vec::new(), |networks| {
            networks
                .iter()
                .map(|(name, network_data)| ContainerNetwork {
                    network_name: name.clone(),
                    ip: network_data["IPAddress"]
                        .as_str()
                        .unwrap_or_default()
                        .into(),
                    gateway: network_data["Gateway"].as_str().unwrap_or_default().into(),
                    mac_address: network_data["MacAddress"]
                        .as_str()
                        .unwrap_or_default()
                        .into(),
                })
                .collect()
        })
    }

    fn port_from_inspect(&self, port_map: &Option<&Map<String, Value>>) -> Vec<String> {
        port_map.map_or(Vec::new(), |ports_map| {
            ports_map
                .iter()
                .flat_map(|(container_port, host_ports)| {
                    host_ports
                        .as_array()
                        .map_or(Vec::new(), |host_ports_array| {
                            host_ports_array
                                .iter()
                                .filter_map(|host_port_details| {
                                    let host_ip =
                                        host_port_details["HostIp"].as_str().unwrap_or("0.0.0.0");
                                    let host_port =
                                        host_port_details["HostPort"].as_str().unwrap_or("");
                                    Some(format!("{}:{}->{}", host_ip, host_port, container_port))
                                })
                                .collect()
                        })
                })
                .collect()
        })
    }

    async fn get_kubernetes_containers(&self) -> Result<Vec<Container>> {
        let output = match CommandExecutor::execute_command(
            "kubectl",
            Some(&["get", "pods", "--all-namespaces", "-o", "json"]),
            None,
        )
        .await
        {
            Ok(output) => output,
            Err(e) => {
                let err = Error::Execution(format!("Failed to get Kubernetes pods: {}", e));
                error!("{}", err);
                return Err(err);
            }
        };

        let pods: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
            .map_err(|e| Error::Execution(format!("Failed to parse Kubernetes JSON: {}", e)))?;

        let mut containers = Vec::new();

        if let Some(items) = pods["items"].as_array() {
            for pod in items {
                let namespace = pod["metadata"]["namespace"].as_str().unwrap_or_default();
                let pod_name = pod["metadata"]["name"].as_str().unwrap_or_default();
                let pod_ip = pod["status"]["podIP"].as_str().unwrap_or_default();

                if let Some(pod_containers) = pod["spec"]["containers"].as_array() {
                    for container_spec in pod_containers {
                        let container_name = container_spec["name"].as_str().unwrap_or_default();

                        // Get container status
                        let status = if let Some(container_statuses) =
                            pod["status"]["containerStatuses"].as_array()
                        {
                            container_statuses
                                .iter()
                                .find(|status| status["name"].as_str() == Some(container_name))
                                .and_then(|status| status["state"].as_object())
                                .and_then(|state| state.keys().next())
                                .map(String::from)
                                .unwrap_or_else(|| "unknown".to_string())
                        } else {
                            "unknown".to_string()
                        };

                        // Get container ID
                        let container_id = if let Some(container_statuses) =
                            pod["status"]["containerStatuses"].as_array()
                        {
                            container_statuses
                                .iter()
                                .find(|status| status["name"].as_str() == Some(container_name))
                                .and_then(|status| status["containerID"].as_str())
                                .map(|id| id.replace("containerd://", ""))
                                .unwrap_or_default()
                        } else {
                            String::new()
                        };

                        // Get command
                        let cmd = container_spec["args"]
                            .as_array()
                            .map(|args| {
                                args.iter()
                                    .filter_map(|arg| arg.as_str())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();

                        // Get port bindings
                        let port_bindings = container_spec["ports"]
                            .as_array()
                            .map(|ports| {
                                ports
                                    .iter()
                                    .filter_map(|port| {
                                        let container_port = port["containerPort"].as_u64()?;
                                        let host_port =
                                            port["hostPort"].as_u64().unwrap_or(container_port);
                                        Some(format!("{}:{}", host_port, container_port))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        // Get volumes
                        let volumes = container_spec["volumeMounts"]
                            .as_array()
                            .map(|mounts| {
                                mounts
                                    .iter()
                                    .filter_map(|mount| {
                                        Some(ContainerVolume {
                                            host_path: mount["name"].as_str()?.into(),
                                            container_path: mount["mountPath"].as_str()?.into(),
                                            mode: "rw".into(),
                                            volume_name: mount["name"].as_str()?.into(),
                                            rw: true,
                                            v_type: "volume".into(),
                                        })
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        // Create network info
                        let networks = vec![ContainerNetwork {
                            network_name: format!("{}/{}", namespace, pod_name),
                            ip: pod_ip.into(),
                            gateway: String::new(),
                            mac_address: String::new(),
                        }];

                        containers.push(Container {
                            name: container_name.into(),
                            image: container_spec["image"].as_str().unwrap_or_default().into(),
                            status,
                            container_id,
                            cmd,
                            port_bindings,
                            volumes,
                            networks,
                        });
                    }
                }
            }
        }

        Ok(containers)
    }

    fn generic_container(&self, inspect_data: &str) -> Result<Container> {
        let json: Value = serde_json::from_str(inspect_data).map_err(|e| {
            let err = Error::Execution(format!("Failed to parse container JSON: {}", e));
            error!("{}", err);
            err
        })?;

        let container_info = &json[0];

        Ok(Container {
            name: container_info["Name"].as_str().unwrap_or_default().into(),
            image: container_info["Config"]["Image"]
                .as_str()
                .unwrap_or_default()
                .into(),
            status: container_info["State"]["Status"]
                .as_str()
                .unwrap_or_default()
                .into(),
            container_id: container_info["Id"].as_str().unwrap_or_default().into(),
            cmd: container_info["Config"]["Cmd"]
                .as_array()
                .unwrap_or(&vec!["".into()])[0]
                .as_str()
                .unwrap_or_default()
                .into(),
            port_bindings: self
                .port_from_inspect(&container_info["NetworkSettings"]["Ports"].as_object()),
            volumes: self.volumes_from_inspect(&container_info["Mounts"].as_array()),
            networks: self
                .networks_from_inspect(&container_info["NetworkSettings"]["Networks"].as_object()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_inventory_mode() {
        let mode = InventoryMode::new();
        let result = mode.execute(None).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_cont() {
        let mode = InventoryMode::new();
        let containers = mode.get_containers().await;
        println!("{:?}", containers);
        assert!(!containers.is_empty());
    }
}
