mod platform;

use super::ModeExecutor;
use crate::error::{Error, Result};
use crate::types::{
    Container, ContainerNetwork, ContainerVolume, Disk, ExecutionMode, ExecutionResult, Host,
    InventorySection, InventorySectionError, User, UserInfo,
};
use crate::utils::CommandExecutor;
use platform::conn_info;

use futures::future::join_all;
use local_ip_address::local_ip;
use log::{debug, error};
use serde_json::{Map, Value};
use std::net::{IpAddr, Ipv4Addr};
use sysinfo::{CpuExt, DiskExt, System, SystemExt, UserExt};

pub struct InventoryMode {
    system: System,
}

impl ModeExecutor for InventoryMode {
    type Args = ();
    type ArgRequirement = super::Optional;

    async fn execute(&self, _args: Option<Self::Args>) -> ExecutionResult {
        match self.collect_inventory_json().await {
            Ok(inventory) => ExecutionResult::new(ExecutionMode::Inventory, true, inventory),
            Err(error) => {
                error!("Failed to collect inventory: {error}");
                ExecutionResult::new(
                    ExecutionMode::Inventory,
                    false,
                    format!("Inventory collection failed: {error}"),
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

    pub async fn collect_inventory_json(&self) -> Result<String> {
        let host = self.fetch_inventory().await?;
        serde_json::to_string(&host)
            .map_err(|e| Error::Execution(format!("Failed to serialize inventory: {}", e)))
    }

    async fn fetch_inventory(&self) -> Result<Host> {
        let mut section_errors = Vec::new();
        let (connections, open_ports, connection_errors) = conn_info().await;
        extend_section_errors(
            &mut section_errors,
            InventorySection::Connections,
            connection_errors,
        );

        let services = match platform::services().await {
            Ok(services) => services,
            Err(error) => {
                section_errors.push(InventorySectionError::new(
                    InventorySection::Services,
                    error.to_string(),
                ));
                Vec::new()
            }
        };
        let (shares, share_errors) = platform::shares();
        extend_section_errors(&mut section_errors, InventorySection::Shares, share_errors);
        let (containers, container_errors) = self.get_containers().await;
        extend_section_errors(
            &mut section_errors,
            InventorySection::Containers,
            container_errors,
        );

        let hostname = self.system.host_name().unwrap_or_default();
        if hostname.is_empty() {
            section_errors.push(InventorySectionError::new(
                InventorySection::Identity,
                "hostname was unavailable",
            ));
        }
        let ip = match local_ip() {
            Ok(ip) => ip,
            Err(error) => {
                section_errors.push(InventorySectionError::new(
                    InventorySection::Identity,
                    format!("primary IP address was unavailable: {error}"),
                ));
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        };
        let cpu = match self.system.cpus().first() {
            Some(cpu) => cpu.brand().to_string(),
            None => {
                section_errors.push(InventorySectionError::new(
                    InventorySection::Identity,
                    "CPU information was unavailable",
                ));
                String::new()
            }
        };

        Ok(Host {
            hostname,
            ip: ip.to_string(),
            os: self.system.long_os_version().unwrap_or_default(),
            cpu,
            cores: u8::try_from(self.system.cpus().len()).unwrap_or(u8::MAX),
            memory: self.system.total_memory() / 1024 / 1024,
            disks: self.get_disks(),
            network_adapters: String::new(),
            ports: open_ports,
            connections,
            services,
            users: self.get_users(),
            shares,
            containers,
            section_errors,
        })
    }

    fn get_disks(&self) -> Vec<Disk> {
        self.system
            .disks()
            .iter()
            .map(|disk| Disk {
                name: disk.name().to_string_lossy().into_owned(),
                mount_point: disk.mount_point().to_string_lossy().into_owned(),
                filesystem: String::from_utf8_lossy(disk.file_system()).into_owned(),
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
                uid: user.id().to_string(),
                gid: user.group_id().to_string(),
                groups: user.groups().to_vec(),
                is_admin: user.is_admin(),
                is_local: user.is_local(),
                shell: None,
            })
            .collect()
    }

    async fn get_containers(&self) -> (Vec<Container>, Vec<String>) {
        if cfg!(target_os = "windows") {
            self.get_generic_containers("docker.exe").await
        } else {
            let (kubernetes, docker, podman) = tokio::join!(
                self.get_kubernetes_containers(),
                self.get_generic_containers("docker"),
                self.get_generic_containers("podman")
            );
            let (mut docker_containers, mut errors) = docker;
            let (podman_containers, podman_errors) = podman;
            docker_containers.extend(podman_containers);
            errors.extend(podman_errors);
            match kubernetes {
                Ok(mut containers) => {
                    containers.extend(docker_containers);
                    (containers, errors)
                }
                Err(error) => {
                    errors.push(format!("Kubernetes inventory failed: {error}"));
                    (docker_containers, errors)
                }
            }
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

    async fn get_generic_containers(&self, command: &str) -> (Vec<Container>, Vec<String>) {
        let container_ids = match self.get_container_ids(command).await {
            Ok(container_ids) => container_ids,
            Err(error) => {
                return (
                    Vec::new(),
                    vec![format!("{command} inventory failed: {error}")],
                );
            }
        };
        debug!("Found {} containers for {}", container_ids.len(), command);

        let inspect_futures = container_ids.iter().map(|id| async move {
            let output = CommandExecutor::execute_command(command, Some(&["inspect", id]), None)
                .await
                .map_err(|error| {
                    Error::Execution(format!(
                        "failed to inspect {command} container {id}: {error}"
                    ))
                })?;
            self.generic_container(&String::from_utf8_lossy(&output.stdout))
        });

        let mut containers = Vec::new();
        let mut errors = Vec::new();
        for result in join_all(inspect_futures).await {
            match result {
                Ok(container) => containers.push(container),
                Err(error) => errors.push(error.to_string()),
            }
        }
        (containers, errors)
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
                        host_path,
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
                                .map(|host_port_details| {
                                    let host_ip =
                                        host_port_details["HostIp"].as_str().unwrap_or("0.0.0.0");
                                    let host_port =
                                        host_port_details["HostPort"].as_str().unwrap_or("");
                                    format!("{}:{}->{}", host_ip, host_port, container_port)
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

        let container_info = json
            .as_array()
            .and_then(|containers| containers.first())
            .ok_or_else(|| Error::Execution("container inspect response was empty".into()))?;

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
                .and_then(|command| command.first())
                .and_then(Value::as_str)
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

fn extend_section_errors(
    section_errors: &mut Vec<InventorySectionError>,
    section: InventorySection,
    messages: impl IntoIterator<Item = String>,
) {
    section_errors.extend(
        messages
            .into_iter()
            .map(|message| InventorySectionError::new(section, message)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_container_fixture_without_panicking_on_empty_commands() {
        let mode = InventoryMode::new();
        let fixture = r#"[{
            "Name": "fixture",
            "Id": "abc123",
            "Config": {"Image": "example:latest", "Cmd": []},
            "State": {"Status": "running"},
            "NetworkSettings": {"Ports": {}, "Networks": {}},
            "Mounts": []
        }]"#;

        let container = mode
            .generic_container(fixture)
            .expect("fixture should parse");
        assert_eq!(container.name, "fixture");
        assert!(container.cmd.is_empty());
    }

    #[test]
    fn rejects_an_empty_container_inspect_response() {
        let mode = InventoryMode::new();
        assert!(mode.generic_container("[]").is_err());
    }
}
