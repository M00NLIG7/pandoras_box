mod platform;

use local_ip_address::local_ip;
use platform::conn_info;
use sysinfo::{CpuExt, DiskExt, System, SystemExt, UserExt};
use crate::types::{Container, ContainerNetwork, ContainerVolume, Disk, Host, User, UserInfo};
use crate::utils::CommandExecutor;
use crate::error::{Error, Result};
use serde_json::{Map, Value};
use futures::future::join_all;


pub async fn fetch_inventory() -> Host {
    let mut sys = System::new_all();

    sys.refresh_all();
    let (connections, open_ports) = conn_info().await;


    Host { 
        hostname: sys.host_name().unwrap_or_default(),
        ip: local_ip().unwrap_or("0.0.0.0".parse().unwrap()).to_string(),
        os: sys.long_os_version().unwrap_or_default(),
        cpu: sys.cpus().first().unwrap().brand().into(),
        cores: sys.cpus().len() as u8,
        memory: sys.total_memory() / 1024 / 1024,
        disks: disks(&sys),
        network_adapters: String::from(""),
        ports: open_ports,
        connections,
        services: platform::services().await,
        users: users(&sys),
        shares: platform::shares(),
        containers: containers().await,
        /*
        #[cfg(target_os = "windows")]
        server_features: platform::server_features().await,
        */
    }
}

async fn containers() -> Vec<Container> {
    if cfg!(target_os = "windows") {
        let command = "docker.exe";
        let containers = match get_generic_containers(command).await {
            Ok(containers) => containers,
            Err(e) => {
                e.log();
                Vec::new()
            }
        };

        containers
    } else {
        let commands = vec!["docker", "podman"];
        let mut containers = Vec::new();

        for command in commands {
            let generic_containers = match get_generic_containers(command).await {
                Ok(containers) => containers,
                Err(e) => {
                    e.log();
                    Vec::new()
                }
            };

            containers.extend(generic_containers);
        }
        containers
    }
}
fn users(sys: &System) -> Vec<User> {
    sys.users()
        .iter()
        .map(|user| User {
            name: user.name().into(),
            uid: user.id().to_string().into(),
            gid: user.group_id().to_string().into(),
            groups: user
                .groups()
                .iter()
                .map(|group| group.clone())
                .collect(),
            is_admin: user.is_admin(),
            is_local: user.is_local(),
            shell: None,
        })
        .collect()
}

fn disks(sys: &System) ->  Vec<Disk> {
    sys.disks()
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

async fn get_container_ids(command: &str) -> Result<Vec<String>> {
    let output = match CommandExecutor::execute_command(command, Some(&["ps", "-q"]), None).await {
        Ok(output) => output,
        Err(e) => {
            let err = Error::Execution(format!("Failed to get Windows container IDs: {}", e));
            err.log();
            return Err(err);
        }
    };

    // Handle Windows CRLF line endings
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

async fn get_generic_containers(command: &str) -> Result<Vec<Container>> {
    let container_ids = get_container_ids(command).await?;

    let inspect_futures: Vec<_> = container_ids
        .iter()
        .map(|id| async move {
            let inspect_result = CommandExecutor::execute_command(
                command,
                Some(&["inspect", id]),
                None,
            ).await;
            
            match inspect_result {
                Ok(output) => {
                    let inspect_str = String::from_utf8_lossy(&output.stdout);
                    generic_container(&inspect_str)
                },
                Err(e) => {
                    let err = Error::Execution(format!("Failed to inspect Windows container {}: {}", id, e));
                    err.log();
                    Err(err)
                }
            }
        })
        .collect();

    let results = join_all(inspect_futures).await;
    
    Ok(results.into_iter()
        .filter_map(|result| {
            match result {
                Ok(container) => Some(container),
                Err(e) => {
                    e.log();
                    None
                }
            }
        })
        .collect())
}

fn volumes_from_inspect(mounts: &Option<&Vec<Value>>) -> Vec<ContainerVolume> {
    mounts.map_or(Vec::new(), |mounts| {
        mounts
            .iter()
            .filter_map(|mount| {
                let source = mount["Source"].as_str()?;
                // Convert to Windows path format
                let host_path = source.replace('/', "\\");

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

fn networks_from_inspect(networks: &Option<&Map<String, Value>>) -> Vec<ContainerNetwork> {
    networks.map_or(Vec::new(), |networks| {
        networks
            .iter()
            .map(|(name, network_data)| ContainerNetwork {
                network_name: name.clone(),
                ip: network_data["IPAddress"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
                gateway: network_data["Gateway"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
                mac_address: network_data["MacAddress"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
            })
            .collect()
    })
}

fn port_from_inspect(port_map: &Option<&Map<String, Value>>) -> Vec<String> {
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
                                let host_ip = host_port_details["HostIp"].as_str().unwrap_or("0.0.0.0");
                                let host_port = host_port_details["HostPort"].as_str().unwrap_or("");
                                Some(format!("{}:{}->{}", host_ip, host_port, container_port))
                            })
                            .collect()
                    })
            })
            .collect()
    })
}

fn generic_container(inspect_data: &str) -> Result<Container> {
    let json: Value = serde_json::from_str(inspect_data).map_err(|e| {
        let err = Error::Execution(format!("Failed to parse Windows container JSON: {}", e));
        err.log();
        err
    })?;

    let container_info = &json[0];

    Ok(Container {
        name: container_info["Name"].as_str().unwrap_or_default().into(),
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
        port_bindings: port_from_inspect(&container_info["NetworkSettings"]["Ports"].as_object()),
        volumes: volumes_from_inspect(&container_info["Mounts"].as_array()),
        networks: networks_from_inspect(&container_info["NetworkSettings"]["Networks"].as_object()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_inventory() {
        let mut sys = System::new_all();

        sys.refresh_all();

        println!("{:?}", sys.host_name());
    }
}
