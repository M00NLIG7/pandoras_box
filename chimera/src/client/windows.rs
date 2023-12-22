use std::collections::HashMap;

use wmi::*;
use serde::Deserialize;
use local_ip_address::local_ip;
use sysinfo::{ProcessExt, System, SystemExt, UserExt};
use netstat::*;
use super::types::*;


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

// Retrieve NetworkInfo
impl OS for Host {
    fn ip() -> Box<str> {
        let my_local_ip = local_ip().unwrap().to_string().into_boxed_str();
        return my_local_ip;
    }

    fn containers() -> Box<[Container]> {
        todo!()
    }

    fn firewall_rules() {
        todo!("firewall_rules")
    }

    fn conn_info() -> (Box<[NetworkConnection]>, Box<[OpenPort]>) {
        let sys = System::new_all();
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        let iterator = iterate_sockets_info(af_flags, proto_flags).expect("Failed to get socket information!");
    
        let mut sockets: Vec<NetworkConnection> = Vec::new();
        let mut open_ports: Vec<OpenPort> = Vec::new();
    
        for info in iterator {
            let si = match info {
                Ok(si) => si,
                Err(_err) => {
                    println!("Failed to get info for socket!");
                    continue;
                }
            };
    
            // gather associated processes
            let process_ids = si.associated_pids;
            let mut processes: Vec<Process> = Vec::new();
            let all_processes = process_info(&sys);
            for pid in process_ids {
                for process in &all_processes {
                    if process.pid == pid {
                        processes.push(Process {
                            pid: process.pid,
                            name: process.name.clone(),
                        });
                    }
                }
            }
    
            match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                sockets.push(NetworkConnection {
                    local_address: tcp.local_addr.to_string().into_boxed_str(),
                    remote_address: Some(tcp.remote_addr.to_string().into_boxed_str()),
                    protocol: "TCP".to_string().into_boxed_str(),
                    state: Some(tcp.state.into()),
                    process: processes.first().cloned(),
                    });
                    

                    let new_open_port = OpenPort {
                        port: tcp.remote_port,
                        protocol: "TCP".to_string().into_boxed_str(),
                        process: processes.first().cloned(),
                        version: "".to_string().into_boxed_str(),
                        state: Some(tcp.state.into()),
                    };
            
                    if !open_ports.iter().any(|existing_port| {
                        existing_port.port == new_open_port.port && existing_port.protocol == new_open_port.protocol
                    }) {
                        open_ports.push(new_open_port);
                    }
                },
                ProtocolSocketInfo::Udp(udp) => sockets.push(NetworkConnection {
                    local_address: udp.local_addr.to_string().into_boxed_str(),
                    remote_address: None,
                    protocol: "UDP".to_string().into_boxed_str(),
                    state: None,
                    process: processes.first().cloned(),
                }),
            }
        }
        (
            sockets.into_boxed_slice(),
            open_ports.into_boxed_slice(),
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
    id: u32,
    parent_id: u32,
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

impl UserInfo for sysinfo::User {
    fn is_admin(&self) -> bool {
        // Check for sudoers group in groups or uid 0 (root)
        self.groups().iter().any(|group| group == "Administrators") || self.id().to_string() == "0"
    }

    fn is_local(&self) -> bool {
        let local_user_sid_pattern = regex::Regex::new(r"S-1-5-21-\d{2,}-1000-\d+").unwrap();

        // Check if user is local based on SID
        // self.id().to_string() == "S-1-5-21-1004336348-1177238915-682003330-513"
        local_user_sid_pattern.is_match(&self.id().to_string())
    }
}

