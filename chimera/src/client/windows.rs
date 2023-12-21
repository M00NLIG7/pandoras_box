use wmi::*;
use serde::{Deserialize};
use local_ip_address::local_ip;
use sysinfo::{ProcessExt, System, SystemExt, UserExt};
use super::client;
use super::client::NetworkConnection;
use super::client::NetworkInfo;
use super::client::Host;
use super::client::Services;
use super::client::Service;
use super::client::OpenPort;
use super::client::Shares;
use super::client::Share;
use netstat::*;



// retrieve windows features


// uint32 ID;
// uint32 ParentID;
// string Name;
#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_ServerFeature")]
#[serde(rename_all = "PascalCase")]
pub struct ServerFeatures {
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

fn retrieve_server_features() -> Result<Vec<ServerFeatures>, wmi::WMIError> {
    let wmi_con = WMIConnection::new(COMLibrary::new()?)?;

    let results: Vec<OperatingSystem> = wmi_con.query()?;

    let mut is_server = false;
    results.iter().filter(|os| {
        os.caption.to_lowercase().contains("server")
    }).for_each(|os| {
        println!("Server: {}", os.caption);
        is_server = true;
    });

    if is_server == true {
        let server_features: Vec<ServerFeatures> = wmi_con.query()?;
        return Ok(server_features);   
    }

    Ok(vec![])
}

// Retrieve NetworkInfo
impl NetworkInfo for Host {
    fn ip() -> Box<str> {
        let my_local_ip = local_ip().unwrap().to_string().into_boxed_str();
        return my_local_ip;
    }

    fn containers() -> Box<[super::client::Container]> {
        todo!()
    }

    fn firewall_rules() {
        todo!("firewall_rules")
    }

    fn net_info() -> (Box<[super::client::NetworkConnection]>, Box<[super::client::OpenPort]>) {
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
                        });
                    }
                }
            }
    
            match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                sockets.push(NetworkConnection {
                    local_address: tcp.local_addr.to_string().into_boxed_str(),
                    remote_address: tcp.remote_addr.to_string().into_boxed_str(),
                    protocol: "TCP".to_string().into_boxed_str(),
                    state: tcp.state.to_string().into_boxed_str(),
                    pid: processes.first().map(|p| p.pid as i32),
                    });
                    


                    let new_open_port = OpenPort {
                        port: tcp.remote_port,
                        protocol: "TCP".to_string().into_boxed_str(),
                        pid: processes.first().map(|p| p.pid as i32),
                        version: "".to_string().into_boxed_str(),
                        state: tcp.state.to_string().into_boxed_str(),
                    };
            
                    if !open_ports.iter().any(|existing_port| {
                        existing_port.port == new_open_port.port && existing_port.protocol == new_open_port.protocol
                    }) {
                        open_ports.push(new_open_port);
                    }
                },
                ProtocolSocketInfo::Udp(udp) => sockets.push(NetworkConnection {
                    local_address: udp.local_addr.to_string().into_boxed_str(),
                    remote_address: "".to_string().into_boxed_str(),
                    protocol: "UDP".to_string().into_boxed_str(),
                    state: "".to_string().into_boxed_str(),
                    pid: processes.first().map(|p| p.pid as i32),
                }),
            }
        }
        (
            sockets.into_boxed_slice(),
            open_ports.into_boxed_slice(),
        )
    }

}


impl Services for Host {
    fn get_services() -> Box<[Service]> {
        let com_lib = match COMLibrary::new() {
            Ok(lib) => lib,
            _ => return Box::new([]), // or handle the error as appropriate
        };
        
        let wmi_con = match WMIConnection::new(com_lib) {
            Ok(con) => con,
            _ => return Box::new([]), // or handle the error as appropriate
        };

        let services_result = wmi_con.query();
        let services = match services_result {
            Ok(services) =>  return services.into_boxed_slice(),
            _ => {
                return Box::new([]);
            }
        };
    }
}

impl Shares for Host {
    fn get_shares() -> Box<[super::client::Share]> {
        let com_lib = match COMLibrary::new() {
            Ok(lib) => lib,
            _ => return Box::new([]), // or handle the error as appropriate
        };
        
        let wmi_con = match WMIConnection::new(com_lib) {
            Ok(con) => con,
            _ => return Box::new([]), // or handle the error as appropriate
        };

        let shares_result = wmi_con.query();
        let shares = match shares_result {
            Ok(shares) =>  return shares.into_boxed_slice(),
            Err(e) => {
                println!("Error: {}", e);   
                return Box::new([]);
            }
        };
    }
}

struct Process {
    pid: u32,
}

fn process_info(sys: &System) -> std::vec::Vec<Process> {
    let processes = sys.processes();

    let mut process_dump = vec![];

    for (pid, process_data) in processes {

        let value = Process {
            pid: pid.to_string().parse::<u32>().unwrap(),
        };
        process_dump.push(value);
    }

    return process_dump
}

impl super::client::UserInfo for sysinfo::User {
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

