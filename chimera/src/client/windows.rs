use wmi::*;
use serde::{Deserialize};
use local_ip_address::local_ip;
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
        // Retrieve active connections and open ports
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        let sockets_info = get_sockets_info(af_flags, proto_flags).unwrap();
        let mut connections = Vec::new();
        let mut open_ports = Vec::new();
        for si in sockets_info {
            match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_si) => {
                    connections.push(NetworkConnection {
                        local_address: tcp_si.local_addr.to_string().into_boxed_str(),
                        remote_address: tcp_si.remote_addr.to_string().into_boxed_str(),
                        state: tcp_si.state.to_string().into_boxed_str(),
                        protocol: "TCP".to_string().into_boxed_str(),
                        pid: None,
                    });
                    open_ports.push(OpenPort {
                        port: tcp_si.remote_port,
                        protocol: "TCP".to_string().into_boxed_str(),
                        pid: None,
                        version: "N/A".to_string().into_boxed_str(),
                        state: "N/A".to_string().into_boxed_str()
                    });
                },
                ProtocolSocketInfo::Udp(udp_si) => {
                    connections.push(NetworkConnection {
                        local_address: udp_si.local_addr.to_string().into_boxed_str(),
                        remote_address: "N/A".to_string().into_boxed_str(),
                        state: "N/A".to_string().into_boxed_str(),
                        protocol: "UDP".to_string().into_boxed_str(),
                        pid: None,
                    });
                },
            }

        }

        (
            connections.into_boxed_slice(),
            open_ports.into_boxed_slice()
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