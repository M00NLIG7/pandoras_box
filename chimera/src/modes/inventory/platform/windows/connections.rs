use sysinfo::{System, SystemExt, ProcessExt};
use netstat::*;
use crate::types::{NetworkConnection, OpenPort, ConnectionState, Process};
use std::collections::{HashSet, HashMap};
use wmi::COMLibrary;

impl From<TcpState> for ConnectionState {
    fn from(tcp_state: TcpState) -> Self {
        match tcp_state {
            TcpState::Established => ConnectionState::Established,
            TcpState::SynSent => ConnectionState::SynSent,
            TcpState::SynReceived => ConnectionState::SynRecv,
            TcpState::FinWait1 => ConnectionState::FinWait1,
            TcpState::FinWait2 => ConnectionState::FinWait2,
            TcpState::TimeWait => ConnectionState::TimeWait,
            TcpState::Closed => ConnectionState::Close,
            TcpState::CloseWait => ConnectionState::CloseWait,
            TcpState::LastAck => ConnectionState::LastAck,
            TcpState::Listen => ConnectionState::Listen,
            TcpState::Closing => ConnectionState::Closing,
            _ => ConnectionState::Unknown,
        }
    }
}


pub async fn conn_info() -> (Vec<NetworkConnection>, Vec<OpenPort>) {
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
    let tcp_protocol = "TCP".to_string();
    let udp_protocol = "UDP".to_string();

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
                let local_address = tcp.local_addr.to_string();
                let remote_address = tcp.remote_addr.to_string();
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
                    process,
                    version: "".to_string(),
                    state,
                };

                // Use HashSet for efficient existence check
                open_ports_set.insert(new_open_port.clone());
            }
            ProtocolSocketInfo::Udp(udp) => {
                sockets.push(NetworkConnection {
                    local_address: udp.local_addr.to_string(),
                    remote_address: None,
                    protocol: udp_protocol.clone(),
                    state: None,
                    process: processes.first().cloned(),
                });
            }
        }
    }
    (
        sockets,
        open_ports_set
            .into_iter()
            .collect::<Vec<_>>() ,
    )

}

fn process_info(sys: &System) -> std::vec::Vec<Process> {
    let processes = sys.processes();

    let mut process_dump = vec![];

    for (pid, process_data) in processes {
        let value = Process {
            pid: pid.to_string().parse::<u32>().unwrap(),
            name: process_data.name().to_string(),
        };
        process_dump.push(value);
    }
    return process_dump;
}

