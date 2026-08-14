use crate::types::{ConnectionState, NetworkConnection, OpenPort, Process};
use netstat::*;
use std::collections::{HashMap, HashSet};
use sysinfo::{ProcessExt, System, SystemExt};

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

pub async fn conn_info() -> (Vec<NetworkConnection>, Vec<OpenPort>, Vec<String>) {
    let sys = System::new_all();
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let iterator = match iterate_sockets_info(af_flags, proto_flags) {
        Ok(iterator) => iterator,
        Err(error) => {
            return (
                Vec::new(),
                Vec::new(),
                vec![format!("socket inventory failed: {error}")],
            );
        }
    };

    let mut sockets: Vec<NetworkConnection> = Vec::new();
    let mut open_ports_set: HashSet<OpenPort> = HashSet::new();
    let mut errors = Vec::new();

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
            Err(error) => {
                errors.push(format!("individual socket inventory failed: {error}"));
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
        open_ports_set.into_iter().collect::<Vec<_>>(),
        errors,
    )
}

fn process_info(sys: &System) -> std::vec::Vec<Process> {
    let processes = sys.processes();

    let mut process_dump = vec![];

    for (pid, process_data) in processes {
        if let Ok(pid) = pid.to_string().parse::<u32>() {
            process_dump.push(Process {
                pid,
                name: process_data.name().to_string(),
            });
        }
    }
    process_dump
}
