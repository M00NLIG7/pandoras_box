use crate::types::{ConnectionState, NetworkConnection, OpenPort, Process as ProcessInfo};
use procfs::net::{TcpNetEntry, TcpState, UdpNetEntry, UdpState};
use procfs::process::{FDTarget, Stat};
use std::collections::{HashMap, HashSet};

macro_rules! impl_from_state {
    ($from_type:ty, $($variant:ident),* $(,)?) => {
        impl From<&$from_type> for ConnectionState {
            fn from(state: &$from_type) -> Self {
                match state {
                    $(
                        <$from_type>::$variant => ConnectionState::$variant,
                    )*
                    #[allow(unreachable_patterns)]
                    _ => ConnectionState::Unknown,
                }
            }
        }
    };
}

impl_from_state!(UdpState, Established, Close);
impl_from_state!(
    TcpState,
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    Close,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
    Listen,
    Closing
);

fn is_localhost(ip: &str) -> bool {
    ip == "localhost" || ip == "::1" || ip.starts_with("127.") || ip == "::ffff:127.0.0.1"
}

trait NetworkScanner {
    fn to_connection(&self, process_map: &HashMap<u64, Stat>) -> NetworkConnection;
    fn to_open_port(&self, process_map: &HashMap<u64, Stat>) -> Option<OpenPort>;
}

macro_rules! impl_network_scanner {
    ($type:ty, $protocol:expr, $version:expr) => {
        impl NetworkScanner for $type {
            fn to_connection(&self, process_map: &HashMap<u64, Stat>) -> NetworkConnection {
                let (local_ip, local_port) = parse_address(&self.local_address.to_string());
                let (remote_ip, remote_port) = parse_address(&self.remote_address.to_string());

                let local_address = format!(
                    "{}:{}",
                    local_ip.unwrap_or_default(),
                    local_port.unwrap_or_default()
                );
                let remote_address = remote_ip
                    .zip(remote_port)
                    .map(|(ip, port)| format!("{ip}:{port}"));
                let process = process_map.get(&self.inode).map(|stat| ProcessInfo {
                    pid: u32::try_from(stat.pid).unwrap_or_default(),
                    name: stat.comm.clone(),
                });

                NetworkConnection {
                    local_address,
                    remote_address,
                    state: Some(ConnectionState::from(&self.state)),
                    protocol: format!("{}-{}", $protocol, $version),
                    process,
                }
            }

            fn to_open_port(&self, process_map: &HashMap<u64, Stat>) -> Option<OpenPort> {
                if !matches!(ConnectionState::from(&self.state), ConnectionState::Listen) {
                    return None;
                }

                let (local_ip, port) = parse_address(&self.local_address.to_string());
                let (remote_ip, _) = parse_address(&self.remote_address.to_string());
                let port = u16::try_from(port?).ok()?;
                let is_public = match (local_ip.as_deref(), remote_ip.as_deref()) {
                    (Some(ip), _) if is_localhost(ip) => false,
                    (Some("0.0.0.0" | "::"), _) => true,
                    (_, Some("0.0.0.0" | "::")) => true,
                    (Some(_), _) => true,
                    _ => true,
                };
                if !is_public {
                    return None;
                }

                let process = process_map.get(&self.inode).map(|stat| ProcessInfo {
                    pid: u32::try_from(stat.pid).unwrap_or_default(),
                    name: stat.comm.clone(),
                });
                Some(OpenPort {
                    port,
                    protocol: $protocol.to_string(),
                    process,
                    version: $version.to_string(),
                    state: Some(ConnectionState::from(&self.state)),
                })
            }
        }
    };
}

impl_network_scanner!(TcpNetEntry, "TCP", "IPv4");
impl_network_scanner!(UdpNetEntry, "UDP", "IPv4");

pub async fn conn_info() -> (Vec<NetworkConnection>, Vec<OpenPort>, Vec<String>) {
    let (process_map, mut errors) = build_process_map();
    let mut connections = Vec::new();
    let mut open_ports = Vec::new();
    let mut seen_ports = HashSet::new();

    scan_entries(
        "IPv4 TCP",
        procfs::net::tcp(),
        &process_map,
        &mut connections,
        &mut open_ports,
        &mut seen_ports,
        &mut errors,
    );
    scan_entries(
        "IPv4 UDP",
        procfs::net::udp(),
        &process_map,
        &mut connections,
        &mut open_ports,
        &mut seen_ports,
        &mut errors,
    );
    scan_entries(
        "IPv6 TCP",
        procfs::net::tcp6(),
        &process_map,
        &mut connections,
        &mut open_ports,
        &mut seen_ports,
        &mut errors,
    );
    scan_entries(
        "IPv6 UDP",
        procfs::net::udp6(),
        &process_map,
        &mut connections,
        &mut open_ports,
        &mut seen_ports,
        &mut errors,
    );

    open_ports.sort_by_key(|port| (port.port, port.protocol.clone()));
    (connections, open_ports, errors)
}

#[allow(clippy::too_many_arguments)]
fn scan_entries<T: NetworkScanner>(
    description: &str,
    entries: Result<Vec<T>, procfs::ProcError>,
    process_map: &HashMap<u64, Stat>,
    connections: &mut Vec<NetworkConnection>,
    open_ports: &mut Vec<OpenPort>,
    seen_ports: &mut HashSet<(u16, String)>,
    errors: &mut Vec<String>,
) {
    let entries = match entries {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!("{description} socket inventory failed: {error}"));
            return;
        }
    };

    for entry in entries {
        connections.push(entry.to_connection(process_map));
        if let Some(port) = entry.to_open_port(process_map) {
            let key = (port.port, port.protocol.clone());
            if seen_ports.insert(key) {
                open_ports.push(port);
            }
        }
    }
}

fn build_process_map() -> (HashMap<u64, Stat>, Vec<String>) {
    let mut map = HashMap::new();
    let mut errors = Vec::new();
    let processes = match procfs::process::all_processes() {
        Ok(processes) => processes,
        Err(error) => {
            errors.push(format!(
                "process socket ownership inventory failed: {error}"
            ));
            return (map, errors);
        }
    };

    let mut inaccessible = 0usize;
    for process in processes {
        let Ok(process) = process else {
            inaccessible += 1;
            continue;
        };
        let (Ok(stat), Ok(file_descriptors)) = (process.stat(), process.fd()) else {
            inaccessible += 1;
            continue;
        };
        for descriptor in file_descriptors.filter_map(Result::ok) {
            if let FDTarget::Socket(inode) = descriptor.target {
                map.insert(inode, stat.clone());
            }
        }
    }
    if inaccessible > 0 {
        errors.push(format!(
            "process ownership was unavailable for {inaccessible} processes"
        ));
    }

    (map, errors)
}

fn parse_address(address: &str) -> (Option<String>, Option<i32>) {
    if address.contains('[') {
        parse_ipv6_address(address)
    } else {
        parse_ipv4_address(address)
    }
}

fn parse_ipv6_address(address: &str) -> (Option<String>, Option<i32>) {
    let mut parts = match address.strip_prefix('[') {
        Some(address) => address.split("]:"),
        None => return (None, None),
    };
    let ip = parts.next().map(String::from);
    let port = parts.next().and_then(|port| port.parse().ok());
    (ip, port)
}

fn parse_ipv4_address(address: &str) -> (Option<String>, Option<i32>) {
    let mut parts = address.split(':');
    let ip = parts.next().map(String::from);
    let port = parts.next().and_then(|port| port.parse().ok());
    (ip, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_socket_addresses() {
        assert_eq!(
            parse_address("192.0.2.4:443"),
            (Some("192.0.2.4".to_string()), Some(443))
        );
        assert_eq!(
            parse_address("[2001:db8::1]:22"),
            (Some("2001:db8::1".to_string()), Some(22))
        );
        assert_eq!(
            parse_address("invalid"),
            (Some("invalid".to_string()), None)
        );
    }
}
