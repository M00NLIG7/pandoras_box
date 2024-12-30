use crate::types::{ConnectionState, NetworkConnection, OpenPort, Process as ProcessInfo};
use procfs::net::{TcpNetEntry, TcpState, UdpNetEntry, UdpState};
use procfs::process::{FDTarget, Process, Stat};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

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
    fn get_inode(&self) -> u64;
}

macro_rules! impl_network_scanner {
    ($type:ty, $protocol:expr, $version:expr) => {
        impl NetworkScanner for $type {
            fn to_connection(&self, process_map: &HashMap<u64, Stat>) -> NetworkConnection {
                let (local_ip, local_port) = parse_address(&self.local_address.to_string());
                let (remote_ip, remote_port) = parse_address(&self.remote_address.to_string());

                let local_addr = format!(
                    "{}:{}",
                    local_ip.unwrap_or_default(),
                    local_port.unwrap_or_default()
                );
                let remote_addr = if remote_ip.is_some() && remote_port.is_some() {
                    Some(format!("{}:{}", remote_ip.unwrap(), remote_port.unwrap()))
                } else {
                    None
                };

                let process = process_map.get(&self.inode).map(|stat| ProcessInfo {
                    pid: stat.pid as u32,
                    name: stat.comm.clone(),
                });

                NetworkConnection {
                    local_address: local_addr,
                    remote_address: remote_addr,
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

                let port = port?;

                let is_public = match (local_ip.as_deref(), remote_ip.as_deref()) {
                    (Some(ip), _) if is_localhost(ip) => false,
                    (Some("0.0.0.0"), _) | (Some("::"), _) => true,
                    (_, Some("0.0.0.0")) | (_, Some("::")) => true,
                    (Some(_), _) => true,
                    _ => true,
                };

                if !is_public {
                    return None;
                }

                let process = process_map.get(&self.inode).map(|stat| ProcessInfo {
                    pid: stat.pid as u32,
                    name: stat.comm.clone(),
                });

                Some(OpenPort {
                    port: port as u16,
                    protocol: $protocol.to_string(),
                    process,
                    version: $version.to_string(),
                    state: Some(ConnectionState::from(&self.state)),
                })
            }

            fn get_inode(&self) -> u64 {
                self.inode
            }
        }
    };
}

impl_network_scanner!(TcpNetEntry, "TCP", "IPv4");
impl_network_scanner!(UdpNetEntry, "UDP", "IPv4");

pub async fn conn_info() -> (Vec<NetworkConnection>, Vec<OpenPort>) {
    let (tx, mut rx) = mpsc::channel(32);
    let connections = Arc::new(Mutex::new(Vec::new()));
    let open_ports = Arc::new(Mutex::new(Vec::new()));
    let seen_ports = Arc::new(Mutex::new(HashSet::new()));

    let process_map = build_process_map();
    let process_map = Arc::new(process_map);

    let seen_ports_tcp = Arc::clone(&seen_ports);
    let seen_ports_udp = Arc::clone(&seen_ports);
    let seen_ports_tcp6 = Arc::clone(&seen_ports);
    let seen_ports_udp6 = Arc::clone(&seen_ports);

    let tcp_task = spawn_scanner::<_, TcpNetEntry>(
        procfs::net::tcp as fn() -> Result<_, _>,
        tx.clone(),
        Arc::clone(&process_map),
        seen_ports_tcp,
    );

    let udp_task = spawn_scanner::<_, UdpNetEntry>(
        procfs::net::udp as fn() -> Result<_, _>,
        tx.clone(),
        Arc::clone(&process_map),
        seen_ports_udp,
    );

    let tcp6_task = spawn_scanner::<_, TcpNetEntry>(
        procfs::net::tcp6 as fn() -> Result<_, _>,
        tx.clone(),
        Arc::clone(&process_map),
        seen_ports_tcp6,
    );

    let udp6_task = spawn_scanner::<_, UdpNetEntry>(
        procfs::net::udp6 as fn() -> Result<_, _>,
        tx.clone(),
        Arc::clone(&process_map),
        seen_ports_udp6,
    );

    drop(tx);

    let connections_clone = Arc::clone(&connections);
    let open_ports_clone = Arc::clone(&open_ports);

    let collector = tokio::spawn(async move {
        while let Some((conn, port)) = rx.recv().await {
            if let Some(conn) = conn {
                connections_clone.lock().await.push(conn);
            }
            if let Some(port) = port {
                open_ports_clone.lock().await.push(port);
            }
        }
    });

    let _ = tokio::join!(tcp_task, udp_task, tcp6_task, udp6_task);
    let _ = collector.await;

    let mut connections = Arc::try_unwrap(connections).unwrap().into_inner();
    let mut open_ports = Arc::try_unwrap(open_ports).unwrap().into_inner();

    open_ports.sort_by_key(|p| (p.port, p.protocol.clone()));
    open_ports.dedup_by_key(|p| (p.port, p.protocol.clone()));

    (connections, open_ports)
}

async fn spawn_scanner<F, T>(
    fetch_entries: F,
    tx: mpsc::Sender<(Option<NetworkConnection>, Option<OpenPort>)>,
    process_map: Arc<HashMap<u64, Stat>>,
    seen_ports: Arc<Mutex<HashSet<(u16, String)>>>,
) -> tokio::task::JoinHandle<()>
where
    F: Fn() -> Result<Vec<T>, procfs::ProcError> + Send + Sync + 'static,
    T: NetworkScanner + Send + 'static,
{
    tokio::spawn(async move {
        if let Ok(entries) = fetch_entries() {
            for entry in entries {
                let conn = entry.to_connection(&process_map);

                let port = if let Some(p) = entry.to_open_port(&process_map) {
                    let key = (p.port, p.protocol.clone());
                    let mut seen = seen_ports.lock().await;
                    if seen.insert(key) {
                        Some(p)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let _ = tx.send((Some(conn), port)).await;
            }
        }
    })
}

fn build_process_map() -> HashMap<u64, Stat> {
    let mut map = HashMap::new();

    if let Ok(all_procs) = procfs::process::all_processes() {
        for proc_result in all_procs {
            if let Ok(process) = proc_result {
                if let (Ok(stat), Ok(fds)) = (process.stat(), process.fd()) {
                    for fd in fds.filter_map(Result::ok) {
                        if let FDTarget::Socket(inode) = fd.target {
                            map.insert(inode, stat.clone());
                        }
                    }
                }
            }
        }
    }

    map
}

fn parse_address(addr: &str) -> (Option<String>, Option<i32>) {
    if addr.contains('[') {
        parse_ipv6_address(addr)
    } else {
        parse_ipv4_address(addr)
    }
}

fn parse_ipv6_address(addr: &str) -> (Option<String>, Option<i32>) {
    let mut parts = match addr.strip_prefix("[") {
        Some(addr) => addr.split("]:"),
        None => return (None, None),
    };

    let ip = parts.next().map(String::from);
    let port = parts.next().and_then(|p| p.parse().ok());

    (ip, port)
}

fn parse_ipv4_address(addr: &str) -> (Option<String>, Option<i32>) {
    let mut parts = addr.split(':');
    let ip = parts.next().map(String::from);
    let port = parts.next().and_then(|p| p.parse().ok());

    (ip, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_conn_info() {
        let (connections, open_ports) = conn_info().await;
        println!("Connections: {:#?}", connections);
        println!("Open ports: {:#?}", open_ports);
    }
}
