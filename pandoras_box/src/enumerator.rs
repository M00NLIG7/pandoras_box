use crate::Result;
use futures::future::join_all;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use surge_ping::{Client, Config, IcmpPacket};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

#[allow(dead_code)]
const TIMEOUT_DURATION: Duration = Duration::from_secs(1);
#[allow(dead_code)]
const TCP_PORTS: [u16; 2] = [139, 22];

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OS {
    Unix,
    Windows,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub ip: String,
    pub os: OS,
    pub open_ports: Vec<u16>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Subnet {
    ip: Ipv4Addr,
    mask: u8,
}

#[allow(dead_code)]
impl Subnet {
    pub fn new(ip: Ipv4Addr, mask: u8) -> Self {
        Self { ip, mask }
    }

    fn iter_hosts(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        let start = u32::from(self.ip) & !((1 << (32 - self.mask)) - 1);
        let end = start | ((1 << (32 - self.mask)) - 1);
        (start + 1..end).map(Ipv4Addr::from)
    }
}

#[allow(dead_code)]
pub struct Enumerator {
    subnet: Subnet,
}

#[allow(dead_code)]
impl Enumerator {
    pub fn new(subnet: Subnet) -> Self {
        Enumerator { subnet }
    }

    pub async fn sweep(&self) -> Result<Vec<Arc<Host>>> {
        let client = Client::new(&Config::default()).await?;

        // First, perform TCP checks
        let tcp_handles: Vec<_> = self
            .subnet
            .iter_hosts()
            .map(|ip| tokio::spawn(async move { Self::tcp_check(ip).await }))
            .collect();

        let tcp_results: Vec<(Ipv4Addr, Vec<u16>)> = join_all(tcp_handles)
            .await
            .into_iter()
            .filter_map(|r| r.ok().flatten())
            .collect();

        // Then, perform ICMP pings only on IPs with open TCP ports
        let icmp_handles: Vec<_> = tcp_results
            .into_iter()
            .map(|(ip, open_ports)| {
                let client_clone = client.clone();
                tokio::spawn(async move { Self::icmp_ping(client_clone, ip, open_ports).await })
            })
            .collect();

        let results: Vec<Arc<Host>> = join_all(icmp_handles)
            .await
            .into_iter()
            .filter_map(|r| r.ok().flatten().map(Arc::new))
            .collect();

        Ok(results)
    }

    async fn tcp_check(ip: Ipv4Addr) -> Option<(Ipv4Addr, Vec<u16>)> {
        let mut open_ports = Vec::new();
        for &port in &TCP_PORTS {
            if Self::tcp_connect(ip, port).await {
                open_ports.push(port);
            }
        }
        if open_ports.is_empty() {
            None
        } else {
            Some((ip, open_ports))
        }
    }

    async fn tcp_connect(ip: Ipv4Addr, port: u16) -> bool {
        let addr = SocketAddr::new(IpAddr::V4(ip), port);
        match timeout(TIMEOUT_DURATION, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    async fn icmp_ping(client: Client, ip: Ipv4Addr, open_ports: Vec<u16>) -> Option<Host> {
        let mut pinger = client.pinger(IpAddr::V4(ip)).await;
        pinger.size(64).timeout(TIMEOUT_DURATION);

        match pinger.ping(0).await {
            Ok((IcmpPacket::V4(packet), _)) => {
                let ttl = packet.get_ttl();
                Some(Host {
                    ip: ip.to_string(),
                    os: Self::determine_os(ttl),
                    open_ports,
                })
            }
            _ => Some(Host {
                ip: ip.to_string(),
                os: OS::Unknown,
                open_ports,
            }),
        }
    }

    fn determine_os(ttl: u8) -> OS {
        match ttl {
            60..=64 => OS::Unix,
            120..=128 => OS::Windows,
            _ => OS::Unknown,
        }
    }
}

/*
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subnet = Subnet::new("139.182.180.0".parse()?, 24);
    let enumerator = Enumerator::new(subnet);
    let hosts = enumerator.sweep().await?;
    for host in hosts {
        println!("{:?}", host);
    }
    Ok(())
}
*/
