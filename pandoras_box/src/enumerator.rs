use crate::Result;
use futures::future::join_all;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use crate::OS;

const TIMEOUT_DURATION: Duration = Duration::from_secs(1);
const TCP_PORTS: [u16; 2] = [139, 22];


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub ip: String,
    pub os: OS,
    pub open_ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4AddrExt(Ipv4Addr);

impl Default for Ipv4AddrExt {
    fn default() -> Self {
        Self(Ipv4Addr::new(0, 0, 0, 0))
    }
}

impl Deref for Ipv4AddrExt {
    type Target = Ipv4Addr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Ipv4AddrExt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Ipv4Addr> for Ipv4AddrExt {
    fn from(ip: Ipv4Addr) -> Self {
        Self(ip)
    }
}

impl From<Ipv4AddrExt> for Ipv4Addr {
    fn from(ip: Ipv4AddrExt) -> Self {
        ip.0
    }
}

impl From<Ipv4AddrExt> for IpAddr {
    fn from(ip: Ipv4AddrExt) -> Self {
        IpAddr::V4(ip.0)
    }
}

impl FromStr for Ipv4AddrExt {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl From<String> for Subnet {
    fn from(value: String) -> Self {
        Subnet::try_from(value.as_str()).unwrap_or_default()
    }
}

impl From<&String> for Subnet {
    fn from(value: &String) -> Self {
        Subnet::try_from(value.as_str()).unwrap_or_default()
    }
}

#[derive(Debug, Default)]
pub struct Subnet {
    ip: Ipv4AddrExt,
    mask: u8,
}

impl Subnet {
    pub fn new(ip: Ipv4AddrExt, mask: u8) -> Self {
        Self { ip, mask }
    }

    fn iter_hosts(&self) -> impl Iterator<Item = Ipv4AddrExt> + '_ {
        let start = u32::from(*self.ip) & !((1 << (32 - self.mask)) - 1);
        let end = start | ((1 << (32 - self.mask)) - 1);
        (start + 1..end).map(|ip| Ipv4AddrExt(Ipv4Addr::from(ip)))
    }
}

impl TryFrom<&str> for Subnet {
    type Error = crate::Error;

    fn try_from(value: &str) -> Result<Self> {
        let parts: Vec<&str> = value.split('/').collect();
        if parts.len() != 2 {
            return Err(Self::Error::ArgumentError(value.to_string()));
        }

        let ip: Ipv4AddrExt = parts[0].parse()?;
        let mask = parts[1].parse()?;
        Ok(Self { ip, mask })
    }
}

pub struct Enumerator {
    subnet: Subnet,
}

impl Enumerator {
    pub fn new(subnet: Subnet) -> Self {
        Enumerator { subnet }
    }

    pub async fn sweep(&self) -> Result<Vec<Arc<Host>>> {
        // First, perform TCP checks
        let tcp_handles: Vec<_> = self
            .subnet
            .iter_hosts()
            .map(|ip| tokio::spawn(async move { Self::tcp_check(ip).await }))
            .collect();

        let tcp_results: Vec<(Ipv4AddrExt, Vec<u16>)> = join_all(tcp_handles)
            .await
            .into_iter()
            .filter_map(|r| r.ok().flatten())
            .collect();

        // Then, perform ICMP pings only on IPs with open TCP ports
        let icmp_handles: Vec<_> = tcp_results
            .into_iter()
            .map(|(ip, open_ports)| {
                tokio::spawn(async move { Self::icmp_ping(ip, open_ports).await })
            })
            .collect();

        let results: Vec<Arc<Host>> = join_all(icmp_handles)
            .await
            .into_iter()
            .filter_map(|r| r.ok().flatten().map(Arc::new))
            .collect();

        Ok(results)
    }

    async fn tcp_check(ip: Ipv4AddrExt) -> Option<(Ipv4AddrExt, Vec<u16>)> {
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

    async fn tcp_connect(ip: Ipv4AddrExt, port: u16) -> bool {
        let addr = SocketAddr::new(IpAddr::V4(*ip), port);
        match timeout(TIMEOUT_DURATION, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    async fn icmp_ping(ip: Ipv4AddrExt, open_ports: Vec<u16>) -> Option<Host> {
        let output = if cfg!(target_os = "windows") {
            Command::new("ping")
                .arg("-n 1")
                .arg(ip.to_string())
                .output()
                .expect("Failed to run ping command")
        } else {
            Command::new("ping")
                .arg("-c 1")
                .arg("-W 1")
                .arg(ip.to_string())
                .output()
                .expect("Failed to run ping command")
        };

        if output.status.success() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let ttl_value = if cfg!(target_os = "windows") {
                // On Windows, `TTL=` is uppercase
                output_str.split("TTL=").nth(1)
            } else {
                // On Linux, `ttl=` is lowercase
                output_str.split("ttl=").nth(1)
            };

            if let Some(ttl_str) = ttl_value {
                let ttl: u8 = ttl_str
                    .split_whitespace()
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0);
                return Some(Host {
                    ip: ip.to_string(),
                    os: Self::determine_os(ttl),
                    open_ports,
                });
            }
        }

        Some(Host {
            ip: ip.to_string(),
            os: OS::Unknown,
            open_ports,
        })
    }

    fn determine_os(ttl: u8) -> OS {
        match ttl {
            60..=64 => OS::Unix,
            120..=128 => OS::Windows,
            _ => OS::Unknown,
        }
    }
}

mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan() -> Result<()> {
        let start_time = std::time::Instant::now();
        let subnet = Subnet::try_from("139.182.180.0/24")?;
        let enumerator = Enumerator::new(subnet);
        let hosts = enumerator.sweep().await?;
        println!("Found {} hosts", hosts.len());
        for host in hosts {
            println!("{:?}", host);
        }

        println!("Elapsed time: {:?}", start_time.elapsed());
        Ok(())
    }
}
