use crate::ttl::{classify_ttl, NativeTtlProber, SharedTtlProber, TtlSignature};
use crate::Host;
use crate::Result;
use crate::OS;
use futures::future::join_all;
use log::warn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const TIMEOUT_DURATION: Duration = Duration::from_secs(1);
const TCP_PORTS: [u16; 4] = [22, 135, 139, 445];

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

impl std::fmt::Display for Ipv4AddrExt {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
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

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.mask)
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

    #[must_use]
    pub fn hosts(&self) -> Vec<IpAddr> {
        self.iter_hosts().map(IpAddr::from).collect()
    }

    fn iter_hosts(&self) -> Box<dyn Iterator<Item = Ipv4AddrExt> + '_> {
        // Prevent overflow: when mask = 0, shift would be 32 which is undefined behavior
        // For /0, iterate entire IPv4 space (impractical, but safe)
        if self.mask == 0 {
            warn!("Subnet mask /0 covers entire IPv4 space (4.3 billion addresses), limiting iteration");
            // Return empty iterator for /0 to prevent DoS
            return Box::new((0..0).map(|ip| Ipv4AddrExt(Ipv4Addr::from(ip))));
        }

        let shift_amount = 32 - self.mask;
        let start = u32::from(*self.ip) & !((1u32 << shift_amount) - 1);
        let end = start | ((1u32 << shift_amount) - 1);
        Box::new((start + 1..end).map(|ip| Ipv4AddrExt(Ipv4Addr::from(ip))))
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
        let mask: u8 = parts[1]
            .parse()
            .map_err(|_| Self::Error::ArgumentError(format!("Invalid CIDR mask: {}", parts[1])))?;

        // Validate mask is in valid range for IPv4 (0-32)
        if mask > 32 {
            return Err(Self::Error::ArgumentError(format!(
                "CIDR mask {} is out of range (0-32)",
                mask
            )));
        }

        Ok(Self { ip, mask })
    }
}

pub struct Enumerator {
    subnet: Subnet,
    ttl_probe: SharedTtlProber,
}

impl Enumerator {
    pub fn new(subnet: Subnet) -> Self {
        Self::with_ttl_probe(subnet, Arc::new(NativeTtlProber::default()))
    }

    pub fn with_ttl_probe(subnet: Subnet, ttl_probe: SharedTtlProber) -> Self {
        Enumerator { subnet, ttl_probe }
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
                let ttl_probe = Arc::clone(&self.ttl_probe);
                tokio::spawn(async move { Self::resolve_host(ip, open_ports, ttl_probe).await })
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

    async fn resolve_host(
        ip: Ipv4AddrExt,
        open_ports: Vec<u16>,
        ttl_probe: SharedTtlProber,
    ) -> Option<Host> {
        let ttl = ttl_probe.probe_ttl(IpAddr::V4(*ip)).await;
        if ttl.is_none() {
            warn!(
                "TTL probe unavailable for {}, falling back to port fingerprinting",
                ip
            );
        }

        Some(Host {
            ip: ip.to_string(),
            os: Self::infer_os(&open_ports, ttl),
            open_ports,
        })
    }

    fn infer_os(open_ports: &[u16], ttl: Option<u8>) -> OS {
        match ttl.map(classify_ttl).unwrap_or(TtlSignature::Unknown) {
            TtlSignature::Unix => OS::Unix,
            TtlSignature::Windows => OS::Windows,
            TtlSignature::Unknown => {
                let has_windows_ports = open_ports.contains(&135)
                    || open_ports.contains(&139)
                    || open_ports.contains(&445);

                if has_windows_ports {
                    OS::Windows
                } else if open_ports.contains(&22) {
                    OS::Unix
                } else {
                    OS::Unknown
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Enumerator, Subnet};
    use crate::ttl::TtlProber;
    use crate::OS;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    struct FakeTtlProber {
        ttl: Option<u8>,
    }

    #[async_trait]
    impl TtlProber for FakeTtlProber {
        async fn probe_ttl(&self, _ip: IpAddr) -> Option<u8> {
            self.ttl
        }
    }

    #[test]
    fn infer_os_prefers_ttl_for_samba_hosts() {
        assert_eq!(Enumerator::infer_os(&[22, 445], Some(64)), OS::Unix);
    }

    #[test]
    fn infer_os_detects_windows_from_ttl_over_ssh_only() {
        assert_eq!(Enumerator::infer_os(&[22], Some(128)), OS::Windows);
    }

    #[test]
    fn infer_os_falls_back_to_ports_when_ttl_is_missing() {
        assert_eq!(Enumerator::infer_os(&[135, 445], None), OS::Windows);
        assert_eq!(Enumerator::infer_os(&[22], None), OS::Unix);
    }

    #[test]
    fn subnet_hosts_returns_ip_list() {
        let subnet = Subnet::new(Ipv4Addr::new(10, 0, 0, 0).into(), 30);
        let hosts = subnet.hosts();

        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(hosts.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[tokio::test]
    async fn resolve_host_uses_injected_ttl_probe() {
        let host = Enumerator::resolve_host(
            Ipv4Addr::new(10, 0, 0, 8).into(),
            vec![22, 445],
            Arc::new(FakeTtlProber { ttl: Some(64) }),
        )
        .await
        .expect("host should resolve");

        assert_eq!(host.ip, "10.0.0.8");
        assert_eq!(host.os, OS::Unix);
        assert_eq!(host.open_ports, vec![22, 445]);
    }
}
