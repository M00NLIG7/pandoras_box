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

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.mask)
    }
}

pub const DEFAULT_MAX_TARGETS: usize = 65_536;

#[derive(Debug, Default, Clone, Copy)]
pub struct Subnet {
    ip: Ipv4AddrExt,
    mask: u8,
}

impl Subnet {
    pub fn new(ip: Ipv4AddrExt, mask: u8) -> Self {
        Self { ip, mask }
    }

    #[must_use]
    pub fn host_count(&self) -> u64 {
        let (first, end_exclusive) = self.host_bounds();
        end_exclusive - first
    }

    pub fn hosts_bounded(&self, max_targets: usize) -> Result<Vec<IpAddr>> {
        if max_targets == 0 {
            return Err(crate::Error::ArgumentError(
                "max_targets must be greater than zero".to_string(),
            ));
        }

        let host_count = self.host_count();
        if host_count > max_targets as u64 {
            return Err(crate::Error::ArgumentError(format!(
                "subnet {self} contains {host_count} usable targets, exceeding the configured limit of {max_targets}"
            )));
        }

        Ok(self.iter_hosts().map(IpAddr::from).collect())
    }

    fn host_bounds(&self) -> (u64, u64) {
        let host_bits = 32 - u32::from(self.mask);
        let address_count = 1u64 << host_bits;
        let network_mask = if self.mask == 0 {
            0
        } else {
            u32::MAX << host_bits
        };
        let network = u64::from(u32::from(*self.ip) & network_mask);

        if self.mask >= 31 {
            (network, network + address_count)
        } else {
            (network + 1, network + address_count - 1)
        }
    }

    fn iter_hosts(&self) -> Box<dyn Iterator<Item = Ipv4AddrExt> + '_> {
        let (first, end_exclusive) = self.host_bounds();
        Box::new((first..end_exclusive).map(|ip| Ipv4AddrExt(Ipv4Addr::from(ip as u32))))
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
        if self.subnet.host_count() > DEFAULT_MAX_TARGETS as u64 {
            return Err(crate::Error::ArgumentError(format!(
                "subnet {} contains {} usable targets, exceeding the enumerator limit of {}",
                self.subnet,
                self.subnet.host_count(),
                DEFAULT_MAX_TARGETS
            )));
        }

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
    use super::{Enumerator, Subnet, DEFAULT_MAX_TARGETS};
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
        let hosts = subnet
            .hosts_bounded(DEFAULT_MAX_TARGETS)
            .expect("small subnet should fit the target bound");

        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(hosts.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn cidr_32_enumerates_the_requested_address() {
        let subnet = Subnet::try_from("192.0.2.10/32").expect("/32 should parse");

        assert_eq!(subnet.host_count(), 1);
        assert_eq!(
            subnet.hosts_bounded(1).expect("one host should fit"),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
        );
    }

    #[test]
    fn cidr_31_enumerates_both_point_to_point_addresses() {
        let subnet = Subnet::try_from("192.0.2.10/31").expect("/31 should parse");

        assert_eq!(subnet.host_count(), 2);
        assert_eq!(
            subnet.hosts_bounded(2).expect("two hosts should fit"),
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
            ]
        );
    }

    #[test]
    fn oversized_cidr_is_rejected_before_materialization() {
        let subnet = Subnet::try_from("0.0.0.0/0").expect("/0 should parse");

        assert_eq!(subnet.host_count(), 4_294_967_294);
        let error = subnet
            .hosts_bounded(DEFAULT_MAX_TARGETS)
            .expect_err("/0 must exceed the bounded target count");
        assert!(error.to_string().contains("exceeding the configured limit"));
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
