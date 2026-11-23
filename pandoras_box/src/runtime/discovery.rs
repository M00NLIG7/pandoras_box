use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, Stream, StreamExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::mission::{HostTarget, PlatformHint};
use crate::ttl::{classify_ttl, NativeTtlProber, SharedTtlProber, TtlSignature};

const DEFAULT_PORTS: [u16; 4] = [22, 135, 139, 445];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryConfig {
    pub ports: Vec<u16>,
    pub ssh_port: u16,
    pub forwarded_smb_ports: Vec<u16>,
    pub connect_timeout: Duration,
    pub concurrency_limit: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            ports: DEFAULT_PORTS.to_vec(),
            ssh_port: 22,
            forwarded_smb_ports: vec![1445],
            connect_timeout: Duration::from_millis(800),
            concurrency_limit: 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRecord {
    pub host: HostTarget,
    pub ttl: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryOutcome {
    Reachable(DiscoveryRecord),
    Unreachable { ip: IpAddr },
}

impl From<DiscoveryRecord> for DiscoveryOutcome {
    fn from(record: DiscoveryRecord) -> Self {
        Self::Reachable(record)
    }
}

#[derive(Clone)]
pub struct TcpDiscovery {
    config: DiscoveryConfig,
    ttl_probe: SharedTtlProber,
}

impl TcpDiscovery {
    #[must_use]
    pub fn new(config: DiscoveryConfig) -> Self {
        Self::with_ttl_probe(config, Arc::new(NativeTtlProber::default()))
    }

    #[must_use]
    pub fn with_ttl_probe(config: DiscoveryConfig, ttl_probe: SharedTtlProber) -> Self {
        Self { config, ttl_probe }
    }

    pub fn probe_ips_outcomes_stream(
        &self,
        ips: Vec<IpAddr>,
    ) -> impl Stream<Item = DiscoveryOutcome> + '_ {
        let concurrency_limit = self.config.concurrency_limit.max(1);

        stream::iter(ips)
            .map(move |ip| async move {
                self.probe_ip(ip).await.map_or(
                    DiscoveryOutcome::Unreachable { ip },
                    DiscoveryOutcome::Reachable,
                )
            })
            .buffer_unordered(concurrency_limit)
    }

    pub fn probe_ips_stream(&self, ips: Vec<IpAddr>) -> impl Stream<Item = DiscoveryRecord> + '_ {
        self.probe_ips_outcomes_stream(ips)
            .filter_map(async move |outcome| match outcome {
                DiscoveryOutcome::Reachable(record) => Some(record),
                DiscoveryOutcome::Unreachable { .. } => None,
            })
    }

    pub async fn probe_ips(&self, ips: Vec<IpAddr>) -> Vec<DiscoveryRecord> {
        self.probe_ips_stream(ips).collect().await
    }

    pub async fn probe_ip(&self, ip: IpAddr) -> Option<DiscoveryRecord> {
        let open_ports = stream::iter(self.config.ports.iter().copied())
            .map(|port| async move {
                if Self::check_port(ip, port, self.config.connect_timeout).await {
                    Some(port)
                } else {
                    None
                }
            })
            .buffer_unordered(self.config.ports.len().max(1))
            .filter_map(async move |port| port)
            .collect::<Vec<_>>()
            .await;

        if open_ports.is_empty() {
            return None;
        }

        let ttl = self.ttl_probe.probe_ttl(ip).await;

        Some(DiscoveryRecord {
            host: HostTarget {
                ip,
                platform: infer_platform(
                    ip,
                    &open_ports,
                    ttl,
                    self.config.ssh_port,
                    &self.config.forwarded_smb_ports,
                ),
                open_ports,
            },
            ttl,
        })
    }

    async fn check_port(ip: IpAddr, port: u16, connect_timeout: Duration) -> bool {
        let socket = (ip, port);
        matches!(
            timeout(connect_timeout, TcpStream::connect(socket)).await,
            Ok(Ok(_))
        )
    }
}

#[must_use]
pub fn infer_platform(
    ip: IpAddr,
    open_ports: &[u16],
    ttl: Option<u8>,
    ssh_port: u16,
    forwarded_smb_ports: &[u16],
) -> PlatformHint {
    let has_ssh = open_ports.contains(&ssh_port);
    let has_windows_rpc = open_ports.contains(&135);
    let has_smb = open_ports.contains(&139) || open_ports.contains(&445);
    let has_forwarded_smb = open_ports
        .iter()
        .copied()
        .any(|port| forwarded_smb_ports.contains(&port));

    if has_forwarded_smb {
        return PlatformHint::Windows;
    }

    if ip.is_loopback() && has_ssh && has_smb {
        return PlatformHint::Windows;
    }

    match ttl.map(classify_ttl).unwrap_or(TtlSignature::Unknown) {
        TtlSignature::Unix => PlatformHint::UnixLike,
        TtlSignature::Windows => PlatformHint::Windows,
        TtlSignature::Unknown => {
            if has_windows_rpc || has_smb {
                return PlatformHint::Windows;
            }

            if has_ssh {
                return PlatformHint::UnixLike;
            }

            PlatformHint::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{infer_platform, DiscoveryConfig, DiscoveryOutcome, TcpDiscovery};
    use crate::runtime::mission::PlatformHint;
    use crate::ttl::TtlProber;
    use async_trait::async_trait;
    use futures::StreamExt;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;

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
    fn infer_platform_prefers_windows_when_smb_is_present() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                &[22, 445],
                None,
                22,
                &[1445],
            ),
            PlatformHint::Windows
        );
    }

    #[test]
    fn infer_platform_prefers_windows_when_custom_ssh_port_and_smb_are_present() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                &[2222, 445],
                None,
                2222,
                &[1445],
            ),
            PlatformHint::Windows
        );
    }

    #[test]
    fn infer_platform_uses_unix_for_ssh_only() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                &[22],
                None,
                22,
                &[1445],
            ),
            PlatformHint::UnixLike
        );
    }

    #[test]
    fn infer_platform_returns_unknown_without_signal_ports() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                &[],
                None,
                22,
                &[1445]
            ),
            PlatformHint::Unknown
        );
    }

    #[test]
    fn infer_platform_prefers_ttl_for_unix_samba_host() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                &[22, 445],
                Some(64),
                22,
                &[1445],
            ),
            PlatformHint::UnixLike
        );
    }

    #[test]
    fn infer_platform_uses_ttl_to_detect_windows_over_ssh_only() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                &[22],
                Some(128),
                22,
                &[1445],
            ),
            PlatformHint::Windows
        );
    }

    #[test]
    fn infer_platform_uses_configured_ssh_port_for_ssh_only_hosts() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                &[2222],
                None,
                2222,
                &[1445],
            ),
            PlatformHint::UnixLike
        );
    }

    #[test]
    fn infer_platform_prefers_windows_for_loopback_forwarded_fixture() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                &[2222, 445],
                Some(64),
                2222,
                &[1445],
            ),
            PlatformHint::Windows
        );
    }

    #[test]
    fn infer_platform_prefers_windows_for_loopback_forwarded_smb_port() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                &[2222, 1445],
                Some(64),
                2222,
                &[1445],
            ),
            PlatformHint::Windows
        );
    }

    #[test]
    fn infer_platform_prefers_windows_for_non_loopback_forwarded_smb_port() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2)),
                &[4222, 1445],
                Some(64),
                4222,
                &[1445],
            ),
            PlatformHint::Windows
        );
    }

    #[test]
    fn infer_platform_prefers_windows_for_custom_forwarded_smb_port() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2)),
                &[4222, 4445],
                Some(64),
                4222,
                &[4445],
            ),
            PlatformHint::Windows
        );
    }

    #[test]
    fn infer_platform_prefers_windows_for_smb_only_forwarded_loopback_port() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                &[1445],
                Some(64),
                2222,
                &[1445],
            ),
            PlatformHint::Windows
        );
    }

    #[test]
    fn infer_platform_prefers_windows_for_smb_only_forwarded_non_loopback_port() {
        assert_eq!(
            infer_platform(
                IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2)),
                &[1445],
                Some(64),
                2222,
                &[1445],
            ),
            PlatformHint::Windows
        );
    }

    #[tokio::test]
    async fn probe_outcomes_preserve_unreachable_targets() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener should bind");
        let port = listener
            .local_addr()
            .expect("listener should have an address")
            .port();
        drop(listener);

        let discovery = TcpDiscovery::with_ttl_probe(
            DiscoveryConfig {
                ports: vec![port],
                ssh_port: port,
                forwarded_smb_ports: Vec::new(),
                connect_timeout: Duration::from_millis(100),
                concurrency_limit: 1,
            },
            Arc::new(FakeTtlProber { ttl: None }),
        );

        let outcomes = discovery
            .probe_ips_outcomes_stream(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            .collect::<Vec<_>>()
            .await;

        assert_eq!(
            outcomes,
            vec![DiscoveryOutcome::Unreachable {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST)
            }]
        );
    }

    #[tokio::test]
    async fn probe_ip_records_ttl_and_uses_it_for_platform() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener should bind");
        let port = listener
            .local_addr()
            .expect("listener should have address")
            .port();

        let discovery = TcpDiscovery::with_ttl_probe(
            DiscoveryConfig {
                ports: vec![port],
                ssh_port: port,
                forwarded_smb_ports: vec![1445],
                connect_timeout: Duration::from_millis(200),
                concurrency_limit: 4,
            },
            Arc::new(FakeTtlProber { ttl: Some(128) }),
        );

        let record = discovery
            .probe_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .await
            .expect("host should be discovered");

        assert_eq!(record.ttl, Some(128));
        assert_eq!(record.host.platform, PlatformHint::Windows);
        assert_eq!(record.host.open_ports, vec![port]);
    }
}
