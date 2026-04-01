use pandoras_box::runtime::{DiscoveryRecord, TcpDiscovery};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub async fn wait_for_discovery(
    discovery: &TcpDiscovery,
    target_ip: IpAddr,
    timeout: Duration,
    interval: Duration,
) -> Option<DiscoveryRecord> {
    let deadline = Instant::now() + timeout;

    loop {
        if let Some(record) = discovery.probe_ip(target_ip).await {
            return Some(record);
        }

        if Instant::now() >= deadline {
            return None;
        }

        tokio::time::sleep(interval).await;
    }
}
