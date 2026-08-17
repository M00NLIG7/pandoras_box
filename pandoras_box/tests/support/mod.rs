use pandoras_box::runtime::{
    CpuArchitecture, DiscoveryRecord, OperatingSystem, PayloadQualification, PayloadSpec,
    TcpDiscovery,
};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub async fn qualified_payload(
    path: PathBuf,
    operating_system: OperatingSystem,
    architecture: CpuArchitecture,
    evidence: &str,
) -> PayloadSpec {
    let bytes = tokio::fs::read(&path)
        .await
        .unwrap_or_else(|error| panic!("failed to read payload {}: {error}", path.display()));
    PayloadSpec {
        operating_system,
        architecture,
        path,
        version: env!("CARGO_PKG_VERSION").to_string(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        qualification: PayloadQualification::LiveQualified,
        evidence: vec![evidence.to_string()],
    }
}

#[allow(dead_code)]
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
