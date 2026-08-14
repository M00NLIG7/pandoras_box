use std::path::Path;

use super::mission::{HostPlan, MissionSpec, TransportKind};
use crate::{Error, Result};

pub async fn ensure_chimera_payload_for_plan(spec: &MissionSpec, plan: &HostPlan) -> Result<()> {
    if spec.dry_run {
        return Ok(());
    }

    if plan_requires_unix_payload(plan) {
        validate_payload(&spec.chimera_unix_path, "Unix").await?;
    }

    if plan_requires_windows_payload(plan) {
        validate_payload(&spec.chimera_windows_path, "Windows").await?;
    }

    Ok(())
}

async fn validate_payload(path: &Path, platform: &str) -> Result<()> {
    let metadata = tokio::fs::metadata(path).await.map_err(|err| {
        Error::DeploymentError(format!(
            "{platform} Chimera payload is unavailable at {}: {err}",
            path.display()
        ))
    })?;

    if !metadata.is_file() || metadata.len() == 0 {
        return Err(Error::DeploymentError(format!(
            "{platform} Chimera payload must be a non-empty regular file: {}",
            path.display()
        )));
    }

    Ok(())
}

fn plan_requires_unix_payload(plan: &HostPlan) -> bool {
    plan.transport_chain
        .iter()
        .any(|transport| matches!(transport, TransportKind::UnixSsh))
}

fn plan_requires_windows_payload(plan: &HostPlan) -> bool {
    plan.transport_chain.iter().any(|transport| {
        matches!(
            transport,
            TransportKind::WindowsSsh | TransportKind::WindowsSmb
        )
    })
}

#[cfg(test)]
mod tests {
    use super::ensure_chimera_payload_for_plan;
    use crate::runtime::{HostPlan, HostTarget, MissionSpec, PlatformHint, TransportKind};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_root(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn unix_plan() -> HostPlan {
        HostPlan::queued(
            HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)),
                platform: PlatformHint::Unix,
                open_ports: vec![22],
            },
            vec![TransportKind::UnixSsh],
        )
    }

    fn windows_plan() -> HostPlan {
        HostPlan::queued(
            HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12)),
                platform: PlatformHint::Windows,
                open_ports: vec![22, 445],
            },
            vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb],
        )
    }

    #[tokio::test]
    async fn missing_default_payload_is_rejected_instead_of_materializing_opaque_bytes() {
        let root = unique_root("pandoras-box-missing-payload");
        let spec = MissionSpec {
            chimera_unix_path: root.join("missing-chimera"),
            ..MissionSpec::default()
        };

        let error = ensure_chimera_payload_for_plan(&spec, &unix_plan())
            .await
            .expect_err("missing payload should fail before staging");

        assert!(error.to_string().contains("payload is unavailable"));
    }

    #[tokio::test]
    async fn only_the_payload_required_by_the_selected_transport_is_validated() {
        let root = unique_root("pandoras-box-explicit-payload");
        let windows_payload = root.join("chimera.exe");
        tokio::fs::create_dir_all(&root)
            .await
            .expect("fixture directory should exist");
        tokio::fs::write(&windows_payload, b"audited windows fixture")
            .await
            .expect("fixture payload should be written");

        let spec = MissionSpec {
            chimera_unix_path: root.join("missing-unix-payload"),
            chimera_windows_path: windows_payload,
            ..MissionSpec::default()
        };

        ensure_chimera_payload_for_plan(&spec, &windows_plan())
            .await
            .expect("the selected explicit payload should validate");

        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
