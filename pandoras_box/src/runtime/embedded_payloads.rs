use super::artifact_store::ArtifactStore;
use super::mission::{HostPlan, MissionSpec, TransportKind};
use crate::{Error, Result};
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const DEFAULT_CHIMERA_UNIX_PATH: &str = "release/chimera";
const DEFAULT_CHIMERA_WINDOWS_PATH: &str = "release/chimera.exe";
const EMBEDDED_CHIMERA_UNIX_GZ: &[u8] =
    include_bytes!("../../assets/chimera-i686-unknown-linux-musl.gz");
const EMBEDDED_CHIMERA_WINDOWS_GZ: &[u8] =
    include_bytes!("../../assets/chimera-i686-pc-windows-gnu.exe.gz");

pub async fn ensure_embedded_chimera_payloads_for_plan(
    spec: &mut MissionSpec,
    store: &ArtifactStore,
    plan: &HostPlan,
) -> Result<()> {
    if plan_requires_unix_payload(plan) && uses_embedded_unix_payload(&spec.chimera_unix_path) {
        spec.chimera_unix_path =
            materialize_payload(store, "chimera", EMBEDDED_CHIMERA_UNIX_GZ, true).await?;
    }

    if plan_requires_windows_payload(plan)
        && uses_embedded_windows_payload(&spec.chimera_windows_path)
    {
        spec.chimera_windows_path =
            materialize_payload(store, "chimera.exe", EMBEDDED_CHIMERA_WINDOWS_GZ, false).await?;
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

fn uses_embedded_unix_payload(path: &Path) -> bool {
    path == Path::new(DEFAULT_CHIMERA_UNIX_PATH)
}

fn uses_embedded_windows_payload(path: &Path) -> bool {
    path == Path::new(DEFAULT_CHIMERA_WINDOWS_PATH)
}

async fn materialize_payload(
    store: &ArtifactStore,
    file_name: &str,
    compressed_payload: &[u8],
    executable: bool,
) -> Result<PathBuf> {
    let path = store.embedded_payload_dir().join(file_name);
    if tokio::fs::try_exists(&path).await? {
        return Ok(path);
    }

    tokio::fs::create_dir_all(store.embedded_payload_dir()).await?;
    let payload = gunzip_payload(compressed_payload)?;
    tokio::fs::write(&path, payload).await?;

    #[cfg(unix)]
    if executable {
        let permissions = std::fs::Permissions::from_mode(0o755);
        tokio::fs::set_permissions(&path, permissions).await?;
    }

    Ok(path)
}

fn gunzip_payload(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut payload = Vec::new();
    decoder.read_to_end(&mut payload).map_err(|err| {
        Error::DeploymentError(format!(
            "failed to decompress embedded Chimera payload: {err}"
        ))
    })?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::ensure_embedded_chimera_payloads_for_plan;
    use crate::runtime::{
        ArtifactStore, HostPlan, HostTarget, MissionSpec, PlatformHint, TransportKind,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
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
    async fn default_mission_spec_materializes_only_the_needed_embedded_chimera_payload() {
        let root = unique_root("pandoras-box-embedded-chimera");
        let mission_id = "embedded-payloads".to_string();
        let store = ArtifactStore::new(&root, &mission_id);
        let mut spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id,
            ..MissionSpec::default()
        };

        ensure_embedded_chimera_payloads_for_plan(&mut spec, &store, &unix_plan())
            .await
            .expect("embedded payloads should materialize");

        assert!(spec
            .chimera_unix_path
            .starts_with(store.embedded_payload_dir()));
        assert!(tokio::fs::try_exists(&spec.chimera_unix_path)
            .await
            .unwrap());
        assert_eq!(
            spec.chimera_windows_path,
            PathBuf::from("release/chimera.exe")
        );

        ensure_embedded_chimera_payloads_for_plan(&mut spec, &store, &windows_plan())
            .await
            .expect("windows payload should materialize when needed");

        assert!(spec
            .chimera_windows_path
            .starts_with(store.embedded_payload_dir()));
        assert!(tokio::fs::try_exists(&spec.chimera_windows_path)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn explicit_chimera_paths_are_not_replaced_by_embedded_payloads() {
        let root = unique_root("pandoras-box-explicit-payload");
        let mission_id = "explicit-payloads".to_string();
        let store = ArtifactStore::new(&root, &mission_id);
        let unix_override = root.join("fixtures/chimera");
        let windows_override = root.join("fixtures/chimera.exe");
        tokio::fs::create_dir_all(unix_override.parent().unwrap())
            .await
            .expect("fixture dir should exist");
        tokio::fs::write(&unix_override, b"unix fixture")
            .await
            .expect("unix fixture should be written");
        tokio::fs::write(&windows_override, b"windows fixture")
            .await
            .expect("windows fixture should be written");

        let mut spec = MissionSpec {
            artifact_root: root,
            mission_id,
            chimera_unix_path: unix_override.clone(),
            chimera_windows_path: windows_override.clone(),
            ..MissionSpec::default()
        };

        ensure_embedded_chimera_payloads_for_plan(&mut spec, &store, &windows_plan())
            .await
            .expect("explicit fixture paths should be preserved");

        assert_eq!(spec.chimera_unix_path, unix_override);
        assert_eq!(spec.chimera_windows_path, windows_override);
    }
}
