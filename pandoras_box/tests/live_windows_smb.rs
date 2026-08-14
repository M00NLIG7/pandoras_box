use pandoras_box::runtime::{
    DiscoveryConfig, MissionSpec, PandorasBoxRunner, RetryPolicy, TcpDiscovery, WindowsSmbExecMode,
};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod support;

use support::wait_for_discovery;

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for live interop tests"))
}

fn temp_root(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pandoras-box-{label}-{unique}"))
}

fn artifact_root() -> PathBuf {
    std::env::var("PANDORAS_BOX_LIVE_WINDOWS_SMB_ARTIFACT_ROOT")
        .or_else(|_| std::env::var("PANDORAS_BOX_LIVE_ARTIFACT_ROOT"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| temp_root("live-windows-smb"))
}

fn smb_exec_mode() -> WindowsSmbExecMode {
    match std::env::var("PANDORAS_BOX_LIVE_WINDOWS_SMB_EXEC_MODE")
        .unwrap_or_else(|_| "smbexec".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "smbexec" => WindowsSmbExecMode::SmbExec,
        "psexec" => WindowsSmbExecMode::PsExec,
        other => {
            panic!("PANDORAS_BOX_LIVE_WINDOWS_SMB_EXEC_MODE must be smbexec or psexec, got {other}")
        }
    }
}

#[tokio::test]
#[ignore = "requires a local Tiny11 SMB target; run scripts/run-windows-smb-interop.sh"]
async fn live_windows_smb_target_collects_inventory_and_cleans_up() {
    let chimera_path = PathBuf::from(required_env("PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH"));
    assert!(
        chimera_path.is_file(),
        "expected Windows Chimera binary at {}",
        chimera_path.display()
    );

    let target_ip = required_env("PANDORAS_BOX_LIVE_WINDOWS_SMB_HOST")
        .parse::<IpAddr>()
        .expect("interop host should be a valid IP address");
    let ssh_probe_port = required_env("PANDORAS_BOX_LIVE_WINDOWS_SMB_SSH_PROBE_PORT")
        .parse::<u16>()
        .expect("interop SSH probe port should be a valid u16");
    let smb_port = required_env("PANDORAS_BOX_LIVE_WINDOWS_SMB_PORT")
        .parse::<u16>()
        .expect("interop SMB port should be a valid u16");
    let username = required_env("PANDORAS_BOX_LIVE_WINDOWS_SMB_USERNAME");
    let password = required_env("PANDORAS_BOX_LIVE_WINDOWS_SMB_PASSWORD");
    let artifact_root = artifact_root();
    let _ = std::fs::remove_dir_all(&artifact_root);
    let mission_id = "live-windows-smb".to_string();
    let retry_policy = RetryPolicy {
        max_attempts: 3,
        connect_timeout: Duration::from_secs(5),
        backoff: Duration::from_millis(500),
    };

    let spec = MissionSpec {
        targets: vec![target_ip],
        artifact_root: artifact_root.clone(),
        mission_id: mission_id.clone(),
        windows_username: username,
        password,
        ssh_port: ssh_probe_port,
        discovery_ports: vec![ssh_probe_port, smb_port],
        chimera_windows_path: chimera_path,
        retry_policy,
        windows_smb_exec_mode: smb_exec_mode(),
        ..MissionSpec::default()
    };

    let discovery = TcpDiscovery::new(DiscoveryConfig {
        ports: vec![ssh_probe_port, smb_port],
        ssh_port: ssh_probe_port,
        forwarded_smb_ports: vec![smb_port],
        connect_timeout: Duration::from_secs(2),
        concurrency_limit: 1,
    });
    let discovery_record = wait_for_discovery(
        &discovery,
        target_ip,
        Duration::from_secs(10),
        Duration::from_millis(250),
    )
    .await
    .expect("expected discovery to reach the Tiny11 fixture before the live run");
    assert_eq!(
        discovery_record.host.platform.as_str(),
        "windows",
        "Tiny11 should classify as Windows when only SMB is visible to Pandora's Box"
    );
    assert!(
        !discovery_record.host.open_ports.contains(&ssh_probe_port),
        "the SMB-only harness expects the configured SSH probe port to stay closed"
    );
    assert!(
        discovery_record.host.open_ports.contains(&smb_port),
        "the SMB-only harness expects the forwarded SMB port to be visible"
    );

    let summary = PandorasBoxRunner::new(spec)
        .run()
        .await
        .expect("live Windows SMB interop run should succeed");

    let host_dir = artifact_root
        .join(mission_id)
        .join("hosts")
        .join(target_ip.to_string());
    let plan_path = host_dir.join("plan.json");
    let status_path = host_dir.join("status.json");
    let status_snapshot = std::fs::read_to_string(&status_path)
        .unwrap_or_else(|err| format!("missing status at {}: {err}", status_path.display()));

    assert_eq!(
        summary.discovered_hosts, 1,
        "summary: {summary:?}\nstatus: {status_snapshot}"
    );
    assert_eq!(
        summary.completed_hosts, 1,
        "summary: {summary:?}\nstatus: {status_snapshot}"
    );
    assert_eq!(
        summary.failed_hosts, 0,
        "summary: {summary:?}\nstatus: {status_snapshot}"
    );

    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", plan_path.display()));
    assert!(
        plan.contains("\"platform\": \"windows\""),
        "plan should classify the fixture as Windows: {plan}"
    );
    assert!(
        plan.contains("\"transport_chain\": [\"windows_smb\"]"),
        "plan should use the SMB fallback path only: {plan}"
    );

    let inventory_path = host_dir.join("files").join("inventory.json");
    let log_path = host_dir.join("logs").join("application.log");
    let cleanup_path = host_dir.join("exec").join("collector_cleanup.txt");

    let inventory = std::fs::read_to_string(&inventory_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", inventory_path.display()));
    assert!(
        inventory.trim_start().starts_with('{'),
        "expected inventory JSON payload, got: {inventory}"
    );

    let log = std::fs::read_to_string(&log_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", log_path.display()));
    assert!(
        !log.trim().is_empty(),
        "application.log should not be empty"
    );

    let status = std::fs::read_to_string(&status_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", status_path.display()));
    assert!(
        status.contains("\"final_state\": \"complete\""),
        "host status should be complete: {status}"
    );
    let cleanup = std::fs::read_to_string(&cleanup_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", cleanup_path.display()));
    assert!(
        cleanup.contains("status: 0"),
        "cleanup should succeed: {cleanup}"
    );

    let _ = std::fs::remove_dir_all(artifact_root);
}
