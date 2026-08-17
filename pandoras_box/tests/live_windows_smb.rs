use pandoras_box::runtime::{
    CpuArchitecture, DeadlinePolicy, DiscoveryConfig, MissionSpec, OperatingSystem,
    PandorasBoxRunner, RetryPolicy, TargetContract, TcpDiscovery, WindowsSmbExecMode,
};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod support;

use support::{qualified_payload, wait_for_discovery};

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
async fn live_windows_smb_refuses_unencrypted_remote_exec_before_authentication() {
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
        backoff: Duration::from_millis(500),
    };
    let payload = qualified_payload(
        chimera_path,
        OperatingSystem::Windows,
        CpuArchitecture::X86_64,
        "explicit live Windows SMB fixture",
    )
    .await;

    let spec = MissionSpec {
        targets: vec![target_ip],
        artifact_root: artifact_root.clone(),
        mission_id: mission_id.clone(),
        windows_username: username,
        password: password.into(),
        ssh_port: ssh_probe_port,
        discovery_ports: vec![ssh_probe_port, smb_port],
        default_target_contract: TargetContract::windows(CpuArchitecture::X86_64, true),
        payload_catalog: vec![payload],
        retry_policy,
        deadlines: DeadlinePolicy {
            connect: Duration::from_secs(5),
            inactivity: Duration::from_secs(30),
            ..DeadlinePolicy::default()
        },
        allow_smb_fallback: true,
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
        .expect("SMB security refusal should be a reconciled host outcome");

    let host_dir = artifact_root
        .join(mission_id)
        .join("hosts")
        .join(target_ip.to_string());
    let plan_path = host_dir.join("plan.json");
    let status_path = host_dir.join("status.json");
    assert_eq!(summary.discovered_hosts, 1, "summary: {summary:?}");
    assert_eq!(summary.attempted_targets, 0, "summary: {summary:?}");
    assert_eq!(summary.completed_hosts, 0, "summary: {summary:?}");
    assert_eq!(summary.failed_hosts, 1, "summary: {summary:?}");

    let plan = std::fs::read_to_string(&plan_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", plan_path.display()));
    assert!(plan.contains("\"operating_system\": \"windows\""), "{plan}");
    assert!(
        plan.contains("windows_smb_encryption_required"),
        "requested SMB contract should remain visible: {plan}"
    );
    assert!(
        plan.contains("\"transport_chain\": []"),
        "unqualified SMB adapter must not enter execution: {plan}"
    );

    let status = std::fs::read_to_string(&status_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", status_path.display()));
    assert!(status.contains("\"attempt_count\": 0"), "{status}");
    assert!(
        status.contains("authentication was not attempted"),
        "{status}"
    );
    assert!(status.contains("cannot enforce encryption"), "{status}");
    assert!(!host_dir.join("files/inventory.json").exists());
    assert!(!host_dir.join("exec/collector_cleanup.txt").exists());

    let _ = std::fs::remove_dir_all(artifact_root);
}
