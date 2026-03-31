use pandoras_box::runtime::{
    DiscoveryConfig, MissionSpec, PandorasBoxRunner, RetryPolicy, TcpDiscovery,
};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct LiveUnixCase {
    label: &'static str,
    host_env: &'static str,
    port_env: &'static str,
    password_env: &'static str,
    chimera_env: &'static str,
    artifact_root_env: &'static str,
}

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

fn artifact_root(case: &LiveUnixCase) -> PathBuf {
    std::env::var(case.artifact_root_env)
        .or_else(|_| std::env::var("PANDORAS_BOX_LIVE_ARTIFACT_ROOT"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| temp_root(case.label))
}

async fn run_live_unix_case(case: LiveUnixCase) {
    let chimera_path = PathBuf::from(required_env(case.chimera_env));
    assert!(
        chimera_path.is_file(),
        "expected Linux Chimera binary at {}",
        chimera_path.display()
    );

    let target_ip = required_env(case.host_env)
        .parse::<IpAddr>()
        .expect("interop host should be a valid IP address");
    let ssh_port = required_env(case.port_env)
        .parse::<u16>()
        .expect("interop SSH port should be a valid u16");
    let password = required_env(case.password_env);
    let artifact_root = artifact_root(&case);
    let mission_id = case.label.to_string();

    let spec = MissionSpec {
        targets: vec![target_ip],
        artifact_root: artifact_root.clone(),
        mission_id: mission_id.clone(),
        unix_username: "root".to_string(),
        password,
        ssh_port,
        discovery_ports: vec![ssh_port],
        chimera_unix_path: chimera_path,
        retry_policy: RetryPolicy {
            max_attempts: 3,
            connect_timeout: Duration::from_secs(5),
            backoff: Duration::from_millis(500),
        },
        ..MissionSpec::default()
    };

    let discovery = TcpDiscovery::new(DiscoveryConfig {
        ports: vec![ssh_port],
        ssh_port,
        forwarded_smb_ports: vec![1445],
        connect_timeout: Duration::from_secs(2),
        concurrency_limit: 1,
    });
    let discovery_record = discovery.probe_ip(target_ip).await;
    assert!(
        discovery_record.is_some(),
        "expected discovery to reach {target_ip}:{ssh_port} before the live run"
    );

    let summary = PandorasBoxRunner::new(spec)
        .run()
        .await
        .expect("live Unix SSH interop run should succeed");

    let host_dir = artifact_root
        .join(mission_id)
        .join("hosts")
        .join(target_ip.to_string());
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

    let cleanup = std::fs::read_to_string(&cleanup_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", cleanup_path.display()));
    assert!(
        cleanup.contains("status: 0"),
        "cleanup should succeed: {cleanup}"
    );

    let status = std::fs::read_to_string(&status_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", status_path.display()));
    assert!(
        status.contains("\"final_state\": \"complete\""),
        "host status should be complete: {status}"
    );

    let _ = std::fs::remove_dir_all(artifact_root);
}

#[tokio::test]
#[ignore = "requires docker-backed SSH target; run scripts/run-unix-ssh-interop.sh"]
async fn live_unix_ssh_target_collects_inventory_and_cleans_up() {
    run_live_unix_case(LiveUnixCase {
        label: "live-unix-ssh",
        host_env: "PANDORAS_BOX_LIVE_UNIX_SSH_HOST",
        port_env: "PANDORAS_BOX_LIVE_UNIX_SSH_PORT",
        password_env: "PANDORAS_BOX_LIVE_UNIX_SSH_PASSWORD",
        chimera_env: "PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH",
        artifact_root_env: "PANDORAS_BOX_LIVE_UNIX_SSH_ARTIFACT_ROOT",
    })
    .await;
}

#[tokio::test]
#[ignore = "requires docker-backed Alpine SSH target; run scripts/run-alpine-ssh-interop.sh"]
async fn live_alpine_ssh_target_collects_inventory_and_cleans_up() {
    run_live_unix_case(LiveUnixCase {
        label: "live-alpine-ssh",
        host_env: "PANDORAS_BOX_LIVE_ALPINE_SSH_HOST",
        port_env: "PANDORAS_BOX_LIVE_ALPINE_SSH_PORT",
        password_env: "PANDORAS_BOX_LIVE_ALPINE_SSH_PASSWORD",
        chimera_env: "PANDORAS_BOX_LIVE_ALPINE_CHIMERA_UNIX_PATH",
        artifact_root_env: "PANDORAS_BOX_LIVE_ALPINE_SSH_ARTIFACT_ROOT",
    })
    .await;
}
