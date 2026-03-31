use pandoras_box::runtime::{
    DiscoveryConfig, MissionSpec, PandorasBoxRunner, RetryPolicy, TcpDiscovery,
};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for mixed live interop tests"))
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn temp_root(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pandoras-box-{label}-{unique}"))
}

fn artifact_root() -> PathBuf {
    std::env::var("PANDORAS_BOX_LIVE_MIXED_ARTIFACT_ROOT")
        .or_else(|_| std::env::var("PANDORAS_BOX_LIVE_ARTIFACT_ROOT"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| temp_root("live-mixed-concurrency"))
}

fn host_timeout() -> Duration {
    optional_env("PANDORAS_BOX_LIVE_MIXED_HOST_TIMEOUT_SECS")
        .map(|value| {
            Duration::from_secs(
                value
                    .parse::<u64>()
                    .expect("mixed host timeout should be a valid u64"),
            )
        })
        .unwrap_or_else(|| Duration::from_secs(120))
}

fn connect_timeout() -> Duration {
    optional_env("PANDORAS_BOX_LIVE_MIXED_CONNECT_TIMEOUT_SECS")
        .map(|value| {
            Duration::from_secs(
                value
                    .parse::<u64>()
                    .expect("mixed connect timeout should be a valid u64"),
            )
        })
        .unwrap_or_else(|| Duration::from_secs(25))
}

struct SlowSshTarget {
    accept_count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl SlowSshTarget {
    async fn bind(addr: SocketAddr) -> Self {
        let listener = TcpListener::bind(addr)
            .await
            .unwrap_or_else(|err| panic!("failed to bind slow SSH target at {addr}: {err}"));
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_task = Arc::clone(&accept_count);
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                accept_count_task.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(socket);
                });
            }
        });

        Self { accept_count, task }
    }

    fn accept_count(&self) -> usize {
        self.accept_count.load(Ordering::Relaxed)
    }
}

impl Drop for SlowSshTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn wait_for_host_state(
    status_path: &Path,
    expected_state: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(status) = std::fs::read_to_string(status_path) {
            if status.contains(&format!("\"final_state\": \"{expected_state}\"")) {
                return status;
            }
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for {status_path:?} to reach {expected_state}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_any_host_state(
    status_paths: &[&Path],
    expected_state: &str,
    timeout: Duration,
) -> (PathBuf, String) {
    let deadline = Instant::now() + timeout;
    loop {
        for status_path in status_paths {
            if let Ok(status) = std::fs::read_to_string(status_path) {
                if status.contains(&format!("\"final_state\": \"{expected_state}\"")) {
                    return ((*status_path).to_path_buf(), status);
                }
            }
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for any host to reach {expected_state}: {:?}",
            status_paths
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn assert_artifacts_exist(host_dir: &Path) {
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
    assert!(!log.trim().is_empty(), "application.log should not be empty");

    let cleanup = std::fs::read_to_string(&cleanup_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", cleanup_path.display()));
    assert!(
        cleanup.contains("status: 0"),
        "cleanup should succeed: {cleanup}"
    );
}

#[tokio::test]
#[ignore = "requires Unix, Alpine, Tiny11, and the containerized slow target harness; run scripts/run-mixed-live-concurrency-container.sh"]
async fn live_mixed_concurrency_keeps_hosts_moving_until_end_reconciliation() {
    let unix_ip = required_env("PANDORAS_BOX_LIVE_MIXED_UNIX_HOST")
        .parse::<IpAddr>()
        .expect("mixed Unix host should be a valid IP address");
    let alpine_ip = required_env("PANDORAS_BOX_LIVE_MIXED_ALPINE_HOST")
        .parse::<IpAddr>()
        .expect("mixed Alpine host should be a valid IP address");
    let windows_ip = required_env("PANDORAS_BOX_LIVE_MIXED_WINDOWS_HOST")
        .parse::<IpAddr>()
        .expect("mixed Windows host should be a valid IP address");
    let slow_ip = required_env("PANDORAS_BOX_LIVE_MIXED_SLOW_HOST")
        .parse::<IpAddr>()
        .expect("mixed slow host should be a valid IP address");
    let ssh_port = required_env("PANDORAS_BOX_LIVE_MIXED_SSH_PORT")
        .parse::<u16>()
        .expect("mixed SSH port should be a valid u16");
    let smb_port = required_env("PANDORAS_BOX_LIVE_MIXED_SMB_PORT")
        .parse::<u16>()
        .expect("mixed SMB port should be a valid u16");
    let password = required_env("PANDORAS_BOX_LIVE_MIXED_PASSWORD");
    let windows_username = required_env("PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME");
    let collector_port = optional_env("PANDORAS_BOX_LIVE_MIXED_COLLECTOR_PORT")
        .map(|value| {
            value
                .parse::<u16>()
                .expect("mixed collector port should be a valid u16")
        })
        .unwrap_or_else(|| MissionSpec::default().collector_port);
    let chimera_unix_path = PathBuf::from(required_env("PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH"));
    let chimera_windows_path =
        PathBuf::from(required_env("PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH"));
    let artifact_root = artifact_root();
    let host_timeout = host_timeout();
    let connect_timeout = connect_timeout();
    let mission_id = "live-mixed-concurrency".to_string();
    let use_external_slow_target = optional_env("PANDORAS_BOX_LIVE_MIXED_EXTERNAL_SLOW_TARGET")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    assert!(
        chimera_unix_path.is_file(),
        "expected Linux Chimera binary at {}",
        chimera_unix_path.display()
    );
    assert!(
        chimera_windows_path.is_file(),
        "expected Windows Chimera binary at {}",
        chimera_windows_path.display()
    );

    let discovery = TcpDiscovery::new(DiscoveryConfig {
        ports: vec![ssh_port, smb_port],
        ssh_port,
        forwarded_smb_ports: vec![smb_port],
        connect_timeout: Duration::from_secs(2),
        concurrency_limit: 4,
    });

    let unix_record = discovery
        .probe_ip(unix_ip)
        .await
        .unwrap_or_else(|| panic!("expected discovery to reach {unix_ip}:{ssh_port}"));
    assert_eq!(unix_record.host.platform.as_str(), "unix");

    let alpine_record = discovery
        .probe_ip(alpine_ip)
        .await
        .unwrap_or_else(|| panic!("expected discovery to reach {alpine_ip}:{ssh_port}"));
    assert_eq!(alpine_record.host.platform.as_str(), "unix");

    let windows_record = discovery
        .probe_ip(windows_ip)
        .await
        .unwrap_or_else(|| panic!("expected discovery to reach {windows_ip}:{ssh_port}"));
    assert_eq!(windows_record.host.platform.as_str(), "windows");

    let slow_target = if use_external_slow_target {
        None
    } else {
        Some(SlowSshTarget::bind(SocketAddr::new(slow_ip, ssh_port)).await)
    };

    let spec = MissionSpec {
        targets: vec![unix_ip, alpine_ip, windows_ip, slow_ip],
        artifact_root: artifact_root.clone(),
        mission_id: mission_id.clone(),
        unix_username: "root".to_string(),
        windows_username,
        password,
        ssh_port,
        discovery_ports: vec![ssh_port, smb_port],
        chimera_unix_path,
        chimera_windows_path,
        collector_port,
        concurrency_limit: 4,
        retry_policy: RetryPolicy {
            max_attempts: 3,
            connect_timeout,
            backoff: Duration::from_millis(500),
        },
        ..MissionSpec::default()
    };

    let summary_path = artifact_root.join(&mission_id).join("summary.json");
    let mission = tokio::spawn(async move { PandorasBoxRunner::new(spec).run().await });

    let unix_dir = artifact_root
        .join(&mission_id)
        .join("hosts")
        .join(unix_ip.to_string());
    let alpine_dir = artifact_root
        .join(&mission_id)
        .join("hosts")
        .join(alpine_ip.to_string());
    let windows_dir = artifact_root
        .join(&mission_id)
        .join("hosts")
        .join(windows_ip.to_string());
    let slow_dir = artifact_root
        .join(&mission_id)
        .join("hosts")
        .join(slow_ip.to_string());
    let slow_status_path = slow_dir.join("status.json");

    let candidate_status_paths = [
        unix_dir.join("status.json"),
        alpine_dir.join("status.json"),
        windows_dir.join("status.json"),
    ];
    let candidate_status_refs = candidate_status_paths
        .iter()
        .map(|path| path.as_path())
        .collect::<Vec<_>>();

    let (first_completed_path, first_completed_status) =
        wait_for_any_host_state(&candidate_status_refs, "complete", host_timeout).await;

    if let Some(slow_target) = slow_target.as_ref() {
        assert!(
            slow_target.accept_count() > 0,
            "expected the slow SSH target to receive at least one connection attempt"
        );
    }
    assert!(
        !summary_path.exists(),
        "summary should not exist before the slow target finishes; first_completed={} status={}",
        first_completed_path.display(),
        first_completed_status
    );
    assert!(
        !slow_status_path.exists(),
        "slow target should still be pending when the first healthy host completes; first_completed={} slow_status={}",
        first_completed_path.display(),
        std::fs::read_to_string(&slow_status_path)
            .unwrap_or_else(|_| "<missing>".to_string())
    );

    wait_for_host_state(&unix_dir.join("status.json"), "complete", host_timeout).await;
    wait_for_host_state(&alpine_dir.join("status.json"), "complete", host_timeout).await;
    wait_for_host_state(&windows_dir.join("status.json"), "complete", host_timeout).await;

    let summary = mission
        .await
        .expect("mixed live concurrency task should not panic")
        .expect("mixed live concurrency run should complete");

    assert_eq!(summary.discovered_hosts, 4, "summary: {summary:?}");
    assert_eq!(summary.completed_hosts, 3, "summary: {summary:?}");
    assert_eq!(summary.failed_hosts, 1, "summary: {summary:?}");

    assert_artifacts_exist(&unix_dir);
    assert_artifacts_exist(&alpine_dir);
    assert_artifacts_exist(&windows_dir);

    let windows_plan = std::fs::read_to_string(windows_dir.join("plan.json"))
        .unwrap_or_else(|err| panic!("failed to read Windows plan: {err}"));
    assert!(
        windows_plan.contains("\"transport_chain\": [\"windows_ssh\", \"windows_smb\"]"),
        "expected Windows plan to prefer SSH then SMB fallback: {windows_plan}"
    );

    let slow_status = std::fs::read_to_string(slow_dir.join("status.json"))
        .unwrap_or_else(|err| panic!("failed to read slow target status: {err}"));
    assert!(
        slow_status.contains("\"final_state\": \"failed\""),
        "expected slow target to fail without stalling the mission: {slow_status}"
    );

    let summary_json = std::fs::read_to_string(&summary_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", summary_path.display()));
    assert!(
        summary_json.contains("\"completed_hosts\": 3"),
        "summary should record completed host count: {summary_json}"
    );
    assert!(
        summary_json.contains("\"failed_hosts\": 1"),
        "summary should record failed host count: {summary_json}"
    );

    let _ = std::fs::remove_dir_all(artifact_root);
}
