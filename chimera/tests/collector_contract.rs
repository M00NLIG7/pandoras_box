use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::Client;
use tempfile::tempdir;
use tokio::process::Command;
use tokio::time::{sleep, Instant};

fn chimera_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chimera"))
}

fn free_loopback_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("ephemeral loopback port should bind")
        .local_addr()
        .expect("local addr should be available")
        .port()
}

fn command_debug_string(command: &Command) -> String {
    format!("{command:?}")
}

async fn run_chimera(args: &[&str], output_root: &Path) -> std::process::Output {
    let mut command = Command::new(chimera_bin());
    command.args(["--output-root", output_root.to_string_lossy().as_ref()]);
    command.args(args);
    command
        .output()
        .await
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", command_debug_string(&command)))
}

async fn wait_for_http_ok(client: &Client, url: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;

    loop {
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => return,
            _ if Instant::now() >= deadline => {
                panic!("timed out waiting for {url}");
            }
            _ => sleep(Duration::from_millis(100)).await,
        }
    }
}

#[tokio::test]
async fn collector_command_writes_inventory_and_application_log() {
    let output_root = tempdir().expect("tempdir should be created");

    let output = run_chimera(&["collector"], output_root.path()).await;

    assert!(
        output.status.success(),
        "collector failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let inventory_path = output_root.path().join("inventory.json");
    let log_path = output_root.path().join("application.log");

    let inventory = tokio::fs::read_to_string(&inventory_path)
        .await
        .expect("inventory.json should exist");
    let log = tokio::fs::read_to_string(&log_path)
        .await
        .expect("application.log should exist");

    serde_json::from_str::<serde_json::Value>(&inventory)
        .expect("inventory.json should contain valid JSON");
    assert!(
        !log.trim().is_empty(),
        "application.log should not be empty after collector run"
    );
}

#[tokio::test]
async fn serve_internal_exposes_and_removes_runtime_artifacts() {
    let output_root = tempdir().expect("tempdir should be created");
    let inventory_path = output_root.path().join("inventory.json");
    let log_path = output_root.path().join("application.log");
    tokio::fs::write(&inventory_path, b"{\"hostname\":\"lab\"}\n")
        .await
        .expect("inventory fixture should be written");
    tokio::fs::write(&log_path, b"collector log\n")
        .await
        .expect("log fixture should be written");

    let port = free_loopback_port();
    let mut child = Command::new(chimera_bin());
    child
        .args([
            "--output-root",
            output_root.path().to_string_lossy().as_ref(),
        ])
        .args(["serve-internal", "--port", &port.to_string()])
        .kill_on_drop(true);

    let mut child = child.spawn().expect("serve-internal should spawn");
    let client = Client::builder()
        .connect_timeout(Duration::from_millis(250))
        .timeout(Duration::from_secs(2))
        .build()
        .expect("HTTP client should build");

    let root_url = format!("http://127.0.0.1:{port}/");
    let inventory_url = format!("http://127.0.0.1:{port}/inventory.json");
    let log_url = format!("http://127.0.0.1:{port}/application.log");
    wait_for_http_ok(&client, &root_url, Duration::from_secs(5)).await;

    let inventory = client
        .get(&inventory_url)
        .send()
        .await
        .expect("inventory request should succeed")
        .text()
        .await
        .expect("inventory body should be readable");
    assert_eq!(inventory, "{\"hostname\":\"lab\"}\n");

    let log = client
        .get(&log_url)
        .send()
        .await
        .expect("log request should succeed")
        .text()
        .await
        .expect("log body should be readable");
    assert_eq!(log, "collector log\n");

    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .expect("serve-internal should stop after terminal artifact fetch")
        .expect("serve-internal wait should succeed");
    assert!(status.success(), "serve-internal should exit cleanly");

    assert!(
        tokio::fs::metadata(&inventory_path).await.is_err(),
        "inventory.json should be removed after serving"
    );
    assert!(
        tokio::fs::metadata(&log_path).await.is_err(),
        "application.log should be removed after serving"
    );
}
