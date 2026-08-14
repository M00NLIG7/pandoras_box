use std::path::{Path, PathBuf};

use tempfile::tempdir;
use tokio::process::Command;

fn chimera_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chimera"))
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
async fn removed_http_surface_cannot_traverse_fetch_replay_or_delete_artifacts() {
    let root = tempdir().expect("tempdir should be created");
    let output_root = root.path().join("artifacts");
    tokio::fs::create_dir_all(&output_root)
        .await
        .expect("artifact root should be created");

    let inventory_path = output_root.join("inventory.json");
    let log_path = output_root.join("application.log");
    let sibling_path = root.path().join("victim.txt");
    tokio::fs::write(&inventory_path, b"{\"hostname\":\"lab\"}\n")
        .await
        .expect("inventory fixture should be written");
    tokio::fs::write(&log_path, b"collector log\n")
        .await
        .expect("log fixture should be written");
    tokio::fs::write(&sibling_path, b"do not expose or delete\n")
        .await
        .expect("sibling fixture should be written");

    for removed_command in ["serve", "serve-internal"] {
        for _ in 0..2 {
            let output = run_chimera(
                &[removed_command, "--port", "44372", "../victim.txt"],
                &output_root,
            )
            .await;
            assert!(
                !output.status.success(),
                "removed HTTP command {removed_command} unexpectedly succeeded"
            );
        }
    }

    assert_eq!(
        tokio::fs::read(&inventory_path)
            .await
            .expect("inventory must remain after rejected requests"),
        b"{\"hostname\":\"lab\"}\n"
    );
    assert_eq!(
        tokio::fs::read(&log_path)
            .await
            .expect("log must remain after rejected requests"),
        b"collector log\n"
    );
    assert_eq!(
        tokio::fs::read(&sibling_path)
            .await
            .expect("sibling must remain after traversal attempts"),
        b"do not expose or delete\n"
    );

    let help = run_chimera(&["--help"], &output_root).await;
    assert!(help.status.success(), "Chimera help should render");
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(
        !stdout
            .lines()
            .any(|line| line.trim_start().starts_with("serve")),
        "HTTP commands must not be advertised"
    );
}
