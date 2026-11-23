use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pandoras-box-{label}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("temporary artifact root should exist");
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_documentation_target(best_effort: bool) -> (Output, serde_json::Value) {
    let root = TempRoot::new(if best_effort {
        "cli-best-effort"
    } else {
        "cli-strict"
    });
    let mission_id = if best_effort {
        "cidr32-best-effort"
    } else {
        "cidr32-strict"
    };

    let mut command = Command::new(env!("CARGO_BIN_EXE_pandoras_box"));
    command.args([
        "--range",
        "192.0.2.10/32",
        "--password-stdin",
        "--mission_id",
        mission_id,
        "--artifact_root",
        root.0.to_str().expect("temporary path should be UTF-8"),
    ]);
    if best_effort {
        command.arg("--best-effort");
    }

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Pandora's Box should start");
    child
        .stdin
        .as_mut()
        .expect("password stdin should be piped")
        .write_all(b"x\n")
        .expect("fixture secret should be written");
    let output = child
        .wait_with_output()
        .expect("Pandora's Box should return an exit status");

    let summary_path = root.0.join(mission_id).join("summary.json");
    let summary = serde_json::from_slice(&std::fs::read(&summary_path).unwrap_or_else(|error| {
        panic!(
            "mission summary {} should be readable: {error}\nstderr:\n{}",
            summary_path.display(),
            String::from_utf8_lossy(&output.stderr)
        )
    }))
    .expect("mission summary should be valid JSON");

    (output, summary)
}

fn assert_truthful_zero_attempt_summary(summary: &serde_json::Value) {
    assert_eq!(summary["requested_targets"], 1);
    assert_eq!(summary["reachable_targets"], 0);
    assert_eq!(summary["unreachable_targets"], 1);
    assert_eq!(summary["skipped_targets"], 0);
    assert_eq!(summary["attempted_targets"], 0);
    assert_eq!(summary["completed_hosts"], 0);
    assert_eq!(summary["failed_hosts"], 1);
}

#[test]
fn cidr32_zero_attempts_fail_strict_cli_without_hiding_accounting() {
    let (strict_output, strict_summary) = run_documentation_target(false);
    assert!(
        !strict_output.status.success(),
        "strict mode must fail when no requested target was attempted"
    );
    assert_truthful_zero_attempt_summary(&strict_summary);
    let strict_stderr = String::from_utf8_lossy(&strict_output.stderr);
    assert!(strict_stderr.contains("mission attempted 0 of 1 targets"));

    let (best_effort_output, best_effort_summary) = run_documentation_target(true);
    assert!(
        best_effort_output.status.success(),
        "the explicit best-effort override should change only the process exit policy\nstderr:\n{}",
        String::from_utf8_lossy(&best_effort_output.stderr)
    );
    assert_truthful_zero_attempt_summary(&best_effort_summary);
}
