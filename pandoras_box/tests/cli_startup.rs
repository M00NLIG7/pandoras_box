use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn help_does_not_write_to_the_working_directory() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let working_directory = std::env::temp_dir().join(format!(
        "pandoras-box-cli-startup-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&working_directory).expect("temporary working directory should exist");

    let output = Command::new(env!("CARGO_BIN_EXE_pandoras_box"))
        .arg("--help")
        .current_dir(&working_directory)
        .output()
        .expect("Pandora's Box help should run");
    let entries: Vec<_> = std::fs::read_dir(&working_directory)
        .expect("temporary working directory should be readable")
        .collect();
    std::fs::remove_dir_all(&working_directory)
        .expect("temporary working directory should be removable");

    assert!(output.status.success());
    assert!(
        entries.is_empty(),
        "help must not create a log or artifact in the current directory"
    );
}
