use clap::{arg as carg, command, value_parser, ArgGroup, ArgMatches, Command as ClapCommand};
use log::{error, info};
use pandoras_box::*;
use std::fs::File;
use std::io::{BufRead, Read};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

const MAX_LOGIN_SECRET_BYTES: u64 = 4096;

fn current_timestamp_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

fn mission_id_value(value: &str) -> std::result::Result<String, String> {
    runtime::validate_mission_id(value)
        .map(|()| value.to_string())
        .map_err(|err| err.to_string())
}

fn normalize_login_secret(mut value: String) -> Result<runtime::SecretString> {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.pop();
    }

    if value.is_empty() {
        return Err(Error::ArgumentError(
            "login secret cannot be empty".to_string(),
        ));
    }
    if value.len() > MAX_LOGIN_SECRET_BYTES as usize {
        return Err(Error::ArgumentError(format!(
            "login secret exceeds {MAX_LOGIN_SECRET_BYTES} bytes"
        )));
    }
    if value.contains('\r') || value.contains('\n') {
        return Err(Error::ArgumentError(
            "login secret input must contain exactly one line".to_string(),
        ));
    }

    Ok(runtime::SecretString::new(value))
}

fn read_login_secret(
    matches: &ArgMatches,
    stdin: &mut impl BufRead,
) -> Result<runtime::SecretString> {
    let mut value = String::new();
    if matches.get_flag("password-stdin") {
        (&mut *stdin)
            .take(MAX_LOGIN_SECRET_BYTES + 2)
            .read_to_string(&mut value)?;
    } else {
        let path = matches
            .get_one::<PathBuf>("password-file")
            .ok_or_else(|| Error::ArgumentError("a login secret source is required".to_string()))?;
        let file = File::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = file.metadata()?;
            if metadata.is_file() && metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::ArgumentError(format!(
                    "password file {} must not be accessible by group or other users",
                    path.display()
                )));
            }
        }
        file.take(MAX_LOGIN_SECRET_BYTES + 2)
            .read_to_string(&mut value)?;
    }

    normalize_login_secret(value)
}

fn build_cli() -> ClapCommand {
    command!()
        .arg(
            carg!(-r --range <IP_RANGE>)
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(--"password-stdin" "Read the login secret from standard input")
                .required(false),
        )
        .arg(
            carg!(--"password-file" <PATH> "Read the login secret from a protected file or file descriptor")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .group(
            ArgGroup::new("password-source")
                .required(true)
                .multiple(false)
                .args(["password-stdin", "password-file"]),
        )
        .arg(carg!(--dry_run "Skip remote mutation operations"))
        .arg(carg!(--"dangerously-accept-unknown-host-keys" "DANGER: permit first contact with an unknown SSH host key; changed enrolled keys are still rejected"))
        .arg(carg!(--"best-effort" "Return success after handled target failures, including zero attempted targets; unhandled mission errors still fail"))
        .arg(
            carg!(--"max-targets" <COUNT> "Reject a CIDR containing more usable targets than this bound")
                .required(false)
                .default_value("65536")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            carg!(--artifact_root <DIR>)
                .required(false)
                .default_value("artifacts")
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(--mission_id <MISSION_ID>)
                .required(false)
                .value_parser(clap::builder::ValueParser::new(mission_id_value)),
        )
        .arg(
            carg!(--identity_command <COMMAND>)
                .required(false)
                .default_value("whoami")
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(--unix_user <USERNAME>)
                .required(false)
                .default_value("root")
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(--windows_user <USERNAME>)
                .required(false)
                .default_value("Administrator")
                .value_parser(value_parser!(String)),
        )
}

fn mission_spec_from_matches(
    matches: &ArgMatches,
    targets: Vec<IpAddr>,
    password: runtime::SecretString,
) -> runtime::MissionSpec {
    let mission_id_explicit =
        matches.contains_id("mission_id") && matches.get_one::<String>("mission_id").is_some();
    let mission_id = matches
        .get_one::<String>("mission_id")
        .cloned()
        .unwrap_or_else(current_timestamp_string);

    runtime::MissionSpec {
        targets,
        artifact_root: PathBuf::from(
            matches
                .get_one::<String>("artifact_root")
                .expect("artifact_root should have a default"),
        ),
        mission_id,
        mission_id_explicit,
        identity_command: matches
            .get_one::<String>("identity_command")
            .expect("identity_command should have a default")
            .clone(),
        unix_username: matches
            .get_one::<String>("unix_user")
            .expect("unix_user should have a default")
            .clone(),
        windows_username: matches
            .get_one::<String>("windows_user")
            .expect("windows_user should have a default")
            .clone(),
        password,
        ssh_host_key_policy: if matches.get_flag("dangerously-accept-unknown-host-keys") {
            runtime::SshHostKeyPolicy::DangerouslyAcceptUnknown
        } else {
            runtime::SshHostKeyPolicy::RequireKnown
        },
        best_effort: matches.get_flag("best-effort"),
        dry_run: matches.get_flag("dry_run"),
        ..runtime::MissionSpec::default()
    }
}

pub fn setup_tracing() -> Result<()> {
    let console_layer = tracing_subscriber::fmt::layer()
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true);
    let filter_layer = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(console_layer)
        .try_init()
        .map_err(|err| Error::CommandError(format!("failed to initialize logging: {err}")))
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = build_cli().get_matches();
    setup_tracing()?;

    let range = matches.get_one::<String>("range").unwrap();
    let password = {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        read_login_secret(&matches, &mut stdin)?
    };

    info!("Starting application with range: {}", range);

    let subnet = match enumerator::Subnet::try_from(range.as_str()) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse subnet: {}", e);
            return Err(Error::InvalidSubnet(e.to_string()));
        }
    };

    info!("Created subnet: {}", range);

    let max_targets = *matches
        .get_one::<usize>("max-targets")
        .expect("max-targets should have a default");
    let targets = subnet.hosts_bounded(max_targets)?;
    let spec = mission_spec_from_matches(&matches, targets, password);
    let best_effort = spec.best_effort;

    let summary = runtime::PandorasBoxRunner::new(spec).run().await?;
    info!(
        concat!(
            "Pandora's Box completed: requested={} reachable={} unreachable={} skipped={} ",
            "attempted={} complete={} failed={} mission_dir={}"
        ),
        summary.requested_targets,
        summary.reachable_targets,
        summary.unreachable_targets,
        summary.skipped_targets,
        summary.attempted_targets,
        summary.completed_hosts,
        summary.failed_hosts,
        summary.mission_dir.display()
    );

    if summary.requires_failure_exit() && !best_effort {
        return Err(Error::MissionFailure(format!(
            "mission attempted {} of {} targets and recorded {} failures ({} unreachable, {} skipped)",
            summary.attempted_targets,
            summary.requested_targets,
            summary.failed_hosts,
            summary.unreachable_targets,
            summary.skipped_targets
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_cli, mission_spec_from_matches, read_login_secret};
    use crate::enumerator::Subnet;
    use std::io::Cursor;
    use std::path::PathBuf;

    #[test]
    fn cli_rejects_public_chimera_override_flags() {
        let error = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--collector_port",
                "45555",
            ])
            .expect_err("CLI should reject collector override flags");

        assert!(error.to_string().contains("--collector_port"));
    }

    #[test]
    fn cli_rejects_engine_flag_from_legacy_selector() {
        let error = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--engine",
                "legacy",
            ])
            .expect_err("CLI should reject the legacy engine selector");

        assert!(error.to_string().contains("--engine"));
    }

    #[test]
    fn mission_spec_from_matches_uses_internal_chimera_defaults() {
        let matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--mission_id",
                "mission-override",
            ])
            .expect("CLI should parse Pandora's Box arguments");
        let targets = Subnet::try_from("10.0.0.0/30")
            .expect("subnet should parse")
            .hosts_bounded(crate::enumerator::DEFAULT_MAX_TARGETS)
            .expect("small subnet should fit the target limit");

        let spec = mission_spec_from_matches(&matches, targets.clone(), "secret".into());

        assert_eq!(spec.targets, targets);
        assert_eq!(spec.mission_id, "mission-override");
        assert!(spec.mission_id_explicit);
        assert_eq!(spec.chimera_unix_path, PathBuf::from("release/chimera"));
        assert_eq!(
            spec.chimera_windows_path,
            PathBuf::from("release/chimera.exe")
        );
        assert_eq!(spec.password.expose_secret(), "secret");
        assert_eq!(
            spec.ssh_host_key_policy,
            crate::runtime::SshHostKeyPolicy::RequireKnown
        );
        assert!(spec.allow_smb_fallback);
    }

    #[test]
    fn cli_rejects_mission_ids_that_escape_one_path_component() {
        for mission_id in ["../escape", "/tmp/escape", r"..\escape", "line\nbreak", "."] {
            let error = build_cli()
                .try_get_matches_from([
                    "pandoras_box",
                    "--range",
                    "10.0.0.0/30",
                    "--password-stdin",
                    "--mission_id",
                    mission_id,
                ])
                .expect_err("unsafe mission identifier should be rejected");

            assert!(error.to_string().contains("portable path component"));
        }
    }

    #[test]
    fn cli_rejects_password_in_process_arguments() {
        let error = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password",
                "must-not-be-an-argv-secret",
            ])
            .expect_err("login secrets in process arguments must not be supported");

        assert!(error.to_string().contains("--password"));
    }

    #[test]
    fn cli_requires_exactly_one_non_argv_secret_source() {
        let missing = build_cli()
            .try_get_matches_from(["pandoras_box", "--range", "10.0.0.0/30"])
            .expect_err("a secret source should be required");
        assert!(missing.to_string().contains("--password-stdin"));

        let duplicate = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--password-file",
                "/dev/null",
            ])
            .expect_err("secret sources should be mutually exclusive");
        assert!(duplicate.to_string().contains("cannot be used with"));
    }

    #[test]
    fn password_stdin_reads_one_redacted_line() {
        let matches = build_cli()
            .try_get_matches_from(["pandoras_box", "--range", "10.0.0.0/30", "--password-stdin"])
            .expect("stdin secret source should parse");
        let mut input = Cursor::new(b"stdin-only-secret\n".to_vec());

        let secret = read_login_secret(&matches, &mut input)
            .expect("one newline-terminated secret should be accepted");
        assert_eq!(secret.expose_secret(), "stdin-only-secret");
        assert!(!format!("{secret:?}").contains("stdin-only-secret"));
    }

    #[test]
    fn dangerous_unknown_host_policy_requires_conspicuous_flag() {
        let matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--dangerously-accept-unknown-host-keys",
            ])
            .expect("explicit dangerous host-key policy should parse");
        let spec = mission_spec_from_matches(&matches, Vec::new(), "secret".into());

        assert_eq!(
            spec.ssh_host_key_policy,
            crate::runtime::SshHostKeyPolicy::DangerouslyAcceptUnknown
        );
    }

    #[cfg(unix)]
    #[test]
    fn password_file_requires_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pandora-password-{unique}"));
        std::fs::write(&path, "file-only-secret\n").expect("secret fixture should be written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secret fixture should be private");
        let path_value = path.to_string_lossy().into_owned();
        let matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-file",
                &path_value,
            ])
            .expect("password file source should parse");

        let secret = read_login_secret(&matches, &mut Cursor::new(Vec::<u8>::new()))
            .expect("private password file should be accepted");
        assert_eq!(secret.expose_secret(), "file-only-secret");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("fixture permissions should change");
        let error = read_login_secret(&matches, &mut Cursor::new(Vec::<u8>::new()))
            .expect_err("group-readable password file should be rejected");
        assert!(error.to_string().contains("must not be accessible"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cli_rejects_removed_password_rotation_flag() {
        let error = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--magic",
                "17",
            ])
            .expect_err("password rotation must not be exposed in the first-release CLI");

        assert!(error.to_string().contains("--magic"));
    }

    #[test]
    fn mission_spec_from_matches_enables_only_explicit_best_effort_mode() {
        let default_matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "192.0.2.10/32",
                "--password-stdin",
            ])
            .expect("default CLI arguments should parse");
        let best_effort_matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "192.0.2.10/32",
                "--password-stdin",
                "--best-effort",
            ])
            .expect("best-effort CLI arguments should parse");
        let targets = vec!["192.0.2.10".parse().expect("target should parse")];

        assert!(
            !mission_spec_from_matches(&default_matches, targets.clone(), "secret".into())
                .best_effort
        );
        assert!(
            mission_spec_from_matches(&best_effort_matches, targets, "secret".into()).best_effort
        );
    }

    #[test]
    fn mission_spec_from_matches_marks_generated_mission_ids_as_auto_resumable() {
        let matches = build_cli()
            .try_get_matches_from(["pandoras_box", "--range", "10.0.0.0/30", "--password-stdin"])
            .expect("CLI should parse Pandora's Box arguments");
        let targets = Subnet::try_from("10.0.0.0/30")
            .expect("subnet should parse")
            .hosts_bounded(crate::enumerator::DEFAULT_MAX_TARGETS)
            .expect("small subnet should fit the target limit");

        let spec = mission_spec_from_matches(&matches, targets, "secret".into());

        assert!(!spec.mission_id_explicit);
        assert!(!spec.mission_id.is_empty());
    }
}
