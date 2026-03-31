use chrono::Local;
use clap::{arg as carg, command, value_parser, ArgMatches, Command as ClapCommand};
use log::{error, info};
use pandoras_box::*;
use std::fs::OpenOptions;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

struct MemoryReport;

impl Drop for MemoryReport {
    fn drop(&mut self) {
        let output = Command::new("ps")
            .arg("-o")
            .arg("rss=")
            .arg("-p")
            .arg(std::process::id().to_string())
            .output()
            .expect("Failed to execute command");

        let memory_usage = String::from_utf8_lossy(&output.stdout);
        info!("Memory Usage at Exit: {} KB", memory_usage.trim());
    }
}

#[cfg(test)]
mod tests {
    use super::{build_cli, mission_spec_from_matches};
    use crate::enumerator::Subnet;
    use std::path::PathBuf;

    #[test]
    fn cli_rejects_public_chimera_override_flags() {
        let error = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password",
                "secret",
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
                "--password",
                "secret",
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
                "--password",
                "secret",
                "--mission_id",
                "mission-override",
            ])
            .expect("CLI should parse Pandora's Box arguments");
        let targets = Subnet::try_from("10.0.0.0/30")
            .expect("subnet should parse")
            .hosts();

        let spec = mission_spec_from_matches(&matches, targets.clone(), "secret".to_string());

        assert_eq!(spec.targets, targets);
        assert_eq!(spec.mission_id, "mission-override");
        assert_eq!(spec.collector_port, 44_372);
        assert_eq!(spec.chimera_unix_path, PathBuf::from("release/chimera"));
        assert_eq!(
            spec.chimera_windows_path,
            PathBuf::from("release/chimera.exe")
        );
        assert_eq!(spec.password, "secret");
        assert!(spec.allow_smb_fallback);
    }
}

fn build_cli() -> ClapCommand {
    command!()
        .arg(
            carg!(-r --range <IP_RANGE>)
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(-p --password <PASSWORD>)
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(carg!(--dry_run "Skip remote mutation operations"))
        .arg(
            carg!(--artifact_root <DIR>)
                .required(false)
                .default_value("artifacts")
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(--mission_id <MISSION_ID>)
                .required(false)
                .value_parser(value_parser!(String)),
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
    password: String,
) -> runtime::MissionSpec {
    let mission_id = matches
        .get_one::<String>("mission_id")
        .cloned()
        .unwrap_or_else(|| Local::now().format("%Y%m%d_%H%M%S").to_string());

    runtime::MissionSpec {
        targets,
        artifact_root: PathBuf::from(
            matches
                .get_one::<String>("artifact_root")
                .expect("artifact_root should have a default"),
        ),
        mission_id,
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
        dry_run: matches.get_flag("dry_run"),
        ..runtime::MissionSpec::default()
    }
}

pub fn setup_tracing() -> Result<()> {
    let mut result = Ok(());

    INIT.call_once(|| {
        // Create log file
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let log_path = format!("./pandoras_box{}.log", timestamp);

        // Create file appender
        let file = match OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&log_path)
        {
            Ok(file) => file,
            Err(e) => {
                result = Err(Error::InvalidSubnet(e.to_string()));
                return;
            }
        };

        // Set up the file layer
        let file_layer = tracing_subscriber::fmt::layer()
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true)
            .with_writer(file);

        // Set up the console layer
        let console_layer = tracing_subscriber::fmt::layer()
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true);

        // Set up the filter
        let filter_layer =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        // Combine everything and initialize
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(console_layer)
            .with(file_layer)
            .init();

        println!("Logging initialized to {}", log_path);
    });

    result
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing()?;

    let _memory_report = MemoryReport;

    let matches = build_cli().get_matches();

    let range = matches.get_one::<String>("range").unwrap();
    let password = matches.get_one::<String>("password").unwrap();

    info!("Starting application with range: {}", range);

    let subnet = match enumerator::Subnet::try_from(range) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse subnet: {}", e);
            return Err(Error::InvalidSubnet(e.to_string()));
        }
    };

    info!("Created subnet: {}", range);

    let spec = mission_spec_from_matches(&matches, subnet.hosts(), password.clone());

    let summary = runtime::PandorasBoxRunner::new(spec).run().await?;
    info!(
        "Pandora's Box completed: discovered={} complete={} failed={} mission_dir={}",
        summary.discovered_hosts,
        summary.completed_hosts,
        summary.failed_hosts,
        summary.mission_dir.display()
    );
    Ok(())
}
