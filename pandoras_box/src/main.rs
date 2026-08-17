use clap::{
    arg as carg, command, value_parser, Arg, ArgAction, ArgGroup, ArgMatches,
    Command as ClapCommand,
};
use log::{error, info};
use pandoras_box::*;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{BufRead, Read};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

const MAX_LOGIN_SECRET_BYTES: u64 = 4096;

fn current_timestamp_string() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut random = [0_u8; 8];
    if getrandom::getrandom(&mut random).is_err() {
        random = timestamp.to_le_bytes();
    }
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{timestamp}-{suffix}")
}

fn mission_id_value(value: &str) -> std::result::Result<String, String> {
    runtime::validate_mission_id(value)
        .map(|()| value.to_string())
        .map_err(|err| err.to_string())
}

fn sha256_value(value: &str) -> std::result::Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("SHA-256 must contain exactly 64 hexadecimal characters".into());
    }
    Ok(normalized)
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
        return runtime::credentials::read_external_secret_file(path);
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
            carg!(--"password-stdin" "Read one legacy global login secret from standard input")
                .required(false)
                .conflicts_with("credential-config"),
        )
        .arg(
            carg!(--"password-file" <PATH> "Read one legacy global login secret from a protected regular file")
                .required(false)
                .conflicts_with("credential-config")
                .value_parser(value_parser!(PathBuf)),
        )
        .group(
            ArgGroup::new("password-source")
                .required(false)
                .multiple(false)
                .args(["password-stdin", "password-file"]),
        )
        .arg(
            carg!(--"credential-config" <PATH> "Named credential profiles with external secrets and per-host overrides")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            carg!(--profile <PROFILE> "Explicit target profile; detect-only never authenticates")
                .default_value("detect-only")
                .value_parser([
                    "detect-only",
                    "linux-x86_64",
                    "windows-x86_64",
                    "freebsd-x86_64",
                    "openbsd-x86_64",
                    "netbsd-x86_64",
                    "dragonflybsd-x86_64",
                    "pfsense-x86_64",
                ]),
        )
        .arg(
            carg!(--"target-contracts" <PATH> "JSON per-host OS/architecture/transport contracts")
                .required(false)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            carg!(--"payload-manifest" <PATH> "Versioned and checksummed payload catalog")
                .default_value("release/payloads.json")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("dry_run")
                .long("dry-run")
                .visible_alias("dry_run")
                .action(ArgAction::SetTrue)
                .help("Plan and write local reports without authentication or remote operations"),
        )
        .arg(carg!(--"allow-encrypted-smb-fallback" "Request Windows SMB encryption-required fallback; pinned Smolder 0.4.0 remains pre-auth blocked until strict remote exec is qualified"))
        .arg(carg!(--"dangerously-accept-unknown-host-keys" "DANGER: permit first contact with an unknown SSH host key; changed enrolled keys are still rejected"))
        .arg(carg!(--"best-effort" "Return success after handled target failures, including zero attempted targets; unhandled mission errors still fail"))
        .arg(carg!(--resume "Resume an existing explicit mission only after exact identity verification"))
        .arg(carg!(--fresh "Delete an existing explicit mission directory and execute from scratch"))
        .group(
            ArgGroup::new("mission-reuse")
                .required(false)
                .multiple(false)
                .args(["resume", "fresh"]),
        )
        .arg(
            carg!(--"max-targets" <COUNT> "Reject a CIDR containing more usable targets than this bound")
                .default_value("65536")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            carg!(--artifact_root <DIR>)
                .default_value("artifacts")
                .visible_alias("artifact-root")
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(--mission_id <MISSION_ID>)
                .required(false)
                .visible_alias("mission-id")
                .value_parser(clap::builder::ValueParser::new(mission_id_value)),
        )
        .arg(
            carg!(--unix_user <USERNAME>)
                .default_value("root")
                .visible_alias("unix-user")
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(--windows_user <USERNAME>)
                .default_value("Administrator")
                .visible_alias("windows-user")
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(--"ssh-port" <PORT>)
                .default_value("22")
                .value_parser(value_parser!(u16).range(1..)),
        )
        .arg(
            Arg::new("discovery-port")
                .long("discovery-port")
                .value_name("PORT")
                .action(ArgAction::Append)
                .value_parser(value_parser!(u16).range(1..))
                .help("Repeat to replace passive defaults; selected credential-profile ports are always added"),
        )
        .arg(
            carg!(--concurrency <COUNT>)
                .default_value("64")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            carg!(--retries <COUNT>)
                .default_value("2")
                .value_parser(value_parser!(u8).range(1..=10)),
        )
        .arg(duration_arg("discovery-timeout-ms", "800", "Per-port discovery connect deadline in milliseconds"))
        .arg(duration_arg("connect-timeout-ms", "5000", "Authenticated transport connection deadline in milliseconds"))
        .arg(duration_arg("inactivity-timeout-ms", "30000", "SSH inactivity deadline in milliseconds"))
        .arg(duration_arg("command-timeout-ms", "120000", "Per-command deadline in milliseconds"))
        .arg(duration_arg("transfer-timeout-ms", "120000", "Per-transfer deadline in milliseconds"))
        .arg(duration_arg("cleanup-timeout-ms", "15000", "Cleanup/disconnect deadline in milliseconds"))
        .arg(duration_arg("host-timeout-ms", "300000", "Total per-host deadline in milliseconds"))
        .arg(duration_arg("mission-timeout-ms", "1800000", "Total mission deadline in milliseconds"))
        .arg(
            carg!(--"retry-backoff-ms" <MILLISECONDS>)
                .default_value("500")
                .value_parser(value_parser!(u64).range(1..=30000)),
        )
        .arg(
            carg!(--"max-command-output-bytes" <BYTES>)
                .default_value("1048576")
                .value_parser(value_parser!(usize)),
        )
        .arg(
            carg!(--"max-download-bytes" <BYTES>)
                .default_value("16777216")
                .value_parser(value_parser!(u64).range(1..)),
        )
        .arg(
            carg!(--"max-payload-bytes" <BYTES>)
                .default_value("134217728")
                .value_parser(value_parser!(u64).range(1..)),
        )
        .arg(duration_arg(
            "renderer-timeout-ms",
            "30000",
            "Optional renderer deadline in milliseconds",
        ))
        .arg(
            carg!(--"max-renderer-output-bytes" <BYTES>)
                .default_value("33554432")
                .value_parser(value_parser!(u64).range(1..)),
        )
        .arg(
            carg!(--"topology-renderer" <PATH> "Explicit standalone renderer executable (input.excalidraw output.png)")
                .required(false)
                .requires("topology-renderer-sha256")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            carg!(--"topology-renderer-sha256" <SHA256> "Pinned SHA-256 for the explicit renderer")
                .required(false)
                .requires("topology-renderer")
                .value_parser(clap::builder::ValueParser::new(sha256_value)),
        )
}

fn duration_arg(name: &'static str, default: &'static str, help: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .value_name("MILLISECONDS")
        .default_value(default)
        .value_parser(value_parser!(u64).range(1..))
        .help(help)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadManifest {
    payloads: Vec<runtime::PayloadSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetContractManifest {
    targets: BTreeMap<String, runtime::TargetContract>,
}

fn profile_contract(profile: &str, allow_smb: bool) -> runtime::TargetContract {
    use runtime::{CpuArchitecture::X86_64, OperatingSystem as Os, TargetContract};
    match profile {
        "linux-x86_64" => TargetContract::ssh(Os::Linux, X86_64),
        "windows-x86_64" => TargetContract::windows(X86_64, allow_smb),
        "freebsd-x86_64" => TargetContract::ssh(Os::FreeBsd, X86_64),
        "openbsd-x86_64" => TargetContract::ssh(Os::OpenBsd, X86_64),
        "netbsd-x86_64" => TargetContract::ssh(Os::NetBsd, X86_64),
        "dragonflybsd-x86_64" => TargetContract::ssh(Os::DragonFlyBsd, X86_64),
        "pfsense-x86_64" => TargetContract::ssh(Os::PfSense, X86_64),
        _ => TargetContract::detect_only(),
    }
}

fn read_bounded_manifest(path: &std::path::Path, maximum: u64) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::ArgumentError(format!(
            "manifest must be a regular non-link file: {}",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(Error::ArgumentError(format!(
            "manifest {} is {} bytes, exceeding the {maximum} byte bound",
            path.display(),
            metadata.len()
        )));
    }
    Ok(std::fs::read_to_string(path)?)
}

fn load_payload_manifest(path: &std::path::Path) -> Result<Vec<runtime::PayloadSpec>> {
    let raw = match read_bounded_manifest(path, 8 * 1024 * 1024) {
        Ok(raw) => raw,
        Err(Error::IoError(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    let mut manifest: PayloadManifest = serde_json::from_str(&raw).map_err(|error| {
        Error::ArgumentError(format!(
            "failed to parse payload manifest {}: {error}",
            path.display()
        ))
    })?;
    if manifest.payloads.len() > 256 {
        return Err(Error::ArgumentError(
            "payload manifest exceeds the 256-entry bound".into(),
        ));
    }
    let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    for payload in &mut manifest.payloads {
        if payload.path.is_relative() {
            payload.path = base.join(&payload.path);
        }
    }
    Ok(manifest.payloads)
}

fn load_target_contracts(
    path: Option<&std::path::Path>,
) -> Result<BTreeMap<IpAddr, runtime::TargetContract>> {
    let Some(path) = path else {
        return Ok(BTreeMap::new());
    };
    let raw = read_bounded_manifest(path, 8 * 1024 * 1024)?;
    let manifest: TargetContractManifest = serde_json::from_str(&raw).map_err(|error| {
        Error::ArgumentError(format!(
            "failed to parse target contract manifest {}: {error}",
            path.display()
        ))
    })?;
    manifest
        .targets
        .into_iter()
        .map(|(ip, contract)| {
            contract.validate().map_err(Error::ArgumentError)?;
            Ok((ip.parse::<IpAddr>()?, contract))
        })
        .collect()
}

fn load_credential_profiles(path: &std::path::Path) -> Result<runtime::CredentialProfileCatalog> {
    let raw = read_bounded_manifest(path, 8 * 1024 * 1024)?;
    let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    runtime::CredentialProfileCatalog::from_json(&raw, base).map_err(|error| {
        Error::ArgumentError(format!(
            "credential configuration {} is invalid: {error}",
            path.display()
        ))
    })
}

fn milliseconds(matches: &ArgMatches, name: &str) -> Duration {
    Duration::from_millis(
        *matches
            .get_one::<u64>(name)
            .expect("duration has a default"),
    )
}

fn mission_spec_from_matches(
    matches: &ArgMatches,
    targets: Vec<IpAddr>,
    password: Option<runtime::SecretString>,
) -> Result<runtime::MissionSpec> {
    let mission_id_explicit =
        matches.contains_id("mission_id") && matches.get_one::<String>("mission_id").is_some();
    let mission_id = matches
        .get_one::<String>("mission_id")
        .cloned()
        .unwrap_or_else(current_timestamp_string);
    let mission_reuse = if matches.get_flag("resume") {
        runtime::MissionReuseMode::Resume
    } else if matches.get_flag("fresh") {
        runtime::MissionReuseMode::Fresh
    } else {
        runtime::MissionReuseMode::ErrorIfExists
    };
    if !mission_id_explicit && mission_reuse != runtime::MissionReuseMode::ErrorIfExists {
        return Err(Error::ArgumentError(
            "--resume and --fresh require --mission-id".into(),
        ));
    }

    let allow_smb_fallback = matches.get_flag("allow-encrypted-smb-fallback");
    let default_target_contract = profile_contract(
        matches
            .get_one::<String>("profile")
            .expect("profile has a default"),
        allow_smb_fallback,
    );
    default_target_contract
        .validate()
        .map_err(Error::ArgumentError)?;
    let target_contracts = load_target_contracts(
        matches
            .get_one::<PathBuf>("target-contracts")
            .map(PathBuf::as_path),
    )?;
    for (ip, contract) in &target_contracts {
        if !targets.contains(ip) {
            return Err(Error::ArgumentError(format!(
                "target contract for {ip} is outside the requested range"
            )));
        }
        contract.validate().map_err(Error::ArgumentError)?;
    }

    let unix_username = matches
        .get_one::<String>("unix_user")
        .expect("unix_user has a default")
        .clone();
    let windows_username = matches
        .get_one::<String>("windows_user")
        .expect("windows_user has a default")
        .clone();
    let ssh_port = *matches
        .get_one::<u16>("ssh-port")
        .expect("ssh port has a default");
    let ssh_host_key_policy = if matches.get_flag("dangerously-accept-unknown-host-keys") {
        runtime::SshHostKeyPolicy::DangerouslyAcceptUnknown
    } else {
        runtime::SshHostKeyPolicy::RequireKnown
    };
    let credential_config = matches.get_one::<PathBuf>("credential-config");
    if credential_config.is_some() {
        for argument in ["unix_user", "windows_user", "ssh-port"] {
            if matches.value_source(argument) == Some(clap::parser::ValueSource::CommandLine) {
                return Err(Error::ArgumentError(format!(
                    "--credential-config cannot be combined with legacy credential option --{}",
                    argument.replace('_', "-")
                )));
            }
        }
        if matches.get_flag("dangerously-accept-unknown-host-keys") {
            return Err(Error::ArgumentError(
                "--credential-config cannot be combined with the legacy global host-key exception; configure it explicitly in a named profile"
                    .into(),
            ));
        }
    }
    let credential_profiles = if let Some(path) = credential_config {
        load_credential_profiles(path)?
    } else {
        runtime::CredentialProfileCatalog::legacy(
            unix_username.clone(),
            windows_username.clone(),
            password.clone(),
            ssh_port,
            ssh_host_key_policy,
            allow_smb_fallback,
            445,
        )
    };

    let payload_catalog = load_payload_manifest(
        matches
            .get_one::<PathBuf>("payload-manifest")
            .expect("payload manifest has a default"),
    )?;

    let concurrency_limit = *matches
        .get_one::<usize>("concurrency")
        .expect("concurrency has a default");
    if !(1..=4096).contains(&concurrency_limit) {
        return Err(Error::ArgumentError(
            "concurrency must be between 1 and 4096".into(),
        ));
    }

    let deadlines = runtime::DeadlinePolicy {
        discovery_connect: milliseconds(matches, "discovery-timeout-ms"),
        connect: milliseconds(matches, "connect-timeout-ms"),
        inactivity: milliseconds(matches, "inactivity-timeout-ms"),
        command: milliseconds(matches, "command-timeout-ms"),
        transfer: milliseconds(matches, "transfer-timeout-ms"),
        cleanup: milliseconds(matches, "cleanup-timeout-ms"),
        host: milliseconds(matches, "host-timeout-ms"),
        mission: milliseconds(matches, "mission-timeout-ms"),
    };
    for (name, value, maximum) in [
        (
            "discovery",
            deadlines.discovery_connect,
            Duration::from_secs(60),
        ),
        ("connect", deadlines.connect, Duration::from_secs(600)),
        (
            "inactivity",
            deadlines.inactivity,
            Duration::from_secs(3600),
        ),
        ("command", deadlines.command, Duration::from_secs(3600)),
        ("transfer", deadlines.transfer, Duration::from_secs(3600)),
        ("cleanup", deadlines.cleanup, Duration::from_secs(600)),
        ("host", deadlines.host, Duration::from_secs(14_400)),
        ("mission", deadlines.mission, Duration::from_secs(86_400)),
    ] {
        if value > maximum {
            return Err(Error::ArgumentError(format!(
                "{name} deadline exceeds the supported maximum of {maximum:?}"
            )));
        }
    }
    let resource_limits = runtime::ResourceLimits {
        max_command_output_bytes: *matches
            .get_one::<usize>("max-command-output-bytes")
            .expect("output bound has a default"),
        max_download_bytes: *matches
            .get_one::<u64>("max-download-bytes")
            .expect("download bound has a default"),
        max_payload_bytes: *matches
            .get_one::<u64>("max-payload-bytes")
            .expect("payload bound has a default"),
    };
    if resource_limits.max_command_output_bytes > 64 * 1024 * 1024
        || resource_limits.max_download_bytes > 1024 * 1024 * 1024
        || resource_limits.max_payload_bytes > 1024 * 1024 * 1024
    {
        return Err(Error::ArgumentError(
            "resource limits exceed the supported maxima (64 MiB output, 1 GiB download/payload)"
                .into(),
        ));
    }
    let renderer_timeout = milliseconds(matches, "renderer-timeout-ms");
    let renderer_output_bound = *matches
        .get_one::<u64>("max-renderer-output-bytes")
        .expect("renderer output bound has a default");
    if renderer_timeout > Duration::from_secs(600) || renderer_output_bound > 512 * 1024 * 1024 {
        return Err(Error::ArgumentError(
            "renderer bounds exceed the supported maxima (10 minutes, 512 MiB)".into(),
        ));
    }
    let mut discovery_ports = matches
        .get_many::<u16>("discovery-port")
        .map(|ports| ports.copied().collect::<Vec<_>>())
        .unwrap_or_default();
    discovery_ports.sort_unstable();
    discovery_ports.dedup();
    if discovery_ports.len() > 64 {
        return Err(Error::ArgumentError(
            "no more than 64 unique discovery ports may be configured".into(),
        ));
    }
    let renderer = matches
        .get_one::<PathBuf>("topology-renderer")
        .map(|executable| runtime::RendererSpec {
            executable: executable.clone(),
            sha256: matches
                .get_one::<String>("topology-renderer-sha256")
                .expect("renderer digest is required with renderer")
                .clone(),
            timeout: renderer_timeout,
            max_output_bytes: renderer_output_bound,
        });

    let spec = runtime::MissionSpec {
        targets,
        default_target_contract,
        target_contracts,
        payload_catalog,
        concurrency_limit,
        best_effort: matches.get_flag("best-effort"),
        retry_policy: runtime::RetryPolicy {
            max_attempts: *matches
                .get_one::<u8>("retries")
                .expect("retries has a default"),
            backoff: milliseconds(matches, "retry-backoff-ms"),
        },
        deadlines,
        resource_limits,
        artifact_root: PathBuf::from(
            matches
                .get_one::<String>("artifact_root")
                .expect("artifact_root has a default"),
        ),
        mission_id,
        mission_id_explicit,
        mission_reuse,
        unix_username,
        windows_username,
        password: password.unwrap_or_default(),
        credential_profiles,
        ssh_port,
        ssh_host_key_policy,
        discovery_ports,
        dry_run: matches.get_flag("dry_run"),
        allow_smb_fallback,
        renderer,
        ..runtime::MissionSpec::default()
    };
    if spec.resolved_discovery_ports().len() > 64 {
        return Err(Error::ArgumentError(
            "resolved credential-profile and discovery ports exceed the 64-port bound".into(),
        ));
    }
    Ok(spec)
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
    let password = if matches.get_flag("password-stdin")
        || matches.get_one::<PathBuf>("password-file").is_some()
    {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        Some(read_login_secret(&matches, &mut stdin)?)
    } else {
        None
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
    if max_targets == 0 {
        return Err(Error::ArgumentError(
            "max-targets must be at least 1".into(),
        ));
    }
    let targets = subnet.hosts_bounded(max_targets)?;
    let spec = mission_spec_from_matches(&matches, targets, password)?;
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
    use crate::runtime::{
        CpuArchitecture, MissionReuseMode, OperatingSystem, SshHostKeyPolicy, TransportKind,
    };
    use std::io::Cursor;

    fn targets() -> Vec<std::net::IpAddr> {
        Subnet::try_from("10.0.0.0/30")
            .expect("subnet")
            .hosts_bounded(crate::enumerator::DEFAULT_MAX_TARGETS)
            .expect("targets")
    }

    #[test]
    fn default_profile_is_non_authenticating_detect_only() {
        let matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--mission-id",
                "mission-override",
            ])
            .expect("arguments");
        let spec = mission_spec_from_matches(&matches, targets(), Some("secret".into()))
            .expect("mission spec");

        assert_eq!(
            spec.default_target_contract.operating_system,
            OperatingSystem::Unknown
        );
        assert!(spec.default_target_contract.transports.is_empty());
        assert!(!spec.allow_smb_fallback);
        assert_eq!(spec.mission_reuse, MissionReuseMode::ErrorIfExists);
        assert_eq!(spec.password.expose_secret(), "secret");
        assert_eq!(spec.ssh_host_key_policy, SshHostKeyPolicy::RequireKnown);
        assert_eq!(spec.deadlines.connect.as_millis(), 5000);
        assert_eq!(spec.deadlines.inactivity.as_millis(), 30000);
        assert!(spec.renderer.is_none());
    }

    #[test]
    fn explicit_windows_profile_and_smb_fallback_are_visible_contracts() {
        let matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--profile",
                "windows-x86_64",
                "--allow-encrypted-smb-fallback",
            ])
            .expect("arguments");
        let spec = mission_spec_from_matches(&matches, targets(), Some("secret".into()))
            .expect("mission spec");

        assert_eq!(
            spec.default_target_contract.operating_system,
            OperatingSystem::Windows
        );
        assert_eq!(
            spec.default_target_contract.architecture,
            CpuArchitecture::X86_64
        );
        assert_eq!(
            spec.default_target_contract.transports,
            vec![TransportKind::SshSftp, TransportKind::WindowsSmb]
        );
        assert!(spec.allow_smb_fallback);
    }

    #[test]
    fn planning_rejects_arbitrary_identity_commands() {
        let error = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--identity_command",
                "touch /tmp/mutated",
            ])
            .expect_err("identity command must not be exposed");
        assert!(error.to_string().contains("--identity_command"));
    }

    #[test]
    fn explicit_resume_and_fresh_require_mission_id() {
        for mode in ["--resume", "--fresh"] {
            let matches = build_cli()
                .try_get_matches_from([
                    "pandoras_box",
                    "--range",
                    "10.0.0.0/30",
                    "--password-stdin",
                    mode,
                ])
                .expect("CLI shape");
            let error = mission_spec_from_matches(&matches, targets(), Some("secret".into()))
                .expect_err("reuse mode requires explicit ID");
            assert!(error.to_string().contains("require --mission-id"));
        }
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
                    "--mission-id",
                    mission_id,
                ])
                .expect_err("unsafe mission identifier");
            assert!(error.to_string().contains("portable path component"));
        }
    }

    #[test]
    fn cli_accepts_profiles_without_a_global_prompt_and_rejects_argv_secrets() {
        build_cli()
            .try_get_matches_from(["pandoras_box", "--range", "10.0.0.0/30"])
            .expect("detect-only and named profiles do not require a global prompt");

        let argv = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password",
                "must-not-be-an-argv-secret",
            ])
            .expect_err("argv secret rejected");
        assert!(argv.to_string().contains("--password"));
    }

    #[test]
    fn named_profiles_resolve_global_defaults_and_host_overrides_without_prompts() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pandora-credential-config-{unique}.json"));
        std::fs::write(
            &path,
            r#"{
              "version":1,
              "default_profile":"global",
              "host_overrides":[{"target":"10.0.0.1","profile":"special"}],
              "profiles":[
                {"name":"global","operating_systems":["linux"],"username":"root","authentication":{"type":"ssh_agent","public_key_sha256":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"transports":["ssh_sftp"],"ssh_port":2200},
                {"name":"special","operating_systems":["linux"],"username":"operator","authentication":{"type":"ssh_agent","public_key_sha256":"SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},"transports":["ssh_sftp"],"ssh_port":2222}
              ]
            }"#,
        )
        .expect("credential fixture");
        let path_value = path.to_string_lossy().into_owned();
        let matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--profile",
                "linux-x86_64",
                "--credential-config",
                &path_value,
            ])
            .expect("named-profile CLI");
        let spec = mission_spec_from_matches(&matches, targets(), None).expect("mission spec");
        let first = spec
            .credential_policy("10.0.0.1".parse().expect("IP"))
            .expect("host override");
        let second = spec
            .credential_policy("10.0.0.2".parse().expect("IP"))
            .expect("global default");

        assert_eq!(first.name, "special");
        assert_eq!(first.ssh_port, 2222);
        assert_eq!(second.name, "global");
        assert_eq!(second.ssh_port, 2200);
        assert!(spec.password.is_empty());
        assert!(spec.resolved_discovery_ports().contains(&2200));
        assert!(spec.resolved_discovery_ports().contains(&2222));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn named_profile_config_rejects_ambiguous_legacy_secret_inputs() {
        let error = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--credential-config",
                "profiles.json",
                "--password-stdin",
            ])
            .expect_err("credential inputs must not be ambiguous");
        assert!(error.to_string().contains("cannot be used with"));
    }

    #[test]
    fn password_stdin_reads_one_redacted_line() {
        let matches = build_cli()
            .try_get_matches_from(["pandoras_box", "--range", "10.0.0.0/30", "--password-stdin"])
            .expect("stdin source");
        let secret = read_login_secret(&matches, &mut Cursor::new(b"stdin-only-secret\n".to_vec()))
            .expect("secret");
        assert_eq!(secret.expose_secret(), "stdin-only-secret");
        assert!(!format!("{secret:?}").contains("stdin-only-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn password_file_requires_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pandora-password-{unique}"));
        std::fs::write(&path, "file-only-secret\n").expect("fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("private");
        let path_value = path.to_string_lossy().into_owned();
        let matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-file",
                &path_value,
            ])
            .expect("file source");
        read_login_secret(&matches, &mut Cursor::new(Vec::<u8>::new()))
            .expect("private file accepted");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("permissions");
        let error = read_login_secret(&matches, &mut Cursor::new(Vec::<u8>::new()))
            .expect_err("public file rejected");
        assert!(error
            .to_string()
            .contains("unsafe ownership or permissions"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bounded_tuning_is_exposed_and_persisted_in_spec() {
        let matches = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--concurrency",
                "7",
                "--retries",
                "3",
                "--command-timeout-ms",
                "9000",
                "--max-command-output-bytes",
                "2048",
                "--max-download-bytes",
                "4096",
            ])
            .expect("tuning");
        let spec = mission_spec_from_matches(&matches, targets(), Some("secret".into()))
            .expect("mission spec");
        assert_eq!(spec.concurrency_limit, 7);
        assert_eq!(spec.retry_policy.max_attempts, 3);
        assert_eq!(spec.deadlines.command.as_millis(), 9000);
        assert_eq!(spec.resource_limits.max_command_output_bytes, 2048);
        assert_eq!(spec.resource_limits.max_download_bytes, 4096);
    }

    #[test]
    fn renderer_must_be_explicit_and_digest_pinned() {
        let missing_digest = build_cli()
            .try_get_matches_from([
                "pandoras_box",
                "--range",
                "10.0.0.0/30",
                "--password-stdin",
                "--topology-renderer",
                "/tmp/renderer",
            ])
            .expect_err("renderer digest required");
        assert!(missing_digest
            .to_string()
            .contains("--topology-renderer-sha256"));
    }
}
