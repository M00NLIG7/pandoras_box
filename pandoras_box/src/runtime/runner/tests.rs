use super::{render_mission_manifest, PandorasBoxRunner, PersistedHostStatus};
use crate::runtime::discovery::DiscoveryRecord;
use crate::runtime::mission::{
    CpuArchitecture, DeadlinePolicy, HostPlan, HostTarget, MissionReuseMode, MissionSpec,
    OperatingSystem, PayloadQualification, PayloadSpec, PlatformHint, ResourceLimits,
    TargetContract, TransportKind,
};
use crate::runtime::payloads::sha256_file_bounded;
use crate::runtime::session_factory::{BoxedHostSession, SessionFactory};
use crate::runtime::transport::{ExecRequest, ExecResponse, FileTransfer, HostSession};
use crate::{Error, Result};
use async_trait::async_trait;
use futures::{stream, StreamExt};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct Behavior {
    auth_failure: bool,
    capability_os: &'static str,
    capability_arch: &'static str,
    workspace_status: u32,
    collector_status: u32,
    cleanup_status: u32,
    fail_log_download: bool,
    command_delay: Duration,
}

impl Default for Behavior {
    fn default() -> Self {
        Self {
            auth_failure: false,
            capability_os: "Linux",
            capability_arch: "x86_64",
            workspace_status: 0,
            collector_status: 0,
            cleanup_status: 0,
            fail_log_download: false,
            command_delay: Duration::ZERO,
        }
    }
}

struct FakeSession {
    behavior: Behavior,
    events: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl HostSession for FakeSession {
    async fn exec(&mut self, request: ExecRequest) -> Result<ExecResponse> {
        self.events
            .lock()
            .expect("events lock")
            .push(format!("exec:{}", request.command));
        if !self.behavior.command_delay.is_zero() {
            tokio::time::sleep(self.behavior.command_delay).await;
        }
        let (stdout, status_code) = if request.command.contains("pandora_os=") {
            (
                format!(
                    "pandora_os={}\npandora_arch={}\n",
                    self.behavior.capability_os, self.behavior.capability_arch
                )
                .into_bytes(),
                0,
            )
        } else if request.command.contains(" collector") {
            (b"collector\n".to_vec(), self.behavior.collector_status)
        } else if request.command.contains("rmdir \"$o\"") || request.command.contains("foreach($f")
        {
            (Vec::new(), self.behavior.cleanup_status)
        } else if request.command.contains("umask 077") || request.command.contains("icacls.exe") {
            (Vec::new(), self.behavior.workspace_status)
        } else {
            (Vec::new(), 0)
        };
        Ok(ExecResponse {
            stdout,
            stderr: Vec::new(),
            status_code: Some(status_code),
        })
    }

    async fn put(&mut self, transfer: &FileTransfer) -> Result<()> {
        self.events
            .lock()
            .expect("events lock")
            .push(format!("put:{}", transfer.remote_path));
        Ok(())
    }

    async fn get(&mut self, transfer: &FileTransfer) -> Result<()> {
        self.events
            .lock()
            .expect("events lock")
            .push(format!("get:{}", transfer.remote_path));
        if self.behavior.fail_log_download && transfer.remote_path.ends_with("application.log") {
            return Err(Error::FileTransferError(
                "fixture interrupted after inventory collection".into(),
            ));
        }
        if let Some(parent) = transfer.local_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let contents = if transfer.remote_path.ends_with("inventory.json") {
            br#"{"hostname":"fixture","os":"fixture","ports":[],"connections":[],"services":[],"users":[],"shares":[],"containers":[],"sectionErrors":[]}"#.as_slice()
        } else {
            b"fixture log\n".as_slice()
        };
        tokio::fs::write(&transfer.local_path, contents).await?;
        Ok(())
    }

    async fn ensure_dir(&mut self, remote_dir: &str) -> Result<()> {
        self.events
            .lock()
            .expect("events lock")
            .push(format!("ensure_dir:{remote_dir}"));
        Ok(())
    }

    async fn cleanup(&mut self) -> Result<()> {
        self.events
            .lock()
            .expect("events lock")
            .push("disconnect".into());
        Ok(())
    }
}

type EventLog = Arc<Mutex<Vec<String>>>;
type HostEventLogs = Arc<Mutex<HashMap<IpAddr, EventLog>>>;

struct FakeFactory {
    behaviors: HashMap<IpAddr, Behavior>,
    preflight_failures: BTreeMap<IpAddr, String>,
    attempts: Arc<Mutex<Vec<(IpAddr, TransportKind)>>>,
    events: HostEventLogs,
}

impl FakeFactory {
    fn new(behaviors: HashMap<IpAddr, Behavior>) -> Self {
        Self {
            behaviors,
            preflight_failures: BTreeMap::new(),
            attempts: Arc::new(Mutex::new(Vec::new())),
            events: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn with_preflight_failure(mut self, ip: IpAddr, message: impl Into<String>) -> Self {
        self.preflight_failures.insert(ip, message.into());
        self
    }

    fn attempts(&self) -> Vec<(IpAddr, TransportKind)> {
        self.attempts.lock().expect("attempts lock").clone()
    }

    fn events(&self, ip: IpAddr) -> Vec<String> {
        self.events
            .lock()
            .expect("events map")
            .get(&ip)
            .map(|events| events.lock().expect("events lock").clone())
            .unwrap_or_default()
    }
}

#[async_trait]
impl SessionFactory for FakeFactory {
    async fn preflight(&self, plan: &HostPlan) -> Result<()> {
        if let Some(message) = self.preflight_failures.get(&plan.target.ip) {
            return Err(Error::CredentialProfileFailure(message.clone()));
        }
        Ok(())
    }

    async fn connect(&self, plan: &HostPlan, transport: TransportKind) -> Result<BoxedHostSession> {
        self.attempts
            .lock()
            .expect("attempts lock")
            .push((plan.target.ip, transport));
        let behavior = self
            .behaviors
            .get(&plan.target.ip)
            .cloned()
            .unwrap_or_default();
        if behavior.auth_failure {
            return Err(Error::AuthenticationFailure(
                "Failed to authenticate with password".into(),
            ));
        }
        let events = self
            .events
            .lock()
            .expect("events map")
            .entry(plan.target.ip)
            .or_insert_with(|| Arc::new(Mutex::new(Vec::new())))
            .clone();
        Ok(Box::new(FakeSession { behavior, events }))
    }
}

fn temp_root(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("pandora-runner-{label}-{unique}"))
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
}

fn record(ip: IpAddr, hint: PlatformHint, ports: Vec<u16>) -> DiscoveryRecord {
    DiscoveryRecord {
        host: HostTarget {
            ip,
            platform: hint,
            open_ports: ports,
        },
        ttl: None,
    }
}

async fn payload(root: &std::path::Path, os: OperatingSystem) -> PayloadSpec {
    tokio::fs::create_dir_all(root).await.expect("payload root");
    let path = root.join(format!("chimera-{}", os.as_str()));
    tokio::fs::write(&path, format!("fixture-{os:?}"))
        .await
        .expect("payload fixture");
    PayloadSpec {
        operating_system: os,
        architecture: CpuArchitecture::X86_64,
        sha256: sha256_file_bounded(&path, 1024)
            .await
            .expect("payload digest"),
        path,
        version: "fixture-v1".into(),
        qualification: PayloadQualification::LiveQualified,
        evidence: vec!["offline-fake-gate".into()],
    }
}

async fn spec(
    root: PathBuf,
    contracts: BTreeMap<IpAddr, TargetContract>,
    payloads: Vec<PayloadSpec>,
) -> MissionSpec {
    MissionSpec {
        targets: contracts.keys().copied().collect(),
        target_contracts: contracts,
        payload_catalog: payloads,
        artifact_root: root.join("artifacts"),
        mission_id: "mission-123".into(),
        mission_id_explicit: true,
        concurrency_limit: 4,
        allow_smb_fallback: true,
        deadlines: DeadlinePolicy {
            discovery_connect: Duration::from_millis(20),
            connect: Duration::from_millis(100),
            inactivity: Duration::from_secs(1),
            command: Duration::from_millis(250),
            transfer: Duration::from_millis(250),
            cleanup: Duration::from_millis(100),
            host: Duration::from_secs(2),
            mission: Duration::from_secs(5),
        },
        resource_limits: ResourceLimits {
            max_command_output_bytes: 4096,
            max_download_bytes: 4096,
            max_payload_bytes: 4096,
        },
        ..MissionSpec::default()
    }
}

async fn host_status(spec: &MissionSpec, ip: IpAddr) -> PersistedHostStatus {
    let path = spec
        .artifact_root
        .join(&spec.mission_id)
        .join("hosts")
        .join(ip.to_string())
        .join("status.json");
    serde_json::from_str(
        &tokio::fs::read_to_string(path)
            .await
            .expect("host status should exist"),
    )
    .expect("host status JSON")
}

#[tokio::test]
async fn missing_payload_isolated_from_healthy_host() {
    let root = temp_root("mixed-payload");
    let linux_ip = ip(2);
    let windows_ip = ip(3);
    let contracts = BTreeMap::from([
        (
            linux_ip,
            TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
        ),
        (
            windows_ip,
            TargetContract::windows(CpuArchitecture::X86_64, true),
        ),
    ]);
    let spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    let factory = Arc::new(FakeFactory::new(HashMap::from([(
        linux_ip,
        Behavior::default(),
    )])));
    let records = stream::iter([
        record(linux_ip, PlatformHint::UnixLike, vec![22]),
        record(windows_ip, PlatformHint::Windows, vec![22, 445]),
    ]);

    let summary = PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(records, Arc::clone(&factory))
        .await
        .expect("mixed mission should reconcile");

    assert_eq!(summary.attempted_targets, 1);
    assert_eq!(summary.completed_hosts, 1);
    assert_eq!(summary.failed_hosts, 1);
    assert_eq!(factory.attempts(), vec![(linux_ip, TransportKind::SshSftp)]);
    let failed = host_status(&spec, windows_ip).await;
    assert_eq!(failed.attempt_count, 0);
    assert!(failed
        .error
        .expect("missing payload error")
        .contains("no exact payload is packaged"));
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn missing_named_profile_isolated_from_healthy_host_without_authentication() {
    let root = temp_root("mixed-credential-profiles");
    let healthy_ip = ip(20);
    let failed_ip = ip(21);
    let contracts = BTreeMap::from([
        (
            healthy_ip,
            TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
        ),
        (
            failed_ip,
            TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
        ),
    ]);
    let mut spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    let profiles = format!(
        r#"{{
              "version":1,
              "default_profile":"healthy",
              "host_overrides":[{{"target":"{failed_ip}","profile":"missing"}}],
              "profiles":[{{
                "name":"healthy",
                "operating_systems":["linux"],
                "username":"root",
                "authentication":{{"type":"ssh_agent","public_key_sha256":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
                "transports":["ssh_sftp"]
              }}]
            }}"#
    );
    spec.credential_profiles =
        crate::runtime::CredentialProfileCatalog::from_json(&profiles, std::path::Path::new("."))
            .expect("profile catalog");
    let factory = Arc::new(FakeFactory::new(HashMap::from([(
        healthy_ip,
        Behavior::default(),
    )])));

    let summary = PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(
            stream::iter([
                record(healthy_ip, PlatformHint::UnixLike, vec![22]),
                record(failed_ip, PlatformHint::UnixLike, vec![22]),
            ]),
            Arc::clone(&factory),
        )
        .await
        .expect("profile failure should remain host-local");

    assert_eq!(summary.attempted_targets, 1);
    assert_eq!(summary.completed_hosts, 1);
    assert_eq!(summary.failed_hosts, 1);
    assert_eq!(
        factory.attempts(),
        vec![(healthy_ip, TransportKind::SshSftp)]
    );
    let failed = host_status(&spec, failed_ip).await;
    assert_eq!(failed.attempt_count, 0);
    assert_eq!(failed.failure_phase.as_deref(), Some("credentials"));
    assert!(failed.error.expect("profile error").contains("is missing"));
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[test]
fn mission_manifest_persists_profile_policy_without_secret_values() {
    let target = ip(23);
    let spec = MissionSpec {
        targets: vec![target],
        default_target_contract: TargetContract::ssh(
            OperatingSystem::Linux,
            CpuArchitecture::X86_64,
        ),
        credential_profiles: crate::runtime::CredentialProfileCatalog::legacy(
            "root",
            "Administrator",
            Some("manifest-secret-must-not-leak".into()),
            22,
            crate::runtime::SshHostKeyPolicy::RequireKnown,
            false,
            445,
        ),
        ..MissionSpec::default()
    };

    let rendered = render_mission_manifest(&spec);

    assert!(rendered.contains("legacy-unix-default"));
    assert!(rendered.contains("policy_sha256"));
    assert!(!rendered.contains("manifest-secret-must-not-leak"));
}

#[tokio::test]
async fn credential_preflight_failure_never_connects_or_falls_back() {
    let root = temp_root("credential-preflight");
    let target = ip(22);
    let contracts = BTreeMap::from([(
        target,
        TargetContract::windows(CpuArchitecture::X86_64, true),
    )]);
    let spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Windows).await],
    )
    .await;
    let factory = Arc::new(
        FakeFactory::new(HashMap::new())
            .with_preflight_failure(target, "external secret is unavailable"),
    );

    let summary = PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(
            stream::iter([record(target, PlatformHint::Windows, vec![22, 445])]),
            Arc::clone(&factory),
        )
        .await
        .expect("credential failure should remain isolated");

    assert_eq!(summary.attempted_targets, 0);
    assert!(factory.attempts().is_empty());
    let status = host_status(&spec, target).await;
    assert_eq!(status.attempt_count, 0);
    assert_eq!(status.failure_phase.as_deref(), Some("credentials"));
    assert!(status
        .error
        .expect("credential error")
        .contains("external secret is unavailable"));
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn dry_run_never_enters_the_transport_stack() {
    let root = temp_root("dry-run");
    let target = ip(4);
    let contracts = BTreeMap::from([(
        target,
        TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
    )]);
    let mut spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    spec.dry_run = true;
    let factory = Arc::new(FakeFactory::new(HashMap::new()));

    let summary = PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(
            stream::iter([record(target, PlatformHint::UnixLike, vec![22])]),
            Arc::clone(&factory),
        )
        .await
        .expect("dry-run should report");

    assert_eq!(summary.attempted_targets, 0);
    assert_eq!(summary.completed_hosts, 1);
    assert!(factory.attempts().is_empty());
    assert!(factory.events(target).is_empty());
    assert_eq!(host_status(&spec, target).await.attempt_count, 0);
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn authentication_failure_wording_is_terminal_and_blocks_smb_fallback() {
    let root = temp_root("auth-terminal");
    let target = ip(5);
    let contracts = BTreeMap::from([(
        target,
        TargetContract::windows(CpuArchitecture::X86_64, true),
    )]);
    let spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Windows).await],
    )
    .await;
    let factory = Arc::new(FakeFactory::new(HashMap::from([(
        target,
        Behavior {
            auth_failure: true,
            capability_os: "windows",
            ..Behavior::default()
        },
    )])));

    PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(
            stream::iter([record(target, PlatformHint::Windows, vec![22, 445])]),
            Arc::clone(&factory),
        )
        .await
        .expect("host failure should remain isolated");

    assert_eq!(factory.attempts(), vec![(target, TransportKind::SshSftp)]);
    let status = host_status(&spec, target).await;
    assert_eq!(status.attempt_count, 1);
    assert!(status
        .error
        .expect("auth error")
        .contains("Failed to authenticate with password"));
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn hostile_preexisting_workspace_stops_before_upload_and_preserves_residue() {
    let root = temp_root("hostile-workspace");
    let target = ip(13);
    let contracts = BTreeMap::from([(
        target,
        TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
    )]);
    let spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    let factory = Arc::new(FakeFactory::new(HashMap::from([(
        target,
        Behavior {
            workspace_status: 75,
            cleanup_status: 83,
            ..Behavior::default()
        },
    )])));

    PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(
            stream::iter([record(target, PlatformHint::UnixLike, vec![22])]),
            Arc::clone(&factory),
        )
        .await
        .expect("hostile workspace should remain isolated");

    let events = factory.events(target);
    assert!(!events.iter().any(|event| event.starts_with("put:")));
    assert!(!events.iter().any(|event| event.contains(" collector")));
    assert!(events.iter().any(|event| event.contains("rmdir \"$o\"")));
    let status = host_status(&spec, target).await;
    assert!(status.residue_present);
    assert_eq!(status.cleanup_outcome.as_deref(), Some("failed"));
    assert!(status
        .error
        .expect("workspace error")
        .contains("exit status 75"));
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn terminal_collector_failure_attempts_cleanup_and_records_residue() {
    let root = temp_root("cleanup-residue");
    let target = ip(6);
    let contracts = BTreeMap::from([(
        target,
        TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
    )]);
    let spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    let factory = Arc::new(FakeFactory::new(HashMap::from([(
        target,
        Behavior {
            collector_status: 23,
            cleanup_status: 71,
            ..Behavior::default()
        },
    )])));

    PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(
            stream::iter([record(target, PlatformHint::UnixLike, vec![22])]),
            Arc::clone(&factory),
        )
        .await
        .expect("terminal failure should reconcile");

    let status = host_status(&spec, target).await;
    assert_eq!(status.cleanup_outcome.as_deref(), Some("failed"));
    assert!(status.residue_present);
    assert!(status.error.expect("error").contains("cleanup residue"));
    assert!(factory
        .events(target)
        .iter()
        .any(|event| event.contains("rmdir \"$o\"")));
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn partial_download_is_preserved_reported_and_cleaned() {
    let root = temp_root("partial-download");
    let target = ip(11);
    let contracts = BTreeMap::from([(
        target,
        TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
    )]);
    let spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    let factory = Arc::new(FakeFactory::new(HashMap::from([(
        target,
        Behavior {
            fail_log_download: true,
            ..Behavior::default()
        },
    )])));

    PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(
            stream::iter([record(target, PlatformHint::UnixLike, vec![22])]),
            Arc::clone(&factory),
        )
        .await
        .expect("partial collection should reconcile");

    let status = host_status(&spec, target).await;
    assert!(status.partial_collection);
    assert_eq!(status.cleanup_outcome.as_deref(), Some("complete"));
    assert!(!status.residue_present);
    assert!(spec
        .artifact_root
        .join(&spec.mission_id)
        .join("hosts")
        .join(target.to_string())
        .join("files/inventory.json")
        .is_file());
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn explicit_resume_reuses_validated_workspace_without_restaging_or_reexecution() {
    let root = temp_root("resume-partial");
    let target = ip(12);
    let contracts = BTreeMap::from([(
        target,
        TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
    )]);
    let spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    let first_factory = Arc::new(FakeFactory::new(HashMap::from([(
        target,
        Behavior {
            fail_log_download: true,
            cleanup_status: 71,
            ..Behavior::default()
        },
    )])));
    PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(
            stream::iter([record(target, PlatformHint::UnixLike, vec![22])]),
            first_factory,
        )
        .await
        .expect("partial first mission");
    assert!(host_status(&spec, target).await.residue_present);

    let mut resumed = spec.clone();
    resumed.mission_reuse = MissionReuseMode::Resume;
    let resume_factory = Arc::new(FakeFactory::new(HashMap::from([(
        target,
        Behavior::default(),
    )])));
    let summary = PandorasBoxRunner::new(resumed.clone())
        .run_with_stream_and_factory(
            stream::iter([record(target, PlatformHint::UnixLike, vec![22])]),
            Arc::clone(&resume_factory),
        )
        .await
        .expect("explicit resume");

    assert_eq!(summary.completed_hosts, 1);
    let events = resume_factory.events(target);
    assert!(!events.iter().any(|event| event.starts_with("put:")));
    assert!(!events.iter().any(|event| event.contains(" collector")));
    assert_eq!(
        host_status(&resumed, target)
            .await
            .cleanup_outcome
            .as_deref(),
        Some("complete")
    );
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn capability_mismatch_prevents_workspace_and_payload_writes() {
    let root = temp_root("capability-mismatch");
    let target = ip(7);
    let contracts = BTreeMap::from([(
        target,
        TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
    )]);
    let spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    let factory = Arc::new(FakeFactory::new(HashMap::from([(
        target,
        Behavior {
            capability_os: "FreeBSD",
            ..Behavior::default()
        },
    )])));

    PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(
            stream::iter([record(target, PlatformHint::UnixLike, vec![22])]),
            Arc::clone(&factory),
        )
        .await
        .expect("mismatch should reconcile");

    let events = factory.events(target);
    assert!(!events.iter().any(|event| event.starts_with("put:")));
    assert!(!events.iter().any(|event| event.contains(".pandora-owner")));
    let status = host_status(&spec, target).await;
    assert_eq!(status.cleanup_outcome.as_deref(), Some("not_required"));
    assert!(status
        .error
        .expect("mismatch")
        .contains("staging was not attempted"));
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn mission_deadline_accounts_for_unobserved_targets_without_authentication() {
    let root = temp_root("mission-deadline");
    let first = ip(9);
    let second = ip(10);
    let contract = TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64);
    let contracts = BTreeMap::from([(first, contract.clone()), (second, contract)]);
    let mut spec = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    spec.dry_run = true;
    spec.deadlines.mission = Duration::from_millis(30);
    let outcomes =
        stream::iter([record(first, PlatformHint::UnixLike, vec![22])]).chain(stream::pending());
    let factory = Arc::new(FakeFactory::new(HashMap::new()));

    let summary = PandorasBoxRunner::new(spec.clone())
        .run_with_stream_and_factory(outcomes, Arc::clone(&factory))
        .await
        .expect("deadline should reconcile");

    assert!(summary.interrupted_or_timed_out);
    assert!(summary
        .terminal_reason
        .as_deref()
        .expect("reason")
        .contains("mission deadline"));
    assert!(factory.attempts().is_empty());
    let second_status = host_status(&spec, second).await;
    assert_eq!(second_status.attempt_count, 0);
    assert!(second_status
        .error
        .expect("deadline error")
        .contains("authentication was not attempted"));
    let _ = tokio::fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn completed_mission_ids_require_explicit_reuse_modes() {
    let root = temp_root("mission-reuse");
    let target = ip(8);
    let contracts = BTreeMap::from([(
        target,
        TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
    )]);
    let mut initial = spec(
        root.clone(),
        contracts,
        vec![payload(&root.join("payloads"), OperatingSystem::Linux).await],
    )
    .await;
    initial.dry_run = true;
    let record = || stream::iter([record(target, PlatformHint::UnixLike, vec![22])]);

    PandorasBoxRunner::new(initial.clone())
        .run_with_stream_and_factory(record(), Arc::new(FakeFactory::new(HashMap::new())))
        .await
        .expect("initial mission");

    let error = PandorasBoxRunner::new(initial.clone())
        .run_with_stream_and_factory(record(), Arc::new(FakeFactory::new(HashMap::new())))
        .await
        .expect_err("implicit stale reuse must fail");
    assert!(error.to_string().contains("already exists"));

    let mut mismatch = initial.clone();
    mismatch.mission_reuse = MissionReuseMode::Resume;
    mismatch.resource_limits.max_download_bytes += 1;
    let error = PandorasBoxRunner::new(mismatch)
        .run_with_stream_and_factory(record(), Arc::new(FakeFactory::new(HashMap::new())))
        .await
        .expect_err("resume identity mismatch must fail");
    assert!(error.to_string().contains("resume identity mismatch"));

    let marker = initial
        .artifact_root
        .join(&initial.mission_id)
        .join("stale-marker");
    tokio::fs::write(&marker, b"stale").await.expect("marker");
    let mut fresh = initial.clone();
    fresh.mission_reuse = MissionReuseMode::Fresh;
    PandorasBoxRunner::new(fresh)
        .run_with_stream_and_factory(record(), Arc::new(FakeFactory::new(HashMap::new())))
        .await
        .expect("explicit fresh mission");
    assert!(!marker.exists());
    let _ = tokio::fs::remove_dir_all(root).await;
}
