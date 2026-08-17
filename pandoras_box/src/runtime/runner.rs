use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use futures::stream::{Stream, StreamExt};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::artifact_store::{ActiveMissionRecord, ArtifactRootLock, ArtifactStore};
use super::discovery::{DiscoveryConfig, DiscoveryOutcome, TcpDiscovery};
use super::mission::{
    HostPlan, HostState, HostTarget, MissionReuseMode, MissionSpec, PlatformHint, RetryPolicy,
    TransportKind,
};
use super::payloads::PayloadPreflight;
use super::planner::Planner;
use super::policy::ExecutionPolicy;
use super::reporting::{render_network_topology_png_explicit, write_asset_inventory_bundle};
use super::scheduler::{CleanupOutcome, HostExecutionReport};
use super::session_executor::{ConnectedSession, SessionExecutor, SessionOperation};
use super::session_factory::SessionFactory;
use super::transport::profile::{CredentialSessionFactory, CredentialSessionPolicy};
use super::workspace::{
    capability_probe_command, collector_plan, validate_capability_capture, CollectorPlan,
};
use crate::{Error, Result};

const SMB_CONNECT_RETRY_COOLDOWN: Duration = Duration::from_secs(3);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PandorasBoxRunSummary {
    pub mission_dir: PathBuf,
    pub requested_targets: usize,
    pub reachable_targets: usize,
    pub unreachable_targets: usize,
    pub skipped_targets: usize,
    pub attempted_targets: usize,
    /// Backward-compatible alias for `reachable_targets`.
    pub discovered_hosts: usize,
    pub completed_hosts: usize,
    pub failed_hosts: usize,
    pub planning_only: bool,
    pub interrupted_or_timed_out: bool,
    pub terminal_reason: Option<String>,
    pub completed_unix_ms: u128,
}

impl PandorasBoxRunSummary {
    #[must_use]
    pub fn requires_failure_exit(&self) -> bool {
        (!self.planning_only && self.attempted_targets == 0)
            || self.failed_hosts > 0
            || self.interrupted_or_timed_out
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TargetAccounting {
    requested: usize,
    reachable: usize,
    unreachable: usize,
    skipped: usize,
    attempted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
struct PersistedHostStatus {
    ip: String,
    final_state: String,
    error: Option<String>,
    failure_phase: Option<String>,
    failure_disposition: Option<String>,
    selected_transport: Option<String>,
    attempt_count: u8,
    completed_phases: Vec<String>,
    cleanup_outcome: Option<String>,
    residue_present: bool,
    partial_collection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResumeMode {
    Fresh,
    CollectOnly,
    CleanupOnly,
    SkipCompleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResumeCheckpoint {
    mode: ResumeMode,
    attempt_count: u8,
    completed_phases: Vec<super::scheduler::FailurePhase>,
    selected_transport: Option<TransportKind>,
}

pub struct PandorasBoxRunner {
    spec: MissionSpec,
}

impl PandorasBoxRunner {
    #[must_use]
    pub fn new(spec: MissionSpec) -> Self {
        Self { spec }
    }

    pub async fn run(&self) -> Result<PandorasBoxRunSummary> {
        let mut spec = self.spec.clone();
        spec.credential_profiles = spec.effective_credential_profiles();
        Self::new(spec).run_configured().await
    }

    async fn run_configured(&self) -> Result<PandorasBoxRunSummary> {
        let discovery_ports = self.spec.resolved_discovery_ports();
        let forwarded_smb_ports = self
            .spec
            .targets
            .iter()
            .filter_map(|ip| self.spec.credential_policy(*ip).ok())
            .filter(|policy| policy.allows_transport(TransportKind::WindowsSmb))
            .map(|policy| policy.smb_port)
            .filter(|port| *port != 445)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let discovery = TcpDiscovery::new(DiscoveryConfig {
            ports: discovery_ports,
            ssh_port: self.spec.ssh_port,
            forwarded_smb_ports,
            connect_timeout: self.spec.deadlines.discovery_connect,
            concurrency_limit: self.spec.concurrency_limit,
        });
        let factory = Arc::new(CredentialSessionFactory::new(
            self.spec.credential_profiles.clone(),
            CredentialSessionPolicy {
                deadlines: self.spec.deadlines.clone(),
                resource_limits: self.spec.resource_limits.clone(),
            },
            self.spec.windows_smb_exec_mode,
        ));

        self.run_with_stream_and_factory(
            discovery.probe_ips_outcomes_stream(self.spec.targets.clone()),
            factory,
        )
        .await
    }

    async fn run_with_stream_and_factory<S, F, I>(
        &self,
        outcomes: S,
        factory: Arc<F>,
    ) -> Result<PandorasBoxRunSummary>
    where
        S: Stream<Item = I>,
        I: Into<DiscoveryOutcome>,
        F: SessionFactory + 'static,
    {
        let (spec, store) = self.prepare_store().await?;
        let mission_deadline = tokio::time::Instant::now() + spec.deadlines.mission;
        let cancellation = Arc::new(AtomicBool::new(false));
        let mut stop_reason = None::<String>;
        // Every catalog entry is hashed and qualified before any host task can
        // authenticate. Individual selection failures stay local to that host.
        let payloads = match tokio::time::timeout_at(
            mission_deadline,
            PayloadPreflight::build(
                &spec.payload_catalog,
                spec.resource_limits.max_payload_bytes,
            ),
        )
        .await
        {
            Ok(payloads) => payloads,
            Err(_) => {
                cancellation.store(true, Ordering::SeqCst);
                stop_reason = Some(format!(
                    "mission deadline {:?} elapsed during payload preflight",
                    spec.deadlines.mission
                ));
                PayloadPreflight::default()
            }
        };
        let policy = ExecutionPolicy {
            dry_run: spec.dry_run,
            allow_smb_fallback: spec.allow_smb_fallback,
        };
        let mut observed_targets = 0usize;
        let mut reachable_targets = 0usize;
        let mut unreachable_targets = 0usize;
        let mut skipped_targets = 0usize;
        let mut attempted_targets = 0usize;
        let semaphore = Arc::new(Semaphore::new(spec.concurrency_limit.max(1)));
        let mut tasks = JoinSet::new();
        let mut reports = Vec::new();
        let mut observed_ips = BTreeSet::new();

        futures::pin_mut!(outcomes);

        loop {
            let next = tokio::select! {
                result = tokio::time::timeout_at(mission_deadline, outcomes.next()) => {
                    match result {
                        Ok(value) => value,
                        Err(_) => {
                            cancellation.store(true, Ordering::SeqCst);
                            if stop_reason.is_none() {
                                stop_reason = Some(format!("mission deadline {:?} elapsed", spec.deadlines.mission));
                            }
                            None
                        }
                    }
                }
                signal = tokio::signal::ctrl_c() => {
                    cancellation.store(true, Ordering::SeqCst);
                    stop_reason = Some(match signal {
                        Ok(()) => "mission interrupted by operator signal".to_string(),
                        Err(error) => format!("mission signal handler failed: {error}"),
                    });
                    None
                }
            };
            let Some(outcome) = next else {
                break;
            };
            while let Some(report) = tasks.try_join_next() {
                match report {
                    Ok(report) => reports.push(report),
                    Err(error) => {
                        return Err(Error::MissionFailure(format!(
                            "host task could not be reconciled after isolation: {error}"
                        )));
                    }
                }
            }
            observed_targets += 1;
            let record = match outcome.into() {
                DiscoveryOutcome::Reachable(record) => {
                    reachable_targets += 1;
                    observed_ips.insert(record.host.ip);
                    record
                }
                DiscoveryOutcome::Unreachable { ip } => {
                    unreachable_targets += 1;
                    observed_ips.insert(ip);
                    let plan = HostPlan::queued(
                        HostTarget {
                            ip,
                            platform: PlatformHint::Unknown,
                            open_ports: Vec::new(),
                        },
                        spec.target_contract(ip),
                        Vec::new(),
                    );
                    store.ensure_layout([ip]).await?;
                    store.write_host_plan(ip, &render_plan_json(&plan)).await?;
                    let report = HostExecutionReport::unattempted_failure(
                        plan,
                        super::scheduler::FailurePhase::Connect,
                        "target was unreachable on every configured discovery port",
                    );
                    store
                        .write_host_status(ip, &render_report_json(&report))
                        .await?;
                    reports.push(report);
                    continue;
                }
            };

            let mut plan = Planner::plan_host(&spec, record.host);
            let ip = plan.target.ip;
            store.ensure_layout([ip]).await?;

            let planning_failure = plan
                .contract
                .validate()
                .err()
                .map(|error| {
                    (
                        super::scheduler::FailurePhase::Stage,
                        format!("invalid target contract: {error}"),
                    )
                })
                .or_else(|| {
                    if plan.contract.is_explicit() && spec.credential_profiles.is_configured() {
                        spec.credential_policy(ip).err().map(|error| {
                            (
                                super::scheduler::FailurePhase::Credentials,
                                error.to_string(),
                            )
                        })
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    payloads
                        .select(&plan.contract)
                        .err()
                        .map(|error| (super::scheduler::FailurePhase::Stage, error.to_string()))
                });
            if let Some((phase, error)) = planning_failure {
                skipped_targets += 1;
                store.write_host_plan(ip, &render_plan_json(&plan)).await?;
                let report = HostExecutionReport::unattempted_failure(plan, phase, error);
                store
                    .write_host_status(ip, &render_report_json(&report))
                    .await?;
                reports.push(report);
                continue;
            }
            let selected_payload = payloads
                .select(&plan.contract)
                .expect("successful selection was checked above");
            plan = plan.with_payload(selected_payload);
            store.write_host_plan(ip, &render_plan_json(&plan)).await?;

            if plan.transport_chain.is_empty() {
                skipped_targets += 1;
                let transport_error = if plan
                    .contract
                    .transports
                    .contains(&TransportKind::WindowsSmb)
                    && !super::transport::smb::ENCRYPTION_REQUIRED_REMOTE_EXEC_QUALIFIED
                {
                    "Windows SMB was explicitly requested, but the pinned adapter cannot enforce encryption for every remote-execution request; authentication was not attempted"
                } else {
                    "target was reachable but no explicitly contracted transport was discovered; authentication was not attempted"
                };
                let report = HostExecutionReport::unattempted_failure(
                    plan,
                    super::scheduler::FailurePhase::Connect,
                    transport_error,
                );
                store
                    .write_host_status(ip, &render_report_json(&report))
                    .await?;
                reports.push(report);
                continue;
            }

            if spec.dry_run {
                skipped_targets += 1;
                let report = HostExecutionReport::planned(plan);
                store
                    .write_host_status(ip, &render_report_json(&report))
                    .await?;
                reports.push(report);
                continue;
            }

            let credential_preflight =
                tokio::time::timeout(spec.deadlines.connect, factory.preflight(&plan)).await;
            if let Err(error) = match credential_preflight {
                Ok(result) => result,
                Err(_) => Err(Error::CredentialProfileFailure(format!(
                    "credential preflight exceeded {:?}",
                    spec.deadlines.connect
                ))),
            } {
                skipped_targets += 1;
                let report = HostExecutionReport::unattempted_failure(
                    plan,
                    super::scheduler::FailurePhase::Credentials,
                    error.to_string(),
                );
                store
                    .write_host_status(ip, &render_report_json(&report))
                    .await?;
                reports.push(report);
                continue;
            }

            let collector_job = match plan_collector_job(&spec, &store, &plan).await {
                Ok(job) => job,
                Err(error) => {
                    skipped_targets += 1;
                    let report = HostExecutionReport::unattempted_failure(
                        plan,
                        super::scheduler::FailurePhase::Stage,
                        format!("collector planning failed: {error}"),
                    );
                    store
                        .write_host_status(ip, &render_report_json(&report))
                        .await?;
                    reports.push(report);
                    continue;
                }
            };

            if tokio::time::Instant::now() >= mission_deadline {
                cancellation.store(true, Ordering::SeqCst);
                if stop_reason.is_none() {
                    stop_reason = Some(format!(
                        "mission deadline {:?} elapsed",
                        spec.deadlines.mission
                    ));
                }
            }
            while tasks.len() >= spec.concurrency_limit.max(1) {
                tokio::select! {
                    report = tasks.join_next() => {
                        match report {
                            Some(Ok(report)) => reports.push(report),
                            Some(Err(error)) => {
                                return Err(Error::MissionFailure(format!(
                                    "host task could not be reconciled after isolation: {error}"
                                )));
                            }
                            None => break,
                        }
                    }
                    _ = tokio::time::sleep_until(mission_deadline) => {
                        cancellation.store(true, Ordering::SeqCst);
                        if stop_reason.is_none() {
                                stop_reason = Some(format!("mission deadline {:?} elapsed", spec.deadlines.mission));
                            }
                    }
                    signal = tokio::signal::ctrl_c(), if !cancellation.load(Ordering::SeqCst) => {
                        cancellation.store(true, Ordering::SeqCst);
                        stop_reason = Some(match signal {
                            Ok(()) => "mission interrupted by operator signal".to_string(),
                            Err(error) => format!("mission signal handler failed: {error}"),
                        });
                    }
                }
                if cancellation.load(Ordering::SeqCst) {
                    break;
                }
            }
            if cancellation.load(Ordering::SeqCst) {
                skipped_targets += 1;
                let report = HostExecutionReport::unattempted_failure(
                    plan,
                    super::scheduler::FailurePhase::Connect,
                    format!(
                        "{}; authentication was not attempted",
                        stop_reason.as_deref().unwrap_or("mission cancelled")
                    ),
                );
                store
                    .write_host_status(ip, &render_report_json(&report))
                    .await?;
                reports.push(report);
                continue;
            }

            attempted_targets += 1;
            let host_spec = spec.clone();
            let semaphore = Arc::clone(&semaphore);
            let store = store.clone();
            let factory = Arc::clone(&factory);
            let panic_plan = plan.clone();
            let cancellation = Arc::clone(&cancellation);
            tasks.spawn(async move {
                let host_future = async move {
                    let _permit = match semaphore.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => {
                            return HostExecutionReport::terminal_failure(
                                plan,
                                super::scheduler::FailurePhase::Unknown,
                                "host execution semaphore closed unexpectedly",
                            )
                            .with_cleanup_outcome(CleanupOutcome::NotRequired, false);
                        }
                    };
                    let mut report = match execute_host_with_persistent_session_with_retry(
                        &host_spec,
                        &store,
                        policy,
                        factory,
                        plan.clone(),
                        collector_job,
                        HostExecutionControl {
                            mission_deadline,
                            cancellation,
                        },
                    )
                    .await
                    {
                        Ok(report) => report,
                        Err(error) => HostExecutionReport::terminal_failure(
                            plan,
                            super::scheduler::FailurePhase::Unknown,
                            format!("isolated host task failed: {error}"),
                        ),
                    };
                    if let Err(error) = store
                        .write_host_status(report.plan.target.ip, &render_report_json(&report))
                        .await
                    {
                        report.final_state = HostState::Failed;
                        report.failure_phase = Some(super::scheduler::FailurePhase::Unknown);
                        report.failure_disposition =
                            Some(super::scheduler::FailureDisposition::Terminal);
                        report.error = Some(format!(
                            "{}host status persistence failed: {error}",
                            report
                                .error
                                .as_deref()
                                .map(|value| format!("{value}; "))
                                .unwrap_or_default()
                        ));
                    }
                    report
                };

                AssertUnwindSafe(host_future)
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| {
                        HostExecutionReport::terminal_failure(
                            panic_plan,
                            super::scheduler::FailurePhase::Unknown,
                            "isolated host task panicked",
                        )
                    })
            });
        }

        if let Some(reason) = &stop_reason {
            for ip in spec
                .targets
                .iter()
                .copied()
                .filter(|ip| !observed_ips.contains(ip))
            {
                skipped_targets += 1;
                let plan = HostPlan::queued(
                    HostTarget {
                        ip,
                        platform: PlatformHint::Unknown,
                        open_ports: Vec::new(),
                    },
                    spec.target_contract(ip),
                    Vec::new(),
                );
                store.ensure_layout([ip]).await?;
                store.write_host_plan(ip, &render_plan_json(&plan)).await?;
                let report = HostExecutionReport::unattempted_failure(
                    plan,
                    super::scheduler::FailurePhase::Connect,
                    format!("{reason}; authentication was not attempted"),
                );
                store
                    .write_host_status(ip, &render_report_json(&report))
                    .await?;
                reports.push(report);
            }
        }

        while !tasks.is_empty() {
            tokio::select! {
                report = tasks.join_next() => {
                    match report {
                        Some(Ok(report)) => reports.push(report),
                        Some(Err(error)) => {
                            return Err(Error::MissionFailure(format!(
                                "host task could not be reconciled after isolation: {error}"
                            )));
                        }
                        None => break,
                    }
                }
                signal = tokio::signal::ctrl_c(), if !cancellation.load(Ordering::SeqCst) => {
                    cancellation.store(true, Ordering::SeqCst);
                    stop_reason = Some(match signal {
                        Ok(()) => "mission interrupted by operator signal".to_string(),
                        Err(error) => format!("mission signal handler failed: {error}"),
                    });
                }
            }
        }

        let requested_targets = if spec.targets.is_empty() {
            observed_targets
        } else {
            spec.targets.len()
        };
        self.finalize_summary(
            &spec,
            &store,
            TargetAccounting {
                requested: requested_targets,
                reachable: reachable_targets,
                unreachable: unreachable_targets,
                skipped: skipped_targets,
                attempted: attempted_targets,
            },
            reports,
            stop_reason,
        )
        .await
    }

    async fn prepare_store(&self) -> Result<(MissionSpec, ArtifactStore)> {
        let root_lock = ArtifactStore::acquire_root_lock(self.spec.artifact_root.clone()).await?;
        let spec = self.resolve_mission_spec(&root_lock).await?;
        let store = ArtifactStore::new_locked(&spec.artifact_root, &spec.mission_id, &root_lock)?;
        ArtifactStore::write_active_mission(
            &root_lock,
            &ActiveMissionRecord {
                mission_id: spec.mission_id.clone(),
                signature: spec.resume_signature(),
            },
        )
        .await?;
        if spec.mission_reuse != MissionReuseMode::Resume {
            store
                .write_mission_manifest(&render_mission_manifest(&spec))
                .await?;
        }
        Ok((spec, store))
    }

    async fn resolve_mission_spec(&self, root_lock: &ArtifactRootLock) -> Result<MissionSpec> {
        let spec = self.spec.clone();
        super::artifact_store::validate_mission_id(&spec.mission_id)?;
        if !spec.mission_id_explicit && spec.mission_reuse != MissionReuseMode::ErrorIfExists {
            return Err(Error::ArgumentError(
                "--resume and --fresh require an explicit mission identifier".into(),
            ));
        }

        let store = ArtifactStore::new_locked(&spec.artifact_root, &spec.mission_id, root_lock)?;
        let mission_dir = store.mission_dir();
        let existing = match tokio::fs::symlink_metadata(&mission_dir).await {
            Ok(metadata) => {
                validate_local_mission_directory(&mission_dir, &metadata)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };

        match (existing, spec.mission_reuse) {
            (true, MissionReuseMode::ErrorIfExists) => {
                return Err(Error::MissionFailure(format!(
                    "mission {} already exists; use --resume after verifying intent or --fresh to start a new execution",
                    spec.mission_id
                )));
            }
            (false, MissionReuseMode::Resume) => {
                return Err(Error::MissionFailure(format!(
                    "mission {} cannot be resumed because it does not exist",
                    spec.mission_id
                )));
            }
            (true, MissionReuseMode::Resume) => {
                let raw = store.read_mission_manifest().await.map_err(|error| {
                    Error::MissionFailure(format!(
                        "resume requires a readable prior mission manifest: {error}"
                    ))
                })?;
                let manifest: ResumeIdentityManifest =
                    serde_json::from_str(&raw).map_err(|error| {
                        Error::MissionFailure(format!(
                            "resume requires a valid prior mission manifest: {error}"
                        ))
                    })?;
                let requested = spec.resume_signature();
                if manifest.resume_signature != requested {
                    return Err(Error::MissionFailure(format!(
                        "resume identity mismatch for mission {}: target, policy, or payload identity changed",
                        spec.mission_id
                    )));
                }
            }
            (true, MissionReuseMode::Fresh) => {
                match tokio::time::timeout(
                    spec.deadlines.cleanup,
                    tokio::fs::remove_dir_all(&mission_dir),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        return Err(Error::MissionFailure(format!(
                            "failed to remove prior mission {} in explicit fresh mode: {error}",
                            spec.mission_id
                        )));
                    }
                    Err(_) => {
                        return Err(Error::MissionFailure(format!(
                            "removing prior mission {} exceeded {:?}",
                            spec.mission_id, spec.deadlines.cleanup
                        )));
                    }
                }
            }
            (false, MissionReuseMode::Fresh | MissionReuseMode::ErrorIfExists) => {}
        }

        Ok(spec)
    }

    async fn finalize_summary(
        &self,
        spec: &MissionSpec,
        store: &ArtifactStore,
        accounting: TargetAccounting,
        reports: Vec<HostExecutionReport>,
        terminal_reason: Option<String>,
    ) -> Result<PandorasBoxRunSummary> {
        let summary = PandorasBoxRunSummary {
            mission_dir: store.mission_dir(),
            requested_targets: accounting.requested,
            reachable_targets: accounting.reachable,
            unreachable_targets: accounting.unreachable,
            skipped_targets: accounting.skipped,
            attempted_targets: accounting.attempted,
            discovered_hosts: accounting.reachable,
            completed_hosts: reports
                .iter()
                .filter(|report| report.final_state == HostState::Complete)
                .count(),
            failed_hosts: reports
                .iter()
                .filter(|report| report.final_state == HostState::Failed)
                .count(),
            planning_only: spec.dry_run,
            interrupted_or_timed_out: terminal_reason.is_some(),
            terminal_reason,
            completed_unix_ms: unix_time_millis(),
        };

        write_asset_inventory_bundle(
            store,
            &reports,
            accounting.requested,
            accounting.reachable,
            accounting.unreachable,
            accounting.skipped,
            accounting.attempted,
        )
        .await?;
        store.write_summary(&render_summary_json(&summary)).await?;
        store
            .clear_active_mission_if_matches(&spec.mission_id)
            .await?;

        // Core reports and mission completion are durable before an optional,
        // explicitly pinned renderer is invoked. Rendering cannot rewrite core success.
        if let Some(renderer) = &spec.renderer {
            let render_result = render_network_topology_png_explicit(store, renderer).await;
            let status = match render_result {
                Ok(()) => serde_json::json!({
                    "state": "complete",
                    "renderer_sha256": renderer.sha256,
                    "output": store.network_topology_png_path(),
                }),
                Err(error) => serde_json::json!({
                    "state": "failed",
                    "renderer_sha256": renderer.sha256,
                    "error": error,
                }),
            };
            let _ = store
                .write_rendering_status(
                    &(serde_json::to_string_pretty(&status).unwrap_or_default() + "\n"),
                )
                .await;
        }

        Ok(summary)
    }
}

#[derive(Deserialize)]
struct ResumeIdentityManifest {
    resume_signature: String,
}

fn validate_local_mission_directory(
    path: &std::path::Path,
    metadata: &std::fs::Metadata,
) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::MissionFailure(format!(
            "mission path must be a non-link directory: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::MissionFailure(format!(
                "mission path has unsafe ownership or permissions: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalSupportFilePlan {
    source_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilityProbeJob {
    command: String,
    capture_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedSupportFile {
    support_file: LocalSupportFilePlan,
    remote_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectorStageJob {
    files: Vec<StagedSupportFile>,
    ensure_remote_directories_command: String,
    post_upload_commands: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectorRunJob {
    collector_command: String,
    collector_capture_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectorArtifact {
    remote_path: String,
    local_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CollectorCollectJob {
    SessionFiles { artifacts: Vec<CollectorArtifact> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CollectorCleanupJob {
    RemoteExec {
        command: String,
        capture_path: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectorJobPlan {
    capability: CapabilityProbeJob,
    stage: Option<CollectorStageJob>,
    run: CollectorRunJob,
    collect: CollectorCollectJob,
    cleanup: CollectorCleanupJob,
}

impl CollectorJobPlan {
    fn capability_operations(&self) -> Vec<SessionOperation> {
        vec![SessionOperation::capture_read_only_exec(
            self.capability.command.clone(),
            self.capability.capture_path.clone(),
        )]
    }

    fn stage_operations(&self) -> Vec<SessionOperation> {
        let mut operations = Vec::new();

        if let Some(stage) = &self.stage {
            operations.push(SessionOperation::idempotent_exec(
                stage.ensure_remote_directories_command.clone(),
            ));

            for file in &stage.files {
                operations.push(SessionOperation::put_file(
                    file.support_file.source_path.clone(),
                    file.remote_path.clone(),
                ));
            }

            for command in &stage.post_upload_commands {
                operations.push(SessionOperation::idempotent_exec(command.clone()));
            }
        }

        operations
    }

    fn run_operations(&self) -> Vec<SessionOperation> {
        let command = self.run.collector_command.clone();
        let capture_path = self.run.collector_capture_path.clone();
        if self.stage.is_none() {
            vec![SessionOperation::capture_read_only_exec(
                command,
                capture_path,
            )]
        } else {
            vec![SessionOperation::capture_idempotent_exec(
                command,
                capture_path,
            )]
        }
    }

    fn collect_operations(&self) -> Vec<SessionOperation> {
        match &self.collect {
            CollectorCollectJob::SessionFiles { artifacts } => artifacts
                .iter()
                .map(|artifact| {
                    SessionOperation::get_file(
                        artifact.remote_path.clone(),
                        artifact.local_path.clone(),
                    )
                })
                .collect(),
        }
    }
}

async fn plan_collector_job(
    spec: &MissionSpec,
    store: &ArtifactStore,
    plan: &HostPlan,
) -> Result<CollectorJobPlan> {
    let capability = CapabilityProbeJob {
        command: capability_probe_command(&plan.contract),
        capture_path: store.host_exec_dir(plan.target.ip).join("capability.txt"),
    };

    let workspace = if spec.mission_reuse == MissionReuseMode::Resume {
        let raw = store
            .read_host_workspace(plan.target.ip)
            .await
            .map_err(|error| {
                Error::DeploymentError(format!(
                    "resume requires a persisted workspace descriptor for {}: {error}",
                    plan.target.ip
                ))
            })?;
        let workspace: super::workspace::RemoteWorkspace =
            serde_json::from_str(&raw).map_err(|error| {
                Error::DeploymentError(format!(
                    "invalid persisted workspace descriptor for {}: {error}",
                    plan.target.ip
                ))
            })?;
        workspace
            .validate_for_plan(plan)
            .map_err(Error::UnsafeWorkspace)?;
        workspace
    } else {
        match collector_plan(spec, plan).map_err(Error::DeploymentError)? {
            CollectorPlan::Preview => {
                return Err(Error::DeploymentError(
                    "dry-run must not construct a remote collector job".into(),
                ));
            }
            CollectorPlan::Chimera { workspace } => {
                let workspace = *workspace;
                workspace
                    .validate_for_plan(plan)
                    .map_err(Error::UnsafeWorkspace)?;
                let descriptor = serde_json::to_string_pretty(&workspace).map_err(|error| {
                    Error::DeploymentError(format!(
                        "failed to serialize workspace descriptor: {error}"
                    ))
                })? + "\n";
                store
                    .write_host_workspace(plan.target.ip, &descriptor)
                    .await?;
                workspace
            }
        }
    };
    let cleanup_command = workspace.cleanup_command();

    Ok(CollectorJobPlan {
        capability,
        stage: Some(CollectorStageJob {
            files: vec![StagedSupportFile {
                support_file: LocalSupportFilePlan {
                    source_path: workspace.collector_source_path.clone(),
                },
                remote_path: workspace.remote_binary_path.clone(),
            }],
            ensure_remote_directories_command: workspace.ensure_directories_command(),
            post_upload_commands: workspace.post_stage_commands(),
        }),
        run: CollectorRunJob {
            collector_command: workspace.collector_command(),
            collector_capture_path: store
                .host_exec_dir(plan.target.ip)
                .join("collector_collect.txt"),
        },
        collect: CollectorCollectJob::SessionFiles {
            artifacts: vec![
                CollectorArtifact {
                    remote_path: workspace.inventory_path,
                    local_path: store.host_inventory_path(plan.target.ip),
                },
                CollectorArtifact {
                    remote_path: workspace.log_path,
                    local_path: store.host_application_log_path(plan.target.ip),
                },
            ],
        },
        cleanup: CollectorCleanupJob::RemoteExec {
            command: cleanup_command,
            capture_path: store
                .host_exec_dir(plan.target.ip)
                .join("collector_cleanup.txt"),
        },
    })
}

fn progress_report(
    plan: &HostPlan,
    state: HostState,
    completed_phases: &[super::scheduler::FailurePhase],
    attempt_count: u8,
    selected_transport: TransportKind,
) -> HostExecutionReport {
    HostExecutionReport::success(plan.force_state(state), state)
        .with_completed_phases(completed_phases.to_vec())
        .with_attempt_count(attempt_count)
        .with_selected_transport(selected_transport)
}

fn phase_strings(completed_phases: &[super::scheduler::FailurePhase]) -> Vec<String> {
    completed_phases
        .iter()
        .map(|phase| phase.as_str().to_string())
        .collect()
}

fn persisted_status_from_report(report: &HostExecutionReport) -> PersistedHostStatus {
    PersistedHostStatus {
        ip: report.plan.target.ip.to_string(),
        final_state: report.final_state.as_str().to_string(),
        error: report.error.clone(),
        failure_phase: report.failure_phase.map(|phase| phase.as_str().to_string()),
        failure_disposition: report
            .failure_disposition
            .map(|disposition| disposition.as_str().to_string()),
        selected_transport: report
            .selected_transport
            .map(|transport| transport.as_str().to_string()),
        attempt_count: report.attempt_count,
        completed_phases: phase_strings(&report.completed_phases),
        cleanup_outcome: Some(report.cleanup_outcome.as_str().to_string()),
        residue_present: report.residue_present,
        partial_collection: report.partial_collection,
    }
}

fn infer_legacy_completed_phases(
    final_state: HostState,
    failure_phase: Option<super::scheduler::FailurePhase>,
) -> Vec<super::scheduler::FailurePhase> {
    use super::scheduler::FailurePhase::{Cleanup, Collect, Execute, Stage};

    match (final_state, failure_phase) {
        (HostState::Complete, _) => vec![Stage, Execute, Collect, Cleanup],
        (HostState::Failed, Some(Cleanup)) => vec![Stage, Execute, Collect],
        (HostState::Failed, Some(Collect)) => vec![Stage, Execute],
        (HostState::Failed, Some(Execute)) => vec![Stage],
        _ => Vec::new(),
    }
}

fn parse_completed_phases(status: &PersistedHostStatus) -> Vec<super::scheduler::FailurePhase> {
    let parsed = status
        .completed_phases
        .iter()
        .filter_map(|phase| super::scheduler::FailurePhase::parse(phase))
        .collect::<Vec<_>>();

    if parsed.is_empty() {
        let final_state = HostState::parse(&status.final_state).unwrap_or(HostState::Failed);
        let failure_phase = status
            .failure_phase
            .as_deref()
            .and_then(super::scheduler::FailurePhase::parse);
        infer_legacy_completed_phases(final_state, failure_phase)
    } else {
        parsed
    }
}

async fn host_artifacts_exist(store: &ArtifactStore, ip: std::net::IpAddr) -> bool {
    async fn regular_non_link(path: PathBuf) -> bool {
        tokio::fs::symlink_metadata(path)
            .await
            .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
    }
    regular_non_link(store.host_inventory_path(ip)).await
        && regular_non_link(store.host_application_log_path(ip)).await
}

async fn load_resume_checkpoint(
    store: &ArtifactStore,
    plan: &HostPlan,
) -> Result<ResumeCheckpoint> {
    let raw = match store.read_host_status(plan.target.ip).await {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ResumeCheckpoint {
                mode: ResumeMode::Fresh,
                attempt_count: 0,
                completed_phases: Vec::new(),
                selected_transport: None,
            });
        }
        Err(err) => return Err(err.into()),
    };

    let status: PersistedHostStatus = serde_json::from_str(&raw).map_err(|err| {
        Error::CommunicatorError(format!(
            "failed to parse {}: {err}",
            store.host_status_path(plan.target.ip).display()
        ))
    })?;

    let completed_phases = parse_completed_phases(&status);
    let final_state = HostState::parse(&status.final_state).unwrap_or(HostState::Failed);
    let artifacts_exist = host_artifacts_exist(store, plan.target.ip).await;
    let workspace_was_removed =
        status.cleanup_outcome.as_deref() == Some("complete") && !status.residue_present;

    let mode = if final_state == HostState::Complete && artifacts_exist {
        ResumeMode::SkipCompleted
    } else if workspace_was_removed {
        ResumeMode::Fresh
    } else if completed_phases.contains(&super::scheduler::FailurePhase::Collect) && artifacts_exist
    {
        ResumeMode::CleanupOnly
    } else if completed_phases.contains(&super::scheduler::FailurePhase::Execute) {
        ResumeMode::CollectOnly
    } else {
        ResumeMode::Fresh
    };

    Ok(ResumeCheckpoint {
        mode,
        attempt_count: status.attempt_count.max(1),
        completed_phases,
        selected_transport: status
            .selected_transport
            .as_deref()
            .and_then(TransportKind::parse),
    })
}

async fn write_checkpoint(store: &ArtifactStore, report: &HostExecutionReport) -> Result<()> {
    store
        .write_host_status(report.plan.target.ip, &render_report_json(report))
        .await?;
    Ok(())
}

fn skipped_resume_report(plan: &HostPlan, checkpoint: &ResumeCheckpoint) -> HostExecutionReport {
    let report = HostExecutionReport::success(plan.clone(), HostState::Complete)
        .with_attempt_count(checkpoint.attempt_count.max(1))
        .with_completed_phases(checkpoint.completed_phases.clone());
    match checkpoint.selected_transport {
        Some(transport) => report.with_selected_transport(transport),
        None => report,
    }
}

async fn collect_host_artifacts_with_live_session<F>(
    spec: &MissionSpec,
    collect_executor: &SessionExecutor<F>,
    report: HostExecutionReport,
    session: &mut ConnectedSession,
) -> HostExecutionReport
where
    F: SessionFactory + 'static,
{
    if report.final_state != HostState::Complete {
        return report;
    }

    let base_attempt_count = report.attempt_count;
    let completed_phases = report.completed_phases.clone();
    let max_attempts = spec.retry_policy.max_attempts.max(1);
    let collect_plan = report.plan.force_state(HostState::Connecting);

    let mut next_report = collect_executor
        .run_connected_session_with_fallback(collect_plan.clone(), session, false)
        .await
        .with_completed_phases(completed_phases.clone())
        .with_attempt_count(base_attempt_count.max(1));

    if !next_report.should_retry(max_attempts) {
        return if next_report.final_state == HostState::Complete {
            next_report.mark_phase_completed(super::scheduler::FailurePhase::Collect)
        } else {
            next_report
        };
    }
    if let Err(error) =
        tokio::time::timeout(spec.deadlines.cleanup, session.session_mut().cleanup())
            .await
            .map_err(|_| {
                Error::DeadlineExceeded("collection reconnect disconnect timed out".into())
            })
            .and_then(|result| result)
    {
        return HostExecutionReport::terminal_failure(
            collect_plan,
            super::scheduler::FailurePhase::Cleanup,
            format!("collection retry blocked by disconnect failure: {error}"),
        )
        .with_completed_phases(completed_phases)
        .with_attempt_count(base_attempt_count)
        .with_cleanup_outcome(CleanupOutcome::Failed, true);
    }

    for attempt in 2..=max_attempts {
        tokio::time::sleep(retry_delay_for_report(&spec.retry_policy, &next_report)).await;

        let mut reconnected = match collect_executor.connect_session(&collect_plan).await {
            Ok(session) => session,
            Err(report) => {
                let report = report
                    .with_completed_phases(completed_phases.clone())
                    .with_attempt_count(base_attempt_count.max(attempt));
                if !report.should_retry(max_attempts) {
                    return report;
                }
                next_report = report;
                continue;
            }
        };

        next_report = collect_executor
            .run_connected_session_with_fallback(collect_plan.clone(), &mut reconnected, false)
            .await
            .with_completed_phases(completed_phases.clone())
            .with_attempt_count(base_attempt_count.max(attempt));
        *session = reconnected;

        if !next_report.should_retry(max_attempts) {
            return if next_report.final_state == HostState::Complete {
                next_report.mark_phase_completed(super::scheduler::FailurePhase::Collect)
            } else {
                next_report
            };
        }
        if let Err(error) =
            tokio::time::timeout(spec.deadlines.cleanup, session.session_mut().cleanup())
                .await
                .map_err(|_| {
                    Error::DeadlineExceeded("collection reconnect disconnect timed out".into())
                })
                .and_then(|result| result)
        {
            return HostExecutionReport::terminal_failure(
                collect_plan,
                super::scheduler::FailurePhase::Cleanup,
                format!("collection retry blocked by disconnect failure: {error}"),
            )
            .with_completed_phases(completed_phases)
            .with_attempt_count(base_attempt_count.max(attempt))
            .with_cleanup_outcome(CleanupOutcome::Failed, true);
        }
    }

    unreachable!("collect_host_artifacts_with_live_session should always return")
}

fn cleanup_session_operations(cleanup: &CollectorCleanupJob) -> Vec<SessionOperation> {
    match cleanup {
        CollectorCleanupJob::RemoteExec {
            command,
            capture_path,
        } => vec![SessionOperation::cleanup_capture_exec(
            command.clone(),
            capture_path.clone(),
        )],
    }
}

async fn disconnect_host_session(
    report: HostExecutionReport,
    session: &mut ConnectedSession,
    deadline: Duration,
) -> HostExecutionReport {
    let selected_transport = session.transport();
    let cleanup = tokio::time::timeout(deadline, session.session_mut().cleanup()).await;
    match cleanup {
        Ok(Ok(())) => report.with_selected_transport(selected_transport),
        Ok(Err(error)) => HostExecutionReport::terminal_failure(
            report.plan,
            super::scheduler::FailurePhase::Cleanup,
            format!("session disconnect failed: {error}"),
        )
        .with_completed_phases(report.completed_phases)
        .with_attempt_count(report.attempt_count)
        .with_selected_transport(selected_transport)
        .with_cleanup_outcome(CleanupOutcome::Failed, report.residue_present),
        Err(_) => HostExecutionReport::terminal_failure(
            report.plan,
            super::scheduler::FailurePhase::Cleanup,
            format!("session disconnect exceeded {deadline:?}"),
        )
        .with_completed_phases(report.completed_phases)
        .with_attempt_count(report.attempt_count)
        .with_selected_transport(selected_transport)
        .with_cleanup_outcome(CleanupOutcome::Failed, report.residue_present),
    }
}

async fn cleanup_host_workspace_with_live_session<F>(
    spec: &MissionSpec,
    cleanup_executor: &SessionExecutor<F>,
    _cleanup: &CollectorCleanupJob,
    report: HostExecutionReport,
    session: &mut ConnectedSession,
    allow_reconnect_retry: bool,
) -> HostExecutionReport
where
    F: SessionFactory + 'static,
{
    if report.final_state != HostState::Complete {
        return report;
    }

    let base_attempt_count = report.attempt_count;
    let max_attempts = spec.retry_policy.max_attempts.max(1);
    let cleanup_plan = report.plan.force_state(HostState::Connecting);

    let mut next_report = cleanup_executor
        .run_connected_session_with_fallback(cleanup_plan.clone(), session, false)
        .await
        .with_completed_phases(report.completed_phases.clone())
        .with_attempt_count(base_attempt_count.max(1));

    if !allow_reconnect_retry || !next_report.should_retry(max_attempts) {
        return if next_report.final_state == HostState::Complete {
            next_report.mark_phase_completed(super::scheduler::FailurePhase::Cleanup)
        } else {
            next_report
        };
    }
    if let Err(error) =
        tokio::time::timeout(spec.deadlines.cleanup, session.session_mut().cleanup())
            .await
            .map_err(|_| Error::DeadlineExceeded("cleanup reconnect disconnect timed out".into()))
            .and_then(|result| result)
    {
        return HostExecutionReport::terminal_failure(
            cleanup_plan,
            super::scheduler::FailurePhase::Cleanup,
            format!("cleanup retry blocked by disconnect failure: {error}"),
        )
        .with_completed_phases(report.completed_phases)
        .with_attempt_count(base_attempt_count)
        .with_cleanup_outcome(CleanupOutcome::Failed, true);
    }

    for attempt in 2..=max_attempts {
        tokio::time::sleep(retry_delay_for_report(&spec.retry_policy, &next_report)).await;

        let mut reconnected = match cleanup_executor.connect_session(&cleanup_plan).await {
            Ok(session) => session,
            Err(report) => {
                let report = report
                    .with_completed_phases(next_report.completed_phases.clone())
                    .with_attempt_count(base_attempt_count.max(attempt));
                if !report.should_retry(max_attempts) {
                    return report;
                }
                next_report = report;
                continue;
            }
        };

        next_report = cleanup_executor
            .run_connected_session_with_fallback(cleanup_plan.clone(), &mut reconnected, false)
            .await
            .with_completed_phases(report.completed_phases.clone())
            .with_attempt_count(base_attempt_count.max(attempt));

        *session = reconnected;

        if !next_report.should_retry(max_attempts) {
            return if next_report.final_state == HostState::Complete {
                next_report.mark_phase_completed(super::scheduler::FailurePhase::Cleanup)
            } else {
                next_report
            };
        }
        if let Err(error) =
            tokio::time::timeout(spec.deadlines.cleanup, session.session_mut().cleanup())
                .await
                .map_err(|_| {
                    Error::DeadlineExceeded("cleanup reconnect disconnect timed out".into())
                })
                .and_then(|result| result)
        {
            return HostExecutionReport::terminal_failure(
                cleanup_plan,
                super::scheduler::FailurePhase::Cleanup,
                format!("cleanup retry blocked by disconnect failure: {error}"),
            )
            .with_completed_phases(report.completed_phases)
            .with_attempt_count(base_attempt_count.max(attempt))
            .with_cleanup_outcome(CleanupOutcome::Failed, true);
        }
    }

    unreachable!("cleanup_host_workspace_with_live_session should always return")
}

async fn partial_collection_exists(store: &ArtifactStore, ip: std::net::IpAddr) -> bool {
    tokio::fs::metadata(store.host_inventory_path(ip))
        .await
        .is_ok()
        || tokio::fs::metadata(store.host_application_log_path(ip))
            .await
            .is_ok()
}

async fn cleanup_after_terminal_failure<F>(
    spec: &MissionSpec,
    cleanup_executor: &SessionExecutor<F>,
    cleanup: &CollectorCleanupJob,
    original: HostExecutionReport,
    session: &mut ConnectedSession,
) -> HostExecutionReport
where
    F: SessionFactory + 'static,
{
    let selected_transport = session.transport();
    let cleanup_seed = HostExecutionReport::success(
        original.plan.force_state(HostState::Collecting),
        HostState::Complete,
    )
    .with_attempt_count(original.attempt_count)
    .with_completed_phases(original.completed_phases.clone())
    .with_selected_transport(selected_transport);
    let cleanup_report = cleanup_host_workspace_with_live_session(
        spec,
        cleanup_executor,
        cleanup,
        cleanup_seed,
        session,
        false,
    )
    .await;
    let cleanup_report =
        disconnect_host_session(cleanup_report, session, spec.deadlines.cleanup).await;

    if cleanup_report.final_state == HostState::Complete {
        return original
            .with_selected_transport(selected_transport)
            .with_cleanup_outcome(CleanupOutcome::Complete, false);
    }

    let residue_present = cleanup_report.residue_present;
    let cleanup_error = cleanup_report
        .error
        .unwrap_or_else(|| "workspace cleanup did not complete".to_string());
    let mut original = original
        .with_selected_transport(selected_transport)
        .with_cleanup_outcome(CleanupOutcome::Failed, residue_present);
    original.error = Some(format!(
        "{}; cleanup residue: {cleanup_error}",
        original
            .error
            .unwrap_or_else(|| "host operation failed".into())
    ));
    original
}

#[derive(Clone)]
struct HostExecutionControl {
    mission_deadline: tokio::time::Instant,
    cancellation: Arc<AtomicBool>,
}

async fn execute_host_with_persistent_session_with_retry<F>(
    spec: &MissionSpec,
    store: &ArtifactStore,
    policy: ExecutionPolicy,
    factory: Arc<F>,
    plan: HostPlan,
    collector_job: CollectorJobPlan,
    control: HostExecutionControl,
) -> Result<HostExecutionReport>
where
    F: SessionFactory + 'static,
{
    let HostExecutionControl {
        mission_deadline,
        cancellation,
    } = control;
    let checkpoint = load_resume_checkpoint(store, &plan).await?;
    if checkpoint.mode == ResumeMode::SkipCompleted {
        let report = skipped_resume_report(&plan, &checkpoint)
            .with_cleanup_outcome(CleanupOutcome::Complete, false);
        write_checkpoint(store, &report).await?;
        return Ok(report);
    }

    let max_attempts = spec.retry_policy.max_attempts.max(1);
    let host_deadline = std::cmp::min(
        tokio::time::Instant::now() + spec.deadlines.host,
        mission_deadline,
    );
    let capability_executor = SessionExecutor::new(
        Arc::clone(&factory),
        policy,
        collector_job.capability_operations(),
    )
    .with_bounds(
        spec.deadlines.clone(),
        spec.resource_limits.clone(),
        Some(host_deadline),
    );
    let stage_executor = SessionExecutor::new(
        Arc::clone(&factory),
        policy,
        collector_job.stage_operations(),
    )
    .with_bounds(
        spec.deadlines.clone(),
        spec.resource_limits.clone(),
        Some(host_deadline),
    );
    let run_executor =
        SessionExecutor::new(Arc::clone(&factory), policy, collector_job.run_operations())
            .with_bounds(
                spec.deadlines.clone(),
                spec.resource_limits.clone(),
                Some(host_deadline),
            );
    let collect_executor = SessionExecutor::new(
        Arc::clone(&factory),
        policy,
        collector_job.collect_operations(),
    )
    .with_bounds(
        spec.deadlines.clone(),
        spec.resource_limits.clone(),
        Some(host_deadline),
    );
    let cleanup_executor = SessionExecutor::new(
        factory,
        policy,
        cleanup_session_operations(&collector_job.cleanup),
    )
    .with_bounds(spec.deadlines.clone(), spec.resource_limits.clone(), None);

    for local_attempt in 1..=max_attempts {
        let attempt = checkpoint.attempt_count.saturating_add(local_attempt);
        if cancellation.load(Ordering::SeqCst) {
            return Ok(HostExecutionReport::unattempted_failure(
                plan,
                super::scheduler::FailurePhase::Connect,
                "mission was interrupted before authentication",
            ));
        }
        if tokio::time::Instant::now() >= host_deadline {
            return Ok(HostExecutionReport::unattempted_failure(
                plan,
                super::scheduler::FailurePhase::Connect,
                format!(
                    "host deadline {:?} elapsed before connection",
                    spec.deadlines.host
                ),
            ));
        }
        let connect_plan = match plan.transition(HostState::Connecting) {
            Ok(plan) => plan,
            Err(error) => {
                return Ok(HostExecutionReport::terminal_failure(
                    plan,
                    super::scheduler::FailurePhase::Connect,
                    error.to_string(),
                )
                .with_completed_phases(checkpoint.completed_phases.clone())
                .with_attempt_count(attempt)
                .with_cleanup_outcome(CleanupOutcome::NotRequired, false));
            }
        };

        let mut session = match capability_executor.connect_session(&connect_plan).await {
            Ok(session) => session,
            Err(report) => {
                let report = report
                    .with_completed_phases(checkpoint.completed_phases.clone())
                    .with_attempt_count(attempt)
                    .with_cleanup_outcome(CleanupOutcome::NotRequired, false);
                if !report.should_retry(max_attempts) {
                    write_checkpoint(store, &report).await?;
                    return Ok(report);
                }
                tokio::time::sleep(retry_delay_for_report(&spec.retry_policy, &report)).await;
                continue;
            }
        };

        let mut completed_phases = checkpoint.completed_phases.clone();

        if cancellation.load(Ordering::SeqCst) {
            let interrupted = HostExecutionReport::terminal_failure(
                plan.clone(),
                super::scheduler::FailurePhase::Connect,
                "mission interrupted after connection and before remote operations",
            )
            .with_attempt_count(attempt)
            .with_cleanup_outcome(CleanupOutcome::NotRequired, false);
            let report =
                disconnect_host_session(interrupted, &mut session, spec.deadlines.cleanup).await;
            write_checkpoint(store, &report).await?;
            return Ok(report);
        }

        if checkpoint.mode == ResumeMode::Fresh {
            let capability_report = capability_executor
                .run_connected_session_with_fallback(connect_plan.clone(), &mut session, false)
                .await
                .with_attempt_count(attempt)
                .with_completed_phases(completed_phases.clone());
            if capability_report.final_state != HostState::Complete {
                let retryable = capability_report.should_retry(max_attempts);
                let report = disconnect_host_session(
                    capability_report.with_cleanup_outcome(CleanupOutcome::NotRequired, false),
                    &mut session,
                    spec.deadlines.cleanup,
                )
                .await;
                write_checkpoint(store, &report).await?;
                if retryable {
                    tokio::time::sleep(retry_delay_for_report(&spec.retry_policy, &report)).await;
                    continue;
                }
                return Ok(report);
            }

            let capability_capture = match tokio::fs::read_to_string(
                &collector_job.capability.capture_path,
            )
            .await
            {
                Ok(capture) => capture,
                Err(error) => {
                    let failure = HostExecutionReport::terminal_failure(
                        plan.clone(),
                        super::scheduler::FailurePhase::Stage,
                        format!(
                            "failed to read capability capture for {}: {error}; staging was not attempted",
                            plan.target.ip
                        ),
                    )
                    .with_attempt_count(attempt)
                    .with_selected_transport(session.transport())
                    .with_cleanup_outcome(CleanupOutcome::NotRequired, false);
                    let report =
                        disconnect_host_session(failure, &mut session, spec.deadlines.cleanup)
                            .await;
                    let _ = write_checkpoint(store, &report).await;
                    return Ok(report);
                }
            };
            if let Err(error) = validate_capability_capture(&capability_capture, &plan.contract) {
                let mismatch = HostExecutionReport::terminal_failure(
                    plan.clone(),
                    super::scheduler::FailurePhase::Stage,
                    error,
                )
                .with_attempt_count(attempt)
                .with_selected_transport(session.transport())
                .with_cleanup_outcome(CleanupOutcome::NotRequired, false);
                let report =
                    disconnect_host_session(mismatch, &mut session, spec.deadlines.cleanup).await;
                write_checkpoint(store, &report).await?;
                return Ok(report);
            }

            if cancellation.load(Ordering::SeqCst) {
                let interrupted = HostExecutionReport::terminal_failure(
                    plan.clone(),
                    super::scheduler::FailurePhase::Stage,
                    "mission interrupted after capability verification; staging was not attempted",
                )
                .with_attempt_count(attempt)
                .with_selected_transport(session.transport())
                .with_cleanup_outcome(CleanupOutcome::NotRequired, false);
                let report =
                    disconnect_host_session(interrupted, &mut session, spec.deadlines.cleanup)
                        .await;
                write_checkpoint(store, &report).await?;
                return Ok(report);
            }

            let stage_report = stage_executor
                .run_connected_session_with_fallback(connect_plan.clone(), &mut session, false)
                .await
                .with_attempt_count(attempt)
                .with_completed_phases(completed_phases.clone());
            if stage_report.final_state != HostState::Complete {
                let retryable = stage_report.should_retry(max_attempts);
                let report = cleanup_after_terminal_failure(
                    spec,
                    &cleanup_executor,
                    &collector_job.cleanup,
                    stage_report,
                    &mut session,
                )
                .await;
                write_checkpoint(store, &report).await?;
                if retryable && report.cleanup_outcome == CleanupOutcome::Complete {
                    tokio::time::sleep(retry_delay_for_report(&spec.retry_policy, &report)).await;
                    continue;
                }
                return Ok(report);
            }

            completed_phases.push(super::scheduler::FailurePhase::Stage);
            let stage_progress = progress_report(
                &plan,
                HostState::Executing,
                &completed_phases,
                attempt,
                session.transport(),
            );
            if let Err(error) = write_checkpoint(store, &stage_progress).await {
                let failure = HostExecutionReport::terminal_failure(
                    plan.clone(),
                    super::scheduler::FailurePhase::Stage,
                    format!("failed to persist stage checkpoint: {error}"),
                )
                .with_attempt_count(attempt)
                .with_completed_phases(completed_phases.clone())
                .with_selected_transport(session.transport());
                let report = cleanup_after_terminal_failure(
                    spec,
                    &cleanup_executor,
                    &collector_job.cleanup,
                    failure,
                    &mut session,
                )
                .await;
                return Ok(report);
            }
        }

        if cancellation.load(Ordering::SeqCst) {
            let interrupted = HostExecutionReport::terminal_failure(
                plan.clone(),
                super::scheduler::FailurePhase::Cleanup,
                "mission interrupted after staging; bounded workspace cleanup was attempted",
            )
            .with_attempt_count(attempt)
            .with_completed_phases(completed_phases.clone())
            .with_selected_transport(session.transport());
            let report = cleanup_after_terminal_failure(
                spec,
                &cleanup_executor,
                &collector_job.cleanup,
                interrupted,
                &mut session,
            )
            .await;
            write_checkpoint(store, &report).await?;
            return Ok(report);
        }

        let run_report = if checkpoint.mode == ResumeMode::CleanupOnly {
            HostExecutionReport::success(
                plan.force_state(HostState::Collecting),
                HostState::Complete,
            )
            .with_completed_phases(completed_phases.clone())
            .with_attempt_count(attempt)
            .with_selected_transport(session.transport())
        } else {
            let should_skip_execute = checkpoint.mode == ResumeMode::CollectOnly
                && completed_phases.contains(&super::scheduler::FailurePhase::Execute);

            if should_skip_execute {
                HostExecutionReport::success(
                    plan.force_state(HostState::Collecting),
                    HostState::Complete,
                )
                .with_completed_phases(completed_phases.clone())
                .with_attempt_count(attempt)
                .with_selected_transport(session.transport())
            } else {
                let run_report = run_executor
                    .run_connected_session_with_fallback(connect_plan.clone(), &mut session, false)
                    .await
                    .with_attempt_count(attempt)
                    .with_completed_phases(completed_phases.clone());
                if run_report.final_state != HostState::Complete {
                    let report = cleanup_after_terminal_failure(
                        spec,
                        &cleanup_executor,
                        &collector_job.cleanup,
                        run_report,
                        &mut session,
                    )
                    .await;
                    write_checkpoint(store, &report).await?;
                    return Ok(report);
                }

                completed_phases.push(super::scheduler::FailurePhase::Execute);
                let execute_progress = progress_report(
                    &plan,
                    HostState::Collecting,
                    &completed_phases,
                    attempt,
                    session.transport(),
                );
                if let Err(error) = write_checkpoint(store, &execute_progress).await {
                    let failure = HostExecutionReport::terminal_failure(
                        plan.clone(),
                        super::scheduler::FailurePhase::Execute,
                        format!("failed to persist execute checkpoint: {error}"),
                    )
                    .with_attempt_count(attempt)
                    .with_completed_phases(completed_phases.clone())
                    .with_selected_transport(session.transport());
                    let report = cleanup_after_terminal_failure(
                        spec,
                        &cleanup_executor,
                        &collector_job.cleanup,
                        failure,
                        &mut session,
                    )
                    .await;
                    return Ok(report);
                }
                run_report
                    .with_completed_phases(completed_phases.clone())
                    .with_attempt_count(attempt)
            }
        };

        if cancellation.load(Ordering::SeqCst) {
            let interrupted = HostExecutionReport::terminal_failure(
                plan.clone(),
                super::scheduler::FailurePhase::Cleanup,
                "mission interrupted after collector execution; collection is partial and cleanup was attempted",
            )
            .with_attempt_count(attempt)
            .with_completed_phases(completed_phases.clone())
            .with_selected_transport(session.transport())
            .with_partial_collection(partial_collection_exists(store, plan.target.ip).await);
            let report = cleanup_after_terminal_failure(
                spec,
                &cleanup_executor,
                &collector_job.cleanup,
                interrupted,
                &mut session,
            )
            .await;
            write_checkpoint(store, &report).await?;
            return Ok(report);
        }

        let collect_report = if checkpoint.mode == ResumeMode::CleanupOnly {
            run_report
                .with_completed_phases(completed_phases.clone())
                .mark_phase_completed(super::scheduler::FailurePhase::Collect)
        } else {
            collect_host_artifacts_with_live_session(
                spec,
                &collect_executor,
                run_report,
                &mut session,
            )
            .await
        };
        if collect_report.final_state != HostState::Complete {
            let partial = partial_collection_exists(store, plan.target.ip).await;
            let report = cleanup_after_terminal_failure(
                spec,
                &cleanup_executor,
                &collector_job.cleanup,
                collect_report.with_partial_collection(partial),
                &mut session,
            )
            .await;
            write_checkpoint(store, &report).await?;
            return Ok(report);
        }

        if cancellation.load(Ordering::SeqCst) {
            let interrupted = HostExecutionReport::terminal_failure(
                plan.clone(),
                super::scheduler::FailurePhase::Cleanup,
                "mission interrupted after collection; collected artifacts were preserved and cleanup was attempted",
            )
            .with_attempt_count(attempt)
            .with_completed_phases(collect_report.completed_phases.clone())
            .with_selected_transport(session.transport())
            .with_partial_collection(false);
            let report = cleanup_after_terminal_failure(
                spec,
                &cleanup_executor,
                &collector_job.cleanup,
                interrupted,
                &mut session,
            )
            .await;
            write_checkpoint(store, &report).await?;
            return Ok(report);
        }

        completed_phases = collect_report.completed_phases.clone();
        let collect_progress = progress_report(
            &plan,
            HostState::Collecting,
            &completed_phases,
            attempt,
            session.transport(),
        );
        if let Err(error) = write_checkpoint(store, &collect_progress).await {
            let failure = HostExecutionReport::terminal_failure(
                plan.clone(),
                super::scheduler::FailurePhase::Collect,
                format!("failed to persist collection checkpoint: {error}"),
            )
            .with_attempt_count(attempt)
            .with_completed_phases(completed_phases.clone())
            .with_selected_transport(session.transport())
            .with_partial_collection(partial_collection_exists(store, plan.target.ip).await);
            let report = cleanup_after_terminal_failure(
                spec,
                &cleanup_executor,
                &collector_job.cleanup,
                failure,
                &mut session,
            )
            .await;
            return Ok(report);
        }

        let cleanup_report = cleanup_host_workspace_with_live_session(
            spec,
            &cleanup_executor,
            &collector_job.cleanup,
            collect_report,
            &mut session,
            true,
        )
        .await;
        if cleanup_report.final_state != HostState::Complete {
            let cleanup_report = disconnect_host_session(
                cleanup_report.with_cleanup_outcome(CleanupOutcome::Failed, true),
                &mut session,
                spec.deadlines.cleanup,
            )
            .await;
            write_checkpoint(store, &cleanup_report).await?;
            return Ok(cleanup_report);
        }

        let final_report = disconnect_host_session(
            cleanup_report.with_cleanup_outcome(CleanupOutcome::Complete, false),
            &mut session,
            spec.deadlines.cleanup,
        )
        .await;
        write_checkpoint(store, &final_report).await?;
        return Ok(final_report);
    }

    unreachable!("execute_host_with_persistent_session_with_retry should always return");
}

fn retry_delay_for_report(retry_policy: &RetryPolicy, report: &HostExecutionReport) -> Duration {
    let requested = if should_apply_smb_connect_cooldown(report) {
        std::cmp::max(retry_policy.backoff, SMB_CONNECT_RETRY_COOLDOWN)
    } else {
        retry_policy.backoff
    };
    requested.min(MAX_RETRY_BACKOFF)
}

fn should_apply_smb_connect_cooldown(report: &HostExecutionReport) -> bool {
    report.failure_phase == Some(super::scheduler::FailurePhase::Connect)
        && report.failure_disposition == Some(super::scheduler::FailureDisposition::Retryable)
        && report
            .plan
            .transport_chain
            .contains(&TransportKind::WindowsSmb)
        && report
            .error
            .as_deref()
            .is_some_and(is_smb_session_setup_burst_error)
}

fn is_smb_session_setup_burst_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("smb")
        && [
            "sessionsetup",
            "session setup",
            "0xc000006d",
            "status_logon_failure",
            "logon failure",
            "account restriction",
            "account locked",
            "user session deleted",
            "session deleted",
            "too many sessions",
            "too many connections",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn unix_time_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[derive(Serialize)]
struct MissionManifest<'a> {
    engine: &'static str,
    mission_id: &'a str,
    started_unix_ms: u128,
    resume_signature: String,
    mission_reuse: &'static str,
    target_count: usize,
    targets: Vec<String>,
    target_contracts: Vec<PersistedTargetContract>,
    payload_catalog: &'a [super::mission::PayloadSpec],
    concurrency_limit: usize,
    best_effort: bool,
    dry_run: bool,
    allow_smb_fallback: bool,
    credential_profiles: Vec<PersistedCredentialProfileSelection>,
    discovery_ports: Vec<u16>,
    retry_max_attempts: u8,
    retry_backoff_ms: u128,
    deadlines_ms: BTreeMap<&'static str, u128>,
    resource_limits: BTreeMap<&'static str, u64>,
    renderer: Option<PersistedRenderer>,
}

#[derive(Serialize)]
struct PersistedRenderer {
    executable: String,
    sha256: String,
    timeout_ms: u128,
    max_output_bytes: u64,
}

#[derive(Serialize)]
struct PersistedTargetContract {
    ip: String,
    operating_system: &'static str,
    architecture: &'static str,
    transports: Vec<&'static str>,
}

#[derive(Serialize)]
struct PersistedCredentialProfileSelection {
    ip: String,
    profile: Option<String>,
    policy_sha256: String,
}

fn pretty_json<T: Serialize>(value: &T, context: &str) -> String {
    serde_json::to_string_pretty(value)
        .unwrap_or_else(|err| panic!("{context} should serialize to JSON: {err}"))
        + "\n"
}

fn render_mission_manifest(spec: &MissionSpec) -> String {
    let mut targets = spec.targets.clone();
    targets.sort();
    let target_contracts = targets
        .iter()
        .map(|ip| {
            let contract = spec.target_contract(*ip);
            PersistedTargetContract {
                ip: ip.to_string(),
                operating_system: contract.operating_system.as_str(),
                architecture: contract.architecture.as_str(),
                transports: contract
                    .transports
                    .iter()
                    .map(|transport| transport.as_str())
                    .collect(),
            }
        })
        .collect();
    let credential_profiles = targets
        .iter()
        .map(|ip| {
            let contract = spec.target_contract(*ip);
            let (profile, policy_sha256) = spec.credential_profiles.policy_identity(
                *ip,
                contract.operating_system,
                &contract.transports,
            );
            PersistedCredentialProfileSelection {
                ip: ip.to_string(),
                profile,
                policy_sha256,
            }
        })
        .collect();
    let deadlines_ms = BTreeMap::from([
        (
            "discovery_connect",
            spec.deadlines.discovery_connect.as_millis(),
        ),
        ("connect", spec.deadlines.connect.as_millis()),
        ("inactivity", spec.deadlines.inactivity.as_millis()),
        ("command", spec.deadlines.command.as_millis()),
        ("transfer", spec.deadlines.transfer.as_millis()),
        ("cleanup", spec.deadlines.cleanup.as_millis()),
        ("host", spec.deadlines.host.as_millis()),
        ("mission", spec.deadlines.mission.as_millis()),
    ]);
    let resource_limits = BTreeMap::from([
        (
            "max_command_output_bytes",
            spec.resource_limits.max_command_output_bytes as u64,
        ),
        (
            "max_download_bytes",
            spec.resource_limits.max_download_bytes,
        ),
        ("max_payload_bytes", spec.resource_limits.max_payload_bytes),
    ]);

    pretty_json(
        &MissionManifest {
            engine: "pandoras_box",
            mission_id: &spec.mission_id,
            started_unix_ms: unix_time_millis(),
            resume_signature: spec.resume_signature(),
            mission_reuse: spec.mission_reuse.as_str(),
            target_count: spec.targets.len(),
            targets: targets.iter().map(ToString::to_string).collect(),
            target_contracts,
            payload_catalog: &spec.payload_catalog,
            concurrency_limit: spec.concurrency_limit,
            best_effort: spec.best_effort,
            dry_run: spec.dry_run,
            allow_smb_fallback: spec.allow_smb_fallback,
            credential_profiles,
            discovery_ports: spec.resolved_discovery_ports(),
            retry_max_attempts: spec.retry_policy.max_attempts,
            retry_backoff_ms: spec.retry_policy.backoff.as_millis(),
            deadlines_ms,
            resource_limits,
            renderer: spec.renderer.as_ref().map(|renderer| PersistedRenderer {
                executable: renderer.executable.to_string_lossy().into_owned(),
                sha256: renderer.sha256.clone(),
                timeout_ms: renderer.timeout.as_millis(),
                max_output_bytes: renderer.max_output_bytes,
            }),
        },
        "mission manifest",
    )
}

#[derive(Serialize)]
struct PersistedHostPlan<'a> {
    ip: String,
    platform: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
    state: &'static str,
    open_ports: &'a [u16],
    contracted_transports: Vec<&'static str>,
    transport_chain: Vec<&'static str>,
    payload: &'a Option<super::mission::ResolvedPayload>,
}

fn render_plan_json(plan: &HostPlan) -> String {
    pretty_json(
        &PersistedHostPlan {
            ip: plan.target.ip.to_string(),
            platform: plan.target.platform.as_str(),
            operating_system: plan.contract.operating_system.as_str(),
            architecture: plan.contract.architecture.as_str(),
            state: plan.state.as_str(),
            open_ports: &plan.target.open_ports,
            contracted_transports: plan
                .contract
                .transports
                .iter()
                .map(|transport| transport.as_str())
                .collect(),
            transport_chain: plan
                .transport_chain
                .iter()
                .map(|transport| transport.as_str())
                .collect(),
            payload: &plan.payload,
        },
        "host plan",
    )
}

fn render_report_json(report: &HostExecutionReport) -> String {
    pretty_json(&persisted_status_from_report(report), "host status")
}

fn render_summary_json(summary: &PandorasBoxRunSummary) -> String {
    pretty_json(summary, "mission summary")
}

#[cfg(test)]
mod tests {
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
            } else if request.command.contains("rmdir \"$o\"")
                || request.command.contains("foreach($f")
            {
                (Vec::new(), self.behavior.cleanup_status)
            } else if request.command.contains("umask 077")
                || request.command.contains("icacls.exe")
            {
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
            if self.behavior.fail_log_download && transfer.remote_path.ends_with("application.log")
            {
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

        async fn connect(
            &self,
            plan: &HostPlan,
            transport: TransportKind,
        ) -> Result<BoxedHostSession> {
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
        spec.credential_profiles = crate::runtime::CredentialProfileCatalog::from_json(
            &profiles,
            std::path::Path::new("."),
        )
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
        let outcomes = stream::iter([record(first, PlatformHint::UnixLike, vec![22])])
            .chain(stream::pending());
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
}
