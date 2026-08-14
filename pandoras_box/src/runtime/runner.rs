use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::artifact_store::{ActiveMissionRecord, ArtifactRootLock, ArtifactStore};
#[cfg(test)]
use super::discovery::DiscoveryRecord;
use super::discovery::{DiscoveryConfig, DiscoveryOutcome, TcpDiscovery};
use super::mission::{
    HostPlan, HostState, HostTarget, MissionSpec, PlatformHint, RetryPolicy, TransportKind,
};
use super::payloads::ensure_chimera_payload_for_plan;
use super::planner::Planner;
use super::policy::ExecutionPolicy;
use super::reporting::write_asset_inventory_bundle;
use super::scheduler::HostExecutionReport;
use super::session_executor::{ConnectedSession, SessionExecutor, SessionOperation};
use super::session_factory::SessionFactory;
use super::transport::password::PasswordSessionFactory;
use super::workspace::{collector_plan, CollectorPlan};
use crate::{Error, Result};

#[cfg(test)]
use super::scheduler::HostExecutor;

const SMB_CONNECT_RETRY_COOLDOWN: Duration = Duration::from_secs(3);

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
}

impl PandorasBoxRunSummary {
    #[must_use]
    pub fn requires_failure_exit(&self) -> bool {
        self.attempted_targets == 0 || self.failed_hosts > 0
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
        let discovery = TcpDiscovery::new(DiscoveryConfig {
            ports: resolved_discovery_ports(&self.spec),
            ssh_port: self.spec.ssh_port,
            forwarded_smb_ports: forwarded_smb_ports(&self.spec),
            connect_timeout: self.spec.retry_policy.connect_timeout,
            concurrency_limit: self.spec.concurrency_limit,
        });
        let factory = Arc::new(
            PasswordSessionFactory::new(
                self.spec.unix_username.clone(),
                self.spec.windows_username.clone(),
                self.spec.password.clone(),
                self.spec.ssh_port,
                forwarded_smb_ports(&self.spec),
                self.spec.retry_policy.connect_timeout,
                self.spec.windows_smb_exec_mode,
            )
            .with_ssh_host_key_policy(self.spec.ssh_host_key_policy),
        );

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

        futures::pin_mut!(outcomes);

        while let Some(outcome) = outcomes.next().await {
            observed_targets += 1;
            let record = match outcome.into() {
                DiscoveryOutcome::Reachable(record) => {
                    reachable_targets += 1;
                    record
                }
                DiscoveryOutcome::Unreachable { ip } => {
                    unreachable_targets += 1;
                    let plan = HostPlan::queued(
                        HostTarget {
                            ip,
                            platform: PlatformHint::Unknown,
                            open_ports: Vec::new(),
                        },
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

            let plan = Planner::plan_host(&spec, record.host);
            let host_spec = spec.clone();
            store.ensure_layout([plan.target.ip]).await?;
            store
                .write_host_plan(plan.target.ip, &render_plan_json(&plan))
                .await?;

            if plan.transport_chain.is_empty() {
                skipped_targets += 1;
                let report = HostExecutionReport::unattempted_failure(
                    plan,
                    super::scheduler::FailurePhase::Connect,
                    "target was reachable but had no eligible authenticated transport",
                );
                store
                    .write_host_status(report.plan.target.ip, &render_report_json(&report))
                    .await?;
                reports.push(report);
                continue;
            }

            attempted_targets += 1;
            let collector_job = plan_collector_job(&host_spec, &store, &plan);
            let semaphore = Arc::clone(&semaphore);
            let store = store.clone();
            let factory = Arc::clone(&factory);
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await.map_err(|_| {
                    Error::MissionFailure("host execution semaphore closed unexpectedly".into())
                })?;
                let report = execute_host_with_persistent_session_with_retry(
                    &host_spec,
                    &store,
                    policy,
                    factory,
                    plan,
                    collector_job,
                )
                .await?;
                store
                    .write_host_status(report.plan.target.ip, &render_report_json(&report))
                    .await?;
                Ok::<HostExecutionReport, Error>(report)
            });
        }

        while let Some(report) = tasks.join_next().await {
            let report = report.map_err(|error| {
                Error::MissionFailure(format!("host execution task failed: {error}"))
            })??;
            reports.push(report);
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
        )
        .await
    }

    #[cfg(test)]
    async fn run_with_stream_and_executor<S, E>(
        &self,
        records: S,
        executor: Arc<E>,
    ) -> Result<PandorasBoxRunSummary>
    where
        S: Stream<Item = DiscoveryRecord>,
        E: HostExecutor + Send + Sync + 'static,
    {
        let (spec, store) = self.prepare_store().await?;
        let mut reachable_targets = 0usize;
        let mut skipped_targets = 0usize;
        let mut attempted_targets = 0usize;
        let semaphore = Arc::new(Semaphore::new(spec.concurrency_limit.max(1)));
        let mut tasks = JoinSet::new();
        let mut reports = Vec::new();

        futures::pin_mut!(records);

        while let Some(record) = records.next().await {
            reachable_targets += 1;
            let plan = Planner::plan_host(&spec, record.host);
            store.ensure_layout([plan.target.ip]).await?;
            store
                .write_host_plan(plan.target.ip, &render_plan_json(&plan))
                .await?;

            if plan.transport_chain.is_empty() {
                skipped_targets += 1;
                let report = HostExecutionReport::unattempted_failure(
                    plan,
                    super::scheduler::FailurePhase::Connect,
                    "target was reachable but had no eligible authenticated transport",
                );
                store
                    .write_host_status(report.plan.target.ip, &render_report_json(&report))
                    .await?;
                reports.push(report);
                continue;
            }

            attempted_targets += 1;
            let executor = Arc::clone(&executor);
            let semaphore = Arc::clone(&semaphore);
            let store = store.clone();
            let retry_policy = spec.retry_policy.clone();
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await.map_err(|_| {
                    Error::MissionFailure("host execution semaphore closed unexpectedly".into())
                })?;
                let report =
                    execute_host_plan_with_retry(&retry_policy, Arc::clone(&executor), plan).await;
                store
                    .write_host_status(report.plan.target.ip, &render_report_json(&report))
                    .await?;
                Ok::<HostExecutionReport, Error>(report)
            });
        }

        while let Some(report) = tasks.join_next().await {
            let report = report.map_err(|error| {
                Error::MissionFailure(format!("host execution task failed: {error}"))
            })??;
            reports.push(report);
        }

        let requested_targets = if spec.targets.is_empty() {
            reachable_targets
        } else {
            spec.targets.len()
        };
        self.finalize_summary(
            &spec,
            &store,
            TargetAccounting {
                requested: requested_targets,
                reachable: reachable_targets,
                unreachable: 0,
                skipped: skipped_targets,
                attempted: attempted_targets,
            },
            reports,
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
        store
            .write_mission_manifest(&render_mission_manifest(&spec))
            .await?;
        Ok((spec, store))
    }

    async fn resolve_mission_spec(&self, root_lock: &ArtifactRootLock) -> Result<MissionSpec> {
        let mut spec = self.spec.clone();
        if spec.mission_id_explicit {
            super::artifact_store::validate_mission_id(&spec.mission_id)?;
            return Ok(spec);
        }

        let signature = spec.resume_signature();
        let Some(active) = ArtifactStore::read_active_mission(root_lock).await? else {
            return Ok(spec);
        };

        if active.signature != signature {
            return Ok(spec);
        }

        let active_store =
            ArtifactStore::new_locked(&spec.artifact_root, &active.mission_id, root_lock)?;
        if !tokio::fs::try_exists(active_store.mission_dir()).await? {
            return Ok(spec);
        }
        if tokio::fs::try_exists(active_store.summary_path()).await? {
            active_store
                .clear_active_mission_if_matches(&active.mission_id)
                .await?;
            return Ok(spec);
        }

        spec.mission_id = active.mission_id;
        Ok(spec)
    }

    async fn finalize_summary(
        &self,
        spec: &MissionSpec,
        store: &ArtifactStore,
        accounting: TargetAccounting,
        reports: Vec<HostExecutionReport>,
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

        Ok(summary)
    }
}

fn default_discovery_ports(ssh_port: u16) -> Vec<u16> {
    let mut ports = vec![ssh_port];
    for port in [135, 139, 445] {
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports
}

fn resolved_discovery_ports(spec: &MissionSpec) -> Vec<u16> {
    if spec.discovery_ports.is_empty() {
        default_discovery_ports(spec.ssh_port)
    } else {
        spec.discovery_ports.clone()
    }
}

fn forwarded_smb_ports(spec: &MissionSpec) -> Vec<u16> {
    resolved_discovery_ports(spec)
        .into_iter()
        .filter(|port| *port != spec.ssh_port && !matches!(*port, 135 | 139 | 445))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalSupportFilePlan {
    source_path: PathBuf,
    staged_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityCaptureJob {
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
    None,
    SessionFiles { artifacts: Vec<CollectorArtifact> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CollectorCleanupJob {
    SessionDisconnectOnly,
    RemoteExec {
        command: String,
        capture_path: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectorJobPlan {
    identity: IdentityCaptureJob,
    stage: Option<CollectorStageJob>,
    run: CollectorRunJob,
    collect: CollectorCollectJob,
    cleanup: CollectorCleanupJob,
}

impl CollectorJobPlan {
    fn support_files(&self) -> Vec<LocalSupportFilePlan> {
        self.stage
            .as_ref()
            .map(|stage| {
                stage
                    .files
                    .iter()
                    .map(|file| file.support_file.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn stage_operations(&self) -> Vec<SessionOperation> {
        let mut operations = vec![SessionOperation::capture_read_only_exec(
            self.identity.command.clone(),
            self.identity.capture_path.clone(),
        )];

        if let Some(stage) = &self.stage {
            operations.push(SessionOperation::idempotent_exec(
                stage.ensure_remote_directories_command.clone(),
            ));

            for file in &stage.files {
                operations.push(SessionOperation::put_file(
                    file.support_file.staged_path.clone(),
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
            CollectorCollectJob::None => Vec::new(),
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

fn plan_collector_job(
    spec: &MissionSpec,
    store: &ArtifactStore,
    plan: &HostPlan,
) -> CollectorJobPlan {
    let identity = IdentityCaptureJob {
        command: spec.identity_command.clone(),
        capture_path: store.host_exec_dir(plan.target.ip).join("identity.txt"),
    };

    match collector_plan(spec, plan) {
        CollectorPlan::Preview { command, .. } => CollectorJobPlan {
            identity,
            stage: None,
            run: CollectorRunJob {
                collector_command: command,
                collector_capture_path: store
                    .host_exec_dir(plan.target.ip)
                    .join("inventory_preview.txt"),
            },
            collect: CollectorCollectJob::None,
            cleanup: CollectorCleanupJob::SessionDisconnectOnly,
        },
        CollectorPlan::Chimera { workspace } => {
            let cleanup_command = workspace.cleanup_command();
            let staged_path = store
                .host_exec_dir(plan.target.ip)
                .join(&workspace.staged_local_name);

            CollectorJobPlan {
                identity,
                stage: Some(CollectorStageJob {
                    files: vec![StagedSupportFile {
                        support_file: LocalSupportFilePlan {
                            source_path: workspace.collector_source_path.clone(),
                            staged_path,
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
            }
        }
    }
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
    tokio::fs::metadata(store.host_inventory_path(ip))
        .await
        .is_ok()
        && tokio::fs::metadata(store.host_application_log_path(ip))
            .await
            .is_ok()
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

    let mode = if final_state == HostState::Complete && artifacts_exist {
        ResumeMode::SkipCompleted
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

async fn stage_support_files(files: &[LocalSupportFilePlan]) -> Result<()> {
    for file in files {
        if let Some(parent) = file.staged_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(&file.source_path, &file.staged_path).await?;
    }

    Ok(())
}

async fn collect_host_artifacts_with_live_session<F>(
    spec: &MissionSpec,
    collect_executor: &SessionExecutor<F>,
    artifact_collection: &CollectorCollectJob,
    report: HostExecutionReport,
    session: &mut ConnectedSession,
) -> HostExecutionReport
where
    F: SessionFactory + 'static,
{
    if report.final_state != HostState::Complete
        || matches!(artifact_collection, CollectorCollectJob::None)
    {
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
    }

    unreachable!("collect_host_artifacts_with_live_session should always return")
}

fn cleanup_session_operations(cleanup: &CollectorCleanupJob) -> Vec<SessionOperation> {
    match cleanup {
        CollectorCleanupJob::SessionDisconnectOnly => Vec::new(),
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
) -> HostExecutionReport {
    let selected_transport = session.transport();
    match session.session_mut().cleanup().await {
        Ok(()) => report.with_selected_transport(selected_transport),
        Err(err) => HostExecutionReport::terminal_failure(
            report.plan,
            super::scheduler::FailurePhase::Cleanup,
            format!("cleanup failed: {err}"),
        )
        .with_completed_phases(report.completed_phases)
        .with_attempt_count(report.attempt_count)
        .with_selected_transport(selected_transport),
    }
}

async fn cleanup_host_workspace_with_live_session<F>(
    spec: &MissionSpec,
    cleanup_executor: &SessionExecutor<F>,
    cleanup: &CollectorCleanupJob,
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

    if matches!(cleanup, CollectorCleanupJob::SessionDisconnectOnly) {
        return report.mark_phase_completed(super::scheduler::FailurePhase::Cleanup);
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
    }

    unreachable!("cleanup_host_workspace_with_live_session should always return")
}

async fn execute_host_with_persistent_session_with_retry<F>(
    spec: &MissionSpec,
    store: &ArtifactStore,
    policy: ExecutionPolicy,
    factory: Arc<F>,
    plan: HostPlan,
    collector_job: CollectorJobPlan,
) -> Result<HostExecutionReport>
where
    F: SessionFactory + 'static,
{
    let checkpoint = load_resume_checkpoint(store, &plan).await?;
    if checkpoint.mode == ResumeMode::SkipCompleted {
        let report = skipped_resume_report(&plan, &checkpoint);
        write_checkpoint(store, &report).await?;
        return Ok(report);
    }
    if checkpoint.mode == ResumeMode::Fresh {
        ensure_chimera_payload_for_plan(spec, &plan).await?;
    }

    let max_attempts = spec.retry_policy.max_attempts.max(1);
    let stage_executor = SessionExecutor::new(
        Arc::clone(&factory),
        policy,
        collector_job.stage_operations(),
    );
    let run_executor =
        SessionExecutor::new(Arc::clone(&factory), policy, collector_job.run_operations());
    let collect_executor = SessionExecutor::new(
        Arc::clone(&factory),
        policy,
        collector_job.collect_operations(),
    );
    let cleanup_executor = SessionExecutor::new(
        factory,
        policy,
        cleanup_session_operations(&collector_job.cleanup),
    );

    for local_attempt in 1..=max_attempts {
        let attempt = checkpoint.attempt_count.saturating_add(local_attempt);
        let connect_plan = match plan.transition(HostState::Connecting) {
            Ok(plan) => plan,
            Err(err) => {
                return Ok(HostExecutionReport::terminal_failure(
                    plan,
                    super::scheduler::FailurePhase::Connect,
                    err.to_string(),
                )
                .with_completed_phases(checkpoint.completed_phases.clone())
                .with_attempt_count(attempt));
            }
        };

        let mut session = match stage_executor.connect_session(&connect_plan).await {
            Ok(session) => session,
            Err(report) => {
                let report = report
                    .with_completed_phases(checkpoint.completed_phases.clone())
                    .with_attempt_count(attempt);
                if !report.should_retry(max_attempts) {
                    write_checkpoint(store, &report).await?;
                    return Ok(report);
                }
                tokio::time::sleep(retry_delay_for_report(&spec.retry_policy, &report)).await;
                continue;
            }
        };

        let mut completed_phases = checkpoint.completed_phases.clone();

        if checkpoint.mode == ResumeMode::Fresh {
            if let Err(err) = stage_support_files(&collector_job.support_files()).await {
                let report = HostExecutionReport::terminal_failure(
                    plan.clone(),
                    super::scheduler::FailurePhase::Stage,
                    format!("stage file prep failed: {err}"),
                )
                .with_completed_phases(completed_phases.clone())
                .with_attempt_count(attempt)
                .with_selected_transport(session.transport());
                write_checkpoint(store, &report).await?;
                let _ = session.session_mut().cleanup().await;
                return Ok(report);
            }

            let stage_report = stage_executor
                .run_connected_session_with_fallback(connect_plan.clone(), &mut session, false)
                .await
                .with_attempt_count(attempt)
                .with_completed_phases(completed_phases.clone());
            if stage_report.final_state != HostState::Complete {
                write_checkpoint(store, &stage_report).await?;
                if !stage_report.should_retry(max_attempts) {
                    return Ok(stage_report);
                }
                tokio::time::sleep(retry_delay_for_report(&spec.retry_policy, &stage_report)).await;
                continue;
            }

            completed_phases.push(super::scheduler::FailurePhase::Stage);
            let stage_progress = progress_report(
                &plan,
                HostState::Executing,
                &completed_phases,
                attempt,
                session.transport(),
            );
            write_checkpoint(store, &stage_progress).await?;
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
                    write_checkpoint(store, &run_report).await?;
                    return Ok(run_report);
                }

                completed_phases.push(super::scheduler::FailurePhase::Execute);
                let execute_progress = progress_report(
                    &plan,
                    HostState::Collecting,
                    &completed_phases,
                    attempt,
                    session.transport(),
                );
                write_checkpoint(store, &execute_progress).await?;
                run_report
                    .with_completed_phases(completed_phases.clone())
                    .with_attempt_count(attempt)
            }
        };

        let collect_report = if checkpoint.mode == ResumeMode::CleanupOnly {
            run_report
                .with_completed_phases(completed_phases.clone())
                .mark_phase_completed(super::scheduler::FailurePhase::Collect)
        } else {
            collect_host_artifacts_with_live_session(
                spec,
                &collect_executor,
                &collector_job.collect,
                run_report,
                &mut session,
            )
            .await
        };
        if collect_report.final_state != HostState::Complete {
            write_checkpoint(store, &collect_report).await?;
            return Ok(collect_report);
        }

        completed_phases = collect_report.completed_phases.clone();
        let collect_progress = progress_report(
            &plan,
            HostState::Collecting,
            &completed_phases,
            attempt,
            session.transport(),
        );
        write_checkpoint(store, &collect_progress).await?;

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
            write_checkpoint(store, &cleanup_report).await?;
            return Ok(cleanup_report);
        }

        let final_report = disconnect_host_session(cleanup_report, &mut session).await;
        write_checkpoint(store, &final_report).await?;
        return Ok(final_report);
    }

    unreachable!("execute_host_with_persistent_session_with_retry should always return");
}

#[cfg(test)]
async fn execute_host_plan_with_retry<E>(
    retry_policy: &RetryPolicy,
    executor: Arc<E>,
    plan: HostPlan,
) -> HostExecutionReport
where
    E: HostExecutor + Send + Sync + 'static,
{
    let max_attempts = retry_policy.max_attempts.max(1);

    for attempt in 1..=max_attempts {
        let report = executor.run(plan.clone()).await.with_attempt_count(attempt);
        if !report.should_retry(max_attempts) {
            return report;
        }

        tokio::time::sleep(retry_delay_for_report(retry_policy, &report)).await;
    }

    unreachable!("execute_host_plan_with_retry should always return");
}

fn retry_delay_for_report(retry_policy: &RetryPolicy, report: &HostExecutionReport) -> Duration {
    if should_apply_smb_connect_cooldown(report) {
        std::cmp::max(retry_policy.backoff, SMB_CONNECT_RETRY_COOLDOWN)
    } else {
        retry_policy.backoff
    }
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

#[derive(Serialize)]
struct MissionManifest<'a> {
    engine: &'static str,
    mission_id: &'a str,
    target_count: usize,
    concurrency_limit: usize,
    best_effort: bool,
    dry_run: bool,
    allow_smb_fallback: bool,
    identity_command: &'a str,
    unix_username: &'a str,
    windows_username: &'a str,
    ssh_port: u16,
    ssh_host_key_policy: &'static str,
    discovery_ports: &'a [u16],
    chimera_unix_path: String,
    chimera_windows_path: String,
}

fn pretty_json<T: Serialize>(value: &T, context: &str) -> String {
    serde_json::to_string_pretty(value)
        .unwrap_or_else(|err| panic!("{context} should serialize to JSON: {err}"))
        + "\n"
}

fn render_mission_manifest(spec: &MissionSpec) -> String {
    pretty_json(
        &MissionManifest {
            engine: "pandoras_box",
            mission_id: &spec.mission_id,
            target_count: spec.targets.len(),
            concurrency_limit: spec.concurrency_limit,
            best_effort: spec.best_effort,
            dry_run: spec.dry_run,
            allow_smb_fallback: spec.allow_smb_fallback,
            identity_command: &spec.identity_command,
            unix_username: &spec.unix_username,
            windows_username: &spec.windows_username,
            ssh_port: spec.ssh_port,
            ssh_host_key_policy: spec.ssh_host_key_policy.as_str(),
            discovery_ports: &spec.discovery_ports,
            chimera_unix_path: spec.chimera_unix_path.to_string_lossy().into_owned(),
            chimera_windows_path: spec.chimera_windows_path.to_string_lossy().into_owned(),
        },
        "mission manifest",
    )
}

#[derive(Serialize)]
struct PersistedHostPlan<'a> {
    ip: String,
    platform: &'static str,
    state: &'static str,
    open_ports: &'a [u16],
    transport_chain: Vec<&'static str>,
}

fn render_plan_json(plan: &HostPlan) -> String {
    pretty_json(
        &PersistedHostPlan {
            ip: plan.target.ip.to_string(),
            platform: plan.target.platform.as_str(),
            state: plan.state.as_str(),
            open_ports: &plan.target.open_ports,
            transport_chain: plan
                .transport_chain
                .iter()
                .map(|transport| transport.as_str())
                .collect(),
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
    use super::{
        plan_collector_job, render_mission_manifest, render_summary_json, resolved_discovery_ports,
        CollectorArtifact, CollectorCleanupJob, CollectorCollectJob, CollectorJobPlan,
        CollectorRunJob, CollectorStageJob, IdentityCaptureJob, LocalSupportFilePlan,
        PandorasBoxRunSummary, PandorasBoxRunner, PersistedHostStatus, StagedSupportFile,
        TargetAccounting,
    };
    use crate::runtime::discovery::{DiscoveryOutcome, DiscoveryRecord};
    use crate::runtime::mission::{
        HostPlan, HostState, HostTarget, MissionSpec, PlatformHint, RetryPolicy, TransportKind,
    };
    use crate::runtime::scheduler::{
        FailureDisposition, FailurePhase, HostExecutionReport, HostExecutor,
    };
    use crate::runtime::session_factory::{BoxedHostSession, SessionFactory};
    use crate::runtime::transport::{ExecRequest, ExecResponse, FileTransfer, HostSession};
    use crate::runtime::workspace::{collector_plan, remote_workspace, CollectorPlan};
    use crate::runtime::Planner;
    use crate::{Error, Result};
    use async_trait::async_trait;
    use futures::stream::{self, StreamExt};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct ExecutorBehavior {
        delay: Duration,
        final_state: HostState,
        error: Option<String>,
        failure_phase: Option<FailurePhase>,
        failure_disposition: Option<FailureDisposition>,
    }

    impl ExecutorBehavior {
        fn complete(delay: Duration) -> Self {
            Self {
                delay,
                final_state: HostState::Complete,
                error: None,
                failure_phase: None,
                failure_disposition: None,
            }
        }

        fn failed(delay: Duration, error: impl Into<String>) -> Self {
            Self {
                delay,
                final_state: HostState::Failed,
                error: Some(error.into()),
                failure_phase: None,
                failure_disposition: None,
            }
        }

        fn terminal_failure(
            delay: Duration,
            phase: FailurePhase,
            error: impl Into<String>,
        ) -> Self {
            Self {
                delay,
                final_state: HostState::Failed,
                error: Some(error.into()),
                failure_phase: Some(phase),
                failure_disposition: Some(FailureDisposition::Terminal),
            }
        }

        fn retryable_failure(
            delay: Duration,
            phase: FailurePhase,
            error: impl Into<String>,
        ) -> Self {
            Self {
                delay,
                final_state: HostState::Failed,
                error: Some(error.into()),
                failure_phase: Some(phase),
                failure_disposition: Some(FailureDisposition::Retryable),
            }
        }
    }

    #[derive(Clone)]
    struct RecordingExecutor {
        behaviors: Arc<Mutex<HashMap<IpAddr, Vec<ExecutorBehavior>>>>,
        completions: Arc<Mutex<Vec<IpAddr>>>,
    }

    impl RecordingExecutor {
        fn new(entries: Vec<(IpAddr, ExecutorBehavior)>) -> Self {
            Self::new_sequences(
                entries
                    .into_iter()
                    .map(|(ip, behavior)| (ip, vec![behavior]))
                    .collect(),
            )
        }

        fn new_sequences(entries: Vec<(IpAddr, Vec<ExecutorBehavior>)>) -> Self {
            Self {
                behaviors: Arc::new(Mutex::new(entries.into_iter().collect())),
                completions: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn completions(&self) -> Vec<IpAddr> {
            self.completions
                .lock()
                .expect("completions lock should be available")
                .clone()
        }
    }

    #[async_trait]
    impl HostExecutor for RecordingExecutor {
        async fn run(&self, plan: HostPlan) -> HostExecutionReport {
            let behavior = self
                .behaviors
                .lock()
                .expect("behaviors lock should be available")
                .get_mut(&plan.target.ip)
                .and_then(|behaviors| {
                    if behaviors.len() > 1 {
                        Some(behaviors.remove(0))
                    } else {
                        behaviors.first().cloned()
                    }
                })
                .expect("behavior should exist for host");
            tokio::time::sleep(behavior.delay).await;
            self.completions
                .lock()
                .expect("completions lock should be available")
                .push(plan.target.ip);

            match behavior.final_state {
                HostState::Complete => HostExecutionReport::success(plan, HostState::Complete),
                HostState::Failed => match (behavior.failure_phase, behavior.failure_disposition) {
                    (Some(phase), Some(FailureDisposition::Retryable)) => {
                        HostExecutionReport::retryable_failure(
                            plan,
                            phase,
                            behavior
                                .error
                                .unwrap_or_else(|| "synthetic failure".to_string()),
                        )
                    }
                    (Some(phase), Some(FailureDisposition::Terminal)) => {
                        HostExecutionReport::terminal_failure(
                            plan,
                            phase,
                            behavior
                                .error
                                .unwrap_or_else(|| "synthetic failure".to_string()),
                        )
                    }
                    _ => HostExecutionReport::failure(
                        plan,
                        behavior
                            .error
                            .unwrap_or_else(|| "synthetic failure".to_string()),
                    ),
                },
                state => HostExecutionReport::success(plan, state),
            }
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("pandoras-box-{label}-{unique}"))
    }

    fn spec(root: PathBuf) -> MissionSpec {
        MissionSpec {
            artifact_root: root,
            mission_id: "mission-123".to_string(),
            concurrency_limit: 4,
            ..MissionSpec::default()
        }
    }

    #[test]
    fn retry_delay_for_report_uses_default_backoff_for_non_smb_failures() {
        let retry_policy = RetryPolicy {
            backoff: Duration::from_millis(500),
            ..RetryPolicy::default()
        };
        let report = HostExecutionReport::retryable_failure(
            HostPlan::queued(
                HostTarget {
                    ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 31)),
                    platform: PlatformHint::Unix,
                    open_ports: vec![22],
                },
                vec![TransportKind::UnixSsh],
            ),
            FailurePhase::Connect,
            "connection reset by peer",
        );

        assert_eq!(
            super::retry_delay_for_report(&retry_policy, &report),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn retry_delay_for_report_extends_backoff_for_smb_session_setup_bursts() {
        let retry_policy = RetryPolicy {
            backoff: Duration::from_millis(500),
            ..RetryPolicy::default()
        };
        let report = HostExecutionReport::retryable_failure(
            HostPlan::queued(
                HostTarget {
                    ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 32)),
                    platform: PlatformHint::Windows,
                    open_ports: vec![445],
                },
                vec![TransportKind::WindowsSmb],
            ),
            FailurePhase::Connect,
            "WindowsSmb: smb exec connect to 10.0.0.32:445 failed: unexpected status code 0xc000006d for SessionSetup",
        );

        assert!(super::retry_delay_for_report(&retry_policy, &report) > Duration::from_millis(500));
    }

    fn record(last_octet: u8) -> DiscoveryRecord {
        DiscoveryRecord {
            host: HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)),
                platform: PlatformHint::Unix,
                open_ports: vec![22],
            },
            ttl: Some(64),
        }
    }

    fn record_for_host(
        ip: IpAddr,
        platform: PlatformHint,
        open_ports: Vec<u16>,
        ttl: Option<u8>,
    ) -> DiscoveryRecord {
        DiscoveryRecord {
            host: HostTarget {
                ip,
                platform,
                open_ports,
            },
            ttl,
        }
    }

    async fn write_fixture(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .expect("fixture parent should be created");
        }
        tokio::fs::write(path, contents)
            .await
            .expect("fixture should be written");
    }

    fn artifact_downloads(
        workspace: &crate::runtime::workspace::RemoteWorkspace,
        inventory: &[u8],
        application_log: &[u8],
    ) -> Arc<HashMap<String, Vec<u8>>> {
        Arc::new(HashMap::from([
            (workspace.inventory_path.clone(), inventory.to_vec()),
            (workspace.log_path.clone(), application_log.to_vec()),
        ]))
    }

    #[derive(Clone)]
    struct SessionTemplate {
        events: Arc<Mutex<Vec<String>>>,
        exec_outputs: Arc<HashMap<String, ExecResponse>>,
        exec_errors: Arc<Mutex<HashMap<String, Vec<String>>>>,
        downloads: Arc<HashMap<String, Vec<u8>>>,
        uploads: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl SessionTemplate {
        fn into_session(self) -> FakeSession {
            FakeSession {
                events: self.events,
                exec_outputs: self.exec_outputs,
                exec_errors: self.exec_errors,
                downloads: self.downloads,
                uploads: self.uploads,
            }
        }
    }

    struct FakeSession {
        events: Arc<Mutex<Vec<String>>>,
        exec_outputs: Arc<HashMap<String, ExecResponse>>,
        exec_errors: Arc<Mutex<HashMap<String, Vec<String>>>>,
        downloads: Arc<HashMap<String, Vec<u8>>>,
        uploads: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    #[async_trait]
    impl HostSession for FakeSession {
        async fn exec(&mut self, request: ExecRequest) -> Result<ExecResponse> {
            self.events
                .lock()
                .expect("events lock should be available")
                .push(format!("exec:{}", request.command));

            if let Some(errors) = self
                .exec_errors
                .lock()
                .expect("exec errors lock should be available")
                .get_mut(&request.command)
            {
                if !errors.is_empty() {
                    return Err(Error::CommunicatorError(errors.remove(0)));
                }
            }

            Ok(self
                .exec_outputs
                .get(&request.command)
                .cloned()
                .unwrap_or(ExecResponse {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    status_code: Some(0),
                }))
        }

        async fn put(&mut self, transfer: &FileTransfer) -> Result<()> {
            self.events
                .lock()
                .expect("events lock should be available")
                .push(format!("put:{}", transfer.remote_path));
            let contents = tokio::fs::read(&transfer.local_path).await?;
            self.uploads
                .lock()
                .expect("uploads lock should be available")
                .insert(transfer.remote_path.clone(), contents);
            Ok(())
        }

        async fn get(&mut self, transfer: &FileTransfer) -> Result<()> {
            self.events
                .lock()
                .expect("events lock should be available")
                .push(format!("get:{}", transfer.remote_path));

            let contents = self
                .downloads
                .get(&transfer.remote_path)
                .cloned()
                .ok_or_else(|| {
                    Error::FileTransferError(format!(
                        "missing fake download contents for {}",
                        transfer.remote_path
                    ))
                })?;
            if let Some(parent) = transfer.local_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&transfer.local_path, contents).await?;
            Ok(())
        }

        async fn ensure_dir(&mut self, _remote_dir: &str) -> Result<()> {
            Ok(())
        }

        async fn cleanup(&mut self) -> Result<()> {
            self.events
                .lock()
                .expect("events lock should be available")
                .push("disconnect".to_string());
            Ok(())
        }
    }

    type SessionTemplateQueues = HashMap<(IpAddr, TransportKind), Vec<SessionTemplate>>;

    struct FakeSessionFactory {
        templates: Arc<Mutex<SessionTemplateQueues>>,
        connect_events: Arc<Mutex<Vec<(IpAddr, TransportKind)>>>,
    }

    impl FakeSessionFactory {
        fn new(entries: Vec<((IpAddr, TransportKind), SessionTemplate)>) -> Self {
            Self {
                templates: Arc::new(Mutex::new(
                    entries
                        .into_iter()
                        .map(|(key, template)| (key, vec![template]))
                        .collect(),
                )),
                connect_events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn new_sequences(entries: Vec<((IpAddr, TransportKind), Vec<SessionTemplate>)>) -> Self {
            Self {
                templates: Arc::new(Mutex::new(entries.into_iter().collect())),
                connect_events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn connect_events(&self) -> Vec<(IpAddr, TransportKind)> {
            self.connect_events
                .lock()
                .expect("connect events lock should be available")
                .clone()
        }
    }

    #[async_trait]
    impl SessionFactory for FakeSessionFactory {
        async fn connect(
            &self,
            plan: &HostPlan,
            transport: TransportKind,
        ) -> Result<BoxedHostSession> {
            self.connect_events
                .lock()
                .expect("connect events lock should be available")
                .push((plan.target.ip, transport));
            let template = self
                .templates
                .lock()
                .expect("templates lock should be available")
                .get_mut(&(plan.target.ip, transport))
                .and_then(|templates| {
                    if templates.len() > 1 {
                        Some(templates.remove(0))
                    } else {
                        templates.first().cloned()
                    }
                })
                .ok_or_else(|| Error::CommunicatorError("missing fake session".to_string()))?;

            Ok(Box::new(template.into_session()))
        }
    }

    #[test]
    fn mission_manifest_omits_password_and_serializes_control_characters() {
        let spec = MissionSpec {
            password: "super-secret".into(),
            discovery_ports: vec![2222],
            identity_command: "printf '\n\u{1}'".to_string(),
            unix_username: "operator\\\"quoted".to_string(),
            ..MissionSpec::default()
        };
        let manifest = render_mission_manifest(&spec);
        let parsed: serde_json::Value =
            serde_json::from_str(&manifest).expect("manifest should always be valid JSON");

        assert_eq!(parsed["engine"], "pandoras_box");
        assert_eq!(parsed["ssh_port"], 22);
        assert_eq!(parsed["ssh_host_key_policy"], "require_known");
        assert_eq!(parsed["discovery_ports"], serde_json::json!([2222]));
        assert_eq!(parsed["identity_command"], "printf '\n\u{1}'");
        assert_eq!(parsed["unix_username"], "operator\\\"quoted");
        assert!(parsed.get("collector_port").is_none());
        assert!(!manifest.contains("super-secret"));
    }

    #[tokio::test]
    async fn runner_rejects_escaped_mission_id_before_mission_writes() {
        let root = temp_root("invalid-mission-id");
        let escaped_name = format!(
            "{}-escaped",
            root.file_name()
                .expect("temporary artifact root should have a file name")
                .to_string_lossy()
        );
        let escaped = root
            .parent()
            .expect("temporary artifact root should have a parent")
            .join(&escaped_name);
        let runner = PandorasBoxRunner::new(MissionSpec {
            artifact_root: root.clone(),
            mission_id: format!("../{escaped_name}"),
            mission_id_explicit: true,
            ..MissionSpec::default()
        });

        let error = runner
            .prepare_store()
            .await
            .expect_err("escaped mission identifier should fail before mission writes");
        assert!(error.to_string().contains("portable path component"));
        assert!(!escaped.exists());

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn resolved_discovery_ports_prefers_explicit_override() {
        let spec = MissionSpec {
            ssh_port: 2222,
            discovery_ports: vec![2222],
            ..MissionSpec::default()
        };

        assert_eq!(resolved_discovery_ports(&spec), vec![2222]);
    }

    #[test]
    fn resolved_discovery_ports_defaults_to_ssh_and_windows_probes() {
        let spec = MissionSpec {
            ssh_port: 2222,
            ..MissionSpec::default()
        };

        assert_eq!(resolved_discovery_ports(&spec), vec![2222, 135, 139, 445]);
    }

    #[test]
    fn summary_json_includes_host_counts() {
        let summary = PandorasBoxRunSummary {
            mission_dir: PathBuf::from("artifacts/mission-123\nquoted\"path"),
            requested_targets: 5,
            reachable_targets: 5,
            unreachable_targets: 0,
            skipped_targets: 0,
            attempted_targets: 5,
            discovered_hosts: 5,
            completed_hosts: 4,
            failed_hosts: 1,
        };
        let json = render_summary_json(&summary);

        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("summary should always be valid JSON");
        assert_eq!(parsed["mission_dir"], "artifacts/mission-123\nquoted\"path");
        assert_eq!(parsed["requested_targets"], 5);
        assert_eq!(parsed["attempted_targets"], 5);
        assert_eq!(parsed["discovered_hosts"], 5);
        assert_eq!(parsed["failed_hosts"], 1);
        assert!(summary.requires_failure_exit());
    }

    #[tokio::test]
    async fn finalize_summary_writes_asset_inventory_bundle_for_completed_hosts() {
        let root = temp_root("asset-inventory-complete");
        let root_lock =
            crate::runtime::artifact_store::ArtifactStore::acquire_root_lock(root.clone())
                .await
                .expect("artifact root lock should be available");
        let store = crate::runtime::artifact_store::ArtifactStore::new_locked(
            &root,
            "mission-123",
            &root_lock,
        )
        .expect("mission identifier should be valid");
        let mission_spec = spec(root.clone());
        let runner = PandorasBoxRunner::new(mission_spec.clone());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 41));
        let plan = HostPlan::queued(
            HostTarget {
                ip,
                platform: PlatformHint::Unix,
                open_ports: vec![22],
            },
            vec![TransportKind::UnixSsh],
        );

        store
            .ensure_layout(vec![ip])
            .await
            .expect("host layout should exist");
        tokio::fs::write(
            store.host_files_dir(ip).join("inventory.json"),
            r#"{
  "hostname": "lab",
  "ip": "10.0.0.41",
  "os": "Ubuntu 24.04",
  "ports": [{"port": 22, "protocol": "TCP"}],
  "services": [{"name": "sshd", "state": "OK", "startMode": "enabled", "status": "active"}],
  "users": [{"name": "root", "uid": "0", "gid": "0", "isAdmin": true, "groups": ["root"], "isLocal": true}],
  "shares": [],
  "containers": []
}"#,
        )
        .await
        .expect("inventory fixture should exist");

        let summary = runner
            .finalize_summary(
                &mission_spec,
                &store,
                TargetAccounting {
                    requested: 1,
                    reachable: 1,
                    unreachable: 0,
                    skipped: 0,
                    attempted: 1,
                },
                vec![HostExecutionReport::success(plan, HostState::Complete)
                    .with_selected_transport(TransportKind::UnixSsh)],
            )
            .await
            .expect("summary finalization should succeed");

        assert_eq!(summary.completed_hosts, 1);
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/asset_inventory.json"))
                .await
                .expect("asset inventory json should exist")
                .contains("\"hostname\": \"lab\"")
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/asset_inventory.md"))
                .await
                .expect("asset inventory markdown should exist")
                .contains(
                    "| 10.0.0.41 | complete | unix | unix_ssh | - | lab | Ubuntu 24.04 | 22 | root | sshd | - |"
                )
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/asset_inventory.csv"))
                .await
                .expect("asset inventory csv should exist")
                .contains("10.0.0.41,complete,unix,unix_ssh,-,-,lab,Ubuntu 24.04,22,root,sshd,-,")
        );
        assert_eq!(
            tokio::fs::read(root.join("mission-123/asset_inventory.pdf"))
                .await
                .expect("asset inventory pdf should exist")
                .as_slice()
                .get(..8),
            Some(&b"%PDF-1.4"[..])
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/network_topology.md"))
                .await
                .expect("network topology markdown should exist")
                .contains("10.0.0.41")
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/network_topology.mmd"))
                .await
                .expect("network topology mermaid should exist")
                .contains("host_10_0_0_41")
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/network_topology.excalidraw"))
                .await
                .expect("network topology excalidraw should exist")
                .contains("\"type\": \"excalidraw\"")
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn finalize_summary_asset_inventory_includes_failed_hosts_without_inventory() {
        let root = temp_root("asset-inventory-failed");
        let root_lock =
            crate::runtime::artifact_store::ArtifactStore::acquire_root_lock(root.clone())
                .await
                .expect("artifact root lock should be available");
        let store = crate::runtime::artifact_store::ArtifactStore::new_locked(
            &root,
            "mission-123",
            &root_lock,
        )
        .expect("mission identifier should be valid");
        let mission_spec = spec(root.clone());
        let runner = PandorasBoxRunner::new(mission_spec.clone());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42));
        let plan = HostPlan::queued(
            HostTarget {
                ip,
                platform: PlatformHint::Windows,
                open_ports: vec![2222, 445],
            },
            vec![TransportKind::WindowsSsh],
        );

        store
            .ensure_layout(vec![ip])
            .await
            .expect("host layout should exist");

        let summary = runner
            .finalize_summary(
                &mission_spec,
                &store,
                TargetAccounting {
                    requested: 1,
                    reachable: 1,
                    unreachable: 0,
                    skipped: 0,
                    attempted: 1,
                },
                vec![HostExecutionReport::failure(
                    plan,
                    "ssh connect failed: timeout waiting for banner",
                )],
            )
            .await
            .expect("summary finalization should still succeed");

        assert_eq!(summary.failed_hosts, 1);
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/asset_inventory.json"))
                .await
                .expect("asset inventory json should exist")
                .contains("\"error\": \"ssh connect failed: timeout waiting for banner\"")
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/asset_inventory.md"))
                .await
                .expect("asset inventory markdown should exist")
                .contains("| 10.0.0.42 | failed | windows | - | terminal | - | - | 2222,445 | - | - | - | ssh connect failed: timeout waiting for banner |")
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn finalize_summary_writes_network_topology_for_connected_hosts() {
        let root = temp_root("network-topology");
        let root_lock =
            crate::runtime::artifact_store::ArtifactStore::acquire_root_lock(root.clone())
                .await
                .expect("artifact root lock should be available");
        let store = crate::runtime::artifact_store::ArtifactStore::new_locked(
            &root,
            "mission-123",
            &root_lock,
        )
        .expect("mission identifier should be valid");
        let mission_spec = spec(root.clone());
        let runner = PandorasBoxRunner::new(mission_spec.clone());
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 51));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 52));
        let plan_a = HostPlan::queued(
            HostTarget {
                ip: ip_a,
                platform: PlatformHint::Unix,
                open_ports: vec![22],
            },
            vec![TransportKind::UnixSsh],
        );
        let plan_b = HostPlan::queued(
            HostTarget {
                ip: ip_b,
                platform: PlatformHint::Unix,
                open_ports: vec![5432],
            },
            vec![TransportKind::UnixSsh],
        );

        store
            .ensure_layout(vec![ip_a, ip_b])
            .await
            .expect("host layout should exist");
        tokio::fs::write(
            store.host_files_dir(ip_a).join("inventory.json"),
            r#"{
  "hostname": "web-01",
  "ip": "10.0.0.51",
  "os": "Ubuntu 24.04",
  "ports": [{"port": 22, "protocol": "TCP"}],
  "connections": [{"remoteAddress": "10.0.0.52:5432", "protocol": "TCP"}],
  "services": [{"name": "sshd"}],
  "users": [],
  "shares": [],
  "containers": []
}"#,
        )
        .await
        .expect("inventory fixture A should exist");
        tokio::fs::write(
            store.host_files_dir(ip_b).join("inventory.json"),
            r#"{
  "hostname": "db-01",
  "ip": "10.0.0.52",
  "os": "Ubuntu 24.04",
  "ports": [{"port": 5432, "protocol": "TCP"}],
  "connections": [],
  "services": [{"name": "postgresql"}],
  "users": [],
  "shares": [],
  "containers": []
}"#,
        )
        .await
        .expect("inventory fixture B should exist");

        runner
            .finalize_summary(
                &mission_spec,
                &store,
                TargetAccounting {
                    requested: 2,
                    reachable: 2,
                    unreachable: 0,
                    skipped: 0,
                    attempted: 2,
                },
                vec![
                    HostExecutionReport::success(plan_a, HostState::Complete),
                    HostExecutionReport::success(plan_b, HostState::Complete),
                ],
            )
            .await
            .expect("summary finalization should succeed");

        assert!(
            tokio::fs::read_to_string(root.join("mission-123/network_topology.mmd"))
                .await
                .expect("network topology mermaid should exist")
                .contains("host_10_0_0_51 -. observed .- host_10_0_0_52")
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/network_topology.md"))
                .await
                .expect("network topology markdown should exist")
                .contains("web-01 <-> db-01")
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/network_topology.excalidraw"))
                .await
                .expect("network topology excalidraw should exist")
                .contains("Subnet 10.0.0.0/24")
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn collector_job_for_unix_host_has_explicit_stage_run_and_collect_steps() {
        let root = PathBuf::from("/tmp/pandoras-box-runner");
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123")
            .expect("mission identifier should be valid");
        let spec = MissionSpec {
            artifact_root: root,
            mission_id: "mission-123".to_string(),
            identity_command: "whoami".to_string(),
            ..MissionSpec::default()
        };
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 31));
        let plan = HostPlan::queued(
            HostTarget {
                ip,
                platform: PlatformHint::Unix,
                open_ports: vec![22],
            },
            vec![TransportKind::UnixSsh],
        );

        let workspace = remote_workspace(&spec, &plan);
        let job = plan_collector_job(&spec, &store, &plan);

        assert_eq!(
            job,
            CollectorJobPlan {
                identity: IdentityCaptureJob {
                    command: "whoami".to_string(),
                    capture_path: store.host_exec_dir(ip).join("identity.txt"),
                },
                stage: Some(CollectorStageJob {
                    files: vec![StagedSupportFile {
                        support_file: LocalSupportFilePlan {
                            source_path: workspace.collector_source_path.clone(),
                            staged_path: store.host_exec_dir(ip).join("chimera"),
                        },
                        remote_path: workspace.remote_binary_path.clone(),
                    }],
                    ensure_remote_directories_command: workspace.ensure_directories_command(),
                    post_upload_commands: workspace.post_stage_commands(),
                }),
                run: CollectorRunJob {
                    collector_command: workspace.collector_command(),
                    collector_capture_path: store.host_exec_dir(ip).join("collector_collect.txt"),
                },
                collect: CollectorCollectJob::SessionFiles {
                    artifacts: vec![
                        CollectorArtifact {
                            remote_path: workspace.inventory_path.clone(),
                            local_path: store.host_inventory_path(ip),
                        },
                        CollectorArtifact {
                            remote_path: workspace.log_path.clone(),
                            local_path: store.host_application_log_path(ip),
                        },
                    ],
                },
                cleanup: CollectorCleanupJob::RemoteExec {
                    command: workspace.cleanup_command(),
                    capture_path: store.host_exec_dir(ip).join("collector_cleanup.txt"),
                },
            }
        );
    }

    #[test]
    fn collector_job_for_windows_host_has_explicit_stage_run_and_collect_steps() {
        let root = PathBuf::from("/tmp/pandoras-box-runner");
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123")
            .expect("mission identifier should be valid");
        let spec = MissionSpec {
            artifact_root: root,
            mission_id: "mission-123".to_string(),
            identity_command: "whoami".to_string(),
            ..MissionSpec::default()
        };
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 32));
        let plan = HostPlan::queued(
            HostTarget {
                ip,
                platform: PlatformHint::Windows,
                open_ports: vec![22, 445],
            },
            vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb],
        );

        let workspace = remote_workspace(&spec, &plan);
        let job = plan_collector_job(&spec, &store, &plan);

        assert_eq!(
            job,
            CollectorJobPlan {
                identity: IdentityCaptureJob {
                    command: "whoami".to_string(),
                    capture_path: store.host_exec_dir(ip).join("identity.txt"),
                },
                stage: Some(CollectorStageJob {
                    files: vec![StagedSupportFile {
                        support_file: LocalSupportFilePlan {
                            source_path: workspace.collector_source_path.clone(),
                            staged_path: store.host_exec_dir(ip).join("chimera.exe"),
                        },
                        remote_path: workspace.remote_binary_path.clone(),
                    }],
                    ensure_remote_directories_command: workspace.ensure_directories_command(),
                    post_upload_commands: workspace.post_stage_commands(),
                }),
                run: CollectorRunJob {
                    collector_command: workspace.collector_command(),
                    collector_capture_path: store.host_exec_dir(ip).join("collector_collect.txt"),
                },
                collect: CollectorCollectJob::SessionFiles {
                    artifacts: vec![
                        CollectorArtifact {
                            remote_path: workspace.inventory_path.clone(),
                            local_path: store.host_inventory_path(ip),
                        },
                        CollectorArtifact {
                            remote_path: workspace.log_path.clone(),
                            local_path: store.host_application_log_path(ip),
                        },
                    ],
                },
                cleanup: CollectorCleanupJob::RemoteExec {
                    command: workspace.cleanup_command(),
                    capture_path: store.host_exec_dir(ip).join("collector_cleanup.txt"),
                },
            }
        );
    }

    #[test]
    fn collector_job_for_unix_dry_run_skips_stage_and_artifact_collection() {
        let root = PathBuf::from("/tmp/pandoras-box-runner");
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123")
            .expect("mission identifier should be valid");
        let spec = MissionSpec {
            artifact_root: root,
            mission_id: "mission-123".to_string(),
            identity_command: "whoami".to_string(),
            dry_run: true,
            ..MissionSpec::default()
        };
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
        let plan = HostPlan::queued(
            HostTarget {
                ip,
                platform: PlatformHint::Unix,
                open_ports: vec![22],
            },
            vec![TransportKind::UnixSsh],
        );

        let workspace = remote_workspace(&spec, &plan);
        let job = plan_collector_job(&spec, &store, &plan);

        assert_eq!(
            job,
            CollectorJobPlan {
                identity: IdentityCaptureJob {
                    command: "whoami".to_string(),
                    capture_path: store.host_exec_dir(ip).join("identity.txt"),
                },
                stage: None,
                run: CollectorRunJob {
                    collector_command: match collector_plan(&spec, &plan) {
                        CollectorPlan::Preview { command, .. } => command,
                        CollectorPlan::Chimera { .. } => panic!("dry-run plan should preview"),
                    },
                    collector_capture_path: store.host_exec_dir(ip).join("inventory_preview.txt"),
                },
                collect: CollectorCollectJob::None,
                cleanup: CollectorCleanupJob::SessionDisconnectOnly,
            }
        );
        assert_eq!(
            workspace.remote_binary_path,
            "/tmp/pandoras_box/mission-123/chimera"
        );
    }

    #[test]
    fn windows_dry_run_collector_plan_uses_preview_command() {
        let spec = MissionSpec {
            dry_run: true,
            ..MissionSpec::default()
        };
        let plan = HostPlan::queued(
            HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 34)),
                platform: PlatformHint::Windows,
                open_ports: vec![22, 445],
            },
            vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb],
        );

        assert_eq!(
            collector_plan(&spec, &plan),
            CollectorPlan::Preview {
                workspace: remote_workspace(&spec, &plan),
                command: r#"cmd.exe /C "ver & whoami""#.to_string(),
            },
        );
    }

    #[tokio::test]
    async fn runner_accounts_for_unreachable_targets_without_attempting_transport() {
        let root = temp_root("runner-unreachable-accounting");
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            targets: vec![ip],
            ..MissionSpec::default()
        };
        let runner = PandorasBoxRunner::new(spec);
        let factory = Arc::new(FakeSessionFactory::new(vec![]));

        let summary = runner
            .run_with_stream_and_factory(
                stream::iter(vec![DiscoveryOutcome::Unreachable { ip }]),
                Arc::clone(&factory),
            )
            .await
            .expect("unreachable targets should produce a completed mission report");

        assert_eq!(summary.requested_targets, 1);
        assert_eq!(summary.reachable_targets, 0);
        assert_eq!(summary.unreachable_targets, 1);
        assert_eq!(summary.skipped_targets, 0);
        assert_eq!(summary.attempted_targets, 0);
        assert_eq!(summary.failed_hosts, 1);
        assert!(summary.requires_failure_exit());
        assert!(factory.connect_events().is_empty());

        let status =
            tokio::fs::read_to_string(root.join("mission-123/hosts/192.0.2.10/status.json"))
                .await
                .expect("unreachable status should exist");
        assert!(status.contains("\"attempt_count\": 0"));
        assert!(status.contains("unreachable"));

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_accounts_for_reachable_targets_without_eligible_transport() {
        let root = temp_root("runner-skipped-accounting");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 30));
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            targets: vec![ip],
            ..MissionSpec::default()
        };
        let runner = PandorasBoxRunner::new(spec);
        let factory = Arc::new(FakeSessionFactory::new(vec![]));
        let record = DiscoveryRecord {
            host: HostTarget {
                ip,
                platform: PlatformHint::Windows,
                open_ports: vec![135],
            },
            ttl: Some(128),
        };

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record]), Arc::clone(&factory))
            .await
            .expect("skipped targets should produce a completed mission report");

        assert_eq!(summary.requested_targets, 1);
        assert_eq!(summary.reachable_targets, 1);
        assert_eq!(summary.unreachable_targets, 0);
        assert_eq!(summary.skipped_targets, 1);
        assert_eq!(summary.attempted_targets, 0);
        assert_eq!(summary.failed_hosts, 1);
        assert!(factory.connect_events().is_empty());

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_starts_fast_host_before_slow_discovery_finishes() {
        let root = temp_root("streaming-fast-first");
        let runner = PandorasBoxRunner::new(spec(root.clone()));
        let fast = record(11);
        let slow = record(12);
        let executor = Arc::new(RecordingExecutor::new(vec![
            (
                fast.host.ip,
                ExecutorBehavior::complete(Duration::from_millis(150)),
            ),
            (
                slow.host.ip,
                ExecutorBehavior::complete(Duration::from_millis(10)),
            ),
        ]));
        let records = stream::iter(vec![
            (Duration::from_millis(20), fast.clone()),
            (Duration::from_millis(700), slow.clone()),
        ])
        .then(|(delay, record)| async move {
            tokio::time::sleep(delay).await;
            record
        });

        let runner_task = tokio::spawn({
            let runner = runner;
            let executor = executor.clone();
            async move { runner.run_with_stream_and_executor(records, executor).await }
        });

        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            executor.completions().first().copied(),
            Some(fast.host.ip),
            "expected the fast host to complete before slow discovery finished"
        );

        let summary = runner_task
            .await
            .expect("streaming runner task should not panic")
            .expect("streaming runner should succeed");

        assert_eq!(summary.discovered_hosts, 2);
        assert_eq!(summary.completed_hosts, 2);
        assert_eq!(executor.completions().first().copied(), Some(fast.host.ip));

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_continues_after_failed_host_and_reconciles_at_end() {
        let root = temp_root("streaming-failure");
        let runner = PandorasBoxRunner::new(spec(root.clone()));
        let first = record(21);
        let failed = record(22);
        let late = record(23);
        let executor = Arc::new(RecordingExecutor::new(vec![
            (
                first.host.ip,
                ExecutorBehavior::complete(Duration::from_millis(20)),
            ),
            (
                failed.host.ip,
                ExecutorBehavior::failed(Duration::from_millis(10), "auth failed"),
            ),
            (
                late.host.ip,
                ExecutorBehavior::complete(Duration::from_millis(20)),
            ),
        ]));
        let records = stream::iter(vec![
            (Duration::from_millis(10), first.clone()),
            (Duration::from_millis(20), failed.clone()),
            (Duration::from_millis(120), late.clone()),
        ])
        .then(|(delay, record)| async move {
            tokio::time::sleep(delay).await;
            record
        });

        let summary = runner
            .run_with_stream_and_executor(records, Arc::clone(&executor))
            .await
            .expect("strict mode is disabled, summary should still return");

        assert_eq!(summary.discovered_hosts, 3);
        assert_eq!(summary.completed_hosts, 2);
        assert_eq!(summary.failed_hosts, 1);
        assert!(
            tokio::fs::metadata(root.join("mission-123/hosts/10.0.0.21/status.json"))
                .await
                .is_ok()
        );
        assert!(
            tokio::fs::metadata(root.join("mission-123/hosts/10.0.0.22/status.json"))
                .await
                .is_ok()
        );
        assert!(
            tokio::fs::metadata(root.join("mission-123/hosts/10.0.0.23/status.json"))
                .await
                .is_ok()
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_retries_retryable_host_failures_and_records_attempts() {
        let root = temp_root("streaming-retryable");
        let runner = PandorasBoxRunner::new(spec(root.clone()));
        let retried = record(24);
        let executor = Arc::new(RecordingExecutor::new_sequences(vec![(
            retried.host.ip,
            vec![
                ExecutorBehavior::retryable_failure(
                    Duration::from_millis(5),
                    FailurePhase::Connect,
                    "connection reset by peer",
                ),
                ExecutorBehavior::complete(Duration::from_millis(5)),
            ],
        )]));

        let summary = runner
            .run_with_stream_and_executor(
                stream::iter(vec![retried.clone()]),
                Arc::clone(&executor),
            )
            .await
            .expect("retryable failures should recover");

        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert_eq!(
            executor.completions(),
            vec![retried.host.ip, retried.host.ip]
        );

        let status =
            tokio::fs::read_to_string(root.join("mission-123/hosts/10.0.0.24/status.json"))
                .await
                .expect("status artifact should exist");
        assert!(status.contains("\"final_state\": \"complete\""));
        assert!(status.contains("\"attempt_count\": 2"));
        assert!(status.contains("\"failure_phase\": null"));

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_stops_after_terminal_host_failures() {
        let root = temp_root("streaming-terminal");
        let runner = PandorasBoxRunner::new(spec(root.clone()));
        let failed = record(26);
        let executor = Arc::new(RecordingExecutor::new_sequences(vec![(
            failed.host.ip,
            vec![
                ExecutorBehavior::terminal_failure(
                    Duration::from_millis(5),
                    FailurePhase::Connect,
                    "auth failed",
                ),
                ExecutorBehavior::complete(Duration::from_millis(5)),
            ],
        )]));

        let summary = runner
            .run_with_stream_and_executor(stream::iter(vec![failed.clone()]), Arc::clone(&executor))
            .await
            .expect("non-strict mode should return a summary");

        assert_eq!(summary.completed_hosts, 0);
        assert_eq!(summary.failed_hosts, 1);
        assert_eq!(executor.completions(), vec![failed.host.ip]);

        let status =
            tokio::fs::read_to_string(root.join("mission-123/hosts/10.0.0.26/status.json"))
                .await
                .expect("status artifact should exist");
        assert!(status.contains("\"failure_phase\": \"connect\""));
        assert!(status.contains("\"failure_disposition\": \"terminal\""));
        assert!(status.contains("\"attempt_count\": 1"));

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_collects_unix_artifacts_over_the_authenticated_session() {
        let root = temp_root("runner-session-factory");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec.clone());
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Unix,
            vec![22],
            Some(64),
        );
        let workspace = remote_workspace(
            &spec,
            &HostPlan::queued(record.host.clone(), vec![TransportKind::UnixSsh]),
        );
        let collector_command = workspace.collector_command();
        let ensure_directories_command = workspace.ensure_directories_command();
        let post_stage_command = workspace
            .post_stage_commands()
            .into_iter()
            .next()
            .expect("unix workspace should require chmod");
        let cleanup_command = workspace.cleanup_command();
        let session_template = SessionTemplate {
            events: Arc::new(Mutex::new(Vec::new())),
            exec_outputs: Arc::new(HashMap::from([
                (
                    "whoami".to_string(),
                    ExecResponse {
                        stdout: b"root\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    ensure_directories_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    post_stage_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    collector_command.clone(),
                    ExecResponse {
                        stdout: b"collector complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    cleanup_command.clone(),
                    ExecResponse {
                        stdout: b"cleanup complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
            ])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: artifact_downloads(
                &workspace,
                b"{\"hostname\":\"lab\"}\n",
                b"collector log\n",
            ),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        };
        let events = Arc::clone(&session_template.events);
        let uploads = Arc::clone(&session_template.uploads);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (record.host.ip, TransportKind::UnixSsh),
            session_template,
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), Arc::clone(&factory))
            .await
            .expect("session factory runner should succeed");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert!(tokio::fs::read_to_string(
            root.join("mission-123/hosts/127.0.0.1/exec/identity.txt")
        )
        .await
        .expect("identity capture should exist")
        .contains("root"));
        assert_eq!(
            tokio::fs::read_to_string(
                root.join("mission-123/hosts/127.0.0.1/files/inventory.json")
            )
            .await
            .expect("inventory file should exist"),
            "{\"hostname\":\"lab\"}\n"
        );
        assert_eq!(
            tokio::fs::read_to_string(
                root.join("mission-123/hosts/127.0.0.1/logs/application.log")
            )
            .await
            .expect("application log should exist"),
            "collector log\n"
        );
        assert!(tokio::fs::read_to_string(
            root.join("mission-123/hosts/127.0.0.1/exec/collector_cleanup.txt")
        )
        .await
        .expect("cleanup capture should exist")
        .contains("cleanup complete"));
        assert_eq!(
            uploads
                .lock()
                .expect("uploads lock should be available")
                .get(&workspace.remote_binary_path)
                .expect("chimera upload should exist"),
            b"fake chimera binary"
        );
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:whoami",
                &format!("exec:{ensure_directories_command}"),
                &format!("put:{}", workspace.remote_binary_path),
                &format!("exec:{post_stage_command}"),
                &format!("exec:{collector_command}"),
                &format!("get:{}", workspace.inventory_path),
                &format!("get:{}", workspace.log_path),
                &format!("exec:{cleanup_command}"),
                "disconnect"
            ]
        );
        assert_eq!(
            factory.connect_events(),
            vec![(record.host.ip, TransportKind::UnixSsh)]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_session_factory_path_reuses_single_windows_smb_connection_across_collector_phases(
    ) {
        let root = temp_root("runner-session-factory-smb");
        let chimera_path = root.join("fixtures/chimera.exe");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_windows_path: chimera_path.clone(),
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec.clone());
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Windows,
            vec![445],
            Some(128),
        );
        let workspace = remote_workspace(
            &spec,
            &HostPlan::queued(record.host.clone(), vec![TransportKind::WindowsSmb]),
        );
        let collector_command = workspace.collector_command();
        let ensure_directories_command = workspace.ensure_directories_command();
        let cleanup_command = workspace.cleanup_command();
        let session_template = SessionTemplate {
            events: Arc::new(Mutex::new(Vec::new())),
            exec_outputs: Arc::new(HashMap::from([
                (
                    "whoami".to_string(),
                    ExecResponse {
                        stdout: b"nt authority\\system\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    ensure_directories_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    collector_command.clone(),
                    ExecResponse {
                        stdout: b"collector complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    cleanup_command.clone(),
                    ExecResponse {
                        stdout: b"cleanup complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
            ])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: artifact_downloads(
                &workspace,
                b"{\"hostname\":\"tiny11\"}\n",
                b"collector log\n",
            ),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        };
        let events = Arc::clone(&session_template.events);
        let uploads = Arc::clone(&session_template.uploads);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (record.host.ip, TransportKind::WindowsSmb),
            session_template,
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), Arc::clone(&factory))
            .await
            .expect("smb session factory runner should succeed");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert_eq!(
            tokio::fs::read_to_string(
                root.join("mission-123/hosts/127.0.0.1/files/inventory.json")
            )
            .await
            .expect("inventory file should exist"),
            "{\"hostname\":\"tiny11\"}\n"
        );
        assert_eq!(
            tokio::fs::read_to_string(
                root.join("mission-123/hosts/127.0.0.1/logs/application.log")
            )
            .await
            .expect("application log should exist"),
            "collector log\n"
        );
        assert_eq!(
            uploads
                .lock()
                .expect("uploads lock should be available")
                .get(&workspace.remote_binary_path)
                .expect("chimera upload should exist"),
            b"fake chimera binary"
        );
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:whoami",
                &format!("exec:{ensure_directories_command}"),
                &format!("put:{}", workspace.remote_binary_path),
                &format!("exec:{collector_command}"),
                &format!("get:{}", workspace.inventory_path),
                &format!("get:{}", workspace.log_path),
                &format!("exec:{cleanup_command}"),
                "disconnect"
            ]
        );
        assert_eq!(
            factory.connect_events(),
            vec![(record.host.ip, TransportKind::WindowsSmb)]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_dry_run_path_writes_preview_without_get_or_cleanup() {
        let root = temp_root("runner-session-dry-run");
        let runner = PandorasBoxRunner::new(MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            dry_run: true,
            ..spec(root.clone())
        });
        let record = record(25);
        let unix_preview_command = "sh -lc 'uname -a && printf \"\\n\" && id'";
        let session_template = SessionTemplate {
            events: Arc::new(Mutex::new(Vec::new())),
            exec_outputs: Arc::new(HashMap::from([
                (
                    "whoami".to_string(),
                    ExecResponse {
                        stdout: b"root\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    unix_preview_command.to_string(),
                    ExecResponse {
                        stdout: b"Linux host\nuid=0(root)\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
            ])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: Arc::new(HashMap::new()),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        };
        let events = Arc::clone(&session_template.events);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (record.host.ip, TransportKind::UnixSsh),
            session_template,
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), factory)
            .await
            .expect("dry-run session factory runner should succeed");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert!(tokio::fs::read_to_string(
            root.join("mission-123/hosts/10.0.0.25/exec/inventory_preview.txt")
        )
        .await
        .expect("inventory preview should exist")
        .contains("uid=0(root)"));
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:whoami",
                &format!("exec:{unix_preview_command}"),
                "disconnect"
            ]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_marks_host_failed_when_authenticated_artifact_read_is_unavailable() {
        let root = temp_root("runner-collection-failure");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec.clone());
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Unix,
            vec![22],
            Some(64),
        );
        let workspace = remote_workspace(
            &spec,
            &HostPlan::queued(record.host.clone(), vec![TransportKind::UnixSsh]),
        );
        let collector_command = workspace.collector_command();
        let ensure_directories_command = workspace.ensure_directories_command();
        let post_stage_command = workspace
            .post_stage_commands()
            .into_iter()
            .next()
            .expect("unix workspace should require chmod");
        let cleanup_command = workspace.cleanup_command();
        let session_template = SessionTemplate {
            events: Arc::new(Mutex::new(Vec::new())),
            exec_outputs: Arc::new(HashMap::from([
                (
                    "whoami".to_string(),
                    ExecResponse {
                        stdout: b"root\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    ensure_directories_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    post_stage_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    collector_command.clone(),
                    ExecResponse {
                        stdout: b"collector complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    cleanup_command.clone(),
                    ExecResponse {
                        stdout: b"cleanup complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
            ])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: Arc::new(HashMap::new()),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        };
        let events = Arc::clone(&session_template.events);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (record.host.ip, TransportKind::UnixSsh),
            session_template,
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), factory)
            .await
            .expect("collection failures should still return a summary in non-strict mode");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 0);
        assert_eq!(summary.failed_hosts, 1);
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/hosts/127.0.0.1/status.json"))
                .await
                .expect("status artifact should exist")
                .contains("\"final_state\": \"failed\"")
        );
        assert!(tokio::fs::read_to_string(
            root.join("mission-123/hosts/127.0.0.1/exec/collector_collect.txt")
        )
        .await
        .expect("collector collect capture should exist")
        .contains("collector complete"));
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:whoami",
                &format!("exec:{ensure_directories_command}"),
                &format!("put:{}", workspace.remote_binary_path),
                &format!("exec:{post_stage_command}"),
                &format!("exec:{collector_command}"),
                &format!("get:{}", workspace.inventory_path),
                "disconnect",
                &format!("get:{}", workspace.inventory_path),
                "disconnect"
            ]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_does_not_collect_artifacts_when_collector_command_fails() {
        let root = temp_root("runner-collector-failure");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec.clone());
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Unix,
            vec![22],
            Some(64),
        );
        let workspace = remote_workspace(
            &spec,
            &HostPlan::queued(record.host.clone(), vec![TransportKind::UnixSsh]),
        );
        let collector_command = workspace.collector_command();
        let ensure_directories_command = workspace.ensure_directories_command();
        let post_stage_command = workspace
            .post_stage_commands()
            .into_iter()
            .next()
            .expect("unix workspace should require chmod");
        let session_template = SessionTemplate {
            events: Arc::new(Mutex::new(Vec::new())),
            exec_outputs: Arc::new(HashMap::from([
                (
                    "whoami".to_string(),
                    ExecResponse {
                        stdout: b"root\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    ensure_directories_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    post_stage_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    collector_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: b"collector failed\n".to_vec(),
                        status_code: Some(1),
                    },
                ),
            ])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: Arc::new(HashMap::new()),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        };
        let events = Arc::clone(&session_template.events);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (record.host.ip, TransportKind::UnixSsh),
            session_template,
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), factory)
            .await
            .expect("non-strict mode should still return a summary");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 0);
        assert_eq!(summary.failed_hosts, 1);
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/hosts/127.0.0.1/status.json"))
                .await
                .expect("status artifact should exist")
                .contains("collector")
        );
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:whoami",
                &format!("exec:{ensure_directories_command}"),
                &format!("put:{}", workspace.remote_binary_path),
                &format!("exec:{post_stage_command}"),
                &format!("exec:{collector_command}"),
                "disconnect"
            ]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_marks_host_failed_when_remote_cleanup_fails() {
        let root = temp_root("runner-cleanup-failure");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec.clone());
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Unix,
            vec![22],
            Some(64),
        );
        let workspace = remote_workspace(
            &spec,
            &HostPlan::queued(record.host.clone(), vec![TransportKind::UnixSsh]),
        );
        let collector_command = workspace.collector_command();
        let ensure_directories_command = workspace.ensure_directories_command();
        let post_stage_command = workspace
            .post_stage_commands()
            .into_iter()
            .next()
            .expect("unix workspace should require chmod");
        let cleanup_command = workspace.cleanup_command();
        let session_template = SessionTemplate {
            events: Arc::new(Mutex::new(Vec::new())),
            exec_outputs: Arc::new(HashMap::from([
                (
                    "whoami".to_string(),
                    ExecResponse {
                        stdout: b"root\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    ensure_directories_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    post_stage_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    collector_command.clone(),
                    ExecResponse {
                        stdout: b"collector complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    cleanup_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: b"cleanup failed\n".to_vec(),
                        status_code: Some(1),
                    },
                ),
            ])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: artifact_downloads(
                &workspace,
                b"{\"hostname\":\"lab\"}\n",
                b"collector log\n",
            ),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        };
        let events = Arc::clone(&session_template.events);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (record.host.ip, TransportKind::UnixSsh),
            session_template,
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), factory)
            .await
            .expect("cleanup failures should still return a summary in non-strict mode");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 0);
        assert_eq!(summary.failed_hosts, 1);
        assert_eq!(
            tokio::fs::read_to_string(
                root.join("mission-123/hosts/127.0.0.1/files/inventory.json")
            )
            .await
            .expect("inventory file should still exist"),
            "{\"hostname\":\"lab\"}\n"
        );
        assert!(tokio::fs::read_to_string(
            root.join("mission-123/hosts/127.0.0.1/exec/collector_cleanup.txt")
        )
        .await
        .expect("cleanup capture should exist")
        .contains("cleanup failed"));
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/hosts/127.0.0.1/status.json"))
                .await
                .expect("status artifact should exist")
                .contains("exit status 1")
        );
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:whoami",
                &format!("exec:{ensure_directories_command}"),
                &format!("put:{}", workspace.remote_binary_path),
                &format!("exec:{post_stage_command}"),
                &format!("exec:{collector_command}"),
                &format!("get:{}", workspace.inventory_path),
                &format!("get:{}", workspace.log_path),
                &format!("exec:{cleanup_command}"),
                "disconnect"
            ]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_skips_completed_host_when_resume_artifacts_exist() {
        let root = temp_root("runner-resume-skip-complete");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path,
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec);
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Unix,
            vec![22],
            Some(64),
        );
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123")
            .expect("mission identifier should be valid");

        store
            .ensure_layout(vec![record.host.ip])
            .await
            .expect("host layout should exist");
        tokio::fs::write(
            store.host_inventory_path(record.host.ip),
            r#"{"hostname":"lab","os":"Ubuntu 24.04","ports":[],"connections":[],"services":[],"users":[],"shares":[],"containers":[]}"#,
        )
        .await
        .expect("inventory fixture should exist");
        tokio::fs::write(
            store.host_application_log_path(record.host.ip),
            "collector log\n",
        )
        .await
        .expect("log fixture should exist");
        let persisted = PersistedHostStatus {
            ip: record.host.ip.to_string(),
            final_state: HostState::Complete.as_str().to_string(),
            error: None,
            failure_phase: None,
            failure_disposition: None,
            selected_transport: Some("unix_ssh".to_string()),
            attempt_count: 3,
            completed_phases: vec![
                "stage".to_string(),
                "execute".to_string(),
                "collect".to_string(),
                "cleanup".to_string(),
            ],
        };
        tokio::fs::write(
            store.host_status_path(record.host.ip),
            serde_json::to_string_pretty(&persisted).expect("status should serialize"),
        )
        .await
        .expect("status fixture should exist");

        let factory = Arc::new(FakeSessionFactory::new(vec![]));
        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), Arc::clone(&factory))
            .await
            .expect("completed host resume should succeed");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert!(factory.connect_events().is_empty());

        let persisted: PersistedHostStatus = serde_json::from_str(
            &tokio::fs::read_to_string(store.host_status_path(record.host.ip))
                .await
                .expect("status artifact should exist"),
        )
        .expect("status should parse");
        assert_eq!(persisted.final_state, "complete");
        assert_eq!(persisted.attempt_count, 3);
        assert_eq!(persisted.selected_transport.as_deref(), Some("unix_ssh"));
        assert_eq!(
            persisted.completed_phases,
            vec!["stage", "execute", "collect", "cleanup"]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_preserves_legacy_credential_cleanup_failure_on_resume() {
        let root = temp_root("runner-resume-credential-cleanup-failure");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path,
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec);
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Unix,
            vec![22],
            Some(64),
        );
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123")
            .expect("mission identifier should be valid");

        store
            .ensure_layout(vec![record.host.ip])
            .await
            .expect("host layout should exist");
        tokio::fs::write(
            store.host_inventory_path(record.host.ip),
            r#"{"hostname":"lab","os":"Ubuntu 24.04","ports":[],"connections":[],"services":[],"users":[],"shares":[],"containers":[]}"#,
        )
        .await
        .expect("inventory fixture should exist");
        tokio::fs::write(
            store.host_application_log_path(record.host.ip),
            "collector log\n",
        )
        .await
        .expect("log fixture should exist");
        let persisted = PersistedHostStatus {
            ip: record.host.ip.to_string(),
            final_state: HostState::Failed.as_str().to_string(),
            error: Some("cleanup failed after legacy credential change".to_string()),
            failure_phase: Some("cleanup".to_string()),
            failure_disposition: Some("terminal".to_string()),
            selected_transport: Some("unix_ssh".to_string()),
            attempt_count: 2,
            completed_phases: vec![
                "stage".to_string(),
                "execute".to_string(),
                "collect".to_string(),
                "credentials".to_string(),
            ],
        };
        tokio::fs::write(
            store.host_status_path(record.host.ip),
            serde_json::to_string_pretty(&persisted).expect("status should serialize"),
        )
        .await
        .expect("status fixture should exist");

        let factory = Arc::new(FakeSessionFactory::new(vec![]));
        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), Arc::clone(&factory))
            .await
            .expect("legacy credential checkpoint should remain reportable");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 0);
        assert_eq!(summary.failed_hosts, 1);
        assert_eq!(factory.connect_events().len(), 1);

        let persisted: PersistedHostStatus = serde_json::from_str(
            &tokio::fs::read_to_string(store.host_status_path(record.host.ip))
                .await
                .expect("status artifact should exist"),
        )
        .expect("status should parse");
        assert_eq!(persisted.final_state, "failed");
        assert_eq!(persisted.attempt_count, 3);
        assert_eq!(persisted.failure_phase.as_deref(), Some("connect"));
        assert_eq!(
            persisted.completed_phases,
            vec!["stage", "execute", "collect", "credentials"]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_resumes_collect_phase_without_restaging_or_reexecuting() {
        let root = temp_root("runner-resume-collect");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec.clone());
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Unix,
            vec![22],
            Some(64),
        );
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123")
            .expect("mission identifier should be valid");
        store
            .ensure_layout(vec![record.host.ip])
            .await
            .expect("host layout should exist");
        let persisted = PersistedHostStatus {
            ip: record.host.ip.to_string(),
            final_state: HostState::Failed.as_str().to_string(),
            error: Some("artifact collection failed".to_string()),
            failure_phase: Some("collect".to_string()),
            failure_disposition: Some("retryable".to_string()),
            selected_transport: Some("unix_ssh".to_string()),
            attempt_count: 1,
            completed_phases: vec!["stage".to_string(), "execute".to_string()],
        };
        tokio::fs::write(
            store.host_status_path(record.host.ip),
            serde_json::to_string_pretty(&persisted).expect("status should serialize"),
        )
        .await
        .expect("status fixture should exist");

        let workspace = remote_workspace(
            &spec,
            &HostPlan::queued(record.host.clone(), vec![TransportKind::UnixSsh]),
        );
        let cleanup_command = workspace.cleanup_command();
        let session_template = SessionTemplate {
            events: Arc::new(Mutex::new(Vec::new())),
            exec_outputs: Arc::new(HashMap::from([(
                cleanup_command.clone(),
                ExecResponse {
                    stdout: b"cleanup complete\n".to_vec(),
                    stderr: Vec::new(),
                    status_code: Some(0),
                },
            )])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: artifact_downloads(
                &workspace,
                b"{\"hostname\":\"lab\"}\n",
                b"collector log\n",
            ),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        };
        let events = Arc::clone(&session_template.events);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (record.host.ip, TransportKind::UnixSsh),
            session_template,
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), Arc::clone(&factory))
            .await
            .expect("collect resume should succeed");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                &format!("get:{}", workspace.inventory_path),
                &format!("get:{}", workspace.log_path),
                &format!("exec:{cleanup_command}"),
                "disconnect"
            ]
        );
        assert_eq!(
            factory.connect_events(),
            vec![(record.host.ip, TransportKind::UnixSsh)]
        );

        let persisted: PersistedHostStatus = serde_json::from_str(
            &tokio::fs::read_to_string(store.host_status_path(record.host.ip))
                .await
                .expect("status artifact should exist"),
        )
        .expect("status should parse");
        assert_eq!(persisted.final_state, "complete");
        assert_eq!(persisted.attempt_count, 2);
        assert_eq!(
            persisted.completed_phases,
            vec!["stage", "execute", "collect", "cleanup"]
        );
        assert_eq!(
            tokio::fs::read_to_string(store.host_inventory_path(record.host.ip))
                .await
                .expect("inventory artifact should exist"),
            "{\"hostname\":\"lab\"}\n"
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_reuses_active_auto_resume_mission_for_matching_spec() {
        let root = temp_root("runner-mission-resume-match");
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let previous_mission_id = "mission-active".to_string();
        let mission_spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-fresh".to_string(),
            mission_id_explicit: false,
            targets: vec![ip],
            ..spec(root.clone())
        };
        let previous_store =
            crate::runtime::artifact_store::ArtifactStore::new(&root, &previous_mission_id)
                .expect("mission identifier should be valid");

        previous_store
            .ensure_layout(vec![ip])
            .await
            .expect("previous mission layout should exist");
        write_fixture(
            &previous_store.host_inventory_path(ip),
            b"{\"hostname\":\"lab\"}\n",
        )
        .await;
        write_fixture(
            &previous_store.host_application_log_path(ip),
            b"collector log\n",
        )
        .await;
        let persisted = PersistedHostStatus {
            ip: ip.to_string(),
            final_state: HostState::Complete.as_str().to_string(),
            error: None,
            failure_phase: None,
            failure_disposition: None,
            selected_transport: Some("unix_ssh".to_string()),
            attempt_count: 2,
            completed_phases: vec![
                "stage".to_string(),
                "execute".to_string(),
                "collect".to_string(),
                "cleanup".to_string(),
            ],
        };
        tokio::fs::write(
            previous_store.host_status_path(ip),
            serde_json::to_string_pretty(&persisted).expect("status should serialize"),
        )
        .await
        .expect("previous host status should be written");
        write_fixture(
            &root.join(".active_mission.json"),
            format!(
                "{{\n  \"mission_id\": \"{}\",\n  \"signature\": \"{}\"\n}}\n",
                previous_mission_id,
                mission_spec.resume_signature()
            )
            .as_bytes(),
        )
        .await;

        let runner = PandorasBoxRunner::new(mission_spec);
        let record = record_for_host(ip, PlatformHint::Unix, vec![22], Some(64));
        let factory = Arc::new(FakeSessionFactory::new(vec![]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record]), Arc::clone(&factory))
            .await
            .expect("matching active mission should resume");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert_eq!(summary.mission_dir, root.join(&previous_mission_id));
        assert!(factory.connect_events().is_empty());
        assert!(!tokio::fs::try_exists(root.join(".active_mission.json"))
            .await
            .expect("active mission marker check should succeed"));

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_ignores_incompatible_active_auto_resume_mission() {
        let root = temp_root("runner-mission-resume-mismatch");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mission_spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-fresh".to_string(),
            mission_id_explicit: false,
            targets: vec![ip],
            chimera_unix_path: chimera_path.clone(),
            ..spec(root.clone())
        };
        let incompatible_spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-other".to_string(),
            mission_id_explicit: false,
            targets: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))],
            ..spec(root.clone())
        };
        write_fixture(
            &root.join(".active_mission.json"),
            format!(
                "{{\n  \"mission_id\": \"mission-other\",\n  \"signature\": \"{}\"\n}}\n",
                incompatible_spec.resume_signature()
            )
            .as_bytes(),
        )
        .await;

        let runner = PandorasBoxRunner::new(mission_spec.clone());
        let record = record_for_host(ip, PlatformHint::Unix, vec![22], Some(64));
        let plan = Planner::plan_host(&mission_spec, record.host.clone());
        let workspace = remote_workspace(&mission_spec, &plan);
        let ensure_directories_command = workspace.ensure_directories_command();
        let post_stage_command = workspace.post_stage_commands()[0].clone();
        let collector_command = workspace.collector_command();
        let cleanup_command = workspace.cleanup_command();
        let session_template = SessionTemplate {
            events: Arc::new(Mutex::new(Vec::new())),
            exec_outputs: Arc::new(HashMap::from([
                (
                    "whoami".to_string(),
                    ExecResponse {
                        stdout: b"root\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    ensure_directories_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    post_stage_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    collector_command.clone(),
                    ExecResponse {
                        stdout: b"collector complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    cleanup_command.clone(),
                    ExecResponse {
                        stdout: b"cleanup complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
            ])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: artifact_downloads(
                &workspace,
                b"{\"hostname\":\"lab\"}\n",
                b"collector log\n",
            ),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        };
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            session_template,
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record]), Arc::clone(&factory))
            .await
            .expect("incompatible active mission should start fresh");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert_eq!(summary.mission_dir, root.join("mission-fresh"));
        assert_eq!(factory.connect_events(), vec![(ip, TransportKind::UnixSsh)]);
        assert!(!tokio::fs::try_exists(root.join(".active_mission.json"))
            .await
            .expect("active mission marker check should succeed"));

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_reconnects_unix_ssh_session_only_after_retryable_cleanup_failure() {
        let root = temp_root("runner-session-factory-ssh-reconnect");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec.clone());
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Unix,
            vec![22],
            Some(64),
        );
        let workspace = remote_workspace(
            &spec,
            &HostPlan::queued(record.host.clone(), vec![TransportKind::UnixSsh]),
        );
        let collector_command = workspace.collector_command();
        let ensure_directories_command = workspace.ensure_directories_command();
        let post_stage_command = workspace
            .post_stage_commands()
            .into_iter()
            .next()
            .expect("unix workspace should require chmod");
        let cleanup_command = workspace.cleanup_command();
        let shared_events = Arc::new(Mutex::new(Vec::new()));
        let shared_uploads = Arc::new(Mutex::new(HashMap::new()));
        let first_session = SessionTemplate {
            events: Arc::clone(&shared_events),
            exec_outputs: Arc::new(HashMap::from([
                (
                    "whoami".to_string(),
                    ExecResponse {
                        stdout: b"root\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    ensure_directories_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    post_stage_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    collector_command.clone(),
                    ExecResponse {
                        stdout: b"collector complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    cleanup_command.clone(),
                    ExecResponse {
                        stdout: b"cleanup complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
            ])),
            exec_errors: Arc::new(Mutex::new(HashMap::from([(
                cleanup_command.clone(),
                vec!["connection reset by peer".to_string()],
            )]))),
            downloads: artifact_downloads(
                &workspace,
                b"{\"hostname\":\"lab\"}\n",
                b"collector log\n",
            ),
            uploads: Arc::clone(&shared_uploads),
        };
        let second_session = SessionTemplate {
            events: Arc::clone(&shared_events),
            exec_outputs: Arc::new(HashMap::from([(
                cleanup_command.clone(),
                ExecResponse {
                    stdout: b"cleanup complete\n".to_vec(),
                    stderr: Vec::new(),
                    status_code: Some(0),
                },
            )])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: Arc::new(HashMap::new()),
            uploads: Arc::clone(&shared_uploads),
        };
        let factory = Arc::new(FakeSessionFactory::new_sequences(vec![(
            (record.host.ip, TransportKind::UnixSsh),
            vec![first_session, second_session],
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), Arc::clone(&factory))
            .await
            .expect("ssh cleanup retry should recover");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert_eq!(
            shared_events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:whoami",
                &format!("exec:{ensure_directories_command}"),
                &format!("put:{}", workspace.remote_binary_path),
                &format!("exec:{post_stage_command}"),
                &format!("exec:{collector_command}"),
                &format!("get:{}", workspace.inventory_path),
                &format!("get:{}", workspace.log_path),
                &format!("exec:{cleanup_command}"),
                "disconnect",
                &format!("exec:{cleanup_command}"),
                "disconnect"
            ]
        );
        assert_eq!(
            factory.connect_events(),
            vec![
                (record.host.ip, TransportKind::UnixSsh),
                (record.host.ip, TransportKind::UnixSsh)
            ]
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/hosts/127.0.0.1/status.json"))
                .await
                .expect("status artifact should exist")
                .contains("\"attempt_count\": 2")
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_reconnects_windows_smb_session_only_after_retryable_cleanup_failure() {
        let root = temp_root("runner-session-factory-smb-reconnect");
        let chimera_path = root.join("fixtures/chimera.exe");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_windows_path: chimera_path.clone(),
            ..spec(root.clone())
        };
        let runner = PandorasBoxRunner::new(spec.clone());
        let record = record_for_host(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            PlatformHint::Windows,
            vec![445],
            Some(128),
        );
        let workspace = remote_workspace(
            &spec,
            &HostPlan::queued(record.host.clone(), vec![TransportKind::WindowsSmb]),
        );
        let collector_command = workspace.collector_command();
        let ensure_directories_command = workspace.ensure_directories_command();
        let cleanup_command = workspace.cleanup_command();
        let shared_events = Arc::new(Mutex::new(Vec::new()));
        let shared_uploads = Arc::new(Mutex::new(HashMap::new()));
        let first_session = SessionTemplate {
            events: Arc::clone(&shared_events),
            exec_outputs: Arc::new(HashMap::from([
                (
                    "whoami".to_string(),
                    ExecResponse {
                        stdout: b"nt authority\\system\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    ensure_directories_command.clone(),
                    ExecResponse {
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    collector_command.clone(),
                    ExecResponse {
                        stdout: b"collector complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
                (
                    cleanup_command.clone(),
                    ExecResponse {
                        stdout: b"cleanup complete\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
            ])),
            exec_errors: Arc::new(Mutex::new(HashMap::from([(
                cleanup_command.clone(),
                vec!["connection reset by peer".to_string()],
            )]))),
            downloads: artifact_downloads(
                &workspace,
                b"{\"hostname\":\"tiny11\"}\n",
                b"collector log\n",
            ),
            uploads: Arc::clone(&shared_uploads),
        };
        let second_session = SessionTemplate {
            events: Arc::clone(&shared_events),
            exec_outputs: Arc::new(HashMap::from([(
                cleanup_command.clone(),
                ExecResponse {
                    stdout: b"cleanup complete\n".to_vec(),
                    stderr: Vec::new(),
                    status_code: Some(0),
                },
            )])),
            exec_errors: Arc::new(Mutex::new(HashMap::new())),
            downloads: Arc::new(HashMap::new()),
            uploads: Arc::clone(&shared_uploads),
        };
        let factory = Arc::new(FakeSessionFactory::new_sequences(vec![(
            (record.host.ip, TransportKind::WindowsSmb),
            vec![first_session, second_session],
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), Arc::clone(&factory))
            .await
            .expect("smb cleanup retry should recover");

        assert_eq!(summary.discovered_hosts, 1);
        assert_eq!(summary.completed_hosts, 1);
        assert_eq!(summary.failed_hosts, 0);
        assert_eq!(
            shared_events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:whoami",
                &format!("exec:{ensure_directories_command}"),
                &format!("put:{}", workspace.remote_binary_path),
                &format!("exec:{collector_command}"),
                &format!("get:{}", workspace.inventory_path),
                &format!("get:{}", workspace.log_path),
                &format!("exec:{cleanup_command}"),
                "disconnect",
                &format!("exec:{cleanup_command}"),
                "disconnect"
            ]
        );
        assert_eq!(
            factory.connect_events(),
            vec![
                (record.host.ip, TransportKind::WindowsSmb),
                (record.host.ip, TransportKind::WindowsSmb)
            ]
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/hosts/127.0.0.1/status.json"))
                .await
                .expect("status artifact should exist")
                .contains("\"attempt_count\": 2")
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
