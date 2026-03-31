use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{Stream, StreamExt};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::artifact_store::ArtifactStore;
use super::discovery::{DiscoveryConfig, DiscoveryRecord, TcpDiscovery};
use super::mission::{HostPlan, HostState, MissionSpec};
use super::planner::Planner;
use super::policy::ExecutionPolicy;
use super::reporting::write_asset_inventory_bundle;
use super::scheduler::{HostExecutionReport, HostExecutor};
use super::session_executor::{SessionExecutor, SessionOperation};
use super::session_factory::SessionFactory;
use super::transport::ssh::PasswordSshSessionFactory;
use super::workspace::{collector_plan, CollectorPlan};
use crate::{Error, Result};

#[cfg(not(test))]
const COLLECTOR_READY_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(test)]
const COLLECTOR_READY_TIMEOUT: Duration = Duration::from_millis(800);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PandorasBoxRunSummary {
    pub mission_dir: PathBuf,
    pub discovered_hosts: usize,
    pub completed_hosts: usize,
    pub failed_hosts: usize,
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
        let factory = Arc::new(PasswordSshSessionFactory::new(
            self.spec.unix_username.clone(),
            self.spec.windows_username.clone(),
            self.spec.password.clone(),
            self.spec.ssh_port,
            self.spec.retry_policy.connect_timeout,
        ));

        self.run_with_stream_and_factory(
            discovery.probe_ips_stream(self.spec.targets.clone()),
            factory,
        )
        .await
    }

    async fn run_with_stream_and_factory<S, F>(
        &self,
        records: S,
        factory: Arc<F>,
    ) -> Result<PandorasBoxRunSummary>
    where
        S: Stream<Item = DiscoveryRecord>,
        F: SessionFactory + 'static,
    {
        let store = self.prepare_store().await?;
        let policy = ExecutionPolicy {
            dry_run: self.spec.dry_run,
            allow_smb_fallback: self.spec.allow_smb_fallback,
        };
        let mut discovered_hosts = 0usize;
        let semaphore = Arc::new(Semaphore::new(self.spec.concurrency_limit.max(1)));
        let mut tasks = JoinSet::new();
        let mut reports = Vec::new();

        futures::pin_mut!(records);

        while let Some(record) = records.next().await {
            discovered_hosts += 1;
            let plan = Planner::plan_host(&self.spec, record.host);
            store.ensure_layout([plan.target.ip]).await?;
            store
                .write_host_plan(plan.target.ip, &render_plan_json(&plan))
                .await?;

            let collector_job = plan_collector_job(&self.spec, &store, &plan);
            stage_support_files(&collector_job.support_files()).await?;
            let executor = SessionExecutor::new(
                Arc::clone(&factory),
                policy,
                collector_job.session_operations(),
            );
            let semaphore = Arc::clone(&semaphore);
            let store = store.clone();
            let spec = self.spec.clone();
            let policy = policy;
            let factory = Arc::clone(&factory);
            tasks.spawn(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .expect("Pandora's Box semaphore unexpectedly closed");
                let report = executor.run(plan).await;
                let report =
                    collect_host_artifacts(&spec, &store, &collector_job.collect, report).await;
                let report =
                    cleanup_host_workspace(policy, factory, &collector_job.cleanup, report).await;
                store
                    .write_host_status(report.plan.target.ip, &render_report_json(&report))
                    .await?;
                Ok::<HostExecutionReport, Error>(report)
            });
        }

        while let Some(report) = tasks.join_next().await {
            reports.push(report.expect("Pandora's Box task should not panic")?);
        }

        self.finalize_summary(&store, discovered_hosts, reports)
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
        let store = self.prepare_store().await?;
        let mut discovered_hosts = 0usize;
        let semaphore = Arc::new(Semaphore::new(self.spec.concurrency_limit.max(1)));
        let mut tasks = JoinSet::new();
        let mut reports = Vec::new();

        futures::pin_mut!(records);

        while let Some(record) = records.next().await {
            discovered_hosts += 1;
            let plan = Planner::plan_host(&self.spec, record.host);
            store.ensure_layout([plan.target.ip]).await?;
            store
                .write_host_plan(plan.target.ip, &render_plan_json(&plan))
                .await?;

            let executor = Arc::clone(&executor);
            let semaphore = Arc::clone(&semaphore);
            let store = store.clone();
            tasks.spawn(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .expect("Pandora's Box semaphore unexpectedly closed");
                let report = executor.run(plan).await;
                store
                    .write_host_status(report.plan.target.ip, &render_report_json(&report))
                    .await?;
                Ok::<HostExecutionReport, Error>(report)
            });
        }

        while let Some(report) = tasks.join_next().await {
            reports.push(report.expect("Pandora's Box task should not panic")?);
        }

        self.finalize_summary(&store, discovered_hosts, reports)
            .await
    }

    async fn prepare_store(&self) -> Result<ArtifactStore> {
        let store = ArtifactStore::new(&self.spec.artifact_root, &self.spec.mission_id);
        store
            .write_mission_manifest(&render_mission_manifest(&self.spec))
            .await?;
        Ok(store)
    }

    async fn finalize_summary(
        &self,
        store: &ArtifactStore,
        discovered_hosts: usize,
        reports: Vec<HostExecutionReport>,
    ) -> Result<PandorasBoxRunSummary> {
        let summary = PandorasBoxRunSummary {
            mission_dir: store.mission_dir(),
            discovered_hosts,
            completed_hosts: reports
                .iter()
                .filter(|report| report.final_state == HostState::Complete)
                .count(),
            failed_hosts: reports
                .iter()
                .filter(|report| report.final_state == HostState::Failed)
                .count(),
        };

        write_asset_inventory_bundle(store, &reports, discovered_hosts).await?;
        store.write_summary(&render_summary_json(&summary)).await?;

        if self.spec.strict_mode && summary.failed_hosts > 0 {
            return Err(Error::CommunicatorError(format!(
                "Pandora's Box finished with {} failed hosts in strict mode",
                summary.failed_hosts
            )));
        }

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
    serve_command: String,
    serve_capture_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CollectorCollectJob {
    None,
    Http {
        inventory_endpoint: String,
        log_endpoint: String,
    },
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

    fn session_operations(&self) -> Vec<SessionOperation> {
        let mut operations = vec![SessionOperation::capture_exec(
            self.identity.command.clone(),
            self.identity.capture_path.clone(),
        )];

        if let Some(stage) = &self.stage {
            operations.push(SessionOperation::exec(
                stage.ensure_remote_directories_command.clone(),
            ));

            for file in &stage.files {
                operations.push(SessionOperation::put_file(
                    file.support_file.staged_path.clone(),
                    file.remote_path.clone(),
                ));
            }

            for command in &stage.post_upload_commands {
                operations.push(SessionOperation::exec(command.clone()));
            }
        }

        operations.push(SessionOperation::capture_exec(
            self.run.collector_command.clone(),
            self.run.collector_capture_path.clone(),
        ));
        if !self.run.serve_command.is_empty() {
            operations.push(SessionOperation::capture_exec(
                self.run.serve_command.clone(),
                self.run.serve_capture_path.clone(),
            ));
        }

        match self.cleanup {
            CollectorCleanupJob::SessionDisconnectOnly | CollectorCleanupJob::RemoteExec { .. } => {
            }
        }

        operations
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
                serve_command: String::new(),
                serve_capture_path: store.host_exec_dir(plan.target.ip).join("serve_skip.txt"),
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
                    serve_command: workspace.serve_command(),
                    serve_capture_path: store
                        .host_exec_dir(plan.target.ip)
                        .join("collector_serve.txt"),
                },
                collect: CollectorCollectJob::Http {
                    inventory_endpoint: workspace.inventory_endpoint,
                    log_endpoint: workspace.log_endpoint,
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

async fn stage_support_files(files: &[LocalSupportFilePlan]) -> Result<()> {
    for file in files {
        if let Some(parent) = file.staged_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(&file.source_path, &file.staged_path).await?;
    }

    Ok(())
}

async fn collect_host_artifacts(
    spec: &MissionSpec,
    store: &ArtifactStore,
    artifact_collection: &CollectorCollectJob,
    report: HostExecutionReport,
) -> HostExecutionReport {
    if report.final_state != HostState::Complete {
        return report;
    }

    let CollectorCollectJob::Http {
        inventory_endpoint,
        log_endpoint,
    } = artifact_collection
    else {
        return report;
    };

    let collecting_plan = report.plan.force_state(HostState::Collecting);
    let client = match reqwest::Client::builder()
        .connect_timeout(spec.retry_policy.connect_timeout)
        .timeout(spec.retry_policy.connect_timeout)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return HostExecutionReport::failure(
                collecting_plan,
                format!("failed to build HTTP client: {err}"),
            );
        }
    };
    let ip = collecting_plan.target.ip;

    if let Err(err) = fetch_host_http_artifact(
        &client,
        ip,
        spec.collector_port,
        inventory_endpoint,
        store
            .host_files_dir(ip)
            .join(http_artifact_filename(inventory_endpoint)),
        spec.retry_policy.backoff,
    )
    .await
    {
        return HostExecutionReport::failure(collecting_plan, err.to_string());
    }

    if let Err(err) = fetch_host_http_artifact(
        &client,
        ip,
        spec.collector_port,
        log_endpoint,
        store
            .host_logs_dir(ip)
            .join(http_artifact_filename(log_endpoint)),
        spec.retry_policy.backoff,
    )
    .await
    {
        return HostExecutionReport::failure(collecting_plan, err.to_string());
    }

    HostExecutionReport::success(collecting_plan, HostState::Complete)
}

async fn cleanup_host_workspace<F>(
    policy: ExecutionPolicy,
    factory: Arc<F>,
    cleanup: &CollectorCleanupJob,
    report: HostExecutionReport,
) -> HostExecutionReport
where
    F: SessionFactory + 'static,
{
    if report.final_state != HostState::Complete {
        return report;
    }

    let CollectorCleanupJob::RemoteExec {
        command,
        capture_path,
    } = cleanup
    else {
        return report;
    };

    let executor = SessionExecutor::new(
        factory,
        policy,
        vec![SessionOperation::capture_exec(
            command.clone(),
            capture_path.clone(),
        )],
    );

    executor
        .run(report.plan.force_state(HostState::Queued))
        .await
}

async fn fetch_host_http_artifact(
    client: &reqwest::Client,
    ip: std::net::IpAddr,
    port: u16,
    endpoint: &str,
    local_path: PathBuf,
    backoff: Duration,
) -> Result<()> {
    let url = collector_url(ip, port, endpoint);
    let deadline = tokio::time::Instant::now() + COLLECTOR_READY_TIMEOUT;
    let retry_delay = std::cmp::max(backoff, Duration::from_millis(250));
    loop {
        let current_error = match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                let body = response.bytes().await.map_err(|err| {
                    Error::CommunicatorError(format!("failed to read {url}: {err}"))
                })?;
                if let Some(parent) = local_path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(&local_path, &body).await?;
                return Ok(());
            }
            Ok(response) => format!("{url} returned {}", response.status()),
            Err(err) => format!("{url} request failed: {err}"),
        };

        if tokio::time::Instant::now() >= deadline {
            return Err(Error::CommunicatorError(format!(
                "artifact collection failed for {ip}: {current_error}"
            )));
        }

        tokio::time::sleep(retry_delay).await;
    }
}

fn collector_url(ip: std::net::IpAddr, port: u16, endpoint: &str) -> String {
    let host = match ip {
        std::net::IpAddr::V4(_) => ip.to_string(),
        std::net::IpAddr::V6(_) => format!("[{ip}]"),
    };
    format!("http://{host}:{port}/{}", endpoint.trim_start_matches('/'))
}

fn http_artifact_filename(endpoint: &str) -> &str {
    endpoint.rsplit('/').next().unwrap_or(endpoint)
}

fn render_mission_manifest(spec: &MissionSpec) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"engine\": \"pandoras_box\",\n",
            "  \"mission_id\": \"{}\",\n",
            "  \"target_count\": {},\n",
            "  \"concurrency_limit\": {},\n",
            "  \"strict_mode\": {},\n",
            "  \"dry_run\": {},\n",
            "  \"allow_smb_fallback\": {},\n",
            "  \"identity_command\": \"{}\",\n",
            "  \"unix_username\": \"{}\",\n",
            "  \"windows_username\": \"{}\",\n",
            "  \"ssh_port\": {},\n",
            "  \"discovery_ports\": [{}],\n",
            "  \"collector_port\": {},\n",
            "  \"chimera_unix_path\": \"{}\",\n",
            "  \"chimera_windows_path\": \"{}\"\n",
            "}}\n"
        ),
        escape_json(&spec.mission_id),
        spec.targets.len(),
        spec.concurrency_limit,
        spec.strict_mode,
        spec.dry_run,
        spec.allow_smb_fallback,
        escape_json(&spec.identity_command),
        escape_json(&spec.unix_username),
        escape_json(&spec.windows_username),
        spec.ssh_port,
        spec.discovery_ports
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        spec.collector_port,
        escape_json(&spec.chimera_unix_path.to_string_lossy()),
        escape_json(&spec.chimera_windows_path.to_string_lossy()),
    )
}

fn render_plan_json(plan: &HostPlan) -> String {
    let open_ports = plan
        .target
        .open_ports
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let transport_chain = plan
        .transport_chain
        .iter()
        .map(|transport| format!("\"{}\"", transport.as_str()))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        concat!(
            "{{\n",
            "  \"ip\": \"{}\",\n",
            "  \"platform\": \"{}\",\n",
            "  \"state\": \"{}\",\n",
            "  \"open_ports\": [{}],\n",
            "  \"transport_chain\": [{}]\n",
            "}}\n"
        ),
        plan.target.ip,
        plan.target.platform.as_str(),
        plan.state.as_str(),
        open_ports,
        transport_chain,
    )
}

fn render_report_json(report: &HostExecutionReport) -> String {
    let error = report
        .error
        .as_ref()
        .map(|error| format!("\"{}\"", escape_json(error)))
        .unwrap_or_else(|| "null".to_string());

    format!(
        concat!(
            "{{\n",
            "  \"ip\": \"{}\",\n",
            "  \"final_state\": \"{}\",\n",
            "  \"error\": {}\n",
            "}}\n"
        ),
        report.plan.target.ip,
        report.final_state.as_str(),
        error,
    )
}

fn render_summary_json(summary: &PandorasBoxRunSummary) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"mission_dir\": \"{}\",\n",
            "  \"discovered_hosts\": {},\n",
            "  \"completed_hosts\": {},\n",
            "  \"failed_hosts\": {}\n",
            "}}\n"
        ),
        escape_json(&summary.mission_dir.to_string_lossy()),
        summary.discovered_hosts,
        summary.completed_hosts,
        summary.failed_hosts,
    )
}

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::{
        collector_url, plan_collector_job, render_mission_manifest, render_summary_json,
        resolved_discovery_ports, CollectorCleanupJob, CollectorCollectJob, CollectorJobPlan,
        CollectorRunJob, CollectorStageJob, IdentityCaptureJob, LocalSupportFilePlan,
        PandorasBoxRunSummary, PandorasBoxRunner, StagedSupportFile,
    };
    use crate::runtime::discovery::DiscoveryRecord;
    use crate::runtime::mission::{
        HostPlan, HostState, HostTarget, MissionSpec, PlatformHint, TransportKind,
    };
    use crate::runtime::scheduler::{HostExecutionReport, HostExecutor};
    use crate::runtime::session_factory::{BoxedHostSession, SessionFactory};
    use crate::runtime::transport::{ExecRequest, ExecResponse, FileTransfer, HostSession};
    use crate::runtime::workspace::{collector_plan, remote_workspace, CollectorPlan};
    use crate::{Error, Result};
    use async_trait::async_trait;
    use futures::stream::{self, StreamExt};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct ExecutorBehavior {
        delay: Duration,
        final_state: HostState,
        error: Option<String>,
    }

    #[derive(Clone)]
    struct RecordingExecutor {
        behaviors: Arc<HashMap<IpAddr, ExecutorBehavior>>,
        completions: Arc<Mutex<Vec<IpAddr>>>,
    }

    impl RecordingExecutor {
        fn new(entries: Vec<(IpAddr, ExecutorBehavior)>) -> Self {
            Self {
                behaviors: Arc::new(entries.into_iter().collect()),
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
                .get(&plan.target.ip)
                .cloned()
                .expect("behavior should exist for host");
            tokio::time::sleep(behavior.delay).await;
            self.completions
                .lock()
                .expect("completions lock should be available")
                .push(plan.target.ip);

            match behavior.final_state {
                HostState::Complete => HostExecutionReport::success(plan, HostState::Complete),
                HostState::Failed => HostExecutionReport::failure(
                    plan,
                    behavior
                        .error
                        .unwrap_or_else(|| "synthetic failure".to_string()),
                ),
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

    fn spawn_http_artifact_server(
        responses: Vec<(&'static str, &'static [u8])>,
    ) -> (u16, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("test HTTP listener should bind to localhost");
        let port = listener
            .local_addr()
            .expect("test HTTP listener should expose a local address")
            .port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests = Arc::clone(&requests);
        let response_map = Arc::new(
            responses
                .into_iter()
                .map(|(path, body)| (path.to_string(), body.to_vec()))
                .collect::<HashMap<_, _>>(),
        );

        let handle = std::thread::spawn(move || {
            for _ in 0..response_map.len() {
                let (mut stream, _) = listener
                    .accept()
                    .expect("test HTTP listener should accept a connection");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("test HTTP stream should accept a read timeout");

                let mut buffer = [0u8; 4096];
                let size = stream
                    .read(&mut buffer)
                    .expect("test HTTP request should be readable");
                let request = String::from_utf8_lossy(&buffer[..size]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                captured_requests
                    .lock()
                    .expect("request log should be available")
                    .push(path.clone());

                let (status_line, body) = match response_map.get(&path) {
                    Some(body) => ("HTTP/1.1 200 OK", body.clone()),
                    None => ("HTTP/1.1 404 Not Found", Vec::new()),
                };
                let headers = format!(
                    "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(headers.as_bytes())
                    .expect("test HTTP response headers should be written");
                stream
                    .write_all(&body)
                    .expect("test HTTP response body should be written");
            }
        });

        (port, requests, handle)
    }

    #[derive(Clone)]
    struct SessionTemplate {
        events: Arc<Mutex<Vec<String>>>,
        exec_outputs: Arc<HashMap<String, ExecResponse>>,
        downloads: Arc<HashMap<String, Vec<u8>>>,
        uploads: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl SessionTemplate {
        fn into_session(self) -> FakeSession {
            FakeSession {
                events: self.events,
                exec_outputs: self.exec_outputs,
                downloads: self.downloads,
                uploads: self.uploads,
            }
        }
    }

    struct FakeSession {
        events: Arc<Mutex<Vec<String>>>,
        exec_outputs: Arc<HashMap<String, ExecResponse>>,
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

    struct FakeSessionFactory {
        templates: Arc<Mutex<HashMap<(IpAddr, TransportKind), SessionTemplate>>>,
    }

    impl FakeSessionFactory {
        fn new(entries: Vec<((IpAddr, TransportKind), SessionTemplate)>) -> Self {
            Self {
                templates: Arc::new(Mutex::new(entries.into_iter().collect())),
            }
        }
    }

    #[async_trait]
    impl SessionFactory for FakeSessionFactory {
        async fn connect(
            &self,
            plan: &HostPlan,
            transport: TransportKind,
        ) -> Result<BoxedHostSession> {
            let template = self
                .templates
                .lock()
                .expect("templates lock should be available")
                .get(&(plan.target.ip, transport))
                .cloned()
                .ok_or_else(|| Error::CommunicatorError("missing fake session".to_string()))?;

            Ok(Box::new(template.into_session()))
        }
    }

    #[test]
    fn mission_manifest_omits_password_and_includes_engine() {
        let spec = MissionSpec {
            password: "super-secret".to_string(),
            discovery_ports: vec![2222],
            ..MissionSpec::default()
        };
        let manifest = render_mission_manifest(&spec);

        assert!(manifest.contains("\"engine\": \"pandoras_box\""));
        assert!(manifest.contains("\"ssh_port\": 22"));
        assert!(manifest.contains("\"discovery_ports\": [2222]"));
        assert!(manifest.contains("\"collector_port\": 44372"));
        assert!(!manifest.contains("super-secret"));
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
            mission_dir: PathBuf::from("artifacts/mission-123"),
            discovered_hosts: 5,
            completed_hosts: 4,
            failed_hosts: 1,
        };
        let json = render_summary_json(&summary);

        assert!(json.contains("\"discovered_hosts\": 5"));
        assert!(json.contains("\"failed_hosts\": 1"));
    }

    #[tokio::test]
    async fn finalize_summary_writes_asset_inventory_bundle_for_completed_hosts() {
        let root = temp_root("asset-inventory-complete");
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123");
        let runner = PandorasBoxRunner::new(spec(root.clone()));
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
                &store,
                1,
                vec![HostExecutionReport::success(plan, HostState::Complete)],
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
                    "| 10.0.0.41 | complete | unix | lab | Ubuntu 24.04 | 22 | root | sshd | - |"
                )
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/asset_inventory.csv"))
                .await
                .expect("asset inventory csv should exist")
                .contains("10.0.0.41,complete,unix,lab,Ubuntu 24.04,22,root,sshd,-,")
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
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123");
        let runner = PandorasBoxRunner::new(spec(root.clone()));
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
                &store,
                1,
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
                .contains("| 10.0.0.42 | failed | windows | - | - | 2222,445 | - | - | - | ssh connect failed: timeout waiting for banner |")
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn finalize_summary_writes_network_topology_for_connected_hosts() {
        let root = temp_root("network-topology");
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123");
        let runner = PandorasBoxRunner::new(spec(root.clone()));
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
                &store,
                2,
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
                .contains("host_10_0_0_51 -. observed .-> host_10_0_0_52")
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/network_topology.md"))
                .await
                .expect("network topology markdown should exist")
                .contains("web-01 -> db-01")
        );
        assert!(
            tokio::fs::read_to_string(root.join("mission-123/network_topology.excalidraw"))
                .await
                .expect("network topology excalidraw should exist")
                .contains("edge_10_0_0_51_to_10_0_0_52")
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn collector_url_formats_ipv4_targets() {
        let url = collector_url(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            44372,
            "/inventory.json",
        );

        assert_eq!(url, "http://10.0.0.9:44372/inventory.json");
    }

    #[test]
    fn collector_url_brackets_ipv6_targets() {
        let url = collector_url(IpAddr::V6(Ipv6Addr::LOCALHOST), 44372, "application.log");

        assert_eq!(url, "http://[::1]:44372/application.log");
    }

    #[test]
    fn collector_job_for_unix_host_has_explicit_stage_run_and_collect_steps() {
        let root = PathBuf::from("/tmp/pandoras-box-runner");
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123");
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
                    serve_command: workspace.serve_command(),
                    serve_capture_path: store.host_exec_dir(ip).join("collector_serve.txt"),
                },
                collect: CollectorCollectJob::Http {
                    inventory_endpoint: "inventory.json".to_string(),
                    log_endpoint: "application.log".to_string(),
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
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123");
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
                    serve_command: workspace.serve_command(),
                    serve_capture_path: store.host_exec_dir(ip).join("collector_serve.txt"),
                },
                collect: CollectorCollectJob::Http {
                    inventory_endpoint: "inventory.json".to_string(),
                    log_endpoint: "application.log".to_string(),
                },
                cleanup: CollectorCleanupJob::RemoteExec {
                    command: workspace.cleanup_command(),
                    capture_path: store.host_exec_dir(ip).join("collector_cleanup.txt"),
                },
            }
        );
    }

    #[test]
    fn collector_job_for_unix_dry_run_skips_stage_and_http_collection() {
        let root = PathBuf::from("/tmp/pandoras-box-runner");
        let store = crate::runtime::artifact_store::ArtifactStore::new(&root, "mission-123");
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
                    serve_command: String::new(),
                    serve_capture_path: store.host_exec_dir(ip).join("serve_skip.txt"),
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
    async fn runner_starts_fast_host_before_slow_discovery_finishes() {
        let root = temp_root("streaming-fast-first");
        let runner = PandorasBoxRunner::new(spec(root.clone()));
        let fast = record(11);
        let slow = record(12);
        let executor = Arc::new(RecordingExecutor::new(vec![
            (
                fast.host.ip,
                ExecutorBehavior {
                    delay: Duration::from_millis(150),
                    final_state: HostState::Complete,
                    error: None,
                },
            ),
            (
                slow.host.ip,
                ExecutorBehavior {
                    delay: Duration::from_millis(10),
                    final_state: HostState::Complete,
                    error: None,
                },
            ),
        ]));
        let records = stream::iter(vec![
            (Duration::from_millis(20), fast.clone()),
            (Duration::from_millis(250), slow.clone()),
        ])
        .then(|(delay, record)| async move {
            tokio::time::sleep(delay).await;
            record
        });

        let start = Instant::now();
        let summary = runner
            .run_with_stream_and_executor(records, executor.clone())
            .await
            .expect("streaming runner should succeed");

        assert!(
            start.elapsed() < Duration::from_millis(340),
            "expected execution to overlap with discovery, took {:?}",
            start.elapsed()
        );
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
                ExecutorBehavior {
                    delay: Duration::from_millis(20),
                    final_state: HostState::Complete,
                    error: None,
                },
            ),
            (
                failed.host.ip,
                ExecutorBehavior {
                    delay: Duration::from_millis(10),
                    final_state: HostState::Failed,
                    error: Some("auth failed".to_string()),
                },
            ),
            (
                late.host.ip,
                ExecutorBehavior {
                    delay: Duration::from_millis(20),
                    final_state: HostState::Complete,
                    error: None,
                },
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
    async fn runner_session_factory_path_stages_chimera_and_persists_http_artifacts() {
        let root = temp_root("runner-session-factory");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let (collector_port, requests, server) = spawn_http_artifact_server(vec![
            ("/inventory.json", b"{\"hostname\":\"lab\"}\n"),
            ("/application.log", b"collector log\n"),
        ]);
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            collector_port,
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
        let serve_command = workspace.serve_command();
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
                    serve_command.clone(),
                    ExecResponse {
                        stdout: b"serve started\n".to_vec(),
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
            downloads: Arc::new(HashMap::new()),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        };
        let events = Arc::clone(&session_template.events);
        let uploads = Arc::clone(&session_template.uploads);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (record.host.ip, TransportKind::UnixSsh),
            session_template,
        )]));

        let summary = runner
            .run_with_stream_and_factory(stream::iter(vec![record.clone()]), factory)
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
            requests
                .lock()
                .expect("requests lock should be available")
                .as_slice(),
            ["/inventory.json", "/application.log"]
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
                &format!("exec:{serve_command}"),
                "disconnect",
                &format!("exec:{cleanup_command}"),
                "disconnect"
            ]
        );
        server
            .join()
            .expect("test HTTP artifact server should exit cleanly");

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
    async fn runner_marks_host_failed_when_http_collection_is_unavailable() {
        let root = temp_root("runner-collection-failure");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let collector_port = 45_999;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            collector_port,
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
        let serve_command = workspace.serve_command();
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
                    serve_command.clone(),
                    ExecResponse {
                        stdout: b"serve started\n".to_vec(),
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
        assert!(tokio::fs::read_to_string(
            root.join("mission-123/hosts/127.0.0.1/exec/collector_serve.txt")
        )
        .await
        .expect("collector serve capture should exist")
        .contains("serve started"));
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
                &format!("exec:{serve_command}"),
                "disconnect"
            ]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn runner_does_not_start_serve_when_collector_command_fails() {
        let root = temp_root("runner-collector-failure");
        let chimera_path = root.join("fixtures/chimera");
        write_fixture(&chimera_path, b"fake chimera binary").await;
        let collector_port = 45_997;
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            collector_port,
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
        let serve_command = workspace.serve_command();
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
                (
                    serve_command.clone(),
                    ExecResponse {
                        stdout: b"serve started\n".to_vec(),
                        stderr: Vec::new(),
                        status_code: Some(0),
                    },
                ),
            ])),
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
        let (collector_port, _requests, server) = spawn_http_artifact_server(vec![
            ("/inventory.json", b"{\"hostname\":\"lab\"}\n"),
            ("/application.log", b"collector log\n"),
        ]);
        let spec = MissionSpec {
            artifact_root: root.clone(),
            mission_id: "mission-123".to_string(),
            chimera_unix_path: chimera_path.clone(),
            collector_port,
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
        let serve_command = workspace.serve_command();
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
                    serve_command.clone(),
                    ExecResponse {
                        stdout: b"serve started\n".to_vec(),
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
                &format!("exec:{serve_command}"),
                "disconnect",
                &format!("exec:{cleanup_command}"),
                "disconnect"
            ]
        );
        server
            .join()
            .expect("test HTTP artifact server should exit cleanly");

        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
