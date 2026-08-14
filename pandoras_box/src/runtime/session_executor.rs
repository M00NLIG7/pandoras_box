use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;

use super::mission::{HostPlan, HostState};
use super::policy::{ExecutionPolicy, OperationMutability};
use super::scheduler::{FailureDisposition, FailurePhase, HostExecutionReport, HostExecutor};
use super::session_factory::{BoxedHostSession, SessionFactory};
use super::transport::{ExecRequest, ExecResponse, FileTransfer, HostSession};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationIdempotency {
    Idempotent,
    NonIdempotent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOperation {
    Exec {
        request: ExecRequest,
        mutability: OperationMutability,
        idempotency: OperationIdempotency,
    },
    CaptureExec {
        request: ExecRequest,
        local_path: PathBuf,
        mutability: OperationMutability,
        idempotency: OperationIdempotency,
    },
    CleanupCaptureExec {
        request: ExecRequest,
        local_path: PathBuf,
    },
    PutFile {
        transfer: FileTransfer,
    },
    GetFile {
        transfer: FileTransfer,
    },
    EnsureDir {
        remote_dir: String,
    },
    CleanupExec {
        request: ExecRequest,
    },
}

impl SessionOperation {
    #[must_use]
    pub fn ensure_dir(remote_dir: impl Into<String>) -> Self {
        Self::EnsureDir {
            remote_dir: remote_dir.into(),
        }
    }

    #[must_use]
    pub fn exec(command: impl Into<String>) -> Self {
        Self::exec_with_semantics(
            command,
            OperationMutability::Mutating,
            OperationIdempotency::NonIdempotent,
        )
    }

    #[must_use]
    pub fn read_only_exec(command: impl Into<String>) -> Self {
        Self::exec_with_semantics(
            command,
            OperationMutability::ReadOnly,
            OperationIdempotency::Idempotent,
        )
    }

    #[must_use]
    pub fn idempotent_exec(command: impl Into<String>) -> Self {
        Self::exec_with_semantics(
            command,
            OperationMutability::Mutating,
            OperationIdempotency::Idempotent,
        )
    }

    fn exec_with_semantics(
        command: impl Into<String>,
        mutability: OperationMutability,
        idempotency: OperationIdempotency,
    ) -> Self {
        Self::Exec {
            request: ExecRequest::new(command),
            mutability,
            idempotency,
        }
    }

    #[must_use]
    pub fn capture_exec(command: impl Into<String>, local_path: impl Into<PathBuf>) -> Self {
        Self::capture_exec_with_semantics(
            command,
            local_path,
            OperationMutability::Mutating,
            OperationIdempotency::NonIdempotent,
        )
    }

    #[must_use]
    pub fn capture_read_only_exec(
        command: impl Into<String>,
        local_path: impl Into<PathBuf>,
    ) -> Self {
        Self::capture_exec_with_semantics(
            command,
            local_path,
            OperationMutability::ReadOnly,
            OperationIdempotency::Idempotent,
        )
    }

    #[must_use]
    pub fn capture_idempotent_exec(
        command: impl Into<String>,
        local_path: impl Into<PathBuf>,
    ) -> Self {
        Self::capture_exec_with_semantics(
            command,
            local_path,
            OperationMutability::Mutating,
            OperationIdempotency::Idempotent,
        )
    }

    fn capture_exec_with_semantics(
        command: impl Into<String>,
        local_path: impl Into<PathBuf>,
        mutability: OperationMutability,
        idempotency: OperationIdempotency,
    ) -> Self {
        Self::CaptureExec {
            request: ExecRequest::new(command),
            local_path: local_path.into(),
            mutability,
            idempotency,
        }
    }

    #[must_use]
    pub fn cleanup_capture_exec(
        command: impl Into<String>,
        local_path: impl Into<PathBuf>,
    ) -> Self {
        Self::CleanupCaptureExec {
            request: ExecRequest::new(command),
            local_path: local_path.into(),
        }
    }

    #[must_use]
    pub fn get_file(remote_path: impl Into<String>, local_path: impl Into<PathBuf>) -> Self {
        Self::GetFile {
            transfer: FileTransfer {
                remote_path: remote_path.into(),
                local_path: local_path.into(),
            },
        }
    }

    #[must_use]
    pub fn put_file(local_path: impl Into<PathBuf>, remote_path: impl Into<String>) -> Self {
        Self::PutFile {
            transfer: FileTransfer {
                local_path: local_path.into(),
                remote_path: remote_path.into(),
            },
        }
    }

    #[must_use]
    pub fn cleanup_exec(command: impl Into<String>) -> Self {
        Self::CleanupExec {
            request: ExecRequest::new(command),
        }
    }

    #[must_use]
    pub fn mutability(&self) -> OperationMutability {
        match self {
            Self::Exec { mutability, .. } | Self::CaptureExec { mutability, .. } => *mutability,
            Self::GetFile { .. } => OperationMutability::ReadOnly,
            Self::PutFile { .. }
            | Self::EnsureDir { .. }
            | Self::CleanupExec { .. }
            | Self::CleanupCaptureExec { .. } => OperationMutability::Mutating,
        }
    }

    #[must_use]
    pub fn idempotency(&self) -> OperationIdempotency {
        match self {
            Self::Exec { idempotency, .. } | Self::CaptureExec { idempotency, .. } => *idempotency,
            Self::PutFile { .. }
            | Self::GetFile { .. }
            | Self::EnsureDir { .. }
            | Self::CleanupExec { .. }
            | Self::CleanupCaptureExec { .. } => OperationIdempotency::Idempotent,
        }
    }
}

pub struct SessionExecutor<F> {
    factory: Arc<F>,
    policy: ExecutionPolicy,
    operations: Vec<SessionOperation>,
}

impl<F> SessionExecutor<F> {
    #[must_use]
    pub fn new(
        factory: Arc<F>,
        policy: ExecutionPolicy,
        operations: Vec<SessionOperation>,
    ) -> Self {
        Self {
            factory,
            policy,
            operations,
        }
    }

    pub(crate) async fn connect_session(
        &self,
        plan: &HostPlan,
    ) -> Result<BoxedHostSession, HostExecutionReport>
    where
        F: SessionFactory + 'static,
    {
        let mut errors = Vec::new();

        for transport in plan.transport_chain.clone() {
            if let Err(err) = self.policy.allow_transport(transport) {
                errors.push(err.to_string());
                continue;
            }

            match self.factory.connect(plan, transport).await {
                Ok(session) => return Ok(session),
                Err(err) => errors.push(format!("{transport:?}: {err}")),
            }
        }

        let error = if errors.is_empty() {
            "no usable transport".to_string()
        } else {
            errors.join("; ")
        };

        Err(classify_connect_failure(
            plan.force_state(HostState::Failed),
            error,
        ))
    }

    pub(crate) async fn run_connected_session(
        &self,
        plan: HostPlan,
        session: &mut dyn HostSession,
        disconnect_on_success: bool,
    ) -> HostExecutionReport {
        let mut plan = plan.force_state(HostState::Connected);

        for operation in &self.operations {
            if self.policy.allow_operation(operation.mutability()).is_err() {
                continue;
            }

            let phase = operation.phase();
            plan = match plan.transition(HostState::Executing) {
                Ok(plan) => plan,
                Err(err) => return transition_failure(plan, phase, err),
            };

            match operation {
                SessionOperation::Exec { request, .. } => match session.exec(request.clone()).await
                {
                    Ok(response) => {
                        if let Err(err) = validate_exec_response(request, &response) {
                            let _ = session.cleanup().await;
                            return terminal_phase_failure(plan, phase, "exec failed", err);
                        }
                    }
                    Err(err) => {
                        let _ = session.cleanup().await;
                        return operation_transport_failure(plan, phase, "exec failed", err);
                    }
                },
                SessionOperation::CaptureExec {
                    request,
                    local_path,
                    ..
                }
                | SessionOperation::CleanupCaptureExec {
                    request,
                    local_path,
                } => match session.exec(request.clone()).await {
                    Ok(response) => {
                        if let Err(err) = write_exec_capture(local_path, request, &response).await {
                            let _ = session.cleanup().await;
                            return terminal_phase_failure(
                                plan,
                                phase,
                                capture_context(phase),
                                err,
                            );
                        }
                        if let Err(err) = validate_exec_response(request, &response) {
                            let _ = session.cleanup().await;
                            return terminal_phase_failure(
                                plan,
                                phase,
                                capture_context(phase),
                                err,
                            );
                        }
                    }
                    Err(err) => {
                        let _ = session.cleanup().await;
                        return operation_transport_failure(
                            plan,
                            phase,
                            capture_context(phase),
                            err,
                        );
                    }
                },
                SessionOperation::PutFile { transfer } => {
                    if let Err(err) = validate_remote_path(&transfer.remote_path) {
                        let _ = session.cleanup().await;
                        return terminal_phase_failure(plan, phase, "put failed", err);
                    }

                    if let Err(err) = session.put(transfer).await {
                        let _ = session.cleanup().await;
                        return operation_transport_failure(plan, phase, "put failed", err);
                    }
                }
                SessionOperation::GetFile { transfer } => {
                    if let Err(err) = validate_remote_path(&transfer.remote_path) {
                        let _ = session.cleanup().await;
                        return terminal_phase_failure(plan, phase, "get failed", err);
                    }

                    if let Err(err) = session.get(transfer).await {
                        let _ = session.cleanup().await;
                        return operation_transport_failure(plan, phase, "get failed", err);
                    }
                }
                SessionOperation::EnsureDir { remote_dir } => {
                    if let Err(err) = validate_remote_path(remote_dir) {
                        let _ = session.cleanup().await;
                        return terminal_phase_failure(plan, phase, "ensure_dir failed", err);
                    }

                    if let Err(err) = session.ensure_dir(remote_dir).await {
                        let _ = session.cleanup().await;
                        return operation_transport_failure(plan, phase, "ensure_dir failed", err);
                    }
                }
                SessionOperation::CleanupExec { request } => {
                    match session.exec(request.clone()).await {
                        Ok(response) => {
                            if let Err(err) = validate_exec_response(request, &response) {
                                let _ = session.cleanup().await;
                                return terminal_phase_failure(
                                    plan,
                                    phase,
                                    "cleanup_exec failed",
                                    err,
                                );
                            }
                        }
                        Err(err) => {
                            let _ = session.cleanup().await;
                            return operation_transport_failure(
                                plan,
                                phase,
                                "cleanup_exec failed",
                                err,
                            );
                        }
                    }
                }
            }
        }

        let complete_plan = match plan.transition(HostState::Complete) {
            Ok(plan) => plan,
            Err(err) => return transition_failure(plan, FailurePhase::Cleanup, err),
        };

        if disconnect_on_success {
            if let Err(err) = session.cleanup().await {
                return terminal_phase_failure(
                    complete_plan,
                    FailurePhase::Cleanup,
                    "cleanup failed",
                    err,
                );
            }
        }

        HostExecutionReport::success(complete_plan, HostState::Complete)
    }
}

async fn write_exec_capture(
    local_path: &Path,
    request: &ExecRequest,
    response: &ExecResponse,
) -> Result<(), std::io::Error> {
    if let Some(parent) = local_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let contents = format!(
        "command: {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}\n",
        request.command,
        response
            .status_code
            .map(|status| status.to_string())
            .unwrap_or_else(|| "null".to_string()),
        String::from_utf8_lossy(&response.stdout),
        String::from_utf8_lossy(&response.stderr),
    );

    tokio::fs::write(local_path, contents).await
}

fn validate_exec_response(request: &ExecRequest, response: &ExecResponse) -> Result<(), String> {
    match response.status_code {
        Some(0) => Ok(()),
        Some(status) => Err(format!(
            "command `{}` returned exit status {status}",
            request.command
        )),
        None => Err(format!(
            "command `{}` returned missing exit status",
            request.command
        )),
    }
}

fn validate_remote_path(remote_path: &str) -> Result<(), String> {
    if is_absolute_remote_path(remote_path) {
        return Ok(());
    }

    Err(format!("remote path must be absolute: {remote_path}"))
}

fn is_absolute_remote_path(remote_path: &str) -> bool {
    remote_path.starts_with('/')
        || remote_path.starts_with(r"\\")
        || remote_path.as_bytes().get(0..3).is_some_and(|prefix| {
            prefix[0].is_ascii_alphabetic()
                && prefix[1] == b':'
                && matches!(prefix[2], b'\\' | b'/')
        })
}

impl SessionOperation {
    fn phase(&self) -> FailurePhase {
        match self {
            Self::PutFile { .. } | Self::EnsureDir { .. } => FailurePhase::Stage,
            Self::GetFile { .. } => FailurePhase::Collect,
            Self::CleanupExec { .. } | Self::CleanupCaptureExec { .. } => FailurePhase::Cleanup,
            Self::Exec { .. } | Self::CaptureExec { .. } => FailurePhase::Execute,
        }
    }
}

fn capture_context(phase: FailurePhase) -> &'static str {
    match phase {
        FailurePhase::Cleanup => "cleanup_exec failed",
        _ => "capture_exec failed",
    }
}

fn transition_failure(
    plan: HostPlan,
    phase: FailurePhase,
    err: impl std::fmt::Display,
) -> HostExecutionReport {
    HostExecutionReport::terminal_failure(plan, phase, err.to_string())
}

fn terminal_phase_failure(
    plan: HostPlan,
    phase: FailurePhase,
    context: &str,
    err: impl std::fmt::Display,
) -> HostExecutionReport {
    HostExecutionReport::terminal_failure(plan, phase, format!("{context}: {err}"))
}

fn operation_transport_failure(
    plan: HostPlan,
    phase: FailurePhase,
    context: &str,
    err: impl std::fmt::Display,
) -> HostExecutionReport {
    let rendered = format!("{context}: {err}");
    let disposition = phase_failure_disposition(phase, &rendered);
    HostExecutionReport::failure_with_disposition(plan, phase, disposition, rendered)
}

fn phase_failure_disposition(phase: FailurePhase, error: &str) -> FailureDisposition {
    if phase == FailurePhase::Execute || is_terminal_error(error) {
        FailureDisposition::Terminal
    } else {
        FailureDisposition::Retryable
    }
}

fn classify_connect_failure(plan: HostPlan, error: impl std::fmt::Display) -> HostExecutionReport {
    let rendered = error.to_string();
    let disposition = if is_terminal_error(&rendered) {
        FailureDisposition::Terminal
    } else {
        FailureDisposition::Retryable
    };
    HostExecutionReport::failure_with_disposition(
        plan,
        FailurePhase::Connect,
        disposition,
        rendered,
    )
}

fn is_terminal_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    [
        "auth failed",
        "authentication failed",
        "permission denied",
        "access denied",
        "access is denied",
        "host key verification failed",
        "host key for",
        "no ssh port",
        "smb fallback is disabled",
        "not valid for unix targets",
        "remote path must be absolute",
        "no usable transport",
        "missing exit status",
        "exit status",
        "invalid ip",
        "invalid subnet",
        "unknown os",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[async_trait]
impl<F> HostExecutor for SessionExecutor<F>
where
    F: SessionFactory + 'static,
{
    async fn run(&self, plan: HostPlan) -> HostExecutionReport {
        let plan = match plan.transition(HostState::Connecting) {
            Ok(plan) => plan,
            Err(err) => return transition_failure(plan, FailurePhase::Connect, err),
        };
        let mut session = match self.connect_session(&plan).await {
            Ok(session) => session,
            Err(report) => return report,
        };

        self.run_connected_session(plan, &mut *session, true).await
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionExecutor, SessionOperation};
    use crate::runtime::mission::{HostPlan, HostState, HostTarget, PlatformHint, TransportKind};
    use crate::runtime::policy::ExecutionPolicy;
    use crate::runtime::scheduler::{FailureDisposition, FailurePhase, HostExecutor, Scheduler};
    use crate::runtime::session_factory::{BoxedHostSession, SessionFactory};
    use crate::runtime::transport::{ExecRequest, ExecResponse, FileTransfer, HostSession};
    use crate::Error;
    use crate::Result;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ConnectBehavior {
        AuthFail,
        TransientFail,
        Success,
    }

    #[derive(Debug, Clone)]
    struct SessionTemplate {
        ensure_dir_delay: Duration,
        cleanup_error: bool,
        ensure_dir_calls: Arc<AtomicUsize>,
        events: Arc<Mutex<Vec<String>>>,
        exec_outputs: Arc<HashMap<String, ExecResponse>>,
        downloads: Arc<HashMap<String, Vec<u8>>>,
        uploads: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl SessionTemplate {
        fn into_session(self) -> FakeSession {
            FakeSession {
                ensure_dir_delay: self.ensure_dir_delay,
                cleanup_error: self.cleanup_error,
                ensure_dir_calls: self.ensure_dir_calls,
                events: self.events,
                exec_outputs: self.exec_outputs,
                downloads: self.downloads,
                uploads: self.uploads,
            }
        }
    }

    struct FakeSession {
        ensure_dir_delay: Duration,
        cleanup_error: bool,
        ensure_dir_calls: Arc<AtomicUsize>,
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

        async fn ensure_dir(&mut self, remote_dir: &str) -> Result<()> {
            self.ensure_dir_calls.fetch_add(1, Ordering::SeqCst);
            self.events
                .lock()
                .expect("events lock should be available")
                .push(format!("ensure_dir:{remote_dir}"));
            if !self.ensure_dir_delay.is_zero() {
                tokio::time::sleep(self.ensure_dir_delay).await;
            }
            Ok(())
        }

        async fn cleanup(&mut self) -> Result<()> {
            self.events
                .lock()
                .expect("events lock should be available")
                .push("disconnect".to_string());
            if self.cleanup_error {
                Err(Error::CommunicatorError("cleanup failure".to_string()))
            } else {
                Ok(())
            }
        }
    }

    struct FakeSessionFactory {
        behaviors: HashMap<(IpAddr, TransportKind), ConnectBehavior>,
        templates: Arc<Mutex<HashMap<(IpAddr, TransportKind), SessionTemplate>>>,
    }

    impl FakeSessionFactory {
        fn new(entries: Vec<((IpAddr, TransportKind), ConnectBehavior, SessionTemplate)>) -> Self {
            let mut behaviors = HashMap::new();
            let mut templates = HashMap::new();

            for (key, behavior, template) in entries {
                behaviors.insert(key, behavior);
                templates.insert(key, template);
            }

            Self {
                behaviors,
                templates: Arc::new(Mutex::new(templates)),
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
            let key = (plan.target.ip, transport);
            match self
                .behaviors
                .get(&key)
                .copied()
                .unwrap_or(ConnectBehavior::AuthFail)
            {
                ConnectBehavior::AuthFail => {
                    Err(Error::CommunicatorError("auth failed".to_string()))
                }
                ConnectBehavior::TransientFail => Err(Error::CommunicatorError(
                    "connection reset by peer".to_string(),
                )),
                ConnectBehavior::Success => {
                    let template = self
                        .templates
                        .lock()
                        .expect("templates lock should be available")
                        .get(&key)
                        .cloned()
                        .expect("template should exist");
                    Ok(Box::new(template.into_session()))
                }
            }
        }
    }

    fn host_plan(ip: IpAddr, chain: Vec<TransportKind>) -> HostPlan {
        HostPlan {
            target: HostTarget {
                ip,
                platform: PlatformHint::Unknown,
                open_ports: vec![22, 445],
            },
            state: HostState::Queued,
            transport_chain: chain,
        }
    }

    fn template(delay_ms: u64, cleanup_error: bool) -> SessionTemplate {
        SessionTemplate {
            ensure_dir_delay: Duration::from_millis(delay_ms),
            cleanup_error,
            ensure_dir_calls: Arc::new(AtomicUsize::new(0)),
            events: Arc::new(Mutex::new(Vec::new())),
            exec_outputs: Arc::new(HashMap::new()),
            downloads: Arc::new(HashMap::new()),
            uploads: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("pandoras-box-{label}-{unique}"))
    }

    #[tokio::test]
    async fn session_executor_skips_mutations_in_dry_run() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8));
        let session_template = template(0, false);
        let calls = Arc::clone(&session_template.ensure_dir_calls);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            session_template,
        )]));
        let executor = SessionExecutor::new(
            factory,
            ExecutionPolicy {
                dry_run: true,
                allow_smb_fallback: true,
            },
            vec![SessionOperation::ensure_dir("/tmp/pandoras-box")],
        );

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Complete);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn dry_run_enforces_mutability_for_every_operation_variant() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        let root = temp_dir("dry-run-operation-boundary");
        let upload_source = root.join("local/chimera");
        let read_capture = root.join("exec/read.txt");
        let mutating_capture = root.join("exec/mutating.txt");
        let idempotent_capture = root.join("exec/idempotent-mutating.txt");
        let cleanup_capture = root.join("exec/cleanup.txt");
        let download_path = root.join("files/inventory.json");
        tokio::fs::create_dir_all(
            upload_source
                .parent()
                .expect("upload source should have a parent"),
        )
        .await
        .expect("fixture directory should exist");
        tokio::fs::write(&upload_source, b"payload")
            .await
            .expect("upload fixture should exist");

        let mut session_template = template(0, false);
        let events = Arc::clone(&session_template.events);
        let uploads = Arc::clone(&session_template.uploads);
        let ensure_dir_calls = Arc::clone(&session_template.ensure_dir_calls);
        session_template.downloads = Arc::new(HashMap::from([(
            "/remote/inventory.json".to_string(),
            b"{\"host\":\"lab\"}\n".to_vec(),
        )]));
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            session_template,
        )]));
        let executor = SessionExecutor::new(
            factory,
            ExecutionPolicy {
                dry_run: true,
                allow_smb_fallback: true,
            },
            vec![
                SessionOperation::capture_read_only_exec("whoami", &read_capture),
                SessionOperation::read_only_exec("hostname"),
                SessionOperation::exec("non-idempotent mutation"),
                SessionOperation::idempotent_exec("idempotent mutation"),
                SessionOperation::capture_exec("captured mutation", &mutating_capture),
                SessionOperation::capture_idempotent_exec(
                    "captured idempotent mutation",
                    &idempotent_capture,
                ),
                SessionOperation::put_file(&upload_source, "/remote/chimera"),
                SessionOperation::get_file("/remote/inventory.json", &download_path),
                SessionOperation::ensure_dir("/remote/workspace"),
                SessionOperation::cleanup_capture_exec("cleanup mutation", &cleanup_capture),
                SessionOperation::cleanup_exec("cleanup mutation without capture"),
            ],
        );

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Complete);
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:whoami",
                "exec:hostname",
                "get:/remote/inventory.json",
                "disconnect"
            ]
        );
        assert!(read_capture.is_file());
        assert_eq!(
            tokio::fs::read(&download_path)
                .await
                .expect("read-only download should be collected"),
            b"{\"host\":\"lab\"}\n"
        );
        assert!(!mutating_capture.exists());
        assert!(!idempotent_capture.exists());
        assert!(!cleanup_capture.exists());
        assert!(uploads
            .lock()
            .expect("uploads lock should be available")
            .is_empty());
        assert_eq!(ensure_dir_calls.load(Ordering::SeqCst), 0);

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn session_executor_captures_exec_and_collects_file_before_cleanup() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 14));
        let root = temp_dir("session-artifacts");
        let capture_path = root.join("exec").join("inventory_hostname.txt");
        let collect_path = root.join("files").join("inventory.json");
        let mut session_template = template(0, false);
        let events = Arc::clone(&session_template.events);
        session_template.exec_outputs = Arc::new(HashMap::from([(
            "hostname".to_string(),
            ExecResponse {
                stdout: b"host-14\n".to_vec(),
                stderr: Vec::new(),
                status_code: Some(0),
            },
        )]));
        session_template.downloads = Arc::new(HashMap::from([(
            "/tmp/inventory.json".to_string(),
            br#"{"host":"10.0.0.14"}"#.to_vec(),
        )]));
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            session_template,
        )]));
        let executor = SessionExecutor::new(
            factory,
            ExecutionPolicy::default(),
            vec![
                SessionOperation::capture_exec("hostname", &capture_path),
                SessionOperation::get_file("/tmp/inventory.json", &collect_path),
                SessionOperation::cleanup_exec("rm -f /tmp/inventory.json"),
            ],
        );

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Complete);
        assert!(tokio::fs::read_to_string(&capture_path)
            .await
            .expect("capture file should exist")
            .contains("host-14"));
        assert_eq!(
            tokio::fs::read_to_string(&collect_path)
                .await
                .expect("collect file should exist"),
            "{\"host\":\"10.0.0.14\"}"
        );
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "exec:hostname",
                "get:/tmp/inventory.json",
                "exec:rm -f /tmp/inventory.json",
                "disconnect"
            ]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn session_executor_puts_file_executes_collector_and_collects_log_artifacts() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 16));
        let root = temp_dir("session-staged-artifacts");
        let script_path = root.join("exec").join("collector.sh");
        let run_capture_path = root.join("exec").join("collector_run.txt");
        let inventory_path = root.join("files").join("inventory.txt");
        let log_path = root.join("logs").join("application.log");
        tokio::fs::create_dir_all(script_path.parent().expect("script parent should exist"))
            .await
            .expect("script dir should be created");
        tokio::fs::write(&script_path, "#!/bin/sh\necho collector\n")
            .await
            .expect("script should be written");

        let mut session_template = template(0, false);
        let events = Arc::clone(&session_template.events);
        let uploads = Arc::clone(&session_template.uploads);
        session_template.exec_outputs = Arc::new(HashMap::from([(
            "sh /tmp/pandoras_box_collect.sh".to_string(),
            ExecResponse {
                stdout: b"collector ok\n".to_vec(),
                stderr: Vec::new(),
                status_code: Some(0),
            },
        )]));
        session_template.downloads = Arc::new(HashMap::from([
            (
                "/tmp/pandoras_box/inventory.txt".to_string(),
                b"inventory payload\n".to_vec(),
            ),
            (
                "/tmp/pandoras_box/application.log".to_string(),
                b"application log payload\n".to_vec(),
            ),
        ]));
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            session_template,
        )]));
        let executor = SessionExecutor::new(
            factory,
            ExecutionPolicy::default(),
            vec![
                SessionOperation::put_file(&script_path, "/tmp/pandoras_box_collect.sh"),
                SessionOperation::capture_exec("sh /tmp/pandoras_box_collect.sh", &run_capture_path),
                SessionOperation::get_file("/tmp/pandoras_box/inventory.txt", &inventory_path),
                SessionOperation::get_file("/tmp/pandoras_box/application.log", &log_path),
                SessionOperation::cleanup_exec(
                    "rm -f /tmp/pandoras_box_collect.sh /tmp/pandoras_box/inventory.txt /tmp/pandoras_box/application.log",
                ),
            ],
        );

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Complete);
        assert!(tokio::fs::read_to_string(&run_capture_path)
            .await
            .expect("run capture should exist")
            .contains("collector ok"));
        assert_eq!(
            tokio::fs::read_to_string(&inventory_path)
                .await
                .expect("inventory file should exist"),
            "inventory payload\n"
        );
        assert_eq!(
            tokio::fs::read_to_string(&log_path)
                .await
                .expect("log file should exist"),
            "application log payload\n"
        );
        assert_eq!(
            uploads
                .lock()
                .expect("uploads lock should be available")
                .get("/tmp/pandoras_box_collect.sh")
                .cloned(),
            Some(b"#!/bin/sh\necho collector\n".to_vec())
        );
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [
                "put:/tmp/pandoras_box_collect.sh",
                "exec:sh /tmp/pandoras_box_collect.sh",
                "get:/tmp/pandoras_box/inventory.txt",
                "get:/tmp/pandoras_box/application.log",
                "exec:rm -f /tmp/pandoras_box_collect.sh /tmp/pandoras_box/inventory.txt /tmp/pandoras_box/application.log",
                "disconnect"
            ]
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn session_executor_skips_cleanup_exec_in_dry_run() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 15));
        let session_template = template(0, false);
        let events = Arc::clone(&session_template.events);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            session_template,
        )]));
        let executor = SessionExecutor::new(
            factory,
            ExecutionPolicy {
                dry_run: true,
                allow_smb_fallback: true,
            },
            vec![SessionOperation::cleanup_exec("rm -f /tmp/inventory.json")],
        );

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Complete);
        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            ["disconnect"]
        );
    }

    #[tokio::test]
    async fn session_executor_surfaces_cleanup_failure() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            template(0, true),
        )]));
        let executor = SessionExecutor::new(factory, ExecutionPolicy::default(), Vec::new());

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Failed);
        assert!(report
            .error
            .as_deref()
            .expect("error should exist")
            .contains("cleanup failed"));
        assert_eq!(report.failure_phase, Some(FailurePhase::Cleanup));
        assert_eq!(
            report.failure_disposition,
            Some(FailureDisposition::Terminal)
        );
    }

    #[tokio::test]
    async fn session_executor_fails_when_exec_has_no_exit_status() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 18));
        let mut session_template = template(0, false);
        session_template.exec_outputs = Arc::new(HashMap::from([(
            "hostname".to_string(),
            ExecResponse {
                stdout: b"host-18\n".to_vec(),
                stderr: Vec::new(),
                status_code: None,
            },
        )]));
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            session_template,
        )]));
        let executor = SessionExecutor::new(
            factory,
            ExecutionPolicy::default(),
            vec![SessionOperation::exec("hostname")],
        );

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Failed);
        assert!(report
            .error
            .as_deref()
            .expect("error should exist")
            .contains("missing exit status"));
        assert_eq!(report.failure_phase, Some(FailurePhase::Execute));
        assert_eq!(
            report.failure_disposition,
            Some(FailureDisposition::Terminal)
        );
    }

    #[tokio::test]
    async fn session_executor_fails_when_capture_exec_returns_non_zero_status() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 19));
        let root = temp_dir("session-capture-failure");
        let capture_path = root.join("exec").join("hostname.txt");
        let mut session_template = template(0, false);
        session_template.exec_outputs = Arc::new(HashMap::from([(
            "hostname".to_string(),
            ExecResponse {
                stdout: b"host-19\n".to_vec(),
                stderr: b"bad status\n".to_vec(),
                status_code: Some(23),
            },
        )]));
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            session_template,
        )]));
        let executor = SessionExecutor::new(
            factory,
            ExecutionPolicy::default(),
            vec![SessionOperation::capture_exec("hostname", &capture_path)],
        );

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Failed);
        assert!(report
            .error
            .as_deref()
            .expect("error should exist")
            .contains("exit status 23"));
        assert_eq!(report.failure_phase, Some(FailurePhase::Execute));
        assert_eq!(
            report.failure_disposition,
            Some(FailureDisposition::Terminal)
        );
        let capture = tokio::fs::read_to_string(&capture_path)
            .await
            .expect("failed capture should still be written");
        assert!(capture.contains("status: 23"));
        assert!(capture.contains("bad status"));
    }

    #[tokio::test]
    async fn session_executor_rejects_relative_remote_put_paths() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20));
        let root = temp_dir("session-relative-put");
        let local_path = root.join("exec").join("collector.sh");
        tokio::fs::create_dir_all(local_path.parent().expect("local parent should exist"))
            .await
            .expect("local dir should exist");
        tokio::fs::write(&local_path, "#!/bin/sh\necho hi\n")
            .await
            .expect("local file should exist");
        let session_template = template(0, false);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            session_template,
        )]));
        let executor = SessionExecutor::new(
            factory,
            ExecutionPolicy::default(),
            vec![SessionOperation::put_file(&local_path, "tmp/collector.sh")],
        );

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Failed);
        assert!(report
            .error
            .as_deref()
            .expect("error should exist")
            .contains("remote path must be absolute"));
        assert_eq!(report.failure_phase, Some(FailurePhase::Stage));
        assert_eq!(
            report.failure_disposition,
            Some(FailureDisposition::Terminal)
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn session_executor_rejects_relative_remote_get_paths() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 21));
        let root = temp_dir("session-relative-get");
        let collect_path = root.join("files").join("inventory.json");
        let session_template = template(0, false);
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::Success,
            session_template,
        )]));
        let executor = SessionExecutor::new(
            factory,
            ExecutionPolicy::default(),
            vec![SessionOperation::get_file(
                "tmp/inventory.json",
                &collect_path,
            )],
        );

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Failed);
        assert!(report
            .error
            .as_deref()
            .expect("error should exist")
            .contains("remote path must be absolute"));
        assert_eq!(report.failure_phase, Some(FailurePhase::Collect));
        assert_eq!(
            report.failure_disposition,
            Some(FailureDisposition::Terminal)
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn session_executor_classifies_auth_connect_failures_as_terminal() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 30));
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::AuthFail,
            template(0, false),
        )]));
        let executor = SessionExecutor::new(factory, ExecutionPolicy::default(), Vec::new());

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Failed);
        assert_eq!(report.failure_phase, Some(FailurePhase::Connect));
        assert_eq!(
            report.failure_disposition,
            Some(FailureDisposition::Terminal)
        );
    }

    #[tokio::test]
    async fn session_executor_classifies_transient_connect_failures_as_retryable() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 31));
        let factory = Arc::new(FakeSessionFactory::new(vec![(
            (ip, TransportKind::UnixSsh),
            ConnectBehavior::TransientFail,
            template(0, false),
        )]));
        let executor = SessionExecutor::new(factory, ExecutionPolicy::default(), Vec::new());

        let report = executor
            .run(host_plan(ip, vec![TransportKind::UnixSsh]))
            .await;

        assert_eq!(report.final_state, HostState::Failed);
        assert_eq!(report.failure_phase, Some(FailurePhase::Connect));
        assert_eq!(
            report.failure_disposition,
            Some(FailureDisposition::Retryable)
        );
    }

    #[tokio::test]
    async fn session_executor_respects_smb_fallback_policy() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let smb_template = template(0, false);
        let factory = Arc::new(FakeSessionFactory::new(vec![
            (
                (ip, TransportKind::WindowsSsh),
                ConnectBehavior::AuthFail,
                template(0, false),
            ),
            (
                (ip, TransportKind::WindowsSmb),
                ConnectBehavior::Success,
                smb_template,
            ),
        ]));

        let denied = SessionExecutor::new(
            Arc::clone(&factory),
            ExecutionPolicy {
                dry_run: false,
                allow_smb_fallback: false,
            },
            Vec::new(),
        );
        let allowed = SessionExecutor::new(factory, ExecutionPolicy::default(), Vec::new());
        let plan = host_plan(
            ip,
            vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb],
        );

        let denied_report = denied.run(plan.clone()).await;
        let allowed_report = allowed.run(plan).await;

        assert_eq!(denied_report.final_state, HostState::Failed);
        assert_eq!(allowed_report.final_state, HostState::Complete);
    }

    #[tokio::test]
    async fn scheduler_with_session_executor_keeps_other_hosts_moving() {
        let slow_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
        let failed_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12));
        let fast_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 13));

        let factory = Arc::new(FakeSessionFactory::new(vec![
            (
                (slow_ip, TransportKind::UnixSsh),
                ConnectBehavior::Success,
                template(200, false),
            ),
            (
                (failed_ip, TransportKind::UnixSsh),
                ConnectBehavior::AuthFail,
                template(0, false),
            ),
            (
                (fast_ip, TransportKind::UnixSsh),
                ConnectBehavior::Success,
                template(10, false),
            ),
        ]));
        let executor = Arc::new(SessionExecutor::new(
            factory,
            ExecutionPolicy::default(),
            vec![SessionOperation::ensure_dir("/tmp/pandoras-box")],
        ));
        let scheduler = Scheduler::new(3);
        let start = Instant::now();

        let reports = scheduler
            .execute(
                vec![
                    host_plan(slow_ip, vec![TransportKind::UnixSsh]),
                    host_plan(failed_ip, vec![TransportKind::UnixSsh]),
                    host_plan(fast_ip, vec![TransportKind::UnixSsh]),
                ],
                executor,
            )
            .await;

        assert_eq!(reports.len(), 3);
        assert_eq!(
            reports
                .iter()
                .filter(|report| report.final_state == HostState::Complete)
                .count(),
            2
        );
        assert_eq!(
            reports
                .iter()
                .filter(|report| report.final_state == HostState::Failed)
                .count(),
            1
        );
        assert!(
            start.elapsed() < Duration::from_millis(280),
            "expected host-local concurrency, took {:?}",
            start.elapsed()
        );
    }
}
