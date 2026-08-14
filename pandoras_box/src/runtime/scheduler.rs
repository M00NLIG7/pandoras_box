use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;

use super::mission::{HostPlan, HostState, TransportKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePhase {
    Connect,
    Stage,
    Execute,
    Collect,
    Credentials,
    Cleanup,
    Unknown,
}

impl FailurePhase {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Stage => "stage",
            Self::Execute => "execute",
            Self::Collect => "collect",
            Self::Credentials => "credentials",
            Self::Cleanup => "cleanup",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "connect" => Some(Self::Connect),
            "stage" => Some(Self::Stage),
            "execute" => Some(Self::Execute),
            "collect" => Some(Self::Collect),
            "credentials" => Some(Self::Credentials),
            "cleanup" => Some(Self::Cleanup),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureDisposition {
    Retryable,
    Terminal,
}

impl FailureDisposition {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Terminal => "terminal",
        }
    }

    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "retryable" => Some(Self::Retryable),
            "terminal" => Some(Self::Terminal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostExecutionReport {
    pub plan: HostPlan,
    pub final_state: HostState,
    pub error: Option<String>,
    pub failure_phase: Option<FailurePhase>,
    pub failure_disposition: Option<FailureDisposition>,
    pub selected_transport: Option<TransportKind>,
    pub attempt_count: u8,
    pub completed_phases: Vec<FailurePhase>,
}

impl HostExecutionReport {
    #[must_use]
    pub fn success(plan: HostPlan, final_state: HostState) -> Self {
        Self {
            plan: plan.force_state(final_state),
            final_state,
            error: None,
            failure_phase: None,
            failure_disposition: None,
            selected_transport: None,
            attempt_count: 1,
            completed_phases: Vec::new(),
        }
    }

    #[must_use]
    pub fn failure(plan: HostPlan, error: impl Into<String>) -> Self {
        Self::terminal_failure(plan, FailurePhase::Unknown, error)
    }

    #[must_use]
    pub fn terminal_failure(plan: HostPlan, phase: FailurePhase, error: impl Into<String>) -> Self {
        Self::failure_with_disposition(plan, phase, FailureDisposition::Terminal, error)
    }

    #[must_use]
    pub fn unattempted_failure(
        plan: HostPlan,
        phase: FailurePhase,
        error: impl Into<String>,
    ) -> Self {
        Self {
            plan: plan.force_state(HostState::Failed),
            final_state: HostState::Failed,
            error: Some(error.into()),
            failure_phase: Some(phase),
            failure_disposition: Some(FailureDisposition::Terminal),
            selected_transport: None,
            attempt_count: 0,
            completed_phases: Vec::new(),
        }
    }

    #[must_use]
    pub fn retryable_failure(
        plan: HostPlan,
        phase: FailurePhase,
        error: impl Into<String>,
    ) -> Self {
        Self::failure_with_disposition(plan, phase, FailureDisposition::Retryable, error)
    }

    #[must_use]
    pub fn failure_with_disposition(
        plan: HostPlan,
        phase: FailurePhase,
        disposition: FailureDisposition,
        error: impl Into<String>,
    ) -> Self {
        Self {
            plan: plan.force_state(HostState::Failed),
            final_state: HostState::Failed,
            error: Some(error.into()),
            failure_phase: Some(phase),
            failure_disposition: Some(disposition),
            selected_transport: None,
            attempt_count: 1,
            completed_phases: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_attempt_count(mut self, attempt_count: u8) -> Self {
        self.attempt_count = attempt_count.max(1);
        self
    }

    #[must_use]
    pub fn with_selected_transport(mut self, transport: TransportKind) -> Self {
        self.selected_transport = Some(transport);
        self
    }

    #[must_use]
    pub fn with_completed_phases(mut self, completed_phases: Vec<FailurePhase>) -> Self {
        self.completed_phases = normalize_completed_phases(completed_phases);
        self
    }

    #[must_use]
    pub fn mark_phase_completed(mut self, phase: FailurePhase) -> Self {
        self.completed_phases.push(phase);
        self.completed_phases = normalize_completed_phases(self.completed_phases);
        self
    }

    #[must_use]
    pub fn has_completed_phase(&self, phase: FailurePhase) -> bool {
        self.completed_phases.contains(&phase)
    }

    #[must_use]
    pub fn should_retry(&self, max_attempts: u8) -> bool {
        self.final_state == HostState::Failed
            && matches!(
                self.failure_disposition,
                Some(FailureDisposition::Retryable)
            )
            && self.attempt_count < max_attempts.max(1)
    }
}

fn normalize_completed_phases(mut completed_phases: Vec<FailurePhase>) -> Vec<FailurePhase> {
    completed_phases.sort_by_key(|phase| match phase {
        FailurePhase::Connect => 0,
        FailurePhase::Stage => 1,
        FailurePhase::Execute => 2,
        FailurePhase::Collect => 3,
        FailurePhase::Credentials => 4,
        FailurePhase::Cleanup => 5,
        FailurePhase::Unknown => 6,
    });
    completed_phases.dedup();
    completed_phases
}

#[async_trait]
pub trait HostExecutor: Send + Sync {
    async fn run(&self, plan: HostPlan) -> HostExecutionReport;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scheduler {
    concurrency_limit: usize,
}

impl Scheduler {
    #[must_use]
    pub fn new(concurrency_limit: usize) -> Self {
        Self {
            concurrency_limit: concurrency_limit.max(1),
        }
    }

    pub async fn execute<E>(
        &self,
        plans: Vec<HostPlan>,
        executor: Arc<E>,
    ) -> Vec<HostExecutionReport>
    where
        E: HostExecutor + 'static,
    {
        let semaphore = Arc::new(Semaphore::new(self.concurrency_limit));
        let mut tasks = FuturesUnordered::new();

        for plan in plans {
            let executor = Arc::clone(&executor);
            let semaphore = Arc::clone(&semaphore);
            tasks.push(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .expect("scheduler semaphore unexpectedly closed");
                executor.run(plan).await
            });
        }

        let mut reports = Vec::new();
        while let Some(report) = tasks.next().await {
            reports.push(report);
        }
        reports
    }
}

#[cfg(test)]
mod tests {
    use super::{HostExecutionReport, HostExecutor, Scheduler};
    use crate::runtime::mission::{HostPlan, HostState, HostTarget, PlatformHint};
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct FakeExecutor;

    #[async_trait]
    impl HostExecutor for FakeExecutor {
        async fn run(&self, mut plan: HostPlan) -> HostExecutionReport {
            let last_octet = match plan.target.ip {
                IpAddr::V4(ip) => ip.octets()[3],
                IpAddr::V6(_) => 0,
            };

            plan.state = HostState::Executing;

            match last_octet {
                2 => {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    HostExecutionReport::failure(plan, "auth failed")
                }
                3 => {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    HostExecutionReport::success(plan, HostState::Complete)
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    HostExecutionReport::success(plan, HostState::Complete)
                }
            }
        }
    }

    fn plan(last_octet: u8) -> HostPlan {
        HostPlan {
            target: HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)),
                platform: PlatformHint::Unknown,
                open_ports: vec![22],
            },
            state: HostState::Queued,
            transport_chain: vec![],
        }
    }

    #[tokio::test]
    async fn scheduler_does_not_fail_fast_on_single_host_error() {
        let scheduler = Scheduler::new(3);
        let reports = scheduler
            .execute(vec![plan(1), plan(2), plan(3)], Arc::new(FakeExecutor))
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
    }

    #[tokio::test]
    async fn scheduler_runs_hosts_concurrently() {
        let scheduler = Scheduler::new(3);
        let start = Instant::now();

        let _reports = scheduler
            .execute(vec![plan(2), plan(3), plan(4)], Arc::new(FakeExecutor))
            .await;

        assert!(
            start.elapsed() < Duration::from_millis(280),
            "expected concurrent execution, took {:?}",
            start.elapsed()
        );
    }
}
