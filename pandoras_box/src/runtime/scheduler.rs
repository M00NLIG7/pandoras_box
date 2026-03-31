use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;

use super::mission::{HostPlan, HostState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostExecutionReport {
    pub plan: HostPlan,
    pub final_state: HostState,
    pub error: Option<String>,
}

impl HostExecutionReport {
    #[must_use]
    pub fn success(plan: HostPlan, final_state: HostState) -> Self {
        Self {
            plan: plan.force_state(final_state),
            final_state,
            error: None,
        }
    }

    #[must_use]
    pub fn failure(plan: HostPlan, error: impl Into<String>) -> Self {
        Self {
            plan: plan.force_state(HostState::Failed),
            final_state: HostState::Failed,
            error: Some(error.into()),
        }
    }
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
