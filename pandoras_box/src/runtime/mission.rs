use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlatformHint {
    Unix,
    Windows,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    UnixSsh,
    WindowsSsh,
    WindowsSmb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowsSmbExecMode {
    SmbExec,
    PsExec,
}

impl WindowsSmbExecMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SmbExec => "smbexec",
            Self::PsExec => "psexec",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTarget {
    pub ip: IpAddr,
    pub platform: PlatformHint,
    pub open_ports: Vec<u16>,
}

impl HostTarget {
    #[must_use]
    pub fn has_port(&self, port: u16) -> bool {
        self.open_ports.contains(&port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub connect_timeout: Duration,
    pub backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 2,
            connect_timeout: Duration::from_secs(3),
            backoff: Duration::from_millis(500),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissionSpec {
    pub targets: Vec<IpAddr>,
    pub concurrency_limit: usize,
    pub strict_mode: bool,
    pub retry_policy: RetryPolicy,
    pub artifact_root: PathBuf,
    pub mission_id: String,
    pub identity_command: String,
    pub unix_username: String,
    pub windows_username: String,
    pub password: String,
    pub ssh_port: u16,
    pub discovery_ports: Vec<u16>,
    pub chimera_unix_path: PathBuf,
    pub chimera_windows_path: PathBuf,
    pub collector_port: u16,
    pub dry_run: bool,
    pub allow_smb_fallback: bool,
    pub windows_smb_exec_mode: WindowsSmbExecMode,
}

impl Default for MissionSpec {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            concurrency_limit: 64,
            strict_mode: false,
            retry_policy: RetryPolicy::default(),
            artifact_root: PathBuf::from("artifacts"),
            mission_id: "mission".to_string(),
            identity_command: "whoami".to_string(),
            unix_username: "root".to_string(),
            windows_username: "Administrator".to_string(),
            password: String::new(),
            ssh_port: 22,
            discovery_ports: Vec::new(),
            chimera_unix_path: PathBuf::from("release/chimera"),
            chimera_windows_path: PathBuf::from("release/chimera.exe"),
            collector_port: 44_372,
            dry_run: false,
            allow_smb_fallback: true,
            windows_smb_exec_mode: WindowsSmbExecMode::SmbExec,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostState {
    Discovered,
    Queued,
    Connecting,
    Connected,
    Executing,
    Collecting,
    Complete,
    Failed,
}

impl HostState {
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Failed)
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Queued => "queued",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Executing => "executing",
            Self::Collecting => "collecting",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "discovered" => Some(Self::Discovered),
            "queued" => Some(Self::Queued),
            "connecting" => Some(Self::Connecting),
            "connected" => Some(Self::Connected),
            "executing" => Some(Self::Executing),
            "collecting" => Some(Self::Collecting),
            "complete" => Some(Self::Complete),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

impl PlatformHint {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unix => "unix",
            Self::Windows => "windows",
            Self::Unknown => "unknown",
        }
    }
}

impl TransportKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnixSsh => "unix_ssh",
            Self::WindowsSsh => "windows_ssh",
            Self::WindowsSmb => "windows_smb",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPlan {
    pub target: HostTarget,
    pub state: HostState,
    pub transport_chain: Vec<TransportKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostStateTransitionError {
    pub from: HostState,
    pub to: HostState,
}

impl std::fmt::Display for HostStateTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid host state transition: {:?} -> {:?}",
            self.from, self.to
        )
    }
}

impl std::error::Error for HostStateTransitionError {}

impl HostPlan {
    #[must_use]
    pub fn queued(target: HostTarget, transport_chain: Vec<TransportKind>) -> Self {
        Self {
            target,
            state: HostState::Queued,
            transport_chain,
        }
    }

    pub fn transition(&self, next: HostState) -> Result<Self, HostStateTransitionError> {
        if Self::can_transition(self.state, next) {
            Ok(self.force_state(next))
        } else {
            Err(HostStateTransitionError {
                from: self.state,
                to: next,
            })
        }
    }

    #[must_use]
    pub fn force_state(&self, state: HostState) -> Self {
        let mut next = self.clone();
        next.state = state;
        next
    }

    #[must_use]
    pub fn can_transition(from: HostState, to: HostState) -> bool {
        use HostState::{
            Collecting, Complete, Connected, Connecting, Discovered, Executing, Failed, Queued,
        };

        match (from, to) {
            (current, next) if current == next => true,
            (Discovered, Queued | Failed) => true,
            (Queued, Connecting | Failed) => true,
            (Connecting, Connected | Failed) => true,
            (Connected, Executing | Collecting | Complete | Failed) => true,
            (Executing, Collecting | Complete | Failed) => true,
            (Collecting, Complete | Failed) => true,
            (Complete | Failed, _) => false,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HostPlan, HostState, HostTarget, PlatformHint, TransportKind};
    use std::net::{IpAddr, Ipv4Addr};

    fn plan(state: HostState) -> HostPlan {
        HostPlan {
            target: HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                platform: PlatformHint::Unix,
                open_ports: vec![22],
            },
            state,
            transport_chain: vec![TransportKind::UnixSsh],
        }
    }

    #[test]
    fn host_plan_allows_expected_transition_chain() {
        let queued = plan(HostState::Queued);
        let connecting = queued
            .transition(HostState::Connecting)
            .expect("queued -> connecting");
        let connected = connecting
            .transition(HostState::Connected)
            .expect("connecting -> connected");
        let executing = connected
            .transition(HostState::Executing)
            .expect("connected -> executing");
        let complete = executing
            .transition(HostState::Complete)
            .expect("executing -> complete");

        assert_eq!(complete.state, HostState::Complete);
        assert!(complete.state.is_terminal());
    }

    #[test]
    fn host_plan_rejects_invalid_transition() {
        let queued = plan(HostState::Queued);
        let error = queued
            .transition(HostState::Complete)
            .expect_err("queued -> complete should fail");

        assert_eq!(error.from, HostState::Queued);
        assert_eq!(error.to, HostState::Complete);
    }
}
