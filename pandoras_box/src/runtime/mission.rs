use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::credentials::{hash_text, CredentialProfileCatalog, ResolvedCredentialPolicy};
use super::secret::SecretString;

/// A passive discovery hint. Hints are never trusted as an execution contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformHint {
    UnixLike,
    Windows,
    Unknown,
}

impl PlatformHint {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnixLike => "unix_like",
            Self::Windows => "windows",
            Self::Unknown => "unknown",
        }
    }
}

/// Operating systems represented by Pandora's target contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Linux,
    Windows,
    #[serde(rename = "freebsd")]
    FreeBsd,
    #[serde(rename = "openbsd")]
    OpenBsd,
    #[serde(rename = "netbsd")]
    NetBsd,
    #[serde(rename = "dragonflybsd")]
    DragonFlyBsd,
    Bsd,
    #[serde(rename = "pfsense")]
    PfSense,
    Unknown,
}

impl OperatingSystem {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::FreeBsd => "freebsd",
            Self::OpenBsd => "openbsd",
            Self::NetBsd => "netbsd",
            Self::DragonFlyBsd => "dragonflybsd",
            Self::Bsd => "bsd",
            Self::PfSense => "pfsense",
            Self::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn uses_windows_shell(self) -> bool {
        self == Self::Windows
    }

    #[must_use]
    pub fn uses_posix_shell(self) -> bool {
        matches!(
            self,
            Self::Linux
                | Self::FreeBsd
                | Self::OpenBsd
                | Self::NetBsd
                | Self::DragonFlyBsd
                | Self::Bsd
                | Self::PfSense
        )
    }
}

/// CPU architectures represented by Pandora's payload contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuArchitecture {
    X86_64,
    X86,
    Aarch64,
    Armv7,
    Unknown,
}

impl CpuArchitecture {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::X86 => "x86",
            Self::Aarch64 => "aarch64",
            Self::Armv7 => "armv7",
            Self::Unknown => "unknown",
        }
    }
}

/// Authenticated transport adapters supported by the shared mission engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    SshSftp,
    WindowsSmb,
}

impl TransportKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SshSftp => "ssh_sftp",
            Self::WindowsSmb => "windows_smb_encryption_required",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ssh_sftp" => Some(Self::SshSftp),
            "windows_smb_encryption_required" | "windows_smb" => Some(Self::WindowsSmb),
            _ => None,
        }
    }
}

/// An operator-supplied, non-secret execution contract for one target class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetContract {
    pub operating_system: OperatingSystem,
    pub architecture: CpuArchitecture,
    pub transports: Vec<TransportKind>,
}

impl TargetContract {
    #[must_use]
    pub fn detect_only() -> Self {
        Self {
            operating_system: OperatingSystem::Unknown,
            architecture: CpuArchitecture::Unknown,
            transports: Vec::new(),
        }
    }

    #[must_use]
    pub fn ssh(operating_system: OperatingSystem, architecture: CpuArchitecture) -> Self {
        Self {
            operating_system,
            architecture,
            transports: vec![TransportKind::SshSftp],
        }
    }

    #[must_use]
    pub fn windows(architecture: CpuArchitecture, allow_smb_fallback: bool) -> Self {
        let mut transports = vec![TransportKind::SshSftp];
        if allow_smb_fallback {
            transports.push(TransportKind::WindowsSmb);
        }
        Self {
            operating_system: OperatingSystem::Windows,
            architecture,
            transports,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.operating_system == OperatingSystem::Unknown
            || self.architecture == CpuArchitecture::Unknown
        {
            if self.transports.is_empty() {
                return Ok(());
            }
            return Err("unknown target contracts cannot enable authenticated transports".into());
        }
        if self.operating_system == OperatingSystem::Bsd {
            return Err(
                "generic BSD is a reporting umbrella; execution requires freebsd, openbsd, netbsd, or dragonflybsd"
                    .into(),
            );
        }
        if self.transports.is_empty() {
            return Err("qualified target contracts require at least one transport".into());
        }
        if self.operating_system != OperatingSystem::Windows
            && self.transports.contains(&TransportKind::WindowsSmb)
        {
            return Err("Windows SMB is valid only for an explicit Windows contract".into());
        }
        if self
            .transports
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.transports.len()
        {
            return Err("target contract transports must be unique".into());
        }
        Ok(())
    }

    #[must_use]
    pub fn is_explicit(&self) -> bool {
        self.operating_system != OperatingSystem::Unknown
            && self.architecture != CpuArchitecture::Unknown
            && !self.transports.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowsSmbExecMode {
    SmbExec,
    PsExec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshHostKeyPolicy {
    RequireKnown,
    DangerouslyAcceptUnknown,
}

impl SshHostKeyPolicy {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequireKnown => "require_known",
            Self::DangerouslyAcceptUnknown => "dangerously_accept_unknown",
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissionReuseMode {
    ErrorIfExists,
    Resume,
    Fresh,
}

impl MissionReuseMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ErrorIfExists => "error_if_exists",
            Self::Resume => "resume",
            Self::Fresh => "fresh",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadQualification {
    ContractOnly,
    LiveQualified,
}

impl PayloadQualification {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractOnly => "contract_only",
            Self::LiveQualified => "live_qualified",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSpec {
    pub operating_system: OperatingSystem,
    pub architecture: CpuArchitecture,
    pub path: PathBuf,
    pub version: String,
    pub sha256: String,
    pub qualification: PayloadQualification,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPayload {
    pub operating_system: OperatingSystem,
    pub architecture: CpuArchitecture,
    pub path: PathBuf,
    pub version: String,
    pub sha256: String,
    pub qualification: PayloadQualification,
    pub evidence: Vec<String>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendererSpec {
    pub executable: PathBuf,
    pub sha256: String,
    pub timeout: Duration,
    pub max_output_bytes: u64,
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
    pub backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 2,
            backoff: Duration::from_millis(500),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadlinePolicy {
    pub discovery_connect: Duration,
    pub connect: Duration,
    pub inactivity: Duration,
    pub command: Duration,
    pub transfer: Duration,
    pub cleanup: Duration,
    pub host: Duration,
    pub mission: Duration,
}

impl Default for DeadlinePolicy {
    fn default() -> Self {
        Self {
            discovery_connect: Duration::from_millis(800),
            connect: Duration::from_secs(5),
            inactivity: Duration::from_secs(30),
            command: Duration::from_secs(120),
            transfer: Duration::from_secs(120),
            cleanup: Duration::from_secs(15),
            host: Duration::from_secs(300),
            mission: Duration::from_secs(1800),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_command_output_bytes: usize,
    pub max_download_bytes: u64,
    pub max_payload_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_command_output_bytes: 1024 * 1024,
            max_download_bytes: 16 * 1024 * 1024,
            max_payload_bytes: 128 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissionSpec {
    pub targets: Vec<IpAddr>,
    pub default_target_contract: TargetContract,
    pub target_contracts: BTreeMap<IpAddr, TargetContract>,
    pub payload_catalog: Vec<PayloadSpec>,
    pub concurrency_limit: usize,
    pub best_effort: bool,
    pub retry_policy: RetryPolicy,
    pub deadlines: DeadlinePolicy,
    pub resource_limits: ResourceLimits,
    pub artifact_root: PathBuf,
    pub mission_id: String,
    pub mission_id_explicit: bool,
    pub mission_reuse: MissionReuseMode,
    pub unix_username: String,
    pub windows_username: String,
    pub password: SecretString,
    pub credential_profiles: CredentialProfileCatalog,
    pub ssh_port: u16,
    pub ssh_host_key_policy: SshHostKeyPolicy,
    pub discovery_ports: Vec<u16>,
    pub dry_run: bool,
    pub allow_smb_fallback: bool,
    pub windows_smb_exec_mode: WindowsSmbExecMode,
    pub renderer: Option<RendererSpec>,
}

impl Default for MissionSpec {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            default_target_contract: TargetContract::detect_only(),
            target_contracts: BTreeMap::new(),
            payload_catalog: Vec::new(),
            concurrency_limit: 64,
            best_effort: false,
            retry_policy: RetryPolicy::default(),
            deadlines: DeadlinePolicy::default(),
            resource_limits: ResourceLimits::default(),
            artifact_root: PathBuf::from("artifacts"),
            mission_id: "mission".to_string(),
            mission_id_explicit: true,
            mission_reuse: MissionReuseMode::ErrorIfExists,
            unix_username: "root".to_string(),
            windows_username: "Administrator".to_string(),
            password: SecretString::default(),
            credential_profiles: CredentialProfileCatalog::default(),
            ssh_port: 22,
            ssh_host_key_policy: SshHostKeyPolicy::RequireKnown,
            discovery_ports: Vec::new(),
            dry_run: false,
            allow_smb_fallback: false,
            windows_smb_exec_mode: WindowsSmbExecMode::SmbExec,
            renderer: None,
        }
    }
}

impl MissionSpec {
    #[must_use]
    pub fn target_contract(&self, ip: IpAddr) -> TargetContract {
        self.target_contracts
            .get(&ip)
            .cloned()
            .unwrap_or_else(|| self.default_target_contract.clone())
    }

    #[must_use]
    pub fn effective_credential_profiles(&self) -> CredentialProfileCatalog {
        if self.credential_profiles.is_configured() {
            return self.credential_profiles.clone();
        }
        CredentialProfileCatalog::legacy(
            self.unix_username.clone(),
            self.windows_username.clone(),
            (!self.password.is_empty()).then(|| self.password.clone()),
            self.ssh_port,
            self.ssh_host_key_policy,
            self.allow_smb_fallback,
            445,
        )
    }

    pub fn credential_policy(&self, ip: IpAddr) -> crate::Result<ResolvedCredentialPolicy> {
        let contract = self.target_contract(ip);
        self.credential_profiles
            .resolve_policy(ip, contract.operating_system, &contract.transports)
    }

    #[must_use]
    pub fn resolved_discovery_ports(&self) -> Vec<u16> {
        let mut ports = if self.discovery_ports.is_empty() {
            vec![self.ssh_port, 135, 139, 445]
        } else {
            self.discovery_ports.clone()
        };
        if self.credential_profiles.is_configured() {
            for ip in &self.targets {
                let contract = self.target_contract(*ip);
                if let Ok(policy) = self.credential_profiles.resolve_policy(
                    *ip,
                    contract.operating_system,
                    &contract.transports,
                ) {
                    for transport in contract.transports {
                        if policy.allows_transport(transport) {
                            ports.push(policy.port_for(transport));
                        }
                    }
                }
            }
        }
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    #[must_use]
    pub fn resume_signature(&self) -> String {
        let mut targets = self.targets.clone();
        targets.sort();
        let target_contracts = targets
            .iter()
            .map(|ip| {
                let contract = self.target_contract(*ip);
                format!(
                    "{}={}/{}/{}",
                    ip,
                    contract.operating_system.as_str(),
                    contract.architecture.as_str(),
                    contract
                        .transports
                        .iter()
                        .map(|transport| transport.as_str())
                        .collect::<Vec<_>>()
                        .join("+")
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        let credential_identity = if self.credential_profiles.is_configured() {
            let bindings = targets
                .iter()
                .map(|ip| {
                    let contract = self.target_contract(*ip);
                    let (name, fingerprint) = self.credential_profiles.policy_identity(
                        *ip,
                        contract.operating_system,
                        &contract.transports,
                    );
                    format!(
                        "{}={}:{}",
                        ip,
                        name.as_deref().unwrap_or("unresolved"),
                        fingerprint
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("profiles:{}", hash_text(&bindings))
        } else {
            format!(
                "legacy:{}:{}:{}:{}",
                self.unix_username,
                self.windows_username,
                self.ssh_port,
                self.ssh_host_key_policy.as_str()
            )
        };

        let mut payloads = self.payload_catalog.clone();
        payloads.sort_by_key(|payload| (payload.operating_system, payload.architecture));
        let payload_identity = payloads
            .iter()
            .map(|payload| {
                format!(
                    "{}/{}/{}/{}/{}",
                    payload.operating_system.as_str(),
                    payload.architecture.as_str(),
                    payload.version,
                    payload.sha256.to_ascii_lowercase(),
                    payload.qualification.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        format!(
            concat!(
                "targets={};contracts={};payloads={};credentials={};",
                "discovery_ports={:?};dry_run={};",
                "allow_smb_fallback={};windows_smb_exec_mode={};execution={}:{};retry={}:{};",
                "deadlines={}:{}:{}:{}:{}:{}:{}:{};limits={}:{}:{}"
            ),
            targets
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            target_contracts,
            payload_identity,
            credential_identity,
            self.resolved_discovery_ports(),
            self.dry_run,
            self.allow_smb_fallback,
            self.windows_smb_exec_mode.as_str(),
            self.concurrency_limit,
            self.best_effort,
            self.retry_policy.max_attempts,
            self.retry_policy.backoff.as_millis(),
            self.deadlines.discovery_connect.as_millis(),
            self.deadlines.connect.as_millis(),
            self.deadlines.inactivity.as_millis(),
            self.deadlines.command.as_millis(),
            self.deadlines.transfer.as_millis(),
            self.deadlines.cleanup.as_millis(),
            self.deadlines.host.as_millis(),
            self.deadlines.mission.as_millis(),
            self.resource_limits.max_command_output_bytes,
            self.resource_limits.max_download_bytes,
            self.resource_limits.max_payload_bytes,
        )
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
    pub fn parse(value: &str) -> Option<Self> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPlan {
    pub target: HostTarget,
    pub contract: TargetContract,
    pub payload: Option<ResolvedPayload>,
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
    pub fn queued(
        target: HostTarget,
        contract: TargetContract,
        transport_chain: Vec<TransportKind>,
    ) -> Self {
        Self {
            target,
            contract,
            payload: None,
            state: HostState::Queued,
            transport_chain,
        }
    }

    #[must_use]
    pub fn with_payload(mut self, payload: ResolvedPayload) -> Self {
        self.payload = Some(payload);
        self
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
    use super::{
        CpuArchitecture, HostPlan, HostState, HostTarget, MissionSpec, OperatingSystem,
        PlatformHint, TargetContract, TransportKind,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn plan(state: HostState) -> HostPlan {
        HostPlan {
            target: HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                platform: PlatformHint::UnixLike,
                open_ports: vec![22],
            },
            contract: TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
            payload: None,
            state,
            transport_chain: vec![TransportKind::SshSftp],
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
    fn mission_debug_redacts_login_secret() {
        let spec = MissionSpec {
            password: "mission-debug-must-not-leak".into(),
            ..MissionSpec::default()
        };
        let rendered = format!("{spec:?}");

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("mission-debug-must-not-leak"));
    }

    #[test]
    fn unknown_contracts_cannot_authenticate() {
        let mut contract = TargetContract::detect_only();
        contract.transports.push(TransportKind::SshSftp);
        assert!(contract.validate().is_err());
        assert!(!contract.is_explicit());
    }

    #[test]
    fn bsd_and_pfsense_are_first_class_posix_contracts() {
        for os in [
            OperatingSystem::FreeBsd,
            OperatingSystem::OpenBsd,
            OperatingSystem::NetBsd,
            OperatingSystem::DragonFlyBsd,
            OperatingSystem::PfSense,
        ] {
            let contract = TargetContract::ssh(os, CpuArchitecture::X86_64);
            contract.validate().expect("contract should be valid");
            assert!(contract.operating_system.uses_posix_shell());
        }
        assert!(
            TargetContract::ssh(OperatingSystem::Bsd, CpuArchitecture::X86_64)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn operator_manifest_uses_stable_platform_spellings() {
        for (spelling, expected) in [
            ("freebsd", OperatingSystem::FreeBsd),
            ("openbsd", OperatingSystem::OpenBsd),
            ("netbsd", OperatingSystem::NetBsd),
            ("dragonflybsd", OperatingSystem::DragonFlyBsd),
            ("pfsense", OperatingSystem::PfSense),
        ] {
            let parsed: OperatingSystem = serde_json::from_str(&format!("\"{spelling}\""))
                .expect("stable platform spelling should parse");
            assert_eq!(parsed, expected);
            assert_eq!(
                serde_json::to_string(&parsed).expect("serialize"),
                format!("\"{spelling}\"")
            );
        }
    }

    #[test]
    fn resume_signature_pins_selected_profile_policy_without_secret_material() {
        let profile = |username: &str| {
            crate::runtime::CredentialProfileCatalog::from_json(
                &format!(
                    r#"{{
                      "version":1,
                      "default_profile":"operator",
                      "profiles":[{{
                        "name":"operator",
                        "operating_systems":["linux"],
                        "username":"{username}",
                        "authentication":{{"type":"ssh_agent","public_key_sha256":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
                        "transports":["ssh_sftp"]
                      }}]
                    }}"#
                ),
                std::path::Path::new("."),
            )
            .expect("credential profile")
        };
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let spec = MissionSpec {
            targets: vec![target],
            default_target_contract: TargetContract::ssh(
                OperatingSystem::Linux,
                CpuArchitecture::X86_64,
            ),
            credential_profiles: profile("operator-a"),
            ..MissionSpec::default()
        };
        let mut changed = spec.clone();
        changed.credential_profiles = profile("operator-b");

        assert_ne!(spec.resume_signature(), changed.resume_signature());
        assert!(!spec.resume_signature().contains("operator-a"));
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
