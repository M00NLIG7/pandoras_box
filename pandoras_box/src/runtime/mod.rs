pub mod artifact_store;
pub mod credentials;
pub mod discovery;
pub mod mission;
pub mod payloads;
pub mod planner;
pub mod policy;
pub mod reporting;
pub mod runner;
pub mod scheduler;
pub mod secret;
pub mod session_executor;
pub mod session_factory;
pub mod transport;
pub mod workspace;

pub use artifact_store::{validate_mission_id, ArtifactStore};
pub use credentials::{
    AuthenticationSpec, CredentialProfile, CredentialProfileCatalog, ExternalSecretSource,
    ResolvedAuthentication, ResolvedCredentialPolicy,
};
pub use discovery::{DiscoveryConfig, DiscoveryOutcome, DiscoveryRecord, TcpDiscovery};
pub use mission::{
    CpuArchitecture, DeadlinePolicy, HostPlan, HostState, HostStateTransitionError, HostTarget,
    MissionReuseMode, MissionSpec, OperatingSystem, PayloadQualification, PayloadSpec,
    PlatformHint, RendererSpec, ResolvedPayload, ResourceLimits, RetryPolicy, SshHostKeyPolicy,
    TargetContract, TransportKind, WindowsSmbExecMode,
};
pub use payloads::{PayloadKey, PayloadPreflight, PayloadSelectionError};
pub use planner::Planner;
pub use policy::{ExecutionPolicy, OperationMutability, PolicyViolation};
pub use reporting::{AssetInventoryBundle, AssetInventoryHost};
pub use runner::{PandorasBoxRunSummary, PandorasBoxRunner};
pub use scheduler::{CleanupOutcome, HostExecutionReport, HostExecutor, Scheduler};
pub use secret::SecretString;
pub use session_executor::{OperationIdempotency, SessionExecutor, SessionOperation};
pub use session_factory::{BoxedHostSession, SessionFactory};
pub use workspace::{
    collector_plan, remote_workspace, CollectorPlan, RemoteShell, RemoteWorkspace,
};
