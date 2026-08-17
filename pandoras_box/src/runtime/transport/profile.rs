use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use rustrc::ssh::HostKeyPolicy;

use crate::runtime::credentials::{
    CredentialProfileCatalog, ResolvedAuthentication, ResolvedCredentialPolicy,
};
use crate::runtime::mission::{
    DeadlinePolicy, HostPlan, OperatingSystem, ResourceLimits, SshHostKeyPolicy, TransportKind,
    WindowsSmbExecMode,
};
use crate::runtime::session_factory::{BoxedHostSession, SessionFactory};
use crate::runtime::transport::smb::{
    require_encryption_qualified_remote_exec, SmbSession, SmbSessionConfig,
};
use crate::runtime::transport::ssh::{SshAuth, SshSession, SshSessionConfig};
use crate::runtime::workspace::RemoteShell;
use crate::{Error, Result};

const DEFAULT_SMB_STAGING_DIRECTORY: &str = r"Temp";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSessionPolicy {
    pub deadlines: DeadlinePolicy,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone)]
enum CachedAuthentication {
    Resolved(ResolvedAuthentication),
    Failed(String),
}

pub struct CredentialSessionFactory {
    catalog: CredentialProfileCatalog,
    deadlines: DeadlinePolicy,
    resource_limits: ResourceLimits,
    windows_smb_exec_mode: WindowsSmbExecMode,
    authentication_cache: Mutex<BTreeMap<String, CachedAuthentication>>,
    validated_profiles: Mutex<BTreeSet<String>>,
}

impl std::fmt::Debug for CredentialSessionFactory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialSessionFactory")
            .field("catalog", &self.catalog)
            .field("deadlines", &self.deadlines)
            .field("resource_limits", &self.resource_limits)
            .field("windows_smb_exec_mode", &self.windows_smb_exec_mode)
            .field("authentication_cache", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl CredentialSessionFactory {
    #[must_use]
    pub fn new(
        catalog: CredentialProfileCatalog,
        runtime_policy: CredentialSessionPolicy,
        windows_smb_exec_mode: WindowsSmbExecMode,
    ) -> Self {
        Self {
            catalog,
            deadlines: runtime_policy.deadlines,
            resource_limits: runtime_policy.resource_limits,
            windows_smb_exec_mode,
            authentication_cache: Mutex::new(BTreeMap::new()),
            validated_profiles: Mutex::new(BTreeSet::new()),
        }
    }

    fn policy_for_plan(&self, plan: &HostPlan) -> Result<ResolvedCredentialPolicy> {
        self.catalog.resolve_policy(
            plan.target.ip,
            plan.contract.operating_system,
            &plan.contract.transports,
        )
    }

    fn authentication_for(
        &self,
        policy: &ResolvedCredentialPolicy,
    ) -> Result<ResolvedAuthentication> {
        let mut cache = self.authentication_cache.lock().map_err(|_| {
            Error::CredentialProfileFailure(
                "credential authentication cache was poisoned".to_string(),
            )
        })?;
        if let Some(cached) = cache.get(&policy.name) {
            return match cached {
                CachedAuthentication::Resolved(authentication) => Ok(authentication.clone()),
                CachedAuthentication::Failed(message) => {
                    Err(Error::CredentialProfileFailure(message.clone()))
                }
            };
        }

        match self.catalog.resolve_authentication(policy) {
            Ok(authentication) => {
                cache.insert(
                    policy.name.clone(),
                    CachedAuthentication::Resolved(authentication.clone()),
                );
                Ok(authentication)
            }
            Err(error) => {
                let message = match error {
                    Error::CredentialProfileFailure(message) => message,
                    other => other.to_string(),
                };
                cache.insert(
                    policy.name.clone(),
                    CachedAuthentication::Failed(message.clone()),
                );
                Err(Error::CredentialProfileFailure(message))
            }
        }
    }

    fn profile_was_validated(&self, name: &str) -> Result<bool> {
        self.validated_profiles
            .lock()
            .map(|profiles| profiles.contains(name))
            .map_err(|_| {
                Error::CredentialProfileFailure(
                    "credential validation cache was poisoned".to_string(),
                )
            })
    }

    fn mark_profile_validated(&self, name: String) -> Result<()> {
        self.validated_profiles
            .lock()
            .map_err(|_| {
                Error::CredentialProfileFailure(
                    "credential validation cache was poisoned".to_string(),
                )
            })?
            .insert(name);
        Ok(())
    }

    async fn validate_policy_authentication(
        &self,
        policy: &ResolvedCredentialPolicy,
    ) -> Result<ResolvedAuthentication> {
        let authentication = self.authentication_for(policy)?;
        if self.profile_was_validated(&policy.name)? {
            return Ok(authentication);
        }

        match &authentication {
            ResolvedAuthentication::Password(_) => {}
            ResolvedAuthentication::SshKey {
                private_key,
                public_key_sha256,
            } => rustrc::ssh::preflight_private_key(private_key, public_key_sha256).map_err(
                |error| {
                    Error::CredentialProfileFailure(format!(
                        "credential profile '{}' SSH key preflight failed: {error}",
                        policy.name
                    ))
                },
            )?,
            ResolvedAuthentication::SshAgent { public_key_sha256 } => {
                match tokio::time::timeout(
                    self.deadlines.connect,
                    rustrc::ssh::preflight_agent_identity(public_key_sha256),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        return Err(Error::CredentialProfileFailure(format!(
                            "credential profile '{}' SSH agent preflight failed: {error}",
                            policy.name
                        )));
                    }
                    Err(_) => {
                        return Err(Error::CredentialProfileFailure(format!(
                            "credential profile '{}' SSH agent preflight exceeded {:?}",
                            policy.name, self.deadlines.connect
                        )));
                    }
                }
            }
        }
        self.mark_profile_validated(policy.name.clone())?;
        Ok(authentication)
    }

    fn require_transport_policy(
        policy: &ResolvedCredentialPolicy,
        transport: TransportKind,
    ) -> Result<()> {
        if policy.allows_transport(transport) {
            Ok(())
        } else {
            Err(Error::CredentialProfileFailure(format!(
                "credential profile '{}' does not permit {}",
                policy.name,
                transport.as_str()
            )))
        }
    }

    fn ssh_config_for_plan(
        &self,
        plan: &HostPlan,
        policy: &ResolvedCredentialPolicy,
        authentication: ResolvedAuthentication,
    ) -> Result<SshSessionConfig> {
        Self::require_transport_policy(policy, TransportKind::SshSftp)?;
        let shell = if plan.contract.operating_system == OperatingSystem::Windows {
            RemoteShell::PowerShell
        } else if plan.contract.operating_system.uses_posix_shell() {
            RemoteShell::Posix
        } else {
            return Err(Error::UnsupportedTarget(
                "SSH requires an explicit supported operating-system contract".to_string(),
            ));
        };
        if !plan.target.has_port(policy.ssh_port) {
            return Err(Error::CredentialProfileFailure(format!(
                "credential profile '{}' requires undiscovered SSH port {} for {}",
                policy.name, policy.ssh_port, plan.target.ip
            )));
        }
        let username = policy.ssh_username()?;
        let auth = match authentication {
            ResolvedAuthentication::Password(password) => SshAuth::Password { username, password },
            ResolvedAuthentication::SshKey {
                private_key,
                public_key_sha256,
            } => SshAuth::Key {
                username,
                key_path: private_key,
                public_key_sha256,
            },
            ResolvedAuthentication::SshAgent { public_key_sha256 } => SshAuth::Agent {
                username,
                public_key_sha256,
            },
        };

        Ok(SshSessionConfig {
            socket: SocketAddr::new(plan.target.ip, policy.ssh_port),
            auth,
            connect_timeout: self.deadlines.connect,
            inactivity_timeout: self.deadlines.inactivity,
            command_timeout: self.deadlines.command,
            transfer_timeout: self.deadlines.transfer,
            max_command_output_bytes: self.resource_limits.max_command_output_bytes,
            max_download_bytes: self.resource_limits.max_download_bytes,
            shell,
            host_key_policy: match policy.ssh_host_key_policy {
                SshHostKeyPolicy::RequireKnown => HostKeyPolicy::RequireKnownHosts,
                SshHostKeyPolicy::DangerouslyAcceptUnknown => {
                    HostKeyPolicy::DangerouslyAcceptUnknown
                }
            },
        })
    }

    fn smb_config_for_plan(
        &self,
        plan: &HostPlan,
        policy: &ResolvedCredentialPolicy,
        authentication: ResolvedAuthentication,
    ) -> Result<SmbSessionConfig> {
        Self::require_transport_policy(policy, TransportKind::WindowsSmb)?;
        if plan.contract.operating_system != OperatingSystem::Windows {
            return Err(Error::UnsupportedTarget(
                "SMB transport requires an explicit Windows contract".to_string(),
            ));
        }
        if !plan.target.has_port(policy.smb_port) {
            return Err(Error::CredentialProfileFailure(format!(
                "credential profile '{}' requires undiscovered SMB port {} for {}",
                policy.name, policy.smb_port, plan.target.ip
            )));
        }
        let ResolvedAuthentication::Password(password) = authentication else {
            return Err(Error::CredentialProfileFailure(format!(
                "credential profile '{}' requires password authentication for Windows SMB",
                policy.name
            )));
        };

        Ok(SmbSessionConfig {
            socket: SocketAddr::new(plan.target.ip, policy.smb_port),
            username: policy.username.clone(),
            password,
            domain: policy.windows_domain.clone(),
            workstation: policy.windows_workstation.clone(),
            staging_directory: DEFAULT_SMB_STAGING_DIRECTORY.to_string(),
            exec_mode: self.windows_smb_exec_mode,
            connect_timeout: self.deadlines.connect,
            command_timeout: self.deadlines.command,
            transfer_timeout: self.deadlines.transfer,
            max_command_output_bytes: self.resource_limits.max_command_output_bytes,
            max_download_bytes: self.resource_limits.max_download_bytes,
        })
    }
}

#[async_trait]
impl SessionFactory for CredentialSessionFactory {
    async fn preflight(&self, plan: &HostPlan) -> Result<()> {
        let policy = self.policy_for_plan(plan)?;
        for transport in &plan.transport_chain {
            Self::require_transport_policy(&policy, *transport)?;
        }
        self.validate_policy_authentication(&policy).await?;
        Ok(())
    }

    async fn connect(&self, plan: &HostPlan, transport: TransportKind) -> Result<BoxedHostSession> {
        if transport == TransportKind::WindowsSmb {
            // The strict SMB gate stays ahead of secret resolution and authentication.
            require_encryption_qualified_remote_exec()?;
        }
        let policy = self.policy_for_plan(plan)?;
        Self::require_transport_policy(&policy, transport)?;
        let authentication = self.validate_policy_authentication(&policy).await?;

        match transport {
            TransportKind::SshSftp => {
                let config = self.ssh_config_for_plan(plan, &policy, authentication)?;
                match tokio::time::timeout(self.deadlines.connect, SshSession::connect(&config))
                    .await
                {
                    Ok(result) => Ok(Box::new(result?)),
                    Err(_) => Err(Error::DeadlineExceeded(format!(
                        "SSH connection to {} exceeded {:?}",
                        plan.target.ip, self.deadlines.connect
                    ))),
                }
            }
            TransportKind::WindowsSmb => {
                let config = self.smb_config_for_plan(plan, &policy, authentication)?;
                match tokio::time::timeout(self.deadlines.connect, SmbSession::connect(&config))
                    .await
                {
                    Ok(result) => Ok(Box::new(result?)),
                    Err(_) => Err(Error::DeadlineExceeded(format!(
                        "SMB connection to {} exceeded {:?}",
                        plan.target.ip, self.deadlines.connect
                    ))),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CredentialSessionFactory, CredentialSessionPolicy};
    use crate::runtime::credentials::CredentialProfileCatalog;
    use crate::runtime::mission::{
        CpuArchitecture, DeadlinePolicy, HostPlan, HostState, HostTarget, OperatingSystem,
        PlatformHint, ResourceLimits, TargetContract, TransportKind, WindowsSmbExecMode,
    };
    use crate::runtime::transport::ssh::SshAuth;
    use crate::runtime::workspace::RemoteShell;
    use rustrc::ssh::HostKeyPolicy;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn plan(contract: TargetContract, open_ports: &[u16]) -> HostPlan {
        HostPlan {
            target: HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
                platform: PlatformHint::Unknown,
                open_ports: open_ports.to_vec(),
            },
            contract,
            payload: None,
            state: HostState::Queued,
            transport_chain: vec![TransportKind::SshSftp],
        }
    }

    fn factory(catalog: CredentialProfileCatalog) -> CredentialSessionFactory {
        CredentialSessionFactory::new(
            catalog,
            CredentialSessionPolicy {
                deadlines: DeadlinePolicy::default(),
                resource_limits: ResourceLimits::default(),
            },
            WindowsSmbExecMode::SmbExec,
        )
    }

    #[test]
    fn profile_factory_builds_password_ssh_config_without_exposing_secret() {
        let catalog = CredentialProfileCatalog::legacy(
            "root",
            "Administrator",
            Some("factory-debug-secret".into()),
            2222,
            crate::runtime::mission::SshHostKeyPolicy::RequireKnown,
            false,
            445,
        );
        let factory = factory(catalog);
        let host = plan(
            TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
            &[2222],
        );
        let policy = factory.policy_for_plan(&host).expect("profile policy");
        let authentication = factory
            .authentication_for(&policy)
            .expect("external authentication");
        let config = factory
            .ssh_config_for_plan(&host, &policy, authentication)
            .expect("SSH config");

        assert_eq!(
            config.socket,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 2222)
        );
        assert_eq!(config.shell, RemoteShell::Posix);
        assert_eq!(config.host_key_policy, HostKeyPolicy::RequireKnownHosts);
        assert!(matches!(
            config.auth,
            SshAuth::Password {
                ref username,
                ref password
            } if username == "root" && password.expose_secret() == "factory-debug-secret"
        ));
        assert!(!format!("{factory:?} {config:?}").contains("factory-debug-secret"));
    }

    #[test]
    fn windows_domain_and_ports_are_applied_without_secret_in_host_contract() {
        let raw = r#"{
          "version":1,
          "default_profile":"windows-domain",
          "profiles":[{
            "name":"windows-domain",
            "operating_systems":["windows"],
            "username":"operator",
            "authentication":{"type":"password","source":{"type":"environment","variable":"PANDORA_TEST_UNUSED"}},
            "transports":["ssh_sftp","windows_smb"],
            "ssh_port":2222,
            "smb_port":1445,
            "windows_domain":"BLUE",
            "windows_workstation":"PANDORA"
          }]
        }"#;
        let catalog =
            CredentialProfileCatalog::from_json(raw, std::path::Path::new(".")).expect("catalog");
        let factory = factory(catalog);
        let host = plan(
            TargetContract::windows(CpuArchitecture::X86_64, true),
            &[2222, 1445],
        );
        let policy = factory.policy_for_plan(&host).expect("profile policy");

        assert_eq!(
            policy.ssh_username().expect("domain username"),
            r"BLUE\operator"
        );
        assert_eq!(policy.ssh_port, 2222);
        assert_eq!(policy.smb_port, 1445);
        assert_eq!(policy.windows_workstation.as_deref(), Some("PANDORA"));
    }

    #[test]
    fn missing_profile_fails_before_any_transport_configuration() {
        let raw = r#"{
          "version":1,
          "default_profile":"missing",
          "profiles":[]
        }"#;
        let factory = factory(
            CredentialProfileCatalog::from_json(raw, std::path::Path::new("."))
                .expect("structurally valid catalog"),
        );
        let host = plan(
            TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
            &[22],
        );
        let error = factory
            .policy_for_plan(&host)
            .expect_err("missing named profile must fail closed");
        assert!(error.to_string().contains("is missing"));
    }
}
