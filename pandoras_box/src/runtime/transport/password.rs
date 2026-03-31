use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use rustrc::ssh::HostKeyPolicy;

use crate::runtime::mission::{HostPlan, PlatformHint, TransportKind};
use crate::runtime::session_factory::{BoxedHostSession, SessionFactory};
use crate::runtime::transport::smb::{SmbSession, SmbSessionConfig};
use crate::runtime::transport::ssh::{SshAuth, SshSession, SshSessionConfig};
use crate::runtime::workspace::RemoteShell;
use crate::{Error, Result};

const DEFAULT_SMB_PORT: u16 = 445;
const DEFAULT_SMB_STAGING_DIRECTORY: &str = r"Temp\pandoras_box";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSessionFactory {
    unix_username: String,
    windows_username: String,
    password: String,
    ssh_port: u16,
    smb_port_hints: Vec<u16>,
    inactivity_timeout: Duration,
}

impl PasswordSessionFactory {
    #[must_use]
    pub fn new(
        unix_username: impl Into<String>,
        windows_username: impl Into<String>,
        password: impl Into<String>,
        ssh_port: u16,
        smb_port_hints: Vec<u16>,
        inactivity_timeout: Duration,
    ) -> Self {
        Self {
            unix_username: unix_username.into(),
            windows_username: windows_username.into(),
            password: password.into(),
            ssh_port,
            smb_port_hints,
            inactivity_timeout,
        }
    }

    fn ssh_config_for_plan(
        &self,
        plan: &HostPlan,
        transport: TransportKind,
    ) -> Result<SshSessionConfig> {
        let (username, shell) = match transport {
            TransportKind::UnixSsh => (self.unix_username.clone(), RemoteShell::Posix),
            TransportKind::WindowsSsh => (self.windows_username.clone(), RemoteShell::Cmd),
            TransportKind::WindowsSmb => {
                return Err(Error::CommunicatorError(
                    "cannot build SSH config for SMB transport".to_string(),
                ));
            }
        };

        if !plan.target.has_port(self.ssh_port) {
            return Err(Error::NoSSHPort);
        }

        Ok(SshSessionConfig {
            socket: SocketAddr::new(plan.target.ip, self.ssh_port),
            auth: SshAuth::Password {
                username,
                password: self.password.clone(),
            },
            inactivity_timeout: self.inactivity_timeout,
            shell,
            host_key_policy: HostKeyPolicy::MatchKnownHostsIfPresent,
        })
    }

    fn smb_config_for_plan(&self, plan: &HostPlan) -> Result<SmbSessionConfig> {
        let port = self.resolve_smb_port(plan).ok_or_else(|| {
            Error::CommunicatorError(format!(
                "no reachable SMB port discovered for {}",
                plan.target.ip
            ))
        })?;

        Ok(SmbSessionConfig {
            socket: SocketAddr::new(plan.target.ip, port),
            username: self.windows_username.clone(),
            password: self.password.clone(),
            staging_directory: DEFAULT_SMB_STAGING_DIRECTORY.to_string(),
        })
    }

    fn resolve_smb_port(&self, plan: &HostPlan) -> Option<u16> {
        if plan.target.has_port(DEFAULT_SMB_PORT) {
            return Some(DEFAULT_SMB_PORT);
        }

        self.smb_port_hints
            .iter()
            .copied()
            .find(|port| plan.target.has_port(*port))
    }
}

#[async_trait]
impl SessionFactory for PasswordSessionFactory {
    async fn connect(&self, plan: &HostPlan, transport: TransportKind) -> Result<BoxedHostSession> {
        match transport {
            TransportKind::UnixSsh | TransportKind::WindowsSsh => {
                let config = self.ssh_config_for_plan(plan, transport)?;
                Ok(Box::new(SshSession::connect(&config).await?))
            }
            TransportKind::WindowsSmb => {
                if plan.target.platform == PlatformHint::Unix {
                    return Err(Error::CommunicatorError(
                        "SMB transport is not valid for Unix targets".to_string(),
                    ));
                }
                let config = self.smb_config_for_plan(plan)?;
                Ok(Box::new(SmbSession::connect(&config).await?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PasswordSessionFactory;
    use crate::runtime::mission::{HostPlan, HostState, HostTarget, PlatformHint, TransportKind};
    use crate::runtime::transport::ssh::SshAuth;
    use crate::runtime::workspace::RemoteShell;
    use crate::Error;
    use rustrc::ssh::HostKeyPolicy;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    fn plan(platform: PlatformHint, open_ports: &[u16]) -> HostPlan {
        HostPlan {
            target: HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)),
                platform,
                open_ports: open_ports.to_vec(),
            },
            state: HostState::Queued,
            transport_chain: vec![],
        }
    }

    #[test]
    fn ssh_config_for_plan_uses_unix_credentials_for_unix_ssh() {
        let factory = PasswordSessionFactory::new(
            "root",
            "Administrator",
            "secret",
            22,
            Vec::new(),
            Duration::from_secs(5),
        );

        let config = factory
            .ssh_config_for_plan(&plan(PlatformHint::Unix, &[22]), TransportKind::UnixSsh)
            .expect("unix ssh should build config");

        assert_eq!(
            config.socket,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22)
        );
        assert_eq!(config.inactivity_timeout, Duration::from_secs(5));
        assert_eq!(config.shell, RemoteShell::Posix);
        assert_eq!(
            config.host_key_policy,
            HostKeyPolicy::MatchKnownHostsIfPresent
        );
        assert_eq!(
            config.auth,
            SshAuth::Password {
                username: "root".to_string(),
                password: "secret".to_string(),
            }
        );
    }

    #[test]
    fn ssh_config_for_plan_uses_windows_credentials_for_windows_ssh() {
        let factory = PasswordSessionFactory::new(
            "root",
            "Administrator",
            "secret",
            22,
            Vec::new(),
            Duration::from_secs(5),
        );

        let config = factory
            .ssh_config_for_plan(
                &plan(PlatformHint::Windows, &[22, 445]),
                TransportKind::WindowsSsh,
            )
            .expect("windows ssh should build config");

        assert_eq!(
            config.auth,
            SshAuth::Password {
                username: "Administrator".to_string(),
                password: "secret".to_string(),
            }
        );
        assert_eq!(config.shell, RemoteShell::Cmd);
    }

    #[test]
    fn ssh_config_for_plan_rejects_hosts_without_ssh() {
        let factory = PasswordSessionFactory::new(
            "root",
            "Administrator",
            "secret",
            22,
            Vec::new(),
            Duration::from_secs(5),
        );

        let error = factory
            .ssh_config_for_plan(
                &plan(PlatformHint::Windows, &[445]),
                TransportKind::WindowsSsh,
            )
            .expect_err("missing port 22 should fail");

        assert!(matches!(error, Error::NoSSHPort));
    }

    #[test]
    fn smb_config_for_plan_prefers_standard_port_445() {
        let factory = PasswordSessionFactory::new(
            "root",
            "Administrator",
            "secret",
            22,
            vec![4445],
            Duration::from_secs(5),
        );

        let config = factory
            .smb_config_for_plan(&plan(PlatformHint::Windows, &[445, 4445]))
            .expect("445 should win when available");

        assert_eq!(
            config.socket,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 445)
        );
        assert_eq!(config.username, "Administrator");
        assert_eq!(config.password, "secret");
        assert_eq!(config.staging_directory, r"Temp\pandoras_box");
    }

    #[test]
    fn smb_config_for_plan_uses_forwarded_port_when_needed() {
        let factory = PasswordSessionFactory::new(
            "root",
            "Administrator",
            "secret",
            22,
            vec![4445],
            Duration::from_secs(5),
        );

        let config = factory
            .smb_config_for_plan(&plan(PlatformHint::Windows, &[4445]))
            .expect("forwarded smb port should be usable");

        assert_eq!(
            config.socket,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 4445)
        );
    }

    #[test]
    fn smb_config_for_plan_rejects_139_only_targets() {
        let factory = PasswordSessionFactory::new(
            "root",
            "Administrator",
            "secret",
            22,
            vec![4445],
            Duration::from_secs(5),
        );

        let error = factory
            .smb_config_for_plan(&plan(PlatformHint::Windows, &[139]))
            .expect_err("139-only targets should not look usable yet");

        assert!(matches!(error, Error::CommunicatorError(_)));
    }
}
