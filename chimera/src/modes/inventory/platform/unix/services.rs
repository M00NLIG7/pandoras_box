use crate::error::{Error, Result};
use crate::types::{Service, ServiceStartType, ServiceStatus};
use crate::utils::CommandExecutor;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::OnceCell;

#[derive(Debug)]
pub enum InitSystem {
    Systemd(SystemdInit),
    OpenRc(OpenrcInit),
    Runit(RunitInit),
    S6(S6Init),
    Slackware(SlackwareInit),
}

impl InitSystem {
    async fn list_services(&self) -> Result<Vec<Service>> {
        match self {
            InitSystem::Systemd(init) => init.list_services().await,
            InitSystem::OpenRc(init) => init.list_services().await,
            InitSystem::Runit(init) => init.list_services().await,
            InitSystem::S6(init) => init.list_services().await,
            InitSystem::Slackware(init) => init.list_services().await,
        }
    }
}

#[derive(Debug)]
pub struct SystemdInit;
#[derive(Debug)]
pub struct OpenrcInit;
#[derive(Debug)]
pub struct RunitInit;
#[derive(Debug)]
pub struct S6Init;
#[derive(Debug)]
pub struct SlackwareInit {
    startup_cache: OnceCell<Arc<HashMap<String, ServiceStartType>>>,
}

macro_rules! define_init_system {
    ($type:ty, $binary:expr, $list_cmd:expr) => {
        impl $type {
            fn binary() -> &'static str {
                $binary
            }

            fn list_services_cmd() -> Vec<&'static str> {
                $list_cmd
            }

            async fn list_services(&self) -> Result<Vec<Service>> {
                let output = CommandExecutor::execute_command(
                    Self::binary(),
                    Some(&Self::list_services_cmd()),
                    None,
                )
                .await
                .map_err(|e| {
                    Error::Execution(format!("Failed to execute {}: {}", Self::binary(), e))
                })?;

                self.parse_services_output(&String::from_utf8_lossy(&output.stdout))
                    .await
            }
        }
    };
}

define_init_system!(
    SystemdInit,
    "systemctl",
    vec![
        "list-units",
        "--type=service",
        "--no-pager",
        "--no-legend",
        "--plain"
    ]
);
define_init_system!(OpenrcInit, "rc-status", vec!["-s"]);
define_init_system!(RunitInit, "sv", vec!["status", "/service/*"]);
define_init_system!(S6Init, "s6-rc", vec!["-a", "list"]);

impl SystemdInit {
    async fn parse_services_output(&self, output: &str) -> Result<Vec<Service>> {
        Ok(output
            .lines()
            .filter(|line| line.contains(".service"))
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                let name = parts.first()?;
                let active_state = *parts.get(2)?;
                let status = match active_state {
                    "active" => ServiceStatus::Active,
                    "inactive" => ServiceStatus::Inactive,
                    "failed" => ServiceStatus::Failed,
                    _ => ServiceStatus::Unknown,
                };
                Some(Service {
                    name: (*name).to_string(),
                    state: active_state.to_string(),
                    start_mode: None,
                    status: Some(status),
                })
            })
            .collect())
    }
}

impl OpenrcInit {
    async fn parse_services_output(&self, output: &str) -> Result<Vec<Service>> {
        Ok(output
            .lines()
            .filter(|line| !line.contains(':'))
            .filter_map(|line| {
                let (name, status) = line.split_once('[')?;
                let status = status.split_once(']')?.0.trim();
                Some(Service {
                    name: name.trim().into(),
                    state: status.into(),
                    start_mode: None,
                    status: Some(match status {
                        "started" => ServiceStatus::Active,
                        "stopped" => ServiceStatus::Inactive,
                        _ => ServiceStatus::Unknown,
                    }),
                })
            })
            .collect())
    }
}

impl RunitInit {
    async fn parse_services_output(&self, output: &str) -> Result<Vec<Service>> {
        Ok(output
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    Some(Service {
                        name: parts[0].trim().to_string(),
                        state: parts[1].trim().to_string(),
                        status: Some(match parts[1].trim() {
                            "run" => ServiceStatus::Active,
                            "down" => ServiceStatus::Inactive,
                            _ => ServiceStatus::Unknown,
                        }),
                        start_mode: None,
                    })
                } else {
                    None
                }
            })
            .collect())
    }
}

impl S6Init {
    async fn parse_services_output(&self, output: &str) -> Result<Vec<Service>> {
        Ok(output
            .lines()
            .filter_map(|line| {
                let name = line.trim();
                if !name.is_empty() {
                    Some(Service {
                        name: name.to_string(),
                        state: "unknown".to_string(),
                        status: None,
                        start_mode: None,
                    })
                } else {
                    None
                }
            })
            .collect())
    }
}

impl SlackwareInit {
    pub fn new() -> Self {
        Self {
            startup_cache: OnceCell::new(),
        }
    }

    async fn build_startup_cache(&self) -> HashMap<String, ServiceStartType> {
        let mut startup_map = HashMap::new();

        // Get list of all rc.init* files plus rc.M
        let mut files_to_check = Vec::new();
        if let Ok(entries) = fs::read_dir("/etc/rc.d").await {
            let mut entries = entries;
            while let Ok(Some(entry)) = entries.next_entry().await {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str == "rc.M" || name_str.starts_with("rc.inet") {
                    files_to_check.push(entry.path());
                }
            }
        }

        // Parse each file
        for file_path in files_to_check {
            if let Ok(content) = fs::read_to_string(&file_path).await {
                for line in content.lines() {
                    // Match patterns like: if [ -x /etc/rc.d/rc.samba ]; then
                    if let Some(service) = line
                        .trim()
                        .strip_prefix("if [ -x /etc/rc.d/rc.")
                        .and_then(|s| s.split(" ").next())
                        .and_then(|s| s.split("]").next())
                    {
                        startup_map
                            .insert(format!("rc.{}", service.trim()), ServiceStartType::Enabled);
                    }
                    // Match direct invocations like: /etc/rc.d/rc.samba start
                    else if let Some(service) = line
                        .trim()
                        .strip_prefix("/etc/rc.d/rc.")
                        .and_then(|s| s.split_whitespace().next())
                    {
                        startup_map.insert(format!("rc.{}", service), ServiceStartType::Enabled);
                    }
                }
            }
        }

        // Also check rc.local
        if let Ok(rc_local) = fs::read_to_string("/etc/rc.d/rc.local").await {
            for line in rc_local.lines() {
                if let Some(service) = line
                    .trim()
                    .strip_prefix("/etc/rc.d/rc.")
                    .and_then(|s| s.split_whitespace().next())
                {
                    startup_map.insert(format!("rc.{}", service), ServiceStartType::Enabled);
                }
            }
        }

        startup_map
    }

    async fn get_startup_cache(&self) -> Arc<HashMap<String, ServiceStartType>> {
        self.startup_cache
            .get_or_init(|| async { Arc::new(self.build_startup_cache().await) })
            .await
            .clone()
    }

    async fn list_services(&self) -> Result<Vec<Service>> {
        let mut services = Vec::new();

        // Check /etc/rc.d
        if let Ok(entries) = fs::read_dir("/etc/rc.d").await {
            let mut entries = entries;
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("rc.") && !name.ends_with("~") && !name.ends_with(".new") {
                        if let Ok(metadata) = fs::metadata(&path).await {
                            if metadata.permissions().mode() & 0o111 != 0 {
                                let status = self.get_service_status(name).await.ok();
                                let start_mode =
                                    self.get_service_start_type(name).await.ok().flatten();

                                services.push(Service {
                                    name: name.to_string(),
                                    state: "Unknown".to_string(),
                                    status,
                                    start_mode,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Check /etc/init.d
        if let Ok(entries) = fs::read_dir("/etc/init.d").await {
            let mut entries = entries;
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Some(name) = entry.file_name().to_str() {
                    if !name.starts_with('.') && !name.ends_with('~') {
                        let path = entry.path();
                        if let Ok(metadata) = fs::metadata(&path).await {
                            if metadata.permissions().mode() & 0o111 != 0 {
                                let status = self.get_service_status(name).await.ok();
                                let start_mode =
                                    self.get_service_start_type(name).await.ok().flatten();

                                services.push(Service {
                                    name: name.to_string(),
                                    state: "Unknown".to_string(),
                                    status,
                                    start_mode,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(services)
    }

    async fn get_service_status(&self, _: &str) -> Result<ServiceStatus> {
        Ok(ServiceStatus::Unknown)
    }

    async fn get_service_start_type(&self, name: &str) -> Result<Option<ServiceStartType>> {
        let cache = self.get_startup_cache().await;
        Ok(Some(
            cache
                .get(name)
                .copied()
                .unwrap_or(ServiceStartType::Disabled),
        ))
    }
}

pub async fn detect_init_system() -> InitSystem {
    if let Ok(output) = tokio::fs::read_link("/proc/1/exe").await {
        if let Some(init_path) = output.to_str() {
            match init_path {
                path if path.contains("systemd") => return InitSystem::Systemd(SystemdInit),
                path if path.contains("openrc") => return InitSystem::OpenRc(OpenrcInit),
                path if path.contains("runit") => return InitSystem::Runit(RunitInit),
                path if path.contains("s6") => return InitSystem::S6(S6Init),
                _ => (),
            }
        }
    }

    // Check for Slackware-specific directories
    if tokio::fs::metadata("/etc/rc.d").await.is_ok()
        && tokio::fs::metadata("/etc/slackware-version").await.is_ok()
    {
        return InitSystem::Slackware(SlackwareInit::new());
    }

    // Rest of the detection logic remains the same...
    if tokio::fs::metadata("/run/systemd/system").await.is_ok() {
        InitSystem::Systemd(SystemdInit)
    } else if tokio::fs::metadata("/run/openrc").await.is_ok() {
        InitSystem::OpenRc(OpenrcInit)
    } else if which::which(SystemdInit::binary()).is_ok() {
        InitSystem::Systemd(SystemdInit)
    } else if which::which(OpenrcInit::binary()).is_ok() {
        InitSystem::OpenRc(OpenrcInit)
    } else if which::which(RunitInit::binary()).is_ok() {
        InitSystem::Runit(RunitInit)
    } else if which::which(S6Init::binary()).is_ok() {
        InitSystem::S6(S6Init)
    } else {
        InitSystem::Systemd(SystemdInit)
    }
}

pub async fn services() -> Result<Vec<Service>> {
    detect_init_system().await.list_services().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_systemd_service_fixture() {
        let fixture = "sshd.service loaded active running OpenSSH daemon\nfailed.service loaded failed failed Broken service\ninvalid\n";
        let services = SystemdInit
            .parse_services_output(fixture)
            .await
            .expect("fixture should parse");

        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, "sshd.service");
        assert_eq!(services[0].status, Some(ServiceStatus::Active));
        assert_eq!(services[1].status, Some(ServiceStatus::Failed));
    }
}
