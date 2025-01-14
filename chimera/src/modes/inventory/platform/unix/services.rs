use futures::future::join_all;
use crate::utils::CommandExecutor;
use crate::types::{Service, ServiceStatus, ServiceStartType};
use crate::error::{Error, Result};

enum InitSystem {
    SYSTEMD,
    UPSTART,
    SYSVINIT,
    OPENRC,
    UNKNOWN,
}

impl InitSystem {
    async fn parse(&self) -> Result<Vec<Service>> {
        match self {
            InitSystem::SYSTEMD => Self::systemd().await,
            InitSystem::UPSTART => Self::upstart().await,
            InitSystem::SYSVINIT => Self::sysvinit().await,
            InitSystem::OPENRC => Self::openrc().await,
            InitSystem::UNKNOWN => Ok(Vec::new()),
        }
    }

    async fn systemd() -> Result<Vec<Service>> {
        let output = match CommandExecutor::execute_command(
            "systemctl",
            Some(&["list-units", "--type=service", "--no-pager"]),
            None,
        ).await {
            Ok(output) => output,
            Err(e) => {
                let err = Error::Execution(format!("Failed to execute systemctl: {}", e));
                err.log();
                return Err(err);
            }
        };

        let output_str = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<String> = output_str.lines().map(|s| s.to_string()).collect();
        
        let service_futures: Vec<_> = lines.iter()
            .filter_map(|line| split_service_line(line))
            .map(|(name, status)| async move {
                parse_service_line((&name, &status)).await
            })
            .collect();

        let results = join_all(service_futures).await;
        Ok(results.into_iter()
            .filter_map(|result| {
                match result {
                    Ok(service) => Some(service),
                    Err(e) => {
                        e.log();
                        None
                    }
                }
            })
            .collect())
    }

    async fn upstart() -> Result<Vec<Service>> {
        Ok(Vec::new())
    }

    async fn sysvinit() -> Result<Vec<Service>> {
        Ok(Vec::new())
    }

    async fn openrc() -> Result<Vec<Service>> {
        let output = match CommandExecutor::execute_command(
            "rc-status",
            Some(&["-a"]),
            None,
        ).await {
            Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
            Err(e) => {
                let err = Error::Execution(format!("Failed to execute rc-status: {}", e));
                err.log();
                return Err(err);
            }
        };

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
                    status: None,
                })
            })
            .collect())
    }
}

fn split_service_line(line: &str) -> Option<(String, String)> {
    const STATUS_KEYWORDS: [&str; 5] = ["loaded", "active", "running", "exited", "dead"];
    
    let split_index = STATUS_KEYWORDS.iter()
        .find_map(|&keyword| line.find(keyword));
        
    split_index.map(|index| {
        let (first, second) = line.split_at(index);
        (first.trim().to_string(), second.to_string())
    })
}

async fn fetch_service_start_mode(name: &str) -> Result<Option<ServiceStartType>> {
    let output = match CommandExecutor::execute_command(
        "systemctl",
        Some(&["is-enabled", name]),
        None,
    ).await {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(e) => {
            let err = Error::Execution(format!("Failed to check service enabled status: {}", e));
            err.log();
            return Err(err);
        }
    };

    Ok(match output.trim() {
        "enabled" => Some(ServiceStartType::Enabled),
        _ => Some(ServiceStartType::Disabled),
    })
}

async fn parse_service_line((name_part, status_part): (&str, &str)) -> Result<Service> {
    let mut status_parts = status_part.split_whitespace();
    let state = status_parts
        .next()
        .ok_or_else(|| {
            let err = Error::Execution("Failed to get service state".to_string());
            err.log();
            err
        })?
        .to_owned();

    let status_str = status_parts
        .next()
        .ok_or_else(|| {
            let err = Error::Execution("Failed to get service status".to_string());
            err.log();
            err
        })?;
    
    let status = match status_str {
        "active" => Some(ServiceStatus::Active),
        "inactive" => Some(ServiceStatus::Inactive),
        "failed" => Some(ServiceStatus::Failed),
        _ => Some(ServiceStatus::Unknown),
    };

    let mode = fetch_service_start_mode(name_part.trim()).await?;
    
    Ok(Service {
        name: name_part.trim().into(),
        state: state.into(),
        start_mode: mode,
        status,
    })
}

pub async fn detect_init_system() -> InitSystem {
    if which::which("systemctl").unwrap_or_default().exists() {
        InitSystem::SYSTEMD
    } else if which::which("open-rc").unwrap_or_default().exists() {
        InitSystem::OPENRC
    } else if which::which("initctl").unwrap_or_default().exists() {
        InitSystem::UPSTART
    } else if which::which("service").unwrap_or_default().exists() {
        InitSystem::SYSVINIT
    } else {
        InitSystem::UNKNOWN
    }
}

pub async fn services() -> Vec<Service> {
    detect_init_system().await.parse().await.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_list_services() {
        let init_system = detect_init_system().await;
        match init_system.parse().await {
            Ok(services) => {
                assert!(!services.is_empty(), "Should find at least some services");
                println!("Found {} services:", services.len());
                for service in services.iter().take(5) {
                    println!(
                        "Service: {}, State: {}, Start Mode: {:?}, Status: {:?}",
                        service.name, service.state, service.start_mode, service.status
                    );
                }
            },
            Err(e) => {
                e.log();
                panic!("Failed to list services: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_specific_service() {
        match fetch_service_start_mode("sshd").await {
            Ok(Some(mode)) => println!("SSH service start mode: {:?}", mode),
            Ok(None) => println!("SSH service status unknown"),
            Err(e) => {
                e.log();
                println!("Failed to fetch SSH service mode: {:?}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_parse_service_line() {
        let test_line = "sshd.service    loaded active running";
        if let Some((name, status)) = split_service_line(test_line) {
            match parse_service_line((&name, &status)).await {
                Ok(service) => {
                    assert_eq!(service.name, "sshd.service");
                    println!("Parsed service: {:?}", service);
                },
                Err(e) => {
                    e.log();
                    panic!("Failed to parse service line: {:?}", e);
                }
            }
        }
    }
}
