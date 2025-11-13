use crate::communicator::HostOperationResult;
use crate::error::Error;
use crate::Host;
use rustrc::client::CommandOutput;
use std::collections::HashMap;
use std::sync::Arc;

use log::{error, info, warn};
use std::fmt::Display; // Make sure to import your specific Error type

pub fn log_success<T: Display, U: Display>(operation: T, target: U) {
    info!("Successfully {}: {}", operation, target);
}

pub fn log_failure<T: Display, U: Display, E: Display>(operation: T, target: U, error: &E) {
    error!("Failed to {}: {}. Error: {}", operation, target, error);
}

pub fn log_skipped<T: Display, U: Display>(operation: T, target: U, reason: &str) {
    warn!("Skipped {} for {}: {}", operation, target, reason);
}

pub fn log_output(stdout: &[u8], stderr: &[u8]) {
    if !stdout.is_empty() {
        info!("Stdout: {}", String::from_utf8_lossy(stdout));
    }
    if !stderr.is_empty() {
        warn!("Stderr: {}", String::from_utf8_lossy(stderr));
    }
}

/*
        let mut results: Vec<_> = mkdir_results.into_iter().filter_map(|md| {
            let host = host_map.get(&md.ip).unwrap();

            match md.result {
                Ok(_) => {
                    log_success("Directory created", &md.ip.to_string());
                    Some((Arc::clone(host), Ok(())))
                }
                Err(e) => {
                    log_failure("Directory creation failed: ", &md.ip.to_string(), &e);
                    Some((Arc::clone(host), Err(e)))
                }
            }
        }).collect();

*/
pub fn log_host_results(
    results: Vec<HostOperationResult<CommandOutput>>,
    host_map: &HashMap<String, Arc<Host>>,
    operation: &str,
) -> Vec<(Arc<Host>, crate::Result<()>)> {
    results
        .into_iter()
        .filter_map(|md| {
            match host_map.get(&md.ip) {
                Some(host) => {
                    match md.result {
                        Ok(output) => {
                            log_success(format!("{} on", operation), &host);
                            // Log stdout/stderr for better debugging
                            if !output.stdout.is_empty() {
                                info!("[{}] Command stdout: {}", md.ip, String::from_utf8_lossy(&output.stdout).trim());
                            }
                            if !output.stderr.is_empty() {
                                warn!("[{}] Command stderr: {}", md.ip, String::from_utf8_lossy(&output.stderr).trim());
                            }
                            Some((Arc::clone(host), Ok(())))
                        }
                        Err(e) => {
                            log_failure(format!("{} on", operation), &host, &e);
                            Some((Arc::clone(host), Err(e)))
                        }
                    }
                }
                None => {
                    error!("Host {} not found in host_map, skipping", md.ip);
                    None
                }
            }
        })
        .collect()
}

pub fn log_results<T, I>(results: I, operation: &str, target: &str)
where
    I: IntoIterator<Item = Result<T, Error>>,
{
    for (index, result) in results.into_iter().enumerate() {
        match result {
            Ok(_) => log_success(format!("{} ({})", operation, index), target),
            Err(e) => log_failure(format!("{} ({})", operation, index), target, &e),
        }
    }
}
