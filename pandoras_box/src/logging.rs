use crate::error::Error;
use log::{error, info, warn};
use std::fmt::Display; // Make sure to import your specific Error type

pub fn log_success<T: Display, U: Display>(operation: T, target: U) {
    info!("Successfully {}: {}", operation, target);
}

pub fn log_failure<T: Display, U: Display, E: Display>(operation: T, target: U, error: E) {
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

pub fn log_results<T, I>(results: I, operation: &str, target: &str)
where
    I: IntoIterator<Item = Result<T, Error>>,
{
    for (index, result) in results.into_iter().enumerate() {
        match result {
            Ok(_) => log_success(format!("{} ({})", operation, index), target),
            Err(e) => log_failure(format!("{} ({})", operation, index), target, e),
        }
    }
}


