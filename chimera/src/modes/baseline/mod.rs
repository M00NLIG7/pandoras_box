mod platform;

use super::ModeExecutor;
use crate::error::Result;
use crate::types::{ExecutionMode, ExecutionResult};
use include_crypt::{include_crypt, EncryptedFile};
use log::{debug, error, info};

pub struct BaselineMode;

impl ModeExecutor for BaselineMode {
    async fn execute(&self) -> ExecutionResult {
        if let Err(e) = platform::establish_baseline().await {
            error!("Failed to establish baseline: {}", e);
            return ExecutionResult::new(
                ExecutionMode::Baseline,
                false,
                format!("Baseline establishment failed: {}", e),
            );
        }

        ExecutionResult::new(
            ExecutionMode::Baseline,
            true,
            "Credentials managed successfully".to_string(),
        )
    }
}

impl BaselineMode {
    pub fn new() -> Self {
        Self
    }
}
