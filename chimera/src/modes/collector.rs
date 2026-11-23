use super::inventory::InventoryMode;
use super::ModeExecutor;
use crate::types::{ExecutionMode, ExecutionResult};
use crate::utils::INVENTORY_FILENAME;
use log::{error, info};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CollectorConfig {
    pub output_dir: PathBuf,
}

pub struct CollectorMode;

impl ModeExecutor for CollectorMode {
    type Args = CollectorConfig;
    type ArgRequirement = super::Required;

    async fn execute(&self, args: Self::Args) -> ExecutionResult {
        if let Err(e) = std::fs::create_dir_all(&args.output_dir) {
            error!("Failed to create collector output directory: {}", e);
            return ExecutionResult::new(
                ExecutionMode::Collector,
                false,
                format!("Failed to create output directory: {}", e),
            );
        }

        let inventory_path = args.output_dir.join(INVENTORY_FILENAME);
        if let Err(e) = remove_existing_inventory(&inventory_path) {
            error!("Failed to prepare inventory artifact: {}", e);
            return ExecutionResult::new(
                ExecutionMode::Collector,
                false,
                format!("Failed to prepare inventory artifact: {}", e),
            );
        }

        let inventory = InventoryMode::new().collect_inventory_json().await;
        let inventory = match inventory {
            Ok(inventory) => inventory,
            Err(e) => {
                error!("Collector inventory failed: {}", e);
                return ExecutionResult::new(
                    ExecutionMode::Collector,
                    false,
                    format!("Inventory collection failed: {}", e),
                );
            }
        };

        match std::fs::File::create(&inventory_path) {
            Ok(mut file) => {
                if let Err(e) = file.write_all(inventory.as_bytes()) {
                    error!("Failed to write inventory artifact: {}", e);
                    return ExecutionResult::new(
                        ExecutionMode::Collector,
                        false,
                        format!("Failed to write inventory artifact: {}", e),
                    );
                }
            }
            Err(e) => {
                error!("Failed to create inventory artifact: {}", e);
                return ExecutionResult::new(
                    ExecutionMode::Collector,
                    false,
                    format!("Failed to create inventory artifact: {}", e),
                );
            }
        }

        info!(
            "Collector artifacts are ready in {}",
            args.output_dir.display()
        );
        ExecutionResult::new(
            ExecutionMode::Collector,
            true,
            format!(
                "Collector wrote {} and application.log to {}",
                INVENTORY_FILENAME,
                args.output_dir.display()
            ),
        )
    }
}

impl CollectorMode {
    pub fn new() -> Self {
        Self
    }
}

fn remove_existing_inventory(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
