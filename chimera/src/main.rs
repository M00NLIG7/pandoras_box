mod error;
mod modes;
mod logging;
mod utils;
mod types;

use crate::modes::inventory::fetch_inventory;

use crate::types::ExecutionResult;
use crate::modes::credentials::CredentialsMode;
use crate::modes::baseline::BaselineMode;
use crate::modes::ModeExecutor;

use clap::{arg, command, Command};
use log::error;

#[tokio::main]
async fn main() {
    // Initialize logging
    if let Err(e) = logging::init_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        return;
    }

    let matches = command!()
        .subcommand(Command::new("inventory").about("Perform system inventory"))
        .subcommand(Command::new("credentials").about("Manage system credentials"))
        .subcommand(Command::new("update").about("Perform system updates"))
        .subcommand(Command::new("baseline").about("Perform OS-specific configurations"))
        .get_matches();

    match matches.subcommand() {
        Some(("inventory", _)) => {
            // inventory JSON
            println!("{}", serde_json::to_string_pretty(&fetch_inventory().await).unwrap());
        }
        Some(("credentials", _)) => {
            // Handle credential management
            let mode = CredentialsMode;
            if let ExecutionResult {
                success: false,
                message,
                ..
            } = mode.execute().await
            {
                error!("Credential management failed: {}", message);
            }
        }
        Some(("update", _)) => {
            // Handle system update
        }
        Some(("baseline", _)) => {
            let mode = BaselineMode;
            if let ExecutionResult {
                success: false,
                message,
                ..
            } = mode.execute().await
            {
                error!("Baseline configuration failed: {}", message);
            }
            #[cfg(target_os = "windows")]
            { /* Windows specific tasks */ }
            #[cfg(target_os = "linux")]
            { /* Linux specific tasks */ }
        }
        _ => {}
    }
}
