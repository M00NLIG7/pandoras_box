mod error;
mod logging;
mod modes;
mod types;
mod utils;

//use crate::modes::inventory::fetch_inventory;

use crate::modes::baseline::BaselineMode;
use crate::modes::credentials::{CredentialsMode, Magic};
use crate::modes::inventory::InventoryMode;
use crate::modes::ModeExecutor;
use crate::types::ExecutionResult;

use clap::{arg, command, value_parser, Command};
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
        .subcommand(
            Command::new("credentials")
                .about("Manage system credentials")
                .arg(
                    arg!(-m --magic <VALUE> "Magic number for credentials")
                        .required(true)
                        .value_parser(value_parser!(u32)),
                ),
        )
        .subcommand(Command::new("update").about("Perform system updates"))
        .subcommand(Command::new("baseline").about("Perform OS-specific configurations"))
        .get_matches();

    match matches.subcommand() {
        Some(("inventory", _)) => {
            let mode = InventoryMode::new();
            match mode.execute(None).await {
                ExecutionResult {
                    success: true,
                    message,
                    ..
                } => {
                    println!("{}", message);
                }
                ExecutionResult {
                    success: false,
                    message,
                    ..
                } => {
                    error!("Inventory failed: {}", message);
                }
            }
        }
        Some(("credentials", sub_matches)) => {
            let magic_value = sub_matches
                .get_one::<u32>("magic")
                .copied()
                .expect("Required argument");

            let mode = CredentialsMode;
            if let ExecutionResult {
                success: false,
                message,
                ..
            } = mode.execute(Magic(magic_value)).await
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
            } = mode.execute(None).await
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
