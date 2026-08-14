mod error;
mod logging;
mod modes;
mod types;
mod utils;

use crate::modes::collector::{CollectorConfig, CollectorMode};
use crate::modes::inventory::InventoryMode;
use crate::modes::ModeExecutor;
use crate::types::{ExecutionMode, ExecutionResult};
use crate::utils::{get_default_output_dir, set_output_root, INVENTORY_FILENAME};
use clap::{arg, command, value_parser, Command};
use log::{error, info};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use sysinfo::System;
use sysinfo::SystemExt;

async fn run_inventory_mode(output_dir: &Path, use_hostname_for_output: bool) -> ExecutionResult {
    let mode = InventoryMode::new();
    info!("Starting inventory mode execution");

    let result = mode.execute(None).await;

    let filename = if use_hostname_for_output {
        let s = System::new();
        let host_name = s.host_name().unwrap_or_else(|| "<unknown>".to_owned());
        format!("{}.json", host_name)
    } else {
        String::from(INVENTORY_FILENAME)
    };

    let output_path = output_dir.join(filename);
    match File::create(&output_path) {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{}", result.message) {
                return ExecutionResult::new(
                    ExecutionMode::Inventory,
                    false,
                    format!("Failed to write inventory data: {}", e),
                );
            }
            info!("Successfully wrote inventory data");
        }
        Err(e) => {
            return ExecutionResult::new(
                ExecutionMode::Inventory,
                false,
                format!("Failed to create inventory file: {}", e),
            );
        }
    }

    result
}

async fn run_collector_mode(output_dir: PathBuf) -> ExecutionResult {
    let mode = CollectorMode::new();
    info!(
        "Starting collector mode execution with output root {}",
        output_dir.display()
    );
    mode.execute(CollectorConfig { output_dir }).await
}

fn build_cli() -> Command {
    command!()
        .arg(
            arg!(--"output-root" <PATH> "Directory for collector artifacts")
                .global(true)
                .value_parser(value_parser!(String)),
        )
        .subcommand(
            Command::new("inventory")
                .about("Perform system inventory")
                .arg(
                    arg!(-o --output <VALUE> "Output and file name path for inventory")
                        .value_parser(value_parser!(String)),
                ),
        )
        .subcommand(
            Command::new("collector")
                .about("Write Pandora runtime artifacts for authenticated retrieval"),
        )
}

fn logging_config_for(subcommand: Option<&str>) -> logging::LoggingConfig {
    match subcommand {
        Some("collector") => logging::LoggingConfig::truncate_file(),
        _ => logging::LoggingConfig::append_file(),
    }
}

#[tokio::main]
async fn main() {
    let matches = build_cli().get_matches();

    if let Some(output_root) = matches.get_one::<String>("output-root") {
        set_output_root(output_root);
    }

    if let Err(error) = logging::init_logging(logging_config_for(matches.subcommand_name())) {
        eprintln!("Failed to initialize logging: {error}");
        std::process::exit(1);
    }

    let mut output_dir = get_default_output_dir();

    if let Err(error) = fs::create_dir_all(&output_dir) {
        error!("Failed to create output directory: {error}");
        std::process::exit(1);
    }

    match matches.subcommand() {
        Some(("collector", _)) => {
            let result = run_collector_mode(output_dir.clone()).await;
            if !result.success {
                error!("Collector mode failed: {}", result.message);
                std::process::exit(1);
            }
        }
        Some(("inventory", sub_matches)) => {
            let output_path = sub_matches;
            // Check whether the user gave a custom path
            let use_hostname_for_output = output_path.get_one::<String>("output").is_some();

            if let Some(custom_path) = output_path.get_one::<String>("output") {
                output_dir = PathBuf::from(custom_path);
            }

            let result = run_inventory_mode(&output_dir, use_hostname_for_output).await;
            if !result.success {
                error!("Inventory mode failed: {}", result.message);
                std::process::exit(1);
            }
        }
        _ => {}
    }
}
