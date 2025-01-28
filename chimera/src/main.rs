mod error;
mod logging;
mod modes;
mod server;
mod types;
mod utils;

use crate::modes::baseline::BaselineMode;
use crate::modes::credentials::{CredentialsMode, Magic};
use crate::modes::inventory::InventoryMode;
use crate::modes::serve::{ServeConfig, ServeMode};
use crate::modes::ModeExecutor;
use crate::types::{ExecutionMode, ExecutionResult};
use clap::{arg, command, value_parser, Command};
use log::{error, info};
use utils::get_default_output_dir;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub async fn run_baseline() -> ExecutionResult {
    let current_exe = std::env::current_exe().expect("Failed to get current executable path");

    #[cfg(windows)]
    {
        // Windows-specific implementation using schtasks
        let task_name = "ChimeraBaseline";
        let current_exe_str = current_exe.to_string_lossy();

        // Create and run the scheduled task
        let create_result = tokio::process::Command::new("schtasks")
            .args(&[
                "/create",
                "/tn",
                task_name,
                "/tr",
                &format!("\"{}\" baseline", current_exe_str),
                "/sc",
                "once",
                "/st",
                &chrono::Local::now().format("%H:%M").to_string(),
                "/f",
                "/ru",
                "System",
            ])
            .output()
            .await;

        match create_result {
            Ok(_) => {
                // Run the task
                let run_result = tokio::process::Command::new("schtasks")
                    .args(&["/run", "/tn", task_name])
                    .output()
                    .await;

                match run_result {
                    Ok(_) => ExecutionResult::new(
                        ExecutionMode::Baseline,
                        true,
                        "Baseline started in background".to_string(),
                    ),
                    Err(e) => {
                        error!("Failed to run baseline scheduled task: {}", e);
                        ExecutionResult::new(
                            ExecutionMode::Baseline,
                            false,
                            format!("Failed to run baseline scheduled task: {}", e),
                        )
                    }
                }
            }
            Err(e) => {
                error!("Failed to create baseline scheduled task: {}", e);
                ExecutionResult::new(
                    ExecutionMode::Baseline,
                    false,
                    format!("Failed to create baseline scheduled task: {}", e),
                )
            }
        }
    }

    #[cfg(unix)]
    {
        use nix::unistd::execvp;
        use nix::unistd::{fork, ForkResult};
        use std::ffi::CString;

        match unsafe { fork() } {
            Ok(ForkResult::Parent { child: _ }) => ExecutionResult::new(
                ExecutionMode::Baseline,
                true,
                "Baseline started in background".to_string(),
            ),
            Ok(ForkResult::Child) => {
                // Convert the executable path and arguments to CString
                let exe = CString::new(current_exe.to_str().unwrap()).unwrap();
                let arg0 = CString::new("baseline").unwrap();

                // Replace the current process with baseline
                match execvp(&exe, &[&exe, &arg0]) {
                    Ok(_) => unreachable!(), // execvp never returns on success
                    Err(e) => {
                        error!("Failed to exec baseline: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                error!("Failed to fork baseline process: {}", e);
                ExecutionResult::new(
                    ExecutionMode::Baseline,
                    false,
                    format!("Failed to fork baseline process: {}", e),
                )
            }
        }
    }
}

async fn run_serve_mode(port: u16) -> ExecutionResult {
    let mode = ServeMode::new();
    info!("Starting serve mode on port {}", port);

    let config = ServeConfig {
        port,
    };
    mode.execute(config).await
}

async fn run_serve_internal(port: u16) -> ExecutionResult {
    info!("Starting internal serve mode on port {}", port);
    ServeMode::serve_internal(port).await
}

async fn run_inventory_mode(output_dir: &Path) -> ExecutionResult {
    let mode = InventoryMode::new();
    info!("Starting inventory mode execution");

    let result = mode.execute(None).await;

    let output_path = output_dir.join("inventory.json");
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

async fn run_credentials_mode(magic_value: u32) -> ExecutionResult {
    let mode = CredentialsMode;
    info!(
        "Starting credentials mode execution with magic value: {}",
        magic_value
    );

    mode.execute(Magic(magic_value)).await
}

async fn run_baseline_mode() -> ExecutionResult {
    let mode = BaselineMode;
    info!("Starting baseline mode execution");

    #[cfg(target_os = "windows")]
    info!("Platform: Windows");
    #[cfg(target_os = "linux")]
    info!("Platform: Linux");

    mode.execute(None).await
}

async fn run_update_mode() -> ExecutionResult {
    info!("Starting update mode execution");
    ExecutionResult::new(ExecutionMode::Update, true, "Update completed".to_string())
}

async fn run_all_modes(output_dir: &Path, magic_value: u32) {
    info!("Starting execution of all modes");

    let results = [
        run_credentials_mode(magic_value).await,
        run_inventory_mode(output_dir).await,
        run_update_mode().await,
        run_serve_mode(44372).await,
        run_baseline().await,
    ];

    let all_succeeded = results.iter().all(|r| r.success);
    let failed_modes: Vec<_> = results
        .iter()
        .filter(|r| !r.success)
        .map(|r| r.mode.as_str())
        .collect();

    if all_succeeded {
        info!("All modes completed successfully");
    } else {
        error!("Failed modes: {}", failed_modes.join(", "));
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = logging::init_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        return;
    }

    let output_dir = get_default_output_dir();

    fs::create_dir_all(&output_dir).expect("Failed to create output directory");

    let matches = command!()
        .subcommand(
            Command::new("all").about("Run all modes sequentially").arg(
                arg!(-m --magic <VALUE> "Magic number for credentials")
                    .required(true)
                    .value_parser(value_parser!(u32)),
            ),
        )
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
        .subcommand(
            Command::new("serve")
                .about("Start HTTP server for file access")
                .arg(
                    arg!(-p --port <PORT> "Port to serve on")
                        .default_value("44372")
                        .value_parser(value_parser!(u16)),
                ),
        )
        .subcommand(
            Command::new("serve-internal")
                .hide(true) // Hide this from help text
                .arg(
                    arg!(-p --port <PORT> "Port to serve on")
                        .required(true)
                        .value_parser(value_parser!(u16)),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("all", sub_matches)) => {
            let magic_value = sub_matches
                .get_one::<u32>("magic")
                .copied()
                .expect("Required argument");
            run_all_modes(&output_dir, magic_value).await;
        }
        Some(("inventory", _)) => {
            let _ = run_inventory_mode(&output_dir).await;
        }
        Some(("credentials", sub_matches)) => {
            let magic_value = sub_matches
                .get_one::<u32>("magic")
                .copied()
                .expect("Required argument");
            let _ = run_credentials_mode(magic_value).await;
        }
        Some(("baseline", _)) => {
            let _ = run_baseline_mode().await;
        }
        Some(("update", _)) => {
            let _ = run_update_mode().await;
        }
        Some(("serve", sub_matches)) => {
            let port = sub_matches.get_one::<u16>("port").copied().unwrap_or(44372);
            let _ = run_serve_mode(port).await;
        }
        Some(("serve-internal", sub_matches)) => {
            let port = sub_matches.get_one::<u16>("port").copied().unwrap_or(44372);
            let _ = run_serve_internal(port).await;
        }
        _ => {}
    }
}
