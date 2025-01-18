use std::path::PathBuf;
use super::ModeExecutor;
use crate::types::{ExecutionMode, ExecutionResult};
use crate::server::FileServer;
use crate::utils::get_default_output_dir;
use log::{error, info};
use tokio::spawn;
use std::process;
use chrono;


#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub port: u16,
}

pub struct ServeMode;

impl ModeExecutor for ServeMode {
    type Args = ServeConfig;
    type ArgRequirement = super::Required;

    async fn execute(&self, args: Self::Args) -> ExecutionResult {
        let config = args;
        let output_dir = get_default_output_dir();
        
        // Ensure output directory exists
        if let Err(e) = std::fs::create_dir_all(&output_dir) {
            error!("Failed to create output directory: {}", e);
            return ExecutionResult::new(
                ExecutionMode::Serve,
                false,
                format!("Failed to create output directory: {}", e)
            );
        }

        info!("Starting file server on port {} in background", config.port);
        let current_exe = std::env::current_exe()
            .expect("Failed to get current executable path");
        
        #[cfg(windows)]
        {
            // Windows-specific implementation using schtasks
            let task_name = format!("ChimeraServer_{}", config.port);
            let current_exe_str = current_exe.to_string_lossy();
            
            // Create and run the scheduled task
            let create_result = tokio::process::Command::new("schtasks")
                .args(&[
                    "/create",
                    "/tn", &task_name,
                    "/tr", &format!("\"{}\" serve-internal --port {}", 
                        current_exe_str, 
                        config.port
                    ),
                    "/sc", "once",
                    "/st", &chrono::Local::now().format("%H:%M").to_string(),
                    "/f",
                    "/ru", "System"
                ])
                .output()
                .await;

            match create_result {
                Ok(_) => {
                    // Run the task
                    let run_result = tokio::process::Command::new("schtasks")
                        .args(&["/run", "/tn", &task_name])
                        .output()
                        .await;

                    match run_result {
                        Ok(_) => ExecutionResult::new(
                            ExecutionMode::Serve,
                            true,
                            format!("Server started in background on port {}", config.port)
                        ),
                        Err(e) => {
                            error!("Failed to run scheduled task: {}", e);
                            ExecutionResult::new(
                                ExecutionMode::Serve,
                                false,
                                format!("Failed to run scheduled task: {}", e)
                            )
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to create scheduled task: {}", e);
                    ExecutionResult::new(
                        ExecutionMode::Serve,
                        false,
                        format!("Failed to create scheduled task: {}", e)
                    )
                }
            }
        }

        #[cfg(unix)]
        {
            // Unix implementation using regular process spawning
            let child = tokio::process::Command::new(current_exe)
                .arg("serve-internal")
                .arg("--port")
                .arg(config.port.to_string())
                .spawn();

            match child {
                Ok(_) => ExecutionResult::new(
                    ExecutionMode::Serve,
                    true,
                    format!("Server started in background on port {}", config.port)
                ),
                Err(e) => {
                    error!("Failed to start background server: {}", e);
                    ExecutionResult::new(
                        ExecutionMode::Serve,
                        false,
                        format!("Failed to start background server: {}", e)
                    )
                }
            }
        }
    }
}

impl ServeMode {
    pub fn new() -> Self {
        Self
    }

    pub async fn serve_internal(port: u16) -> ExecutionResult {
        let output_dir = get_default_output_dir();
        
        // Ensure output directory exists
        if let Err(e) = std::fs::create_dir_all(&output_dir) {
            error!("Failed to create output directory: {}", e);
            return ExecutionResult::new(
                ExecutionMode::Serve,
                false,
                format!("Failed to create output directory: {}", e)
            );
        }
        
        // Create the server without a timeout
        let server = FileServer::new(output_dir.clone(), port);
        
        // Start a monitoring task
        let monitor_handle = spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                
                // Check if output directory is empty
                if let Ok(entries) = std::fs::read_dir(&output_dir) {
                    if entries.count() == 0 {
                        info!("Output directory is empty, shutting down server");
                        process::exit(0);
                    }
                }
            }
        });

        // Run the server
        match server.serve().await {
            Ok(_) => ExecutionResult::new(
                ExecutionMode::Serve,
                true,
                format!("Server completed successfully on port {}", port)
            ),
            Err(e) => {
                error!("Server failed: {}", e);
                ExecutionResult::new(
                    ExecutionMode::Serve,
                    false,
                    format!("Server failed: {}", e)
                )
            }
        }
    }
}
