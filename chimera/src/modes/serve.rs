use std::path::PathBuf;
use super::ModeExecutor;
use crate::types::{ExecutionMode, ExecutionResult};
use crate::server::FileServer;
use log::{error, info};
use tokio::spawn;
use std::process;

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
        let output_dir = PathBuf::from("./output");
        
        info!("Starting file server on port {} in background", config.port);

        // Start the server in a detached process
        let current_exe = std::env::current_exe()
            .expect("Failed to get current executable path");
        
        // Fork the process using tokio::process
        let child = tokio::process::Command::new(current_exe)
            .arg("serve-internal")  // New internal command
            .arg("--port")
            .arg(config.port.to_string())
            .spawn();

        match child {
            Ok(_) => {
                info!("File server started in background on port {}", config.port);
                ExecutionResult::new(
                    ExecutionMode::Serve,
                    true,
                    format!("Server started in background on port {}", config.port)
                )
            },
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

impl ServeMode {
    pub fn new() -> Self {
        Self
    }

    // This is called by the internal serve command
    pub async fn serve_internal(port: u16) -> ExecutionResult {
        let output_dir = PathBuf::from("./output");
        
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
                        // Use process::exit since we're in a forked process
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
