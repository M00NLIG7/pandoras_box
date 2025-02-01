use super::ModeExecutor;
use crate::server::FileServer;
use crate::types::{ExecutionMode, ExecutionResult};
use crate::utils::get_default_output_dir;
use log::{error, info};
use std::process;
use tokio::spawn;

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
                format!("Failed to create output directory: {}", e),
            );
        }

        info!("Starting file server on port {} in background", config.port);
        let current_exe = std::env::current_exe().expect("Failed to get current executable path");

        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::System::Threading::{
                CreateProcessW, CREATE_NO_WINDOW, DETACHED_PROCESS, PROCESS_INFORMATION,
                STARTUPINFOW,
            };

            // Prepare command line
            let mut cmd = format!(
                "\"{}\" serve-internal --port {}",
                current_exe.to_string_lossy(),
                config.port
            );

            // Convert to wide string for Windows API
            let wide_cmd: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

            let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

            let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

            // Create detached process
            let success = unsafe {
                CreateProcessW(
                    std::ptr::null(),
                    wide_cmd.as_ptr() as *mut _,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    DETACHED_PROCESS | CREATE_NO_WINDOW,
                    std::ptr::null(),
                    std::ptr::null(),
                    &startup_info,
                    &mut process_info,
                )
            };

            if success == 0 {
                let error = std::io::Error::last_os_error();
                error!("Failed to create background process: {}", error);
                ExecutionResult::new(
                    ExecutionMode::Serve,
                    false,
                    format!("Failed to create background process: {}", error),
                )
            } else {
                // Close handle immediately since we don't need them
                unsafe {
                    CloseHandle(process_info.hProcess);
                    CloseHandle(process_info.hThread);
                }

                ExecutionResult::new(
                    ExecutionMode::Serve,
                    true,
                    format!("Server started in background on port {}", config.port),
                )
            }
        }

        #[cfg(unix)]
        {
            use nix::unistd::execvp;
            use nix::unistd::{fork, ForkResult};
            use std::ffi::CString;

            match unsafe { fork() } {
                Ok(ForkResult::Parent { child: _ }) => ExecutionResult::new(
                    ExecutionMode::Serve,
                    true,
                    format!("Server started in background on port {}", config.port),
                ),
                Ok(ForkResult::Child) => {
                    // Convert the executable path and arguments to CString
                    let exe = CString::new(current_exe.to_str().unwrap()).unwrap();
                    let arg0 = CString::new("serve-internal").unwrap();
                    let arg1 = CString::new("--port").unwrap();
                    let arg2 = CString::new(config.port.to_string()).unwrap();

                    // Replace the current process with serve-internal
                    match execvp(&exe, &[&exe, &arg0, &arg1, &arg2]) {
                        Ok(_) => unreachable!(), // execvp never returns on success
                        Err(e) => {
                            error!("Failed to exec: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to fork process: {}", e);
                    ExecutionResult::new(
                        ExecutionMode::Serve,
                        false,
                        format!("Failed to fork process: {}", e),
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
                format!("Failed to create output directory: {}", e),
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
                format!("Server completed successfully on port {}", port),
            ),
            Err(e) => {
                error!("Server failed: {}", e);
                ExecutionResult::new(ExecutionMode::Serve, false, format!("Server failed: {}", e))
            }
        }
    }
}
