use super::ModeExecutor;
use crate::server::FileServer;
use crate::types::{ExecutionMode, ExecutionResult};
use crate::utils::get_default_output_dir;
use log::{error, info, warn};
use std::path::Path;
use tokio::spawn;

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::CloseHandle;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
    DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
};

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub port: u16,
}

pub struct ServeMode;

fn serve_internal_args(output_root: &Path, port: u16) -> Vec<String> {
    vec![
        "serve-internal".to_string(),
        "--port".to_string(),
        port.to_string(),
        "--output-root".to_string(),
        output_root.to_string_lossy().into_owned(),
    ]
}

#[cfg(windows)]
fn windows_command_line(current_exe: &Path, output_root: &Path, port: u16) -> String {
    let mut parts = Vec::with_capacity(1 + 5);
    parts.push(format!("\"{}\"", current_exe.to_string_lossy()));
    parts.extend(
        serve_internal_args(output_root, port)
            .into_iter()
            .map(|arg| format!("\"{}\"", arg.replace('"', "\\\""))),
    );
    parts.join(" ")
}

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

        // Check if port is already in use (server already running)
        // This makes the serve mode idempotent - safe to run multiple times
        let addr: std::net::SocketAddr = ([0, 0, 0, 0], config.port).into();
        match std::net::TcpListener::bind(addr) {
            Ok(_) => {
                // Port is available, proceed with starting server
                info!("Starting file server on port {} in background", config.port);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                // Port already in use - server is already running
                info!("File server already running on port {}", config.port);
                return ExecutionResult::new(
                    ExecutionMode::Serve,
                    true,
                    format!("Server already running on port {}", config.port),
                );
            }
            Err(e) => {
                // Other bind error
                error!("Failed to check port availability: {}", e);
                return ExecutionResult::new(
                    ExecutionMode::Serve,
                    false,
                    format!("Failed to check port {}: {}", config.port, e),
                );
            }
        }

        let current_exe = match std::env::current_exe() {
            Ok(path) => path,
            Err(e) => {
                error!("Failed to get current executable path: {}", e);
                return ExecutionResult::new(
                    ExecutionMode::Serve,
                    false,
                    format!("Failed to get current executable path: {}", e),
                );
            }
        };

        #[cfg(windows)]
        {
            // Prepare command line
            let mut cmd = windows_command_line(&current_exe, &output_dir, config.port);

            // Convert to wide string for Windows API
            let wide_cmd: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

            let mut startup_info: STARTUPINFOW = unsafe { std::mem::zeroed() };
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

            let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

            // Create fully independent process with combined flags
            let creation_flags = DETACHED_PROCESS
                | CREATE_NEW_PROCESS_GROUP
                | CREATE_NO_WINDOW
                | CREATE_BREAKAWAY_FROM_JOB;

            let success = unsafe {
                CreateProcessW(
                    std::ptr::null(),
                    wide_cmd.as_ptr() as *mut _,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    creation_flags,
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
                // Close handles immediately since we don't need them
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
                    // Handle errors gracefully since we're in child process
                    let exe_str = match current_exe.to_str() {
                        Some(s) => s,
                        None => {
                            error!("Executable path contains invalid UTF-8");
                            std::process::exit(1);
                        }
                    };

                    let exe = match CString::new(exe_str) {
                        Ok(c) => c,
                        Err(e) => {
                            error!("Executable path contains null bytes: {}", e);
                            std::process::exit(1);
                        }
                    };

                    let arg_values = serve_internal_args(&output_dir, config.port);
                    let arg_cstrings = match arg_values
                        .iter()
                        .map(|arg| CString::new(arg.as_str()))
                        .collect::<Result<Vec<_>, _>>()
                    {
                        Ok(values) => values,
                        Err(e) => {
                            error!("Serve arguments contain null bytes: {}", e);
                            std::process::exit(1);
                        }
                    };
                    let mut argv = Vec::with_capacity(1 + arg_cstrings.len());
                    argv.push(&exe);
                    argv.extend(arg_cstrings.iter());

                    // Replace the current process with serve-internal
                    match execvp(&exe, &argv) {
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
        let monitor_task = spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

                // Check if output directory is empty using async fs to avoid blocking
                match tokio::fs::read_dir(&output_dir).await {
                    Ok(mut entries) => {
                        // Check if there are any entries
                        match entries.next_entry().await {
                            Ok(None) => {
                                // Directory is empty
                                info!("Output directory is empty, triggering shutdown");
                                return;
                            }
                            Ok(Some(_)) => {
                                // Directory has files, continue monitoring
                            }
                            Err(e) => {
                                warn!("Error reading directory entry: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error reading directory: {}", e);
                    }
                }
            }
        });

        // Run the server and monitor task concurrently
        tokio::select! {
            result = server.serve() => {
                match result {
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
            },
            _ = monitor_task => {
                info!("Monitor task detected empty directory, shutting down gracefully");
                ExecutionResult::new(
                    ExecutionMode::Serve,
                    true,
                    "Server shutdown due to empty output directory".to_string(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::serve_internal_args;
    use std::path::Path;

    #[test]
    fn serve_internal_args_include_output_root() {
        let args = serve_internal_args(Path::new("/tmp/chimera-output"), 44_372);
        assert_eq!(
            args,
            vec![
                "serve-internal".to_string(),
                "--port".to_string(),
                "44372".to_string(),
                "--output-root".to_string(),
                "/tmp/chimera-output".to_string(),
            ]
        );
    }
}
