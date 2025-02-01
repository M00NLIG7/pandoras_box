use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use log::{error, info, warn};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::time::timeout;

#[cfg(target_os = "windows")]
use tokio::process::Command;

pub struct FileServer {
    root_dir: Arc<PathBuf>,
    port: u16,
    #[cfg(target_os = "windows")]
    rule_name: String,
    shutdown_flag: Arc<AtomicBool>,
}

impl FileServer {
    pub fn new(root_dir: PathBuf, port: u16) -> Self {
        #[cfg(target_os = "windows")]
        let rule_name = format!("ChimeraFileServer_{}", port);

        #[cfg(target_os = "windows")]
        return Self {
            root_dir: Arc::new(root_dir),
            port,
            rule_name,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        };

        #[cfg(not(target_os = "windows"))]
        Self {
            root_dir: Arc::new(root_dir),
            port,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(target_os = "windows")]
    async fn configure_windows_firewall(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Starting Windows Firewall configuration for port {}",
            self.port
        );

        // First check if the rule already exists
        info!(
            "Checking for existing firewall rule '{}'...",
            self.rule_name
        );
        let should_create_rule = match timeout(
            Duration::from_secs(5),
            Command::new("netsh")
                .args(&[
                    "advfirewall",
                    "firewall",
                    "show",
                    "rule",
                    &format!("name={}", self.rule_name),
                ])
                .output(),
        )
        .await
        {
            Ok(output) => {
                match output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        !stdout.contains(&self.rule_name)
                    }
                    Err(e) => {
                        warn!(
                            "Failed to execute firewall check command: {}. Will attempt to create rule.",
                            e
                        );
                        true
                    }
                }
            }
            Err(_) => {
                warn!("Firewall check command timed out after 5 seconds. Will attempt to create rule.");
                true
            }
        };

        // If we should create the rule (either because it doesn't exist or we couldn't check)
        if should_create_rule {
            info!("Attempting to create firewall rule...");

            match Command::new("netsh")
                .args(&[
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", self.rule_name),
                    "dir=in",
                    "action=allow",
                    &format!("localport={}", self.port),
                    "protocol=TCP",
                    "profile=private,domain",
                    "description=Temporary rule for Chimera file server",
                ])
                .output()
                .await
            {
                Ok(output) => {
                    if !output.status.success() {
                        let error_msg = String::from_utf8_lossy(&output.stderr);
                        error!("Failed to add firewall rule: {}", error_msg);

                        // Check if it's a permission error
                        if error_msg.contains("access is denied") {
                            error!("Access denied - ensure the application is running with administrative privileges");
                            return Err(
                                "Administrative privileges required to configure firewall".into()
                            );
                        }

                        return Err(format!("Failed to add firewall rule: {}", error_msg).into());
                    }
                    info!("Successfully added firewall rule for port {}", self.port);
                }
                Err(e) => {
                    error!("Failed to execute add rule command: {}", e);
                    return Err(format!("Add rule command failed: {}", e).into());
                }
            }
        } else {
            info!("Firewall rule '{}' already exists", self.rule_name);
        }

        info!("Firewall configuration completed successfully");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn cleanup_windows_firewall(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Cleaning up firewall rule...");
        let status = Command::new("netsh")
            .args(&[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", self.rule_name),
            ])
            .status()
            .await?;

        if !status.success() {
            error!("Failed to cleanup firewall rule");
            return Err("Failed to cleanup firewall".into());
        }

        info!("Successfully cleaned up firewall rule");
        Ok(())
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        #[cfg(target_os = "windows")]
        self.configure_windows_firewall().await?;

        let addr: std::net::SocketAddr = ([0, 0, 0, 0], self.port).into();
        let listener = TcpListener::bind(addr).await?;

        info!("Starting file server on port {}", self.port);
        let root_dir = Arc::clone(&self.root_dir);
        let shutdown_flag = Arc::clone(&self.shutdown_flag);

        let mut connection_tasks = Vec::new();

        loop {
            if self.shutdown_flag.load(Ordering::SeqCst) {
                info!("Shutdown flag detected, stopping server");
                break;
            }

            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _)) => {
                            let io = TokioIo::new(stream);
                            let root_dir_clone = Arc::clone(&root_dir);
                            let shutdown_flag = Arc::clone(&self.shutdown_flag);

                            let handle = tokio::spawn(async move {
                                if let Err(err) = http1::Builder::new()
                                    .serve_connection(
                                        io,
                                        service_fn(move |req| {
                                            handle_request(req, Arc::clone(&root_dir_clone), Arc::clone(&shutdown_flag))
                                        }),
                                    )
                                    .await
                                {
                                    error!("Error serving connection: {:?}", err);
                                }
                            });

                            connection_tasks.push(handle);
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {:?}", e);
                        }
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    // Cleanup finished tasks
                    connection_tasks.retain(|task| !task.is_finished());
                }
            }
        }

        // Wait for ongoing connections to complete
        info!(
            "Waiting for {} ongoing connections to complete",
            connection_tasks.len()
        );
        for task in connection_tasks {
            let _ = task.await;
        }

        #[cfg(target_os = "windows")]
        self.cleanup_windows_firewall().await?;

        info!("File server shutdown complete");
        std::process::exit(0);

        #[allow(unreachable_code)]
        Ok(())
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    root: Arc<PathBuf>,
    shutdown_flag: Arc<AtomicBool>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/") => serve_directory_listing(&root).await,
        (&hyper::Method::GET, path) => serve_file(&root, path, shutdown_flag).await,
        _ => Ok(Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::new()))
            .unwrap()),
    }
}

async fn serve_directory_listing(root: &Path) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut entries = match tokio::fs::read_dir(root).await {
        Ok(entries) => entries,
        Err(e) => {
            error!("Failed to read directory: {}", e);
            return Ok(Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
    };

    let mut html = String::from(
        "<!DOCTYPE html><html><head><style>\
        body { font-family: sans-serif; margin: 2em; }\
        h1 { color: #333; }\
        ul { list-style-type: none; padding: 0; }\
        li { margin: 0.5em 0; }\
        a { color: #0066cc; text-decoration: none; }\
        a:hover { text-decoration: underline; }\
        </style></head>\
        <body><h1>Available Files</h1><ul>",
    );

    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Ok(file_name) = entry.file_name().into_string() {
            html.push_str(&format!(
                r#"<li><a href="/{}">{}</a></li>"#,
                file_name, file_name
            ));
        }
    }

    html.push_str("</ul></body></html>");

    Ok(Response::builder()
        .header("content-type", "text/html")
        .body(Full::new(Bytes::from(html)))
        .unwrap())
}

async fn serve_file(
    root: &Path,
    path: &str,
    shutdown_flag: Arc<AtomicBool>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = path.trim_start_matches('/');
    let full_path = root.join(path);

    // Prevent directory traversal
    if !full_path.starts_with(root) {
        return Ok(Response::builder()
            .status(hyper::StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    match File::open(&full_path).await {
        Ok(mut file) => {
            let mut contents = Vec::new();
            match file.read_to_end(&mut contents).await {
                Ok(_) => {
                    let content_type = mime_guess::from_path(&full_path)
                        .first_or_octet_stream()
                        .to_string();

                    // Check if this is application.log and set the shutdown flag
                    if path == "application.log" {
                        info!("application.log has been served, triggering shutdown");
                        shutdown_flag.store(true, Ordering::SeqCst);
                    }

                    // Try to delete the file, but don't require it to succeed
                    if let Err(e) = tokio::fs::remove_file(&full_path).await {
                        error!("Failed to delete file after serving: {}", e);
                    } else {
                        info!("Successfully served and deleted file: {}", path);
                    }

                    Ok(Response::builder()
                        .header("content-type", content_type)
                        .body(Full::new(Bytes::from(contents)))
                        .unwrap())
                }
                Err(e) => {
                    error!("Failed to read file: {}", e);
                    Ok(Response::builder()
                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::new()))
                        .unwrap())
                }
            }
        }
        Err(_) => Ok(Response::builder()
            .status(hyper::StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap()),
    }
}
