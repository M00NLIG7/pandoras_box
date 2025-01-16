use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use log::{error, info};

pub struct FileServer {
    root_dir: PathBuf,
    port: u16,
    #[cfg(target_os = "windows")]
    rule_name: String,
}

impl FileServer {
    pub fn new(root_dir: PathBuf, port: u16) -> Self {
        #[cfg(target_os = "windows")]
        let rule_name = format!("ChimeraFileServer_{}", port);
        
        #[cfg(target_os = "windows")]
        return Self { root_dir, port, rule_name };
        
        #[cfg(not(target_os = "windows"))]
        Self { root_dir, port }
    }

    #[cfg(target_os = "windows")]
    fn configure_windows_firewall(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Configuring Windows Firewall for port {}", self.port);

        // First check if the rule already exists
        let check_cmd = Command::new("netsh")
            .args(&["advfirewall", "firewall", "show", "rule", "name=all"])
            .output()?;

        let output = String::from_utf8_lossy(&check_cmd.stdout);
        if !output.contains(&self.rule_name) {
            // Add new firewall rule
            let status = Command::new("netsh")
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
                ])
                .status()?;

            if !status.success() {
                error!("Failed to add firewall rule");
                return Err("Failed to configure firewall".into());
            }

            info!("Successfully added firewall rule for port {}", self.port);
        } else {
            info!("Firewall rule already exists for port {}", self.port);
        }

        Ok(())
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Configure firewall on Windows and set up cleanup
        #[cfg(target_os = "windows")] {
            self.configure_windows_firewall()?;
            let rule_name = self.rule_name.clone();
            let _guard = CleanupGuard::new(move || {
                info!("Cleaning up firewall rule...");
                let cleanup_cmd = Command::new("netsh")
                    .args(&[
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name={}", rule_name),
                    ])
                    .status();
                
                if let Err(e) = cleanup_cmd {
                    error!("Failed to cleanup firewall: {}", e);
                }
            });
        }

        let addr: std::net::SocketAddr = ([0, 0, 0, 0], self.port).into();
        let listener = TcpListener::bind(addr).await?;

        info!("Starting file server on port {}", self.port);
        let root_dir = Arc::new(self.root_dir);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let io = TokioIo::new(stream);
                    let root_dir_clone = Arc::clone(&root_dir);

                    tokio::task::spawn(async move {
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(
                                io,
                                service_fn(move |req| handle_request(req, Arc::clone(&root_dir_clone))),
                            )
                            .await
                        {
                            error!("Error serving connection: {:?}", err);
                        }
                    });

                    // Check if all files have been served
                    if let Ok(entries) = tokio::fs::read_dir(&*root_dir).await {
                        let mut has_files = false;
                        let mut entries = entries;
                        while let Ok(Some(_)) = entries.next_entry().await {
                            has_files = true;
                            break;
                        }
                        if !has_files {
                            info!("All files have been served, shutting down server");
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to accept connection: {:?}", e);
                }
            }
        }

        Ok(())
    }
}

// RAII guard for cleanup
#[cfg(target_os = "windows")]
struct CleanupGuard<F: FnOnce()> {
    cleanup: Option<F>,
}

#[cfg(target_os = "windows")]
impl<F: FnOnce()> CleanupGuard<F> {
    fn new(cleanup: F) -> Self {
        Self {
            cleanup: Some(cleanup),
        }
    }
}

#[cfg(target_os = "windows")]
impl<F: FnOnce()> Drop for CleanupGuard<F> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    root: Arc<PathBuf>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/") => serve_directory_listing(&root).await,
        (&hyper::Method::GET, path) => serve_file(&root, path).await,
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

async fn serve_file(root: &Path, path: &str) -> Result<Response<Full<Bytes>>, Infallible> {
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

                    // After successful read, delete the file
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
