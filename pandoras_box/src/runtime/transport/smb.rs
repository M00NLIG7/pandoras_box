use std::net::SocketAddr;
use std::path::Path;

use async_trait::async_trait;
use smolder_tools::prelude::{
    ExecMode, ExecRequest as SmolderExecRequest, NtlmCredentials, RemoteExecClient, Share,
    SmbClientBuilder,
};

use crate::runtime::transport::{ExecRequest, ExecResponse, FileTransfer, HostSession};
use crate::{Error, Result};

const ADMIN_SHARE_ROOT: &str = r"C:\Windows";
const ADMIN_SHARE_NAME: &str = "ADMIN$";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbSessionConfig {
    pub socket: SocketAddr,
    pub username: String,
    pub password: String,
    pub staging_directory: String,
}

#[async_trait]
trait SmbExecHandle: Send {
    async fn run(&mut self, command: String) -> Result<ExecResponse>;
}

#[async_trait]
trait AdminShareHandle: Send {
    async fn put(&mut self, local_path: &Path, remote_relative_path: &str) -> Result<()>;
    async fn get(&mut self, remote_relative_path: &str, local_path: &Path) -> Result<()>;
    async fn disconnect(&mut self) -> Result<()>;
}

pub(crate) struct SmolderExecHandle {
    client: RemoteExecClient,
    socket: SocketAddr,
}

#[async_trait]
impl SmbExecHandle for SmolderExecHandle {
    async fn run(&mut self, command: String) -> Result<ExecResponse> {
        let result = self
            .client
            .run(SmolderExecRequest::command(command.clone()))
            .await
            .map_err(|err| {
                Error::CommandError(format!(
                    "smb exec `{command}` on {} failed: {err}",
                    self.socket
                ))
            })?;
        Ok(ExecResponse {
            stdout: result.stdout,
            stderr: result.stderr,
            status_code: Some(result.exit_code as u32),
        })
    }
}

pub(crate) struct SmolderAdminShareHandle {
    share: Option<Share>,
    socket: SocketAddr,
}

#[async_trait]
impl AdminShareHandle for SmolderAdminShareHandle {
    async fn put(&mut self, local_path: &Path, remote_relative_path: &str) -> Result<()> {
        let share = self.share.as_mut().ok_or_else(|| {
            Error::CommunicatorError(format!(
                "smb ADMIN$ share to {} is already disconnected",
                self.socket
            ))
        })?;
        share
            .put(local_path, remote_relative_path)
            .await
            .map_err(|err| {
                Error::FileTransferError(format!(
                    "smb upload {} -> {} via {} failed: {err}",
                    local_path.display(),
                    remote_relative_path,
                    self.socket
                ))
            })?;
        Ok(())
    }

    async fn get(&mut self, remote_relative_path: &str, local_path: &Path) -> Result<()> {
        let share = self.share.as_mut().ok_or_else(|| {
            Error::CommunicatorError(format!(
                "smb ADMIN$ share to {} is already disconnected",
                self.socket
            ))
        })?;
        share
            .get(remote_relative_path, local_path)
            .await
            .map_err(|err| {
                Error::FileTransferError(format!(
                    "smb download {} -> {} via {} failed: {err}",
                    remote_relative_path,
                    local_path.display(),
                    self.socket
                ))
            })?;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        let Some(share) = self.share.take() else {
            return Ok(());
        };
        let client = share.disconnect().await.map_err(|err| {
            Error::CommunicatorError(format!(
                "smb tree disconnect from {} failed: {err}",
                self.socket
            ))
        })?;
        client.logoff().await.map_err(|err| {
            Error::CommunicatorError(format!(
                "smb session logoff from {} failed: {err}",
                self.socket
            ))
        })?;
        Ok(())
    }
}

pub(crate) struct SmbSession<E = SmolderExecHandle, A = SmolderAdminShareHandle> {
    exec: E,
    admin_share: A,
    socket: SocketAddr,
}

impl SmbSession<SmolderExecHandle, SmolderAdminShareHandle> {
    pub async fn connect(config: &SmbSessionConfig) -> Result<Self> {
        let server = config.socket.ip().to_string();
        let exec_client = RemoteExecClient::builder()
            .server(server.clone())
            .port(config.socket.port())
            .mode(ExecMode::SmbExec)
            .credentials(NtlmCredentials::new(
                config.username.clone(),
                config.password.clone(),
            ))
            .staging_directory(config.staging_directory.clone())
            .connect()
            .await
            .map_err(|err| {
                Error::CommunicatorError(format!(
                    "smb exec connect to {} failed: {err}",
                    config.socket
                ))
            })?;

        let smb_client = SmbClientBuilder::new()
            .server(server)
            .port(config.socket.port())
            .credentials(NtlmCredentials::new(
                config.username.clone(),
                config.password.clone(),
            ))
            .connect()
            .await
            .map_err(|err| {
                Error::CommunicatorError(format!(
                    "smb session connect to {} failed: {err}",
                    config.socket
                ))
            })?;
        let admin_share = smb_client.share(ADMIN_SHARE_NAME).await.map_err(|err| {
            Error::CommunicatorError(format!(
                "smb share connect to {} on {} failed: {err}",
                ADMIN_SHARE_NAME, config.socket
            ))
        })?;

        Ok(Self {
            exec: SmolderExecHandle {
                client: exec_client,
                socket: config.socket,
            },
            admin_share: SmolderAdminShareHandle {
                share: Some(admin_share),
                socket: config.socket,
            },
            socket: config.socket,
        })
    }
}

impl<E, A> SmbSession<E, A> {
    #[cfg(test)]
    fn for_test(exec: E, admin_share: A, socket: SocketAddr) -> Self {
        Self {
            exec,
            admin_share,
            socket,
        }
    }
}

#[async_trait]
impl<E, A> HostSession for SmbSession<E, A>
where
    E: SmbExecHandle,
    A: AdminShareHandle,
{
    async fn exec(&mut self, request: ExecRequest) -> Result<ExecResponse> {
        self.exec.run(request.command).await
    }

    async fn put(&mut self, transfer: &FileTransfer) -> Result<()> {
        let remote_relative = admin_share_relative_path(&transfer.remote_path)?;
        self.admin_share
            .put(&transfer.local_path, &remote_relative)
            .await
    }

    async fn get(&mut self, transfer: &FileTransfer) -> Result<()> {
        let remote_relative = admin_share_relative_path(&transfer.remote_path)?;
        self.admin_share
            .get(&remote_relative, &transfer.local_path)
            .await
    }

    async fn ensure_dir(&mut self, remote_dir: &str) -> Result<()> {
        let command = format!(
            r#"cmd.exe /C if not exist "{}" md "{}""#,
            quote_for_cmd(remote_dir),
            quote_for_cmd(remote_dir)
        );
        let response = self.exec.run(command.clone()).await?;
        require_success_status("ensure_dir", &command, &response, self.socket)
    }

    async fn cleanup(&mut self) -> Result<()> {
        self.admin_share.disconnect().await
    }
}

fn admin_share_relative_path(remote_path: &str) -> Result<String> {
    let normalized = remote_path.replace('/', "\\");
    let prefix = format!(r"{ADMIN_SHARE_ROOT}\");
    if normalized.eq_ignore_ascii_case(ADMIN_SHARE_ROOT) {
        return Ok(String::new());
    }
    if normalized.len() >= prefix.len()
        && normalized[..prefix.len()].eq_ignore_ascii_case(prefix.as_str())
    {
        return Ok(normalized[prefix.len()..].to_string());
    }

    Err(Error::FileTransferError(format!(
        "remote SMB path must stay under {}: {}",
        ADMIN_SHARE_ROOT, remote_path
    )))
}

fn quote_for_cmd(value: &str) -> String {
    value.replace('"', "\"\"")
}

fn require_success_status(
    operation: &str,
    command: &str,
    response: &ExecResponse,
    socket: SocketAddr,
) -> Result<()> {
    match response.status_code {
        Some(0) => Ok(()),
        Some(status) => Err(Error::CommandError(format!(
            "smb {operation} `{command}` on {socket} returned exit status {status}"
        ))),
        None => Err(Error::CommandError(format!(
            "smb {operation} `{command}` on {socket} returned missing exit status"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{admin_share_relative_path, AdminShareHandle, SmbExecHandle, SmbSession};
    use crate::runtime::transport::{ExecRequest, ExecResponse, FileTransfer, HostSession};
    use crate::{Error, Result};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn socket() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 445)
    }

    fn temp_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("pandoras-box-smb-{label}-{unique}"))
    }

    #[derive(Clone)]
    struct FakeExecHandle {
        commands: Arc<Mutex<Vec<String>>>,
        responses: Arc<HashMap<String, ExecResponse>>,
    }

    impl FakeExecHandle {
        fn successful() -> Self {
            Self {
                commands: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl SmbExecHandle for FakeExecHandle {
        async fn run(&mut self, command: String) -> Result<ExecResponse> {
            self.commands
                .lock()
                .expect("commands lock should be available")
                .push(command.clone());
            Ok(self
                .responses
                .get(&command)
                .cloned()
                .unwrap_or(ExecResponse {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    status_code: Some(0),
                }))
        }
    }

    #[derive(Clone)]
    struct FakeAdminShareHandle {
        puts: Arc<Mutex<Vec<(PathBuf, String)>>>,
        gets: Arc<Mutex<Vec<(String, PathBuf)>>>,
        disconnects: Arc<Mutex<usize>>,
    }

    impl FakeAdminShareHandle {
        fn new() -> Self {
            Self {
                puts: Arc::new(Mutex::new(Vec::new())),
                gets: Arc::new(Mutex::new(Vec::new())),
                disconnects: Arc::new(Mutex::new(0)),
            }
        }
    }

    #[async_trait]
    impl AdminShareHandle for FakeAdminShareHandle {
        async fn put(&mut self, local_path: &Path, remote_relative_path: &str) -> Result<()> {
            self.puts
                .lock()
                .expect("puts lock should be available")
                .push((local_path.to_path_buf(), remote_relative_path.to_string()));
            Ok(())
        }

        async fn get(&mut self, remote_relative_path: &str, local_path: &Path) -> Result<()> {
            self.gets
                .lock()
                .expect("gets lock should be available")
                .push((remote_relative_path.to_string(), local_path.to_path_buf()));
            Ok(())
        }

        async fn disconnect(&mut self) -> Result<()> {
            let mut disconnects = self
                .disconnects
                .lock()
                .expect("disconnects lock should be available");
            *disconnects += 1;
            Ok(())
        }
    }

    #[test]
    fn admin_share_relative_path_maps_windows_temp_paths() {
        assert_eq!(
            admin_share_relative_path(r"C:\Windows\Temp\pandoras_box\mission\chimera.exe")
                .expect("windows temp path should map"),
            r"Temp\pandoras_box\mission\chimera.exe"
        );
        assert_eq!(
            admin_share_relative_path(
                r"C:/Windows/Temp/pandoras_box/mission/output/inventory.json"
            )
            .expect("slash variants should map"),
            r"Temp\pandoras_box\mission\output\inventory.json"
        );
    }

    #[test]
    fn admin_share_relative_path_rejects_paths_outside_admin_root() {
        let error = admin_share_relative_path(
            r"C:\Users\mitre\AppData\Local\Temp\pandoras_box\mission\chimera.exe",
        )
        .expect_err("user temp path should not be allowed for ADMIN$ transfers");

        assert!(matches!(error, Error::FileTransferError(_)));
    }

    #[tokio::test]
    async fn smb_session_put_uses_admin_share_relative_path() {
        let root = temp_path("put");
        let local_path = root.join("chimera.exe");
        tokio::fs::create_dir_all(&root)
            .await
            .expect("temp root should exist");
        tokio::fs::write(&local_path, b"binary")
            .await
            .expect("local file should exist");
        let exec = FakeExecHandle::successful();
        let share = FakeAdminShareHandle::new();
        let puts = Arc::clone(&share.puts);
        let mut session = SmbSession::for_test(exec, share, socket());

        session
            .put(&FileTransfer {
                local_path: local_path.clone(),
                remote_path: r"C:\Windows\Temp\pandoras_box\mission\chimera.exe".to_string(),
            })
            .await
            .expect("put should succeed");

        assert_eq!(
            puts.lock()
                .expect("puts lock should be available")
                .as_slice(),
            [(
                local_path,
                r"Temp\pandoras_box\mission\chimera.exe".to_string()
            )]
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn smb_session_get_uses_admin_share_relative_path() {
        let root = temp_path("get");
        let local_path = root.join("inventory.json");
        let exec = FakeExecHandle::successful();
        let share = FakeAdminShareHandle::new();
        let gets = Arc::clone(&share.gets);
        let mut session = SmbSession::for_test(exec, share, socket());

        session
            .get(&FileTransfer {
                local_path: local_path.clone(),
                remote_path: r"C:\Windows\Temp\pandoras_box\mission\output\inventory.json"
                    .to_string(),
            })
            .await
            .expect("get should succeed");

        assert_eq!(
            gets.lock()
                .expect("gets lock should be available")
                .as_slice(),
            [(
                r"Temp\pandoras_box\mission\output\inventory.json".to_string(),
                local_path
            )]
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn smb_session_ensure_dir_uses_cmd_and_requires_success_status() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let ensure_command = r#"cmd.exe /C if not exist "C:\Windows\Temp\pandoras_box\mission\output" md "C:\Windows\Temp\pandoras_box\mission\output""#;
        let exec = FakeExecHandle {
            commands: Arc::clone(&commands),
            responses: Arc::new(HashMap::from([(
                ensure_command.to_string(),
                ExecResponse {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    status_code: Some(0),
                },
            )])),
        };
        let share = FakeAdminShareHandle::new();
        let mut session = SmbSession::for_test(exec, share, socket());

        session
            .ensure_dir(r"C:\Windows\Temp\pandoras_box\mission\output")
            .await
            .expect("ensure_dir should succeed");

        assert_eq!(
            commands
                .lock()
                .expect("commands lock should be available")
                .as_slice(),
            [ensure_command.to_string()]
        );
    }

    #[tokio::test]
    async fn smb_session_cleanup_disconnects_admin_share() {
        let exec = FakeExecHandle::successful();
        let share = FakeAdminShareHandle::new();
        let disconnects = Arc::clone(&share.disconnects);
        let mut session = SmbSession::for_test(exec, share, socket());

        session.cleanup().await.expect("cleanup should succeed");

        assert_eq!(
            *disconnects
                .lock()
                .expect("disconnects lock should be available"),
            1
        );
    }

    #[tokio::test]
    async fn smb_session_fails_when_ensure_dir_returns_missing_status() {
        let ensure_command = r#"cmd.exe /C if not exist "C:\Windows\Temp\pandoras_box\mission\output" md "C:\Windows\Temp\pandoras_box\mission\output""#;
        let exec = FakeExecHandle {
            commands: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(HashMap::from([(
                ensure_command.to_string(),
                ExecResponse {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    status_code: None,
                },
            )])),
        };
        let share = FakeAdminShareHandle::new();
        let mut session = SmbSession::for_test(exec, share, socket());

        let error = session
            .ensure_dir(r"C:\Windows\Temp\pandoras_box\mission\output")
            .await
            .expect_err("missing status should fail");

        assert!(matches!(error, Error::CommandError(_)));
    }

    #[tokio::test]
    async fn smb_session_exec_passes_command_through() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let exec = FakeExecHandle {
            commands: Arc::clone(&commands),
            responses: Arc::new(HashMap::from([(
                "whoami".to_string(),
                ExecResponse {
                    stdout: b"nt authority\\system\r\n".to_vec(),
                    stderr: Vec::new(),
                    status_code: Some(0),
                },
            )])),
        };
        let share = FakeAdminShareHandle::new();
        let mut session = SmbSession::for_test(exec, share, socket());

        let response = session
            .exec(ExecRequest::new("whoami"))
            .await
            .expect("exec should succeed");

        assert_eq!(response.stdout, b"nt authority\\system\r\n");
        assert_eq!(
            commands
                .lock()
                .expect("commands lock should be available")
                .as_slice(),
            ["whoami".to_string()]
        );
    }
}
