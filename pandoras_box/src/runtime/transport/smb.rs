use std::net::SocketAddr;
use std::path::Path;

use async_trait::async_trait;
use smolder_tools::prelude::{
    ExecMode, ExecRequest as SmolderExecRequest, NtlmCredentials, RemoteExecClient, Share,
    SmbClientBuilder,
};

use crate::runtime::mission::WindowsSmbExecMode;
use crate::runtime::secret::SecretString;
use crate::runtime::transport::{ExecRequest, ExecResponse, FileTransfer, HostSession};
use crate::{Error, Result};

const ADMIN_SHARE_ROOT: &str = r"C:\Windows";
const ADMIN_SHARE_NAME: &str = "ADMIN$";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbSessionConfig {
    pub socket: SocketAddr,
    pub username: String,
    pub password: SecretString,
    pub staging_directory: String,
    pub exec_mode: WindowsSmbExecMode,
}

#[async_trait]
trait SmbExecHandle: Send {
    async fn run(&mut self, command: String) -> Result<ExecResponse>;
}

#[async_trait]
trait AdminShareHandle: Send {
    async fn put(&mut self, local_path: &Path, remote_relative_path: &str) -> Result<()>;
    async fn get(&mut self, remote_relative_path: &str, local_path: &Path) -> Result<()>;
    async fn reconnect(&mut self) -> Result<()>;
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
    config: SmbSessionConfig,
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

    async fn reconnect(&mut self) -> Result<()> {
        if let Some(share) = self.share.take() {
            match share.disconnect().await {
                Ok(client) => {
                    let _ = client.logoff().await;
                }
                Err(_) => {}
            }
        }

        self.share = Some(connect_admin_share(&self.config).await?);
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        let Some(share) = self.share.take() else {
            return Ok(());
        };
        let client = match share.disconnect().await {
            Ok(client) => client,
            Err(err) => {
                let error = Error::CommunicatorError(format!(
                    "smb tree disconnect from {} failed: {err}",
                    self.socket
                ));
                if should_ignore_disconnect_error(&error) {
                    return Ok(());
                }
                return Err(error);
            }
        };
        if let Err(err) = client.logoff().await {
            let error = Error::CommunicatorError(format!(
                "smb session logoff from {} failed: {err}",
                self.socket
            ));
            if should_ignore_disconnect_error(&error) {
                return Ok(());
            }
            return Err(error);
        }
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
            .mode(smolder_exec_mode(config.exec_mode))
            .credentials(NtlmCredentials::new(
                config.username.clone(),
                config.password.expose_secret().to_string(),
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
        let admin_share = connect_admin_share(config).await?;

        Ok(Self {
            exec: SmolderExecHandle {
                client: exec_client,
                socket: config.socket,
            },
            admin_share: SmolderAdminShareHandle {
                share: Some(admin_share),
                socket: config.socket,
                config: config.clone(),
            },
            socket: config.socket,
        })
    }
}

fn smolder_exec_mode(mode: WindowsSmbExecMode) -> ExecMode {
    match mode {
        WindowsSmbExecMode::SmbExec => ExecMode::SmbExec,
        WindowsSmbExecMode::PsExec => ExecMode::PsExec,
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
        self.exec
            .run(normalize_windows_exec_command(&request.command))
            .await
    }

    async fn put(&mut self, transfer: &FileTransfer) -> Result<()> {
        let remote_relative = admin_share_relative_path(&transfer.remote_path)?;
        put_with_reconnect(
            &mut self.admin_share,
            &transfer.local_path,
            &remote_relative,
        )
        .await
    }

    async fn get(&mut self, transfer: &FileTransfer) -> Result<()> {
        let remote_relative = admin_share_relative_path(&transfer.remote_path)?;
        get_with_reconnect(
            &mut self.admin_share,
            &remote_relative,
            &transfer.local_path,
        )
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
        match self.admin_share.disconnect().await {
            Ok(()) => Ok(()),
            Err(err) if should_ignore_disconnect_error(&err) => Ok(()),
            Err(err) => Err(err),
        }
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

fn normalize_windows_exec_command(command: &str) -> String {
    let trimmed = command.trim_start();
    if starts_with_windows_shell(trimmed) {
        return command.to_string();
    }

    format!(r#"cmd.exe /C "{}""#, quote_for_cmd(command))
}

fn starts_with_windows_shell(command: &str) -> bool {
    starts_with_ignore_ascii_case(command, "cmd.exe")
        || starts_with_ignore_ascii_case(command, r"c:\windows\system32\cmd.exe")
        || starts_with_ignore_ascii_case(command, "powershell.exe")
        || starts_with_ignore_ascii_case(
            command,
            r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
        )
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
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

async fn connect_admin_share(config: &SmbSessionConfig) -> Result<Share> {
    let smb_client = SmbClientBuilder::new()
        .server(config.socket.ip().to_string())
        .port(config.socket.port())
        .credentials(NtlmCredentials::new(
            config.username.clone(),
            config.password.expose_secret().to_string(),
        ))
        .connect()
        .await
        .map_err(|err| {
            Error::CommunicatorError(format!(
                "smb session connect to {} failed: {err}",
                config.socket
            ))
        })?;
    smb_client.share(ADMIN_SHARE_NAME).await.map_err(|err| {
        Error::CommunicatorError(format!(
            "smb share connect to {} on {} failed: {err}",
            ADMIN_SHARE_NAME, config.socket
        ))
    })
}

async fn put_with_reconnect<A>(
    admin_share: &mut A,
    local_path: &Path,
    remote_relative_path: &str,
) -> Result<()>
where
    A: AdminShareHandle,
{
    match admin_share.put(local_path, remote_relative_path).await {
        Ok(()) => Ok(()),
        Err(err) if should_retry_admin_share_error(&err) => {
            admin_share.reconnect().await?;
            admin_share.put(local_path, remote_relative_path).await
        }
        Err(err) => Err(err),
    }
}

async fn get_with_reconnect<A>(
    admin_share: &mut A,
    remote_relative_path: &str,
    local_path: &Path,
) -> Result<()>
where
    A: AdminShareHandle,
{
    match admin_share.get(remote_relative_path, local_path).await {
        Ok(()) => Ok(()),
        Err(err) if should_retry_admin_share_error(&err) => {
            admin_share.reconnect().await?;
            admin_share.get(remote_relative_path, local_path).await
        }
        Err(err) => Err(err),
    }
}

fn should_retry_admin_share_error(error: &Error) -> bool {
    let rendered = error.to_string().to_ascii_lowercase();
    if [
        "permission denied",
        "access denied",
        "access is denied",
        "logon failure",
        "bad network name",
        "path invalid",
    ]
    .iter()
    .any(|needle| rendered.contains(needle))
    {
        return false;
    }

    [
        "already disconnected",
        "timed out",
        "timeout",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "transport connection",
        "network name deleted",
        "user session deleted",
        "session deleted",
        "invalid handle",
    ]
    .iter()
    .any(|needle| rendered.contains(needle))
}

fn should_ignore_disconnect_error(error: &Error) -> bool {
    let rendered = error.to_string().to_ascii_lowercase();
    [
        "already disconnected",
        "timed out",
        "timeout",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "transport connection",
        "network name deleted",
        "user session deleted",
        "session deleted",
        "invalid handle",
        "tree disconnect",
        "logoff failed",
    ]
    .iter()
    .any(|needle| rendered.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{
        admin_share_relative_path, normalize_windows_exec_command, should_ignore_disconnect_error,
        should_retry_admin_share_error, AdminShareHandle, SmbExecHandle, SmbSession,
    };
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
        reconnects: Arc<Mutex<usize>>,
        put_errors: Arc<Mutex<Vec<Error>>>,
        get_errors: Arc<Mutex<Vec<Error>>>,
    }

    impl FakeAdminShareHandle {
        fn new() -> Self {
            Self {
                puts: Arc::new(Mutex::new(Vec::new())),
                gets: Arc::new(Mutex::new(Vec::new())),
                disconnects: Arc::new(Mutex::new(0)),
                reconnects: Arc::new(Mutex::new(0)),
                put_errors: Arc::new(Mutex::new(Vec::new())),
                get_errors: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl AdminShareHandle for FakeAdminShareHandle {
        async fn put(&mut self, local_path: &Path, remote_relative_path: &str) -> Result<()> {
            let mut put_errors = self
                .put_errors
                .lock()
                .expect("put errors lock should be available");
            if !put_errors.is_empty() {
                let error = put_errors.remove(0);
                return Err(error);
            }
            drop(put_errors);
            self.puts
                .lock()
                .expect("puts lock should be available")
                .push((local_path.to_path_buf(), remote_relative_path.to_string()));
            Ok(())
        }

        async fn get(&mut self, remote_relative_path: &str, local_path: &Path) -> Result<()> {
            let mut get_errors = self
                .get_errors
                .lock()
                .expect("get errors lock should be available");
            if !get_errors.is_empty() {
                let error = get_errors.remove(0);
                return Err(error);
            }
            drop(get_errors);
            self.gets
                .lock()
                .expect("gets lock should be available")
                .push((remote_relative_path.to_string(), local_path.to_path_buf()));
            Ok(())
        }

        async fn reconnect(&mut self) -> Result<()> {
            let mut reconnects = self
                .reconnects
                .lock()
                .expect("reconnects lock should be available");
            *reconnects += 1;
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
    async fn smb_session_cleanup_ignores_benign_disconnect_errors() {
        let exec = FakeExecHandle::successful();
        let share = FakeAdminShareHandle::new();
        let disconnects = Arc::clone(&share.disconnects);
        struct CleanupErrorShare(FakeAdminShareHandle);

        #[async_trait]
        impl AdminShareHandle for CleanupErrorShare {
            async fn put(&mut self, local_path: &Path, remote_relative_path: &str) -> Result<()> {
                self.0.put(local_path, remote_relative_path).await
            }

            async fn get(&mut self, remote_relative_path: &str, local_path: &Path) -> Result<()> {
                self.0.get(remote_relative_path, local_path).await
            }

            async fn reconnect(&mut self) -> Result<()> {
                self.0.reconnect().await
            }

            async fn disconnect(&mut self) -> Result<()> {
                let mut disconnects = self
                    .0
                    .disconnects
                    .lock()
                    .expect("disconnects lock should be available");
                *disconnects += 1;
                Err(Error::CommunicatorError(
                    "smb tree disconnect from 10.0.0.8:445 failed: broken pipe".to_string(),
                ))
            }
        }

        let mut session = SmbSession::for_test(exec, CleanupErrorShare(share), socket());
        session
            .cleanup()
            .await
            .expect("benign disconnect errors should be ignored");

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
    async fn smb_session_retries_put_after_transient_admin_share_failure() {
        let root = temp_path("put-retry");
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
        let reconnects = Arc::clone(&share.reconnects);
        share
            .put_errors
            .lock()
            .expect("put errors lock should be available")
            .push(Error::CommunicatorError(
                "smb ADMIN$ share to 10.0.0.8:445 is already disconnected".to_string(),
            ));
        let mut session = SmbSession::for_test(exec, share, socket());

        session
            .put(&FileTransfer {
                local_path: local_path.clone(),
                remote_path: r"C:\Windows\Temp\pandoras_box\mission\chimera.exe".to_string(),
            })
            .await
            .expect("put should succeed after reconnect");

        assert_eq!(
            *reconnects
                .lock()
                .expect("reconnects lock should be available"),
            1
        );
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
    async fn smb_session_does_not_retry_put_after_terminal_admin_share_failure() {
        let root = temp_path("put-terminal");
        let local_path = root.join("chimera.exe");
        tokio::fs::create_dir_all(&root)
            .await
            .expect("temp root should exist");
        tokio::fs::write(&local_path, b"binary")
            .await
            .expect("local file should exist");
        let exec = FakeExecHandle::successful();
        let share = FakeAdminShareHandle::new();
        let reconnects = Arc::clone(&share.reconnects);
        share
            .put_errors
            .lock()
            .expect("put errors lock should be available")
            .push(Error::FileTransferError("permission denied".to_string()));
        let mut session = SmbSession::for_test(exec, share, socket());

        let error = session
            .put(&FileTransfer {
                local_path,
                remote_path: r"C:\Windows\Temp\pandoras_box\mission\chimera.exe".to_string(),
            })
            .await
            .expect_err("terminal put failure should surface");

        assert!(matches!(error, Error::FileTransferError(_)));
        assert_eq!(
            *reconnects
                .lock()
                .expect("reconnects lock should be available"),
            0
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn smb_session_retries_get_after_transient_admin_share_failure() {
        let root = temp_path("get-retry");
        let local_path = root.join("inventory.json");
        let exec = FakeExecHandle::successful();
        let share = FakeAdminShareHandle::new();
        let gets = Arc::clone(&share.gets);
        let reconnects = Arc::clone(&share.reconnects);
        share
            .get_errors
            .lock()
            .expect("get errors lock should be available")
            .push(Error::CommunicatorError(
                "smb ADMIN$ share to 10.0.0.8:445 is already disconnected".to_string(),
            ));
        let mut session = SmbSession::for_test(exec, share, socket());

        session
            .get(&FileTransfer {
                local_path: local_path.clone(),
                remote_path: r"C:\Windows\Temp\pandoras_box\mission\output\inventory.json"
                    .to_string(),
            })
            .await
            .expect("get should succeed after reconnect");

        assert_eq!(
            *reconnects
                .lock()
                .expect("reconnects lock should be available"),
            1
        );
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

    #[test]
    fn smb_error_classifiers_split_retryable_and_benign_disconnects() {
        assert!(should_retry_admin_share_error(&Error::CommunicatorError(
            "smb ADMIN$ share to 10.0.0.8:445 is already disconnected".to_string(),
        )));
        assert!(!should_retry_admin_share_error(&Error::FileTransferError(
            "permission denied".to_string(),
        )));
        assert!(should_ignore_disconnect_error(&Error::CommunicatorError(
            "smb tree disconnect from 10.0.0.8:445 failed: broken pipe".to_string(),
        )));
        assert!(!should_ignore_disconnect_error(&Error::CommunicatorError(
            "smb session logoff from 10.0.0.8:445 failed: access denied".to_string(),
        )));
    }

    #[tokio::test]
    async fn smb_session_exec_wraps_raw_commands_with_cmd_shell() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let wrapped_command = r#"cmd.exe /C "whoami""#;
        let exec = FakeExecHandle {
            commands: Arc::clone(&commands),
            responses: Arc::new(HashMap::from([(
                wrapped_command.to_string(),
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
            [wrapped_command.to_string()]
        );
    }

    #[test]
    fn normalize_windows_exec_command_preserves_shell_qualified_commands() {
        assert_eq!(
            normalize_windows_exec_command(r#"cmd.exe /C "ver & whoami""#),
            r#"cmd.exe /C "ver & whoami""#
        );
        assert_eq!(
            normalize_windows_exec_command(
                r#"powershell.exe -NoProfile -Command "Write-Output test""#
            ),
            r#"powershell.exe -NoProfile -Command "Write-Output test""#
        );
    }
}
