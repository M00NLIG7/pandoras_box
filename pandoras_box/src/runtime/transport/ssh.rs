use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustrc::client::{Client, Command};
use rustrc::ssh::{HostKeyPolicy, SSHConfig};

use crate::runtime::secret::SecretString;
use crate::runtime::transport::{ExecRequest, ExecResponse, FileTransfer, HostSession};
use crate::runtime::workspace::RemoteShell;
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAuth {
    Password {
        username: String,
        password: SecretString,
    },
    Key {
        username: String,
        key_path: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSessionConfig {
    pub socket: SocketAddr,
    pub auth: SshAuth,
    pub inactivity_timeout: Duration,
    pub shell: RemoteShell,
    pub host_key_policy: HostKeyPolicy,
}

#[async_trait]
trait SshClientHandle: Send {
    async fn exec(&mut self, command: String) -> Result<ExecResponse>;
    async fn transfer_file(&mut self, contents: Arc<Vec<u8>>, remote_path: &str) -> Result<()>;
    async fn download_file(&mut self, remote_path: &str, local_path: &str) -> Result<()>;
    async fn disconnect(&mut self) -> Result<()>;
}

pub(crate) struct RustrcSshClient {
    client: Client<SSHConfig>,
}

#[async_trait]
impl SshClientHandle for RustrcSshClient {
    async fn exec(&mut self, command: String) -> Result<ExecResponse> {
        let output = self.client.exec(&Command::new(command)).await?;
        Ok(ExecResponse {
            stdout: output.stdout,
            stderr: output.stderr,
            status_code: output.status_code,
        })
    }

    async fn transfer_file(&mut self, contents: Arc<Vec<u8>>, remote_path: &str) -> Result<()> {
        self.client.transfer_file(contents, remote_path).await?;
        Ok(())
    }

    async fn download_file(&mut self, remote_path: &str, local_path: &str) -> Result<()> {
        self.client.download_file(remote_path, local_path).await?;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        self.client.disconnect().await?;
        Ok(())
    }
}

pub struct SshSession<C> {
    client: C,
    socket: SocketAddr,
    shell: RemoteShell,
}

impl SshSession<RustrcSshClient> {
    pub async fn connect(config: &SshSessionConfig) -> Result<Self> {
        let ssh_config = match &config.auth {
            SshAuth::Password { username, password } => {
                SSHConfig::password_with_policy(
                    username.clone(),
                    password.expose_secret().to_string(),
                    config.socket,
                    config.inactivity_timeout,
                    config.host_key_policy,
                )
                .await?
            }
            SshAuth::Key { username, key_path } => {
                SSHConfig::key_with_policy(
                    username.clone(),
                    config.socket,
                    key_path.clone(),
                    config.inactivity_timeout,
                    config.host_key_policy,
                )
                .await?
            }
        };

        Ok(Self {
            client: RustrcSshClient {
                client: Client::connect(ssh_config).await.map_err(|err| {
                    Error::CommunicatorError(format!(
                        "ssh connect to {} failed under {:?}: {err}",
                        config.socket, config.host_key_policy
                    ))
                })?,
            },
            socket: config.socket,
            shell: config.shell,
        })
    }
}

impl<C> SshSession<C> {
    #[cfg(test)]
    fn for_test(client: C, socket: SocketAddr, shell: RemoteShell) -> Self {
        Self {
            client,
            socket,
            shell,
        }
    }
}

#[async_trait]
impl<C> HostSession for SshSession<C>
where
    C: SshClientHandle,
{
    async fn exec(&mut self, request: ExecRequest) -> Result<ExecResponse> {
        self.client
            .exec(request.command.clone())
            .await
            .map_err(|err| {
                Error::CommandError(format!(
                    "ssh exec `{}` on {} failed: {err}",
                    request.command, self.socket
                ))
            })
    }

    async fn put(&mut self, transfer: &FileTransfer) -> Result<()> {
        let local_path = transfer.local_path.display();
        let contents = tokio::fs::read(&transfer.local_path).await.map_err(|err| {
            Error::FileTransferError(format!(
                "failed to read local file {} for ssh upload to {} via {}: {err}",
                local_path, transfer.remote_path, self.socket
            ))
        })?;
        self.client
            .transfer_file(Arc::new(contents), &transfer.remote_path)
            .await
            .map_err(|err| {
                Error::FileTransferError(format!(
                    "ssh upload {} -> {} via {} failed: {err}",
                    transfer.local_path.display(),
                    transfer.remote_path,
                    self.socket
                ))
            })?;
        Ok(())
    }

    async fn get(&mut self, transfer: &FileTransfer) -> Result<()> {
        let local_path = local_download_path(&transfer.local_path)?;
        self.client
            .download_file(&transfer.remote_path, &local_path)
            .await
            .map_err(|err| {
                Error::FileTransferError(format!(
                    "ssh download {} -> {} via {} failed: {err}",
                    transfer.remote_path,
                    transfer.local_path.display(),
                    self.socket
                ))
            })?;
        Ok(())
    }

    async fn ensure_dir(&mut self, remote_dir: &str) -> Result<()> {
        let command = ensure_dir_command(self.shell, remote_dir);
        let response = self.client.exec(command.clone()).await.map_err(|err| {
            Error::CommandError(format!(
                "ssh ensure_dir `{command}` on {} failed: {err}",
                self.socket
            ))
        })?;
        require_success_status("ensure_dir", &command, &response, self.socket)
    }

    async fn cleanup(&mut self) -> Result<()> {
        match self.client.disconnect().await {
            Ok(()) => Ok(()),
            Err(err) if is_benign_disconnect_error(&err) => Ok(()),
            Err(err) => Err(Error::CommunicatorError(format!(
                "ssh disconnect from {} failed: {err}",
                self.socket
            ))),
        }
    }
}

fn quote_for_shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn quote_for_cmd(value: &str) -> String {
    value.replace('"', "\"\"")
}

fn ensure_dir_command(shell: RemoteShell, remote_dir: &str) -> String {
    match shell {
        RemoteShell::Posix => format!("mkdir -p {}", quote_for_shell(remote_dir)),
        RemoteShell::Cmd => {
            let quoted = quote_for_cmd(remote_dir);
            format!(r#"cmd.exe /C if not exist "{quoted}" md "{quoted}""#)
        }
    }
}

fn local_download_path(path: &Path) -> Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        Error::FileTransferError(format!(
            "local destination path for ssh download is not valid UTF-8: {}",
            path.display()
        ))
    })
}

fn is_benign_disconnect_error(err: &Error) -> bool {
    let rendered = err.to_string().to_ascii_lowercase();
    rendered.contains("channel send error")
        || rendered.contains("senderror")
        || rendered.contains("connection closed")
        || rendered.contains("already disconnected")
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
            "ssh {operation} `{command}` on {socket} returned exit status {status}"
        ))),
        None => Err(Error::CommandError(format!(
            "ssh {operation} `{command}` on {socket} returned missing exit status"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{SshClientHandle, SshSession};
    use crate::runtime::transport::{ExecResponse, FileTransfer, HostSession};
    use crate::runtime::workspace::RemoteShell;
    use crate::Error;
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("pandoras-box-ssh-{label}-{unique}"))
    }

    #[derive(Debug, Clone)]
    struct FakeSshClient {
        events: Arc<Mutex<Vec<String>>>,
        exec_response: std::result::Result<ExecResponse, String>,
        transfer_result: std::result::Result<(), String>,
        download_result: std::result::Result<(), String>,
        disconnect_result: std::result::Result<(), String>,
    }

    impl FakeSshClient {
        fn successful() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                exec_response: Ok(ExecResponse {
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    status_code: Some(0),
                }),
                transfer_result: Ok(()),
                download_result: Ok(()),
                disconnect_result: Ok(()),
            }
        }
    }

    #[async_trait]
    impl SshClientHandle for FakeSshClient {
        async fn exec(&mut self, command: String) -> Result<ExecResponse, Error> {
            self.events
                .lock()
                .expect("events lock should be available")
                .push(format!("exec:{command}"));
            self.exec_response.clone().map_err(Error::CommunicatorError)
        }

        async fn transfer_file(
            &mut self,
            _contents: Arc<Vec<u8>>,
            remote_path: &str,
        ) -> Result<(), Error> {
            self.events
                .lock()
                .expect("events lock should be available")
                .push(format!("put:{remote_path}"));
            self.transfer_result
                .clone()
                .map_err(Error::FileTransferError)
        }

        async fn download_file(
            &mut self,
            remote_path: &str,
            local_path: &str,
        ) -> Result<(), Error> {
            self.events
                .lock()
                .expect("events lock should be available")
                .push(format!("get:{remote_path}->{local_path}"));
            self.download_result
                .clone()
                .map_err(Error::FileTransferError)
        }

        async fn disconnect(&mut self) -> Result<(), Error> {
            self.events
                .lock()
                .expect("events lock should be available")
                .push("disconnect".to_string());
            self.disconnect_result
                .clone()
                .map_err(Error::CommunicatorError)
        }
    }

    #[tokio::test]
    async fn ensure_dir_uses_windows_shell_and_requires_success_status() {
        let client = FakeSshClient::successful();
        let events = Arc::clone(&client.events);
        let mut session = SshSession::for_test(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22),
            RemoteShell::Cmd,
        );

        session
            .ensure_dir(r"C:\Temp\output")
            .await
            .expect("windows ensure_dir should succeed");

        assert_eq!(
            events
                .lock()
                .expect("events lock should be available")
                .as_slice(),
            [r#"exec:cmd.exe /C if not exist "C:\Temp\output" md "C:\Temp\output""#]
        );
    }

    #[tokio::test]
    async fn put_wraps_transfer_error_with_local_and_remote_paths() {
        let root = temp_path("ssh-put");
        let local_path = root.join("chimera");
        tokio::fs::create_dir_all(local_path.parent().expect("parent should exist"))
            .await
            .expect("parent dir should exist");
        tokio::fs::write(&local_path, b"collector")
            .await
            .expect("fixture should exist");
        let client = FakeSshClient {
            transfer_result: Err("network exploded".to_string()),
            ..FakeSshClient::successful()
        };
        let mut session = SshSession::for_test(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22),
            RemoteShell::Posix,
        );

        let error = session
            .put(&FileTransfer {
                local_path: local_path.clone(),
                remote_path: "/tmp/chimera".to_string(),
            })
            .await
            .expect_err("transfer failures should be wrapped");

        let rendered = error.to_string();
        assert!(rendered.contains("ssh upload"));
        assert!(rendered.contains("/tmp/chimera"));
        assert!(rendered.contains(local_path.to_string_lossy().as_ref()));
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn get_wraps_download_error_with_remote_and_local_paths() {
        let root = temp_path("ssh-get");
        let local_path = root.join("inventory.json");
        let client = FakeSshClient {
            download_result: Err("sftp timed out".to_string()),
            ..FakeSshClient::successful()
        };
        let mut session = SshSession::for_test(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22),
            RemoteShell::Posix,
        );

        let error = session
            .get(&FileTransfer {
                local_path: local_path.clone(),
                remote_path: "/tmp/output/inventory.json".to_string(),
            })
            .await
            .expect_err("download failures should be wrapped");

        let rendered = error.to_string();
        assert!(rendered.contains("ssh download"));
        assert!(rendered.contains("/tmp/output/inventory.json"));
        assert!(rendered.contains(local_path.to_string_lossy().as_ref()));
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn cleanup_ignores_already_closed_disconnect_errors() {
        let client = FakeSshClient {
            disconnect_result: Err("Connection error: Channel send error".to_string()),
            ..FakeSshClient::successful()
        };
        let mut session = SshSession::for_test(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22),
            RemoteShell::Posix,
        );

        session
            .cleanup()
            .await
            .expect("already-closed SSH sessions should not fail cleanup");
    }

    #[tokio::test]
    async fn cleanup_still_surfaces_unexpected_disconnect_errors() {
        let client = FakeSshClient {
            disconnect_result: Err("permission denied".to_string()),
            ..FakeSshClient::successful()
        };
        let mut session = SshSession::for_test(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22),
            RemoteShell::Posix,
        );

        let error = session
            .cleanup()
            .await
            .expect_err("unexpected disconnect failures should still surface");

        assert!(error.to_string().contains("permission denied"));
    }
}
