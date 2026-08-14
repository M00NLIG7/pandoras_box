use crate::client::{Command, CommandOutput, Config, Session};
use async_trait::async_trait;
use russh::client;
use russh_keys::key::PrivateKeyWithHashAlg;
use russh_keys::known_hosts::{
    check_known_hosts, check_known_hosts_path, known_host_keys, known_host_keys_path,
};
use russh_keys::load_secret_key;
use russh_keys::ssh_key::public::PublicKey;
use std::{
    borrow::Cow,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::time::{timeout, Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{lookup_host, ToSocketAddrs},
};
use tracing::{debug, error, instrument, trace, warn};
use zeroize::Zeroize;

pub struct Connected;
pub struct Disconnected;

#[allow(unused)]
pub struct SSHSession {
    session: client::Handle<Handler>,
    config: SSHConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPolicy {
    RequireKnownHosts,
    DangerouslyAcceptUnknown,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone)]
pub enum SSHConfig {
    Key {
        username: String,
        socket: SocketAddr,
        key_path: PathBuf,
        inactivity_timeout: Duration,
        host_key_policy: HostKeyPolicy,
    },
    Password {
        username: String,
        socket: SocketAddr,
        password: SecretString,
        inactivity_timeout: Duration,
        host_key_policy: HostKeyPolicy,
    },
}

impl SSHConfig {
    async fn resolve_socket<S: ToSocketAddrs>(socket: S) -> crate::Result<SocketAddr> {
        lookup_host(&socket)
            .await?
            .next()
            .ok_or_else(|| crate::Error::ConnectionError("Error Parsing Socket".to_string()))
    }

    pub async fn key<U: Into<String>, S: ToSocketAddrs, P: Into<PathBuf>>(
        username: U,
        socket: S,
        key_path: P,
        inactivity_timeout: Duration,
    ) -> crate::Result<Self> {
        Self::key_with_policy(
            username,
            socket,
            key_path,
            inactivity_timeout,
            HostKeyPolicy::RequireKnownHosts,
        )
        .await
    }

    pub async fn key_with_policy<U: Into<String>, S: ToSocketAddrs, P: Into<PathBuf>>(
        username: U,
        socket: S,
        key_path: P,
        inactivity_timeout: Duration,
        host_key_policy: HostKeyPolicy,
    ) -> crate::Result<Self> {
        Ok(SSHConfig::Key {
            username: username.into(),
            socket: Self::resolve_socket(socket).await?,
            key_path: key_path.into(),
            inactivity_timeout,
            host_key_policy,
        })
    }

    pub async fn password<U: Into<String>, S: ToSocketAddrs, P: Into<SecretString>>(
        username: U,
        password: P,
        socket: S,
        inactivity_timeout: Duration,
    ) -> crate::Result<Self> {
        Self::password_with_policy(
            username,
            password,
            socket,
            inactivity_timeout,
            HostKeyPolicy::RequireKnownHosts,
        )
        .await
    }

    pub async fn password_with_policy<U: Into<String>, S: ToSocketAddrs, P: Into<SecretString>>(
        username: U,
        password: P,
        socket: S,
        inactivity_timeout: Duration,
        host_key_policy: HostKeyPolicy,
    ) -> crate::Result<Self> {
        Ok(SSHConfig::Password {
            username: username.into(),
            socket: Self::resolve_socket(socket).await?,
            password: password.into(),
            inactivity_timeout,
            host_key_policy,
        })
    }
}

impl Session for SSHSession {
    async fn disconnect(&mut self) -> crate::Result<()> {
        self.session
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }

    #[instrument(skip(self, cmd), fields(command = ?cmd))]
    async fn exec(&self, cmd: &Command) -> crate::Result<CommandOutput> {
        debug!("Opening new SSH channel for command execution");

        let mut channel = match self.session.channel_open_session().await {
            Ok(ch) => ch,
            Err(e) => {
                let details = match e {
                    russh::Error::Disconnect => "SSH connection closed by remote".to_string(),
                    russh::Error::SendError => {
                        error!("SSH connection closed - command: {:?}", cmd);
                        "SSH connection closed (SendError) - session may have timed out or been closed by server".to_string()
                    }
                    _ => format!("Failed to open SSH channel: {:?}", e),
                };
                return Err(crate::Error::ConnectionError(details));
            }
        };

        // Convert command to string and escape it properly
        let command_str: String = cmd.into();
        debug!(command = %command_str, "Executing escaped command");

        // Execute the escaped command
        match channel.exec(true, command_str.as_bytes()).await {
            Ok(_) => {
                debug!("Command sent successfully");
                self.process_channel_output(&mut channel).await
            }
            Err(e) => {
                error!(error = ?e, "Failed to execute command");
                Err(crate::Error::ConnectionError(format!(
                    "Failed to execute command: {:?}",
                    e
                )))
            }
        }
    }

    async fn download_file(&self, remote_path: &str, local_path: &str) -> crate::Result<()> {
        // Create parent directories if they don't exist
        if let Some(parent) = Path::new(local_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let sftp = self.create_sftp_session().await?;

        // Create temporary file for download
        let temp_path = format!("{}.tmp", local_path);
        let mut local_file = match tokio::fs::File::create(&temp_path).await {
            Ok(file) => file,
            Err(e) => {
                return Err(crate::Error::FileTransferError(format!(
                    "Failed to create local file: {}",
                    e
                )));
            }
        };

        // Open remote file with error handling
        let mut remote_file = match sftp.open(remote_path).await {
            Ok(file) => file,
            Err(e) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(crate::Error::FileTransferError(format!(
                    "Failed to open remote file: {}",
                    e
                )));
            }
        };

        // Copy with timeout
        match tokio::time::timeout(
            Duration::from_secs(300), // 5 minute timeout
            tokio::io::copy(&mut remote_file, &mut local_file),
        )
        .await
        {
            Ok(Ok(_)) => {
                // Ensure file is flushed
                local_file.sync_all().await?;
                // Rename temp file to target
                tokio::fs::rename(temp_path, local_path).await?;
                Ok(())
            }
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(crate::Error::FileTransferError(format!(
                    "Copy failed: {}",
                    e
                )))
            }
            Err(_) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(crate::Error::FileTransferError("Download timed out".into()))
            }
        }
    }

    #[instrument(skip(self, file_contents))]
    async fn transfer_file(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> crate::Result<()> {
        self.transfer_file_with_timeout(file_contents, remote_dest)
            .await
    }
}

fn is_windows_remote_path(path: &str) -> bool {
    path.starts_with("C:\\")
        || path.starts_with("c:\\")
        || path.starts_with("C:/")
        || path.starts_with("c:/")
}

fn normalized_sftp_path(remote_dest: &str) -> Cow<'_, str> {
    if is_windows_remote_path(remote_dest) {
        Cow::Owned(windows_sftp_path_candidates(remote_dest)[0].clone())
    } else {
        Cow::Borrowed(remote_dest)
    }
}

fn push_unique_path(paths: &mut Vec<String>, candidate: String) {
    if !paths
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&candidate))
    {
        paths.push(candidate);
    }
}

fn windows_sftp_path_candidates(remote_dest: &str) -> Vec<String> {
    let normalized = remote_dest.replace('\\', "/");
    let mut candidates = Vec::new();

    if let Some((drive, rest)) = normalized.split_once(":/") {
        let rest = rest.trim_start_matches('/');
        push_unique_path(&mut candidates, format!("/{drive}:/{rest}"));
        push_unique_path(&mut candidates, format!("/{drive}/{rest}"));
        push_unique_path(&mut candidates, format!("{drive}:/{rest}"));
    } else {
        push_unique_path(&mut candidates, normalized);
    }

    candidates
}

fn windows_parent_directories(remote_dest: &str) -> Option<Vec<String>> {
    let normalized = remote_dest.replace('\\', "/");

    let (prefix, rest) = if let Some(rest) = normalized.strip_prefix('/') {
        if let Some((drive, remainder)) = rest.split_once(":/") {
            (format!("/{drive}:"), remainder)
        } else if let Some((drive, remainder)) = rest.split_once('/') {
            if drive.len() != 1 || !drive.chars().all(|ch| ch.is_ascii_alphabetic()) {
                return None;
            }
            (format!("/{drive}"), remainder)
        } else {
            return None;
        }
    } else if let Some((drive, remainder)) = normalized.split_once(":/") {
        (format!("/{drive}:"), remainder)
    } else {
        return None;
    };

    let mut parts = rest
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();

    if parts.is_empty() {
        return Some(Vec::new());
    }

    parts.pop();

    let mut current = format!("{prefix}/");
    let mut parent_dirs = Vec::with_capacity(parts.len());
    for part in parts {
        if current.ends_with('/') {
            current.push_str(part);
        } else {
            current.push('/');
            current.push_str(part);
        }
        parent_dirs.push(current.clone());
    }

    Some(parent_dirs)
}

impl SSHSession {
    async fn verify_sftp_connection(
        &self,
        sftp: &russh_sftp::client::SftpSession,
    ) -> crate::Result<()> {
        match sftp.try_exists("/").await {
            Ok(_) => Ok(()),
            Err(_) => Err(crate::Error::ConnectionError(
                "SFTP connection verification failed".into(),
            )),
        }
    }

    #[instrument(skip(self))]
    async fn create_sftp_session_with_retry(
        &self,
    ) -> crate::Result<russh_sftp::client::SftpSession> {
        let mut attempt = 0;
        let max_attempts = 3;

        while attempt < max_attempts {
            debug!(attempt, "Attempting to create SFTP session");

            match self.create_sftp_session().await {
                Ok(sftp) => match self.verify_sftp_connection(&sftp).await {
                    Ok(()) => {
                        debug!("SFTP session created and verified");
                        return Ok(sftp);
                    }
                    Err(e) => {
                        warn!(
                            attempt,
                            error = ?e,
                            "SFTP connection verification failed"
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        attempt,
                        error = ?e,
                        "Failed to create SFTP session"
                    );
                }
            }

            attempt += 1;
            if attempt < max_attempts {
                let delay = Duration::from_secs(1 << attempt);
                debug!(delay_ms = delay.as_millis(), "Waiting before retry");
                tokio::time::sleep(delay).await;
            }
        }

        error!("Failed to create SFTP session after all retries");
        Err(crate::Error::FileTransferError(
            "Failed to create SFTP session after retries".into(),
        ))
    }

    #[instrument(skip(self, channel))]
    async fn process_channel_output(
        &self,
        channel: &mut russh::Channel<russh::client::Msg>,
    ) -> crate::Result<CommandOutput> {
        const TIMEOUT_SECONDS: u64 = 300; // Increased from 120s to 5 minutes for long-running operations
        const BUFFER_CAPACITY: usize = 1024 * 1024; // 1MB initial capacity

        let processing = async {
            let mut stdout = Vec::with_capacity(BUFFER_CAPACITY);
            let mut stderr = Vec::with_capacity(BUFFER_CAPACITY);

            // Track EOF and exit status
            let mut remote_eof_received = false;
            let mut exit_status = None;

            loop {
                match channel.wait().await {
                    Some(msg) => {
                        match msg {
                            russh::ChannelMsg::Data { ref data } => {
                                if !data.is_empty() {
                                    stdout.extend_from_slice(data);
                                    trace!(bytes = data.len(), "Received stdout data");
                                }
                            }
                            russh::ChannelMsg::ExtendedData { ref data, .. } => {
                                if !data.is_empty() {
                                    stderr.extend_from_slice(data);
                                    trace!(bytes = data.len(), "Received stderr data");
                                }
                            }
                            russh::ChannelMsg::Eof => {
                                debug!("Remote EOF received");
                                remote_eof_received = true;

                                // If we already have an exit status, we can finish
                                if exit_status.is_some() {
                                    debug!("EOF received after exit status - terminating");
                                    break;
                                }
                            }
                            russh::ChannelMsg::ExitStatus { exit_status: code } => {
                                debug!(status = code, "Received exit status");
                                exit_status = Some(code);

                                // If we already have EOF, we can finish
                                if remote_eof_received {
                                    debug!("Exit status received after EOF - terminating");
                                    break;
                                }
                            }
                            russh::ChannelMsg::ExitSignal { signal_name, .. } => {
                                warn!("Remote process terminated by signal: {:?}", signal_name);
                                // Convention: use status code 128 + signal number for signal termination
                                exit_status = Some(128);
                                break;
                            }
                            _ => {
                                trace!("Received other channel message");
                            }
                        }
                    }
                    None => {
                        debug!("Channel closed");
                        break;
                    }
                }
            }

            // Send EOF if we haven't received an exit status
            if !remote_eof_received {
                if let Err(e) = channel.eof().await {
                    warn!(error = ?e, "Failed to send EOF");
                }
            }

            Ok(CommandOutput {
                stdout,
                stderr,
                status_code: exit_status,
            })
        };

        // Wrap the processing in a timeout
        match timeout(Duration::from_secs(TIMEOUT_SECONDS), processing).await {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    "Command execution timed out after {} seconds",
                    TIMEOUT_SECONDS
                );
                Err(crate::Error::CommandError(format!(
                    "Command execution timed out after {} seconds",
                    TIMEOUT_SECONDS
                )))
            }
        }
    }

    #[instrument(skip(self))]
    async fn create_sftp_session(&self) -> crate::Result<russh_sftp::client::SftpSession> {
        debug!("Opening SSH channel for SFTP session");
        let channel = match self.session.channel_open_session().await {
            Ok(ch) => ch,
            Err(e) => {
                let details = match e {
                    russh::Error::Disconnect => {
                        error!("SSH connection closed while creating SFTP session");
                        "SSH connection closed by remote".to_string()
                    }
                    russh::Error::SendError => {
                        error!("SSH connection closed while creating SFTP session");
                        "SSH connection closed (SendError) while creating SFTP - session may have timed out".to_string()
                    }
                    _ => {
                        error!(error = ?e, "Failed to open SSH channel for SFTP");
                        format!("Failed to open SSH channel: {:?}", e)
                    }
                };
                return Err(crate::Error::FileTransferError(details));
            }
        };

        debug!("Requesting SFTP subsystem");
        match channel.request_subsystem(true, "sftp").await {
            Ok(_) => debug!("SFTP subsystem request successful"),
            Err(e) => {
                error!(error = ?e, "SFTP subsystem request failed");
                return Err(crate::Error::FileTransferError(format!(
                    "SFTP subsystem request failed: {:?}",
                    e
                )));
            }
        }

        debug!("Initializing SFTP session");
        match russh_sftp::client::SftpSession::new(channel.into_stream()).await {
            Ok(session) => {
                debug!("SFTP session successfully initialized");
                Ok(session)
            }
            Err(e) => {
                error!(error = ?e, "SFTP session initialization failed");
                Err(crate::Error::FileTransferError(format!(
                    "SFTP session initialization failed: {:?}",
                    e
                )))
            }
        }
    }

    async fn transfer_file_with_timeout(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> crate::Result<()> {
        const TRANSFER_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

        match tokio::time::timeout(
            TRANSFER_TIMEOUT,
            self.transfer_file_inner(file_contents, remote_dest),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(crate::Error::FileTransferError(
                "File transfer operation timed out".into(),
            )),
        }
    }

    async fn transfer_file_inner(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> crate::Result<()> {
        let mut last_error = None;
        for attempt in 0..2 {
            match self
                .try_sftp_transfer(file_contents.clone(), remote_dest)
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last_error = Some(error);
                    if attempt == 0 {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            crate::Error::FileTransferError(format!("SFTP transfer failed for path: {remote_dest}"))
        }))
    }

    async fn try_sftp_transfer(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> crate::Result<()> {
        let sftp = match self.create_sftp_session_with_retry().await {
            Ok(session) => session,
            Err(e) => {
                // Add context to error messages
                return Err(match e {
                    crate::Error::FileTransferError(msg) if msg.contains("Disconnect") => {
                        crate::Error::FileTransferError(
                            "Remote host terminated the SSH connection. This might indicate system resource issues or connection problems.".to_string()
                        )
                    },
                    crate::Error::FileTransferError(msg) if msg.contains("Send") => {
                        crate::Error::FileTransferError(
                            "Lost connection to remote host while trying to establish SFTP session. This might indicate network issues or system resource constraints.".to_string()
                        )
                    },
                    _ => e
                });
            }
        };

        if is_windows_remote_path(remote_dest) {
            let mut failures = Vec::new();
            for candidate in windows_sftp_path_candidates(remote_dest) {
                match self
                    .try_direct_file_transfer(&sftp, &file_contents, &candidate)
                    .await
                {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        let _ = sftp.remove_file(&candidate).await;
                        failures.push(format!("{candidate}: {err}"));
                    }
                }
            }

            return Err(crate::Error::FileTransferError(format!(
                "SFTP Error: {}",
                failures.join(" | ")
            )));
        }

        let sftp_dest = normalized_sftp_path(remote_dest);
        match self
            .try_direct_file_transfer(&sftp, &file_contents, sftp_dest.as_ref())
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = sftp.remove_file(sftp_dest.as_ref()).await;
                Err(e)
            }
        }
    }

    #[instrument(skip(self, sftp, file_contents))]
    async fn try_direct_file_transfer(
        &self,
        sftp: &russh_sftp::client::SftpSession,
        file_contents: &[u8],
        remote_dest: &str,
    ) -> crate::Result<()> {
        debug!(dest = %remote_dest, "Attempting direct file transfer");

        let mut remote_file = match sftp.create(remote_dest).await {
            Ok(file) => {
                debug!("Created remote file");
                file
            }
            Err(e) => {
                debug!(error = ?e, "Failed to create remote file, attempting to create parent directories");
                match self.create_parent_directories(sftp, remote_dest).await {
                    Ok(_) => {
                        debug!("Parent directories created, retrying file creation");
                        match sftp.create(remote_dest).await {
                            Ok(file) => file,
                            Err(e) => {
                                error!(error = ?e, "Failed to create remote file after directory creation");
                                return Err(crate::Error::FileTransferError(format!(
                                    "Failed to create remote file: {:?}",
                                    e
                                )));
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = ?e, "Failed to create parent directories");
                        return Err(e);
                    }
                }
            }
        };

        debug!(bytes = file_contents.len(), "Writing file contents");
        match remote_file.write_all(file_contents).await {
            Ok(_) => {
                debug!("Successfully wrote file contents");
            }
            Err(e) => {
                error!(
                    error = ?e,
                    bytes_written = 0,
                    total_bytes = file_contents.len(),
                    "Failed to write file contents"
                );
                let _ = remote_file.shutdown().await;
                return Err(crate::Error::FileTransferError(format!(
                    "Failed to write file contents: {:?}",
                    e
                )));
            }
        }

        debug!("Closing remote file");
        match remote_file.shutdown().await {
            Ok(_) => {
                debug!("File transfer completed successfully");
                Ok(())
            }
            Err(e) => {
                error!(error = ?e, "Failed to close remote file");
                Err(crate::Error::FileTransferError(format!(
                    "Failed to close remote file: {:?}",
                    e
                )))
            }
        }
    }

    async fn create_parent_directories(
        &self,
        sftp: &russh_sftp::client::SftpSession,
        remote_dest: &str,
    ) -> crate::Result<()> {
        if let Some(parent_dirs) = windows_parent_directories(remote_dest) {
            for dir in parent_dirs {
                if !sftp.try_exists(&dir).await.unwrap_or(false) {
                    match sftp.create_dir(&dir).await {
                        Ok(()) => {}
                        Err(err) if sftp.try_exists(&dir).await.unwrap_or(false) => {
                            debug!(path = %dir, error = ?err, "Windows SFTP directory appeared during creation");
                        }
                        Err(err) => return Err(err.into()),
                    }
                }
            }
            return Ok(());
        }

        let path = Path::new(remote_dest);
        if let Some(parent) = path.parent() {
            let mut current = String::with_capacity(remote_dest.len());

            if let Some(Component::Prefix(p)) = parent.components().next() {
                current.push_str(p.as_os_str().to_str().ok_or_else(|| {
                    crate::Error::FileTransferError("Invalid UTF-8 in path prefix".to_string())
                })?);
            }

            for comp in parent.components() {
                match comp {
                    Component::Normal(dir) => {
                        if !current.is_empty() {
                            current.push(std::path::MAIN_SEPARATOR);
                        }
                        current.push_str(dir.to_str().ok_or_else(|| {
                            crate::Error::FileTransferError("Invalid UTF-8 in path".to_string())
                        })?);

                        if !sftp.try_exists(&current).await.unwrap_or(false) {
                            sftp.create_dir(&current).await?;
                        }
                    }
                    Component::RootDir => current.push(std::path::MAIN_SEPARATOR),
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

impl Config for SSHConfig {
    type SessionType = SSHSession;

    async fn create_session(&self) -> crate::Result<Self::SessionType> {
        match self {
            SSHConfig::Key {
                key_path,
                inactivity_timeout,
                username,
                socket,
                host_key_policy,
            } => {
                let mut session =
                    get_handle(*socket, *inactivity_timeout, *host_key_policy).await?;

                let key_pair = load_secret_key(key_path, None)?;
                let auth_res = session
                    .authenticate_publickey(
                        username,
                        PrivateKeyWithHashAlg::new(Arc::new(key_pair), None)?,
                    )
                    .await?;

                if !auth_res {
                    return Err(crate::Error::AuthenticationError(
                        "Failed to authenticate with public key".to_string(),
                    ));
                }

                Ok(SSHSession {
                    session,
                    config: self.clone(),
                })
            }
            SSHConfig::Password {
                username,
                socket,
                password,
                inactivity_timeout,
                host_key_policy,
            } => {
                let mut session =
                    get_handle(*socket, *inactivity_timeout, *host_key_policy).await?;
                let auth_res = session
                    .authenticate_password(username, password.expose_secret())
                    .await?;

                if !auth_res {
                    return Err(crate::Error::AuthenticationError(
                        "Failed to authenticate with password".to_string(),
                    ));
                }

                Ok(SSHSession {
                    session,
                    config: self.clone(),
                })
            }
        }
    }
}

async fn get_handle(
    socket: SocketAddr,
    timeout: Duration,
    host_key_policy: HostKeyPolicy,
) -> crate::Result<russh::client::Handle<Handler>> {
    let config = client::Config {
        inactivity_timeout: Some(timeout),
        ..Default::default()
    };

    let config = Arc::new(config);
    let sh = Handler {
        socket,
        host_key_policy,
    };
    Ok(client::connect(config, socket, sh).await?)
}

struct Handler {
    socket: SocketAddr,
    host_key_policy: HostKeyPolicy,
}

fn verify_server_key(
    socket: SocketAddr,
    host_key_policy: HostKeyPolicy,
    key: &PublicKey,
    known_hosts_path: Option<&Path>,
) -> crate::Result<()> {
    let host = socket.ip().to_string();
    let port = socket.port();

    match host_key_policy {
        HostKeyPolicy::DangerouslyAcceptUnknown => {
            let known_entries =
                lookup_known_hosts(&host, port, known_hosts_path).map_err(|err| {
                    crate::Error::ConnectionError(format!(
                        "known_hosts lookup failed for {socket}: {err}"
                    ))
                })?;

            if known_entries.is_empty() {
                return Ok(());
            }

            if check_known_host_match(&host, port, key, known_hosts_path).map_err(|err| {
                crate::Error::ConnectionError(format!(
                    "host key verification failed for {socket}: {err}"
                ))
            })? {
                Ok(())
            } else {
                Err(crate::Error::ConnectionError(format!(
                    "host key for {socket} is not present in known_hosts"
                )))
            }
        }
        HostKeyPolicy::RequireKnownHosts => {
            if check_known_host_match(&host, port, key, known_hosts_path).map_err(|err| {
                crate::Error::ConnectionError(format!(
                    "host key verification failed for {socket}: {err}"
                ))
            })? {
                Ok(())
            } else {
                Err(crate::Error::ConnectionError(format!(
                    "host key for {socket} is not present in known_hosts"
                )))
            }
        }
    }
}

fn lookup_known_hosts(
    host: &str,
    port: u16,
    known_hosts_path: Option<&Path>,
) -> std::result::Result<Vec<(usize, PublicKey)>, russh_keys::Error> {
    match known_hosts_path {
        Some(path) => known_host_keys_path(host, port, path),
        None => known_host_keys(host, port),
    }
}

fn check_known_host_match(
    host: &str,
    port: u16,
    key: &PublicKey,
    known_hosts_path: Option<&Path>,
) -> std::result::Result<bool, russh_keys::Error> {
    match known_hosts_path {
        Some(path) => check_known_hosts_path(host, port, key, path),
        None => check_known_hosts(host, port, key),
    }
}

#[async_trait]
impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        match verify_server_key(self.socket, self.host_key_policy, key, None) {
            Ok(()) => Ok(true),
            Err(err) => {
                warn!(
                    socket = %self.socket,
                    policy = ?self.host_key_policy,
                    error = %err,
                    "rejecting SSH server key"
                );
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        normalized_sftp_path, verify_server_key, windows_parent_directories,
        windows_sftp_path_candidates, HostKeyPolicy,
    };
    use russh_keys::ssh_key::PublicKey;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const RSA_3072_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCmjkeMm8k3JkNrf16eb5pG4bc77B6Mt3VN4saltsRV8vASpyWa/PlBgdaeldOaNJ5NK0gqU3KyiUNzHbdcc8572e7IUBDJS/rlaWARiSL4aos2VbNX0k56Z5zYp9m/bq5m9/mlb+PQkNBjIhimgpYNiq2TwBiYeA6tLb79cPtHA0cX5BLk/a5oUpLsiR4kI/f+Q98vVDKasKXXVh5YLkLobrruDB6er2A9fOcIUF0O4JCRLh/Dc161gE3fQrYTMQenbppZzfxrZfQ8YwLPvKjnqm+XRX+pbTtaJuj0EgTSzUK+EZxoSw8CNwiZpxrjwecTMVQ8w/srQmh4ABGuTqk0wP8HcI7hg+fpBv7kiejh5X/Oehxt+Puu85u9GVXb1a0av/vhJvUCBcuISvCA/z1wVJ0xdLhb1/ZiTDdTzyNbZQ0OQijzK+e1SlkNhp+3eGVZu3pNZvnTppwIXv3wg6kV1HodkWGgh1ayY7Buc52Z8okDYqvJat5CzOj5OaQNr/k= user@example.com";
    const RSA_4096_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC0WRHtxuxefSJhpIxGq4ibGFgwYnESPm8C3JFM88A1JJLoprenklrd7VJ+VH3Ov/bQwZwLyRU5dRmfR/SWTtIPWs7tToJVayKKDB+/qoXmM5ui/0CU2U4rCdQ6PdaCJdC7yFgpPL8WexjWN06+eSIKYz1AAXbx9rRv1iasslK/KUqtsqzVliagI6jl7FPO2GhRZMcso6LsZGgSxuYf/Lp0D/FcBU8GkeOo1Sx5xEt8H8bJcErtCe4Blb8JxcW6EXO3sReb4z+zcR07gumPgFITZ6hDA8sSNuvo/AlWg0IKTeZSwHHVknWdQqDJ0uczE837caBxyTZllDNIGkBjCIIOFzuTT76HfYc/7CTTGk07uaNkUFXKN79xDiFOX8JQ1ZZMZvGOTwWjuT9CqgdTvQRORbRWwOYv3MH8re9ykw3Ip6lrPifY7s6hOaAKry/nkGPMt40m1TdiW98MTIpooE7W+WXu96ax2l2OJvxX8QR7l+LFlKnkIEEJd/ItF1G22UmOjkVwNASTwza/hlY+8DoVvEmwum/nMgH2TwQT3bTQzF9s9DOJkH4d8p4Mw4gEDjNx0EgUFA91ysCAeUMQQyIvuR8HXXa+VcvhOOO5mmBcVhxJ3qUOJTyDBsT0932Zb4mNtkxdigoVxu+iiwk0vwtvKwGVDYdyMP5EAQeEIP1t0w== user@example.com";

    fn temp_known_hosts_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("rustrc-known-hosts-{label}-{unique}"))
    }

    fn key(value: &str) -> PublicKey {
        let without_comment = value
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        PublicKey::from_openssh(&without_comment).expect("test public key should parse")
    }

    #[test]
    fn normalized_sftp_path_rewrites_windows_separators() {
        assert_eq!(
            normalized_sftp_path(r"C:\Temp\pandoras_box\chimera.exe"),
            "/C:/Temp/pandoras_box/chimera.exe"
        );
    }

    #[test]
    fn windows_parent_directories_build_drive_aware_chain() {
        assert_eq!(
            windows_parent_directories(r"C:\Temp\pandoras_box\mission\chimera.exe"),
            Some(vec![
                "/C:/Temp".to_string(),
                "/C:/Temp/pandoras_box".to_string(),
                "/C:/Temp/pandoras_box/mission".to_string(),
            ])
        );
    }

    #[test]
    fn windows_sftp_path_candidates_try_multiple_shapes() {
        assert_eq!(
            windows_sftp_path_candidates(r"C:\Temp\pandoras_box\chimera.exe"),
            vec![
                "/C:/Temp/pandoras_box/chimera.exe".to_string(),
                "/C/Temp/pandoras_box/chimera.exe".to_string(),
                "C:/Temp/pandoras_box/chimera.exe".to_string(),
            ]
        );
    }

    #[test]
    fn windows_parent_directories_support_drive_without_colon_segment() {
        assert_eq!(
            windows_parent_directories("/C/Temp/pandoras_box/mission/chimera.exe"),
            Some(vec![
                "/C/Temp".to_string(),
                "/C/Temp/pandoras_box".to_string(),
                "/C/Temp/pandoras_box/mission".to_string(),
            ])
        );
    }

    #[test]
    fn dangerously_accept_unknown_allows_explicit_first_contact() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22);
        let path = temp_known_hosts_path("unknown-host");

        verify_server_key(
            socket,
            HostKeyPolicy::DangerouslyAcceptUnknown,
            &key(RSA_3072_PUBLIC_KEY),
            Some(&path),
        )
        .expect("explicit dangerous policy should accept an unknown host");
    }

    #[test]
    fn dangerously_accept_unknown_still_rejects_changed_key() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22);
        let path = temp_known_hosts_path("key-change");
        std::fs::write(&path, format!("10.0.0.8 {RSA_3072_PUBLIC_KEY}\n"))
            .expect("known_hosts fixture should be written");

        let error = verify_server_key(
            socket,
            HostKeyPolicy::DangerouslyAcceptUnknown,
            &key(RSA_4096_PUBLIC_KEY),
            Some(&path),
        )
        .expect_err("changed keys should be rejected");

        assert!(error.to_string().contains("host key verification failed"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn convenience_config_requires_known_hosts_and_redacts_password() {
        let config = super::SSHConfig::password(
            "operator",
            "debug-must-not-leak-this",
            "127.0.0.1:22",
            Duration::from_secs(5),
        )
        .await
        .expect("loopback socket should resolve");
        let rendered = format!("{config:?}");

        assert!(rendered.contains("RequireKnownHosts"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("debug-must-not-leak-this"));
    }

    #[test]
    fn require_known_hosts_accepts_enrolled_key() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22);
        let path = temp_known_hosts_path("enrolled-host");
        std::fs::write(&path, format!("10.0.0.8 {RSA_3072_PUBLIC_KEY}\n"))
            .expect("known_hosts fixture should be written");

        verify_server_key(
            socket,
            HostKeyPolicy::RequireKnownHosts,
            &key(RSA_3072_PUBLIC_KEY),
            Some(&path),
        )
        .expect("enrolled key should be accepted");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn require_known_hosts_rejects_unknown_host() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22);
        let path = temp_known_hosts_path("require-known");

        let error = verify_server_key(
            socket,
            HostKeyPolicy::RequireKnownHosts,
            &key(RSA_3072_PUBLIC_KEY),
            Some(&path),
        )
        .expect_err("strict known_hosts policy should reject unseen hosts");

        assert!(error.to_string().contains("is not present in known_hosts"));
    }
}
