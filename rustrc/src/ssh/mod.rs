use crate::client::{Command, CommandOutput, Config, Session};
use russh::client;
use russh::keys::agent::{
    client::{AgentClient, AgentStream},
    AgentIdentity,
};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::known_hosts::{
    check_known_hosts, check_known_hosts_path, known_host_keys, known_host_keys_path,
};
use russh::keys::{load_secret_key, HashAlg, PublicKey};
use std::{
    borrow::Cow,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

static DOWNLOAD_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
use tokio::time::{timeout, Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
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

/// Per-operation deadlines and byte bounds for SSH/SFTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshOperationLimits {
    pub command_timeout: Duration,
    pub transfer_timeout: Duration,
    pub max_command_output_bytes: usize,
    pub max_download_bytes: u64,
}

impl Default for SshOperationLimits {
    fn default() -> Self {
        Self {
            command_timeout: Duration::from_secs(300),
            transfer_timeout: Duration::from_secs(300),
            max_command_output_bytes: 1024 * 1024,
            max_download_bytes: 16 * 1024 * 1024,
        }
    }
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
        expected_public_key_sha256: Option<String>,
        connection_timeout: Duration,
        inactivity_timeout: Duration,
        operation_limits: SshOperationLimits,
        host_key_policy: HostKeyPolicy,
    },
    Agent {
        username: String,
        socket: SocketAddr,
        public_key_sha256: String,
        connection_timeout: Duration,
        inactivity_timeout: Duration,
        operation_limits: SshOperationLimits,
        host_key_policy: HostKeyPolicy,
    },
    Password {
        username: String,
        socket: SocketAddr,
        password: SecretString,
        connection_timeout: Duration,
        inactivity_timeout: Duration,
        operation_limits: SshOperationLimits,
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
            expected_public_key_sha256: None,
            connection_timeout: Duration::from_secs(10),
            inactivity_timeout,
            operation_limits: SshOperationLimits::default(),
            host_key_policy,
        })
    }

    pub async fn key_with_policy_and_fingerprint<
        U: Into<String>,
        S: ToSocketAddrs,
        P: Into<PathBuf>,
        F: Into<String>,
    >(
        username: U,
        socket: S,
        key_path: P,
        expected_public_key_sha256: F,
        inactivity_timeout: Duration,
        host_key_policy: HostKeyPolicy,
    ) -> crate::Result<Self> {
        Ok(SSHConfig::Key {
            username: username.into(),
            socket: Self::resolve_socket(socket).await?,
            key_path: key_path.into(),
            expected_public_key_sha256: Some(expected_public_key_sha256.into()),
            connection_timeout: Duration::from_secs(10),
            inactivity_timeout,
            operation_limits: SshOperationLimits::default(),
            host_key_policy,
        })
    }

    pub async fn agent_with_policy<U: Into<String>, S: ToSocketAddrs, F: Into<String>>(
        username: U,
        socket: S,
        public_key_sha256: F,
        inactivity_timeout: Duration,
        host_key_policy: HostKeyPolicy,
    ) -> crate::Result<Self> {
        Ok(SSHConfig::Agent {
            username: username.into(),
            socket: Self::resolve_socket(socket).await?,
            public_key_sha256: public_key_sha256.into(),
            connection_timeout: Duration::from_secs(10),
            inactivity_timeout,
            operation_limits: SshOperationLimits::default(),
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
            connection_timeout: Duration::from_secs(10),
            inactivity_timeout,
            operation_limits: SshOperationLimits::default(),
            host_key_policy,
        })
    }

    #[must_use]
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        match &mut self {
            Self::Key {
                connection_timeout, ..
            }
            | Self::Agent {
                connection_timeout, ..
            }
            | Self::Password {
                connection_timeout, ..
            } => *connection_timeout = timeout,
        }
        self
    }

    #[must_use]
    pub fn with_operation_limits(mut self, limits: SshOperationLimits) -> Self {
        match &mut self {
            Self::Key {
                operation_limits, ..
            }
            | Self::Agent {
                operation_limits, ..
            }
            | Self::Password {
                operation_limits, ..
            } => *operation_limits = limits,
        }
        self
    }

    fn operation_limits(&self) -> SshOperationLimits {
        match self {
            Self::Key {
                operation_limits, ..
            }
            | Self::Agent {
                operation_limits, ..
            }
            | Self::Password {
                operation_limits, ..
            } => *operation_limits,
        }
    }
}

fn append_bounded_output(
    destination: &mut Vec<u8>,
    incoming: &[u8],
    other_stream_len: usize,
    maximum: usize,
) -> crate::Result<()> {
    let requested = destination
        .len()
        .checked_add(other_stream_len)
        .and_then(|current| current.checked_add(incoming.len()))
        .ok_or_else(|| crate::Error::CommandError("SSH output length overflowed usize".into()))?;
    if requested > maximum {
        return Err(crate::Error::CommandError(format!(
            "SSH command output exceeded the {maximum} byte bound"
        )));
    }
    destination.extend_from_slice(incoming);
    Ok(())
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
        let limits = self.config.operation_limits();
        if let Some(parent) = Path::new(local_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let sftp = self.create_sftp_session().await?;
        let candidates = if is_windows_remote_path(remote_path) {
            windows_sftp_path_candidates(remote_path)
        } else {
            vec![remote_path.to_string()]
        };
        let mut failures = Vec::new();
        let mut selected_remote_file = None;
        for candidate in candidates {
            let metadata = match sftp.symlink_metadata(&candidate).await {
                Ok(metadata) => metadata,
                Err(error) => {
                    failures.push(format!("{candidate}: metadata: {error}"));
                    continue;
                }
            };
            if metadata.is_symlink() || !metadata.is_regular() {
                return Err(crate::Error::FileTransferError(format!(
                    "Remote download source must be a regular non-link file: {candidate}"
                )));
            }
            if metadata
                .size
                .is_some_and(|size| size > limits.max_download_bytes)
            {
                return Err(crate::Error::FileTransferError(format!(
                    "Remote file exceeds the {} byte download bound: {candidate}",
                    limits.max_download_bytes
                )));
            }
            match sftp.open(&candidate).await {
                Ok(file) => {
                    selected_remote_file = Some(file);
                    break;
                }
                Err(error) => failures.push(format!("{candidate}: open: {error}")),
            }
        }
        let remote_file = selected_remote_file.ok_or_else(|| {
            crate::Error::FileTransferError(format!(
                "Failed to open remote file through any safe SFTP path: {}",
                failures.join(" | ")
            ))
        })?;

        let sequence = DOWNLOAD_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = format!("{local_path}.tmp-{}-{sequence}", std::process::id());
        let mut options = tokio::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut local_file = options.open(&temp_path).await.map_err(|error| {
            crate::Error::FileTransferError(format!("Failed to create local file: {error}"))
        })?;

        let mut bounded_remote = remote_file.take(limits.max_download_bytes.saturating_add(1));

        match tokio::time::timeout(
            limits.transfer_timeout,
            tokio::io::copy(&mut bounded_remote, &mut local_file),
        )
        .await
        {
            Ok(Ok(copied)) if copied <= limits.max_download_bytes => {
                let finalize_result = async {
                    local_file.sync_all().await?;
                    tokio::fs::rename(&temp_path, local_path).await?;
                    Ok::<(), crate::Error>(())
                }
                .await;
                if finalize_result.is_err() {
                    let _ = tokio::fs::remove_file(&temp_path).await;
                }
                finalize_result
            }
            Ok(Ok(_)) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(crate::Error::FileTransferError(format!(
                    "Remote file exceeded the {} byte download bound",
                    limits.max_download_bytes
                )))
            }
            Ok(Err(error)) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(crate::Error::FileTransferError(format!(
                    "Copy failed: {error}"
                )))
            }
            Err(_) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(crate::Error::FileTransferError(format!(
                    "Download timed out after {:?}",
                    limits.transfer_timeout
                )))
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
        let limits = self.config.operation_limits();
        let initial_capacity = limits.max_command_output_bytes.min(64 * 1024);

        let processing = async {
            let mut stdout = Vec::with_capacity(initial_capacity);
            let mut stderr = Vec::with_capacity(initial_capacity);

            // Track EOF and exit status
            let mut remote_eof_received = false;
            let mut exit_status = None;

            loop {
                match channel.wait().await {
                    Some(msg) => {
                        match msg {
                            russh::ChannelMsg::Data { ref data } => {
                                if !data.is_empty() {
                                    append_bounded_output(
                                        &mut stdout,
                                        data,
                                        stderr.len(),
                                        limits.max_command_output_bytes,
                                    )?;
                                    trace!(bytes = data.len(), "Received stdout data");
                                }
                            }
                            russh::ChannelMsg::ExtendedData { ref data, .. } => {
                                if !data.is_empty() {
                                    append_bounded_output(
                                        &mut stderr,
                                        data,
                                        stdout.len(),
                                        limits.max_command_output_bytes,
                                    )?;
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
        match timeout(limits.command_timeout, processing).await {
            Ok(result) => result,
            Err(_) => {
                warn!(timeout = ?limits.command_timeout, "Command execution timed out");
                Err(crate::Error::CommandError(format!(
                    "Command execution timed out after {:?}",
                    limits.command_timeout
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
        let transfer_timeout = self.config.operation_limits().transfer_timeout;

        match tokio::time::timeout(
            transfer_timeout,
            self.transfer_file_inner(file_contents, remote_dest),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(crate::Error::FileTransferError(format!(
                "File transfer operation timed out after {transfer_timeout:?}"
            ))),
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
                expected_public_key_sha256,
                connection_timeout,
                inactivity_timeout,
                username,
                socket,
                host_key_policy,
                ..
            } => {
                // Key availability, algorithm policy, and pinned identity are checked
                // before any connection to the target is opened.
                let key_pair =
                    load_validated_private_key(key_path, expected_public_key_sha256.as_deref())?;
                let mut session = get_handle(
                    *socket,
                    *connection_timeout,
                    *inactivity_timeout,
                    *host_key_policy,
                )
                .await?;
                let auth_res = session
                    .authenticate_publickey(
                        username,
                        PrivateKeyWithHashAlg::new(Arc::new(key_pair), None),
                    )
                    .await?;

                if !auth_res.success() {
                    return Err(crate::Error::AuthenticationError(
                        "Failed to authenticate with public key".to_string(),
                    ));
                }

                Ok(SSHSession {
                    session,
                    config: self.clone(),
                })
            }
            SSHConfig::Agent {
                username,
                socket,
                public_key_sha256,
                connection_timeout,
                inactivity_timeout,
                host_key_policy,
                ..
            } => {
                // Agent availability and exact identity selection happen locally,
                // before opening a connection to the target.
                let (mut agent, identity) = configured_agent_identity(public_key_sha256).await?;
                let mut session = get_handle(
                    *socket,
                    *connection_timeout,
                    *inactivity_timeout,
                    *host_key_policy,
                )
                .await?;
                let auth_res = match identity {
                    AgentIdentity::PublicKey { key, .. } => {
                        session
                            .authenticate_publickey_with(username, key, None, &mut agent)
                            .await
                    }
                    AgentIdentity::Certificate { certificate, .. } => {
                        session
                            .authenticate_certificate_with(username, certificate, None, &mut agent)
                            .await
                    }
                }
                .map_err(|error| {
                    crate::Error::AuthenticationError(format!("SSH agent signing failed: {error}"))
                })?;

                if !auth_res.success() {
                    return Err(crate::Error::AuthenticationError(
                        "Failed to authenticate with selected SSH agent identity".to_string(),
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
                connection_timeout,
                inactivity_timeout,
                host_key_policy,
                ..
            } => {
                let mut session = get_handle(
                    *socket,
                    *connection_timeout,
                    *inactivity_timeout,
                    *host_key_policy,
                )
                .await?;
                let auth_res = session
                    .authenticate_password(username, password.expose_secret())
                    .await?;

                if !auth_res.success() {
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

fn ensure_private_key_algorithm_supported(algorithm: russh::keys::Algorithm) -> crate::Result<()> {
    if algorithm.is_rsa() {
        return Err(crate::Error::ConfigError(
            "RSA SSH private keys are disabled pending resolution of RUSTSEC-2023-0071".to_string(),
        ));
    }
    Ok(())
}

fn load_validated_private_key(
    key_path: &Path,
    expected_public_key_sha256: Option<&str>,
) -> crate::Result<russh::keys::PrivateKey> {
    let key_pair = load_secret_key(key_path, None).map_err(|error| {
        crate::Error::ConfigError(format!(
            "failed to load SSH private key {}: {error}",
            key_path.display()
        ))
    })?;
    ensure_private_key_algorithm_supported(key_pair.algorithm())?;
    let actual = key_pair
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    if expected_public_key_sha256.is_some_and(|expected| expected != actual) {
        return Err(crate::Error::ConfigError(format!(
            "SSH private key {} does not match the pinned public-key fingerprint",
            key_path.display()
        )));
    }
    Ok(key_pair)
}

pub fn preflight_private_key(
    key_path: &Path,
    expected_public_key_sha256: &str,
) -> crate::Result<()> {
    load_validated_private_key(key_path, Some(expected_public_key_sha256)).map(drop)
}

type DynamicAgentClient = AgentClient<Box<dyn AgentStream + Send + Unpin>>;

#[cfg(unix)]
async fn connect_configured_agent() -> crate::Result<DynamicAgentClient> {
    AgentClient::connect_env()
        .await
        .map(AgentClient::dynamic)
        .map_err(|error| crate::Error::ConfigError(format!("SSH agent is unavailable: {error}")))
}

#[cfg(windows)]
async fn connect_configured_agent() -> crate::Result<DynamicAgentClient> {
    let pipe = std::env::var_os("SSH_AUTH_SOCK")
        .unwrap_or_else(|| std::ffi::OsString::from(r"\\.\pipe\openssh-ssh-agent"));
    AgentClient::<tokio::net::windows::named_pipe::NamedPipeClient>::connect_named_pipe(pipe)
        .await
        .map(AgentClient::dynamic)
        .map_err(|error| crate::Error::ConfigError(format!("SSH agent is unavailable: {error}")))
}

#[cfg(not(any(unix, windows)))]
async fn connect_configured_agent() -> crate::Result<DynamicAgentClient> {
    Err(crate::Error::ConfigError(
        "SSH agent authentication is unavailable on this operator platform".to_string(),
    ))
}

async fn configured_agent_identity(
    expected_public_key_sha256: &str,
) -> crate::Result<(DynamicAgentClient, AgentIdentity)> {
    let mut agent = connect_configured_agent().await?;
    let identities = agent.request_identities().await.map_err(|error| {
        crate::Error::ConfigError(format!("failed to enumerate SSH agent identities: {error}"))
    })?;
    let mut matching = identities.into_iter().filter(|identity| {
        identity
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
            == expected_public_key_sha256
    });
    let identity = matching.next().ok_or_else(|| {
        crate::Error::ConfigError(format!(
            "SSH agent does not contain pinned identity {expected_public_key_sha256}"
        ))
    })?;
    if matching.next().is_some() {
        return Err(crate::Error::ConfigError(format!(
            "SSH agent identity {expected_public_key_sha256} is ambiguous"
        )));
    }
    ensure_private_key_algorithm_supported(identity.public_key().algorithm())?;
    Ok((agent, identity))
}

pub async fn preflight_agent_identity(expected_public_key_sha256: &str) -> crate::Result<()> {
    configured_agent_identity(expected_public_key_sha256)
        .await
        .map(drop)
}

async fn get_handle(
    socket: SocketAddr,
    connection_timeout: Duration,
    inactivity_timeout: Duration,
    host_key_policy: HostKeyPolicy,
) -> crate::Result<russh::client::Handle<Handler>> {
    let config = client::Config {
        inactivity_timeout: Some(inactivity_timeout),
        ..Default::default()
    };

    let config = Arc::new(config);
    let sh = Handler {
        socket,
        host_key_policy,
    };
    match timeout(connection_timeout, client::connect(config, socket, sh)).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(crate::Error::ConnectionError(format!(
            "SSH connection to {socket} timed out after {connection_timeout:?}"
        ))),
    }
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
) -> std::result::Result<Vec<(usize, PublicKey)>, russh::keys::Error> {
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
) -> std::result::Result<bool, russh::keys::Error> {
    match known_hosts_path {
        Some(path) => check_known_hosts_path(host, port, key, path),
        None => check_known_hosts(host, port, key),
    }
}

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
        append_bounded_output, ensure_private_key_algorithm_supported, normalized_sftp_path,
        verify_server_key, windows_parent_directories, windows_sftp_path_candidates, HostKeyPolicy,
        SshOperationLimits,
    };
    use russh::keys::{Algorithm, PublicKey};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    const ED25519_PUBLIC_KEY_ONE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxAmhZJPwGJReZkxexeDbUT2lNzlBja1wwZ73IWPgnc fixture-one";
    const ED25519_PUBLIC_KEY_TWO: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPC+qyaLgo1fXCJMVIw3eWCWM1MchFSj3pkhHZW+lMDU fixture-two";

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
    fn command_output_buffer_rejects_bytes_beyond_the_exact_bound() {
        let mut stdout = b"1234".to_vec();
        append_bounded_output(&mut stdout, b"56", 2, 8).expect("exact bound");
        let error = append_bounded_output(&mut stdout, b"7", 2, 8)
            .expect_err("one byte beyond the bound must fail");
        assert!(error.to_string().contains("8 byte bound"));
    }

    #[tokio::test]
    async fn operation_limits_are_separate_from_inactivity_and_connection_deadlines() {
        let limits = SshOperationLimits {
            command_timeout: Duration::from_secs(11),
            transfer_timeout: Duration::from_secs(12),
            max_command_output_bytes: 13,
            max_download_bytes: 14,
        };
        let config = super::SSHConfig::password(
            "operator",
            "secret",
            "127.0.0.1:22",
            Duration::from_secs(30),
        )
        .await
        .expect("config")
        .with_connection_timeout(Duration::from_secs(5))
        .with_operation_limits(limits);
        assert_eq!(config.operation_limits(), limits);
        match config {
            super::SSHConfig::Password {
                connection_timeout,
                inactivity_timeout,
                ..
            } => {
                assert_eq!(connection_timeout, Duration::from_secs(5));
                assert_eq!(inactivity_timeout, Duration::from_secs(30));
            }
            _ => panic!("password config expected"),
        }
    }

    #[tokio::test]
    async fn agent_config_pins_one_identity_and_preserves_operation_bounds() {
        let limits = SshOperationLimits {
            command_timeout: Duration::from_secs(11),
            transfer_timeout: Duration::from_secs(12),
            max_command_output_bytes: 13,
            max_download_bytes: 14,
        };
        let fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let config = super::SSHConfig::agent_with_policy(
            "operator",
            "127.0.0.1:22",
            fingerprint,
            Duration::from_secs(30),
            HostKeyPolicy::RequireKnownHosts,
        )
        .await
        .expect("agent config")
        .with_connection_timeout(Duration::from_secs(5))
        .with_operation_limits(limits);

        assert_eq!(config.operation_limits(), limits);
        match config {
            super::SSHConfig::Agent {
                public_key_sha256,
                connection_timeout,
                inactivity_timeout,
                host_key_policy,
                ..
            } => {
                assert_eq!(public_key_sha256, fingerprint);
                assert_eq!(connection_timeout, Duration::from_secs(5));
                assert_eq!(inactivity_timeout, Duration::from_secs(30));
                assert_eq!(host_key_policy, HostKeyPolicy::RequireKnownHosts);
            }
            _ => panic!("agent config expected"),
        }
    }

    #[test]
    fn rsa_private_keys_are_rejected_at_the_auth_boundary() {
        let error = ensure_private_key_algorithm_supported(Algorithm::Rsa { hash: None })
            .expect_err("RSA private keys must be rejected before authentication");
        assert!(error.to_string().contains("RUSTSEC-2023-0071"));
        ensure_private_key_algorithm_supported(Algorithm::Ed25519)
            .expect("Ed25519 keys should remain supported");
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
            &key(ED25519_PUBLIC_KEY_ONE),
            Some(&path),
        )
        .expect("explicit dangerous policy should accept an unknown host");
    }

    #[test]
    fn dangerously_accept_unknown_still_rejects_changed_key() {
        let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 22);
        let path = temp_known_hosts_path("key-change");
        std::fs::write(&path, format!("10.0.0.8 {ED25519_PUBLIC_KEY_ONE}\n"))
            .expect("known_hosts fixture should be written");

        let error = verify_server_key(
            socket,
            HostKeyPolicy::DangerouslyAcceptUnknown,
            &key(ED25519_PUBLIC_KEY_TWO),
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
        std::fs::write(&path, format!("10.0.0.8 {ED25519_PUBLIC_KEY_ONE}\n"))
            .expect("known_hosts fixture should be written");

        verify_server_key(
            socket,
            HostKeyPolicy::RequireKnownHosts,
            &key(ED25519_PUBLIC_KEY_ONE),
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
            &key(ED25519_PUBLIC_KEY_ONE),
            Some(&path),
        )
        .expect_err("strict known_hosts policy should reject unseen hosts");

        assert!(error.to_string().contains("is not present in known_hosts"));
    }
}
