use crate::client::{Command, CommandOutput, Config, Session};
use async_trait::async_trait;
use byteorder::{BigEndian, WriteBytesExt};
use russh::client;
use russh_keys::key::PrivateKeyWithHashAlg;
use russh_keys::load_secret_key;
use russh_keys::ssh_key::public::PublicKey;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::{
    io::AsyncWriteExt,
    net::{lookup_host, ToSocketAddrs},
    time::Duration,
};
use tracing::{debug, error, info, instrument, trace, warn};

pub struct Connected;
pub struct Disconnected;

#[allow(unused)]
pub struct SSHSession {
    session: client::Handle<Handler>,
    config: SSHConfig,
}

#[derive(Debug, Clone)]
pub enum SSHConfig {
    Key {
        username: String,
        socket: SocketAddr,
        key_path: PathBuf,
        inactivity_timeout: Duration,
    },
    Password {
        username: String,
        socket: SocketAddr,
        password: String,
        inactivity_timeout: Duration,
    },
}

impl SSHConfig {
    fn ip(&self) -> IpAddr {
        match self {
            Self::Key { socket, .. } => socket.ip(),
            Self::Password { socket, .. } => socket.ip(),
        }
    }

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
        Ok(SSHConfig::Key {
            username: username.into(),
            socket: Self::resolve_socket(socket).await?,
            key_path: key_path.into(),
            inactivity_timeout,
        })
    }

    pub async fn password<U: Into<String>, S: ToSocketAddrs, P: Into<String>>(
        username: U,
        password: P,
        socket: S,
        inactivity_timeout: Duration,
    ) -> crate::Result<Self> {
        Ok(SSHConfig::Password {
            username: username.into(),
            socket: Self::resolve_socket(socket).await?,
            password: password.into(),
            inactivity_timeout,
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
                        panic!("Channel closed while trying to exec {:?}", cmd)
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
        info!(
            dest = remote_dest,
            size = file_contents.len(),
            "Starting file transfer"
        );

        let sftp = match self.create_sftp_session_with_retry().await {
            Ok(session) => {
                debug!("Successfully created SFTP session");
                session
            }
            Err(e) => {
                error!(error = ?e, "Failed to create SFTP session");
                return Err(e);
            }
        };

        match self
            .try_direct_file_transfer(&sftp, &file_contents, remote_dest)
            .await
        {
            Ok(()) => {
                info!("File transfer completed successfully");
                Ok(())
            }
            Err(e) => {
                warn!(
                    error = ?e,
                    "Direct file transfer failed, attempting batch transfer"
                );

                let _ = sftp.remove_file(remote_dest).await;

                match self.ensure_transfer_helper(&sftp).await {
                    Ok(()) => {
                        debug!("Transfer helper ensured");
                        match self.batch_transfer_file(file_contents, remote_dest).await {
                            Ok(()) => {
                                info!("Batch file transfer completed successfully");
                                Ok(())
                            }
                            Err(e) => {
                                error!(error = ?e, "Batch file transfer failed");
                                let _ = sftp.remove_file(remote_dest).await;
                                Err(e)
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = ?e, "Failed to ensure transfer helper");
                        Err(e)
                    }
                }
            }
        }
    }
}

fn extract_disconnect_message(error_msg: &str) -> Option<String> {
    // Common disconnect messages we might see from russh
    if error_msg.contains("description:") {
        if let Some(start) = error_msg.find("description:") {
            let rest = &error_msg[start + "description:".len()..];
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].trim().to_string());
            }
        }
    }

    // Try to find any message in quotes after "Disconnect"
    if let Some(start) = error_msg.find("Disconnect") {
        let rest = &error_msg[start..];
        if let Some(quote_start) = rest.find('"') {
            let after_quote = &rest[quote_start + 1..];
            if let Some(quote_end) = after_quote.find('"') {
                return Some(after_quote[..quote_end].to_string());
            }
        }
    }

    None
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
        let mut code = None;
        let mut stdout = vec![];
        let mut stderr = vec![];
        let mut consecutive_empty_reads = 0;
        const MAX_EMPTY_READS: u32 = 3;

        debug!("Starting to process channel output");

        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    if data.is_empty() {
                        consecutive_empty_reads += 1;
                        if consecutive_empty_reads >= MAX_EMPTY_READS {
                            warn!("Multiple empty data reads, assuming channel done");
                            break;
                        }
                    } else {
                        consecutive_empty_reads = 0;
                        trace!(bytes_received = data.len(), "Received stdout data");
                        stdout.extend_from_slice(data);
                    }
                }
                russh::ChannelMsg::ExtendedData { ref data, ext } => {
                    if data.is_empty() {
                        consecutive_empty_reads += 1;
                        if consecutive_empty_reads >= MAX_EMPTY_READS {
                            warn!("Multiple empty extended data reads, assuming channel done");
                            break;
                        }
                    } else {
                        consecutive_empty_reads = 0;
                        trace!(
                            bytes_received = data.len(),
                            channel = ext,
                            "Received stderr data"
                        );
                        stderr.extend_from_slice(data);
                    }
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    debug!(status = exit_status, "Received exit status");
                    code = Some(exit_status);
                    // Don't break immediately - there might still be buffered data
                    consecutive_empty_reads += 1;
                }
                russh::ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                } => {
                    error!(
                        ?signal_name,
                        ?core_dumped,
                        ?error_message,
                        ?lang_tag,
                        "Command terminated by signal"
                    );
                    // Break immediately on signal
                    break;
                }
                russh::ChannelMsg::Eof => {
                    debug!("Received EOF");
                    break;
                }
                _ => {
                    trace!("Received other channel message type");
                    consecutive_empty_reads += 1;
                }
            }

            if consecutive_empty_reads >= MAX_EMPTY_READS {
                debug!("Maximum consecutive empty reads reached, closing channel");
                break;
            }
        }

        // Attempt to close the channel gracefully
        if let Err(e) = channel.eof().await {
            warn!(error = ?e, "Failed to send EOF to channel");
        }

        debug!(
            exit_code = ?code,
            stdout_size = stdout.len(),
            stderr = ?String::from_utf8_lossy(&stderr),
            "Command execution completed"
        );

        Ok(CommandOutput {
            stdout,
            stderr,
            status_code: code,
        })
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
                        panic!("Channel closed while trying to create SFTP session");
                        "Channel closed during SFTP session creation".to_string()
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

    async fn transfer_file(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> crate::Result<()> {
        const TRANSFER_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

        match tokio::time::timeout(
            TRANSFER_TIMEOUT,
            self._transfer_file_inner(file_contents, remote_dest),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(crate::Error::FileTransferError(
                "File transfer operation timed out".into(),
            )),
        }
    }

    async fn _transfer_file_inner(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> crate::Result<()> {
        let is_windows = remote_dest.starts_with("C:\\") || remote_dest.starts_with("c:\\");

        // For Windows paths, try SFTP once and then immediately try batch transfer
        if is_windows {
            match self
                .try_sftp_transfer(file_contents.clone(), remote_dest)
                .await
            {
                Ok(()) => return Ok(()),
                Err(sftp_err) => {
                    debug!("SFTP failed for Windows path, attempting batch transfer");
                    match self
                        .try_batch_transfer(file_contents.clone(), remote_dest)
                        .await
                    {
                        Ok(()) => return Ok(()),
                        Err(batch_err) => {
                            return Err(crate::Error::FileTransferError(
                            format!("All transfer methods failed. SFTP error: {}. Batch transfer error: {}", 
                                sftp_err, batch_err)
                        ));
                        }
                    }
                }
            }
        }

        // For non-Windows paths, use existing retry logic with SFTP only
        let mut last_error = None;
        for attempt in 0..2 {
            match self
                .try_sftp_transfer(file_contents.clone(), remote_dest)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < 1 {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            crate::Error::FileTransferError(format!(
                "File transfer failed for path: {}",
                remote_dest
            ))
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
                            format!("Remote host terminated the SSH connection. This might indicate system resource issues or connection problems.")
                        )
                    },
                    crate::Error::FileTransferError(msg) if msg.contains("Send") => {
                        crate::Error::FileTransferError(
                            format!("Lost connection to remote host while trying to establish SFTP session. This might indicate network issues or system resource constraints.")
                        )
                    },
                    _ => e
                });
            }
        };

        match self
            .try_direct_file_transfer(&sftp, &file_contents, remote_dest)
            .await
        {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = sftp.remove_file(remote_dest).await;
                Err(e)
            }
        }
    }

    async fn try_batch_transfer(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_dest: &str,
    ) -> crate::Result<()> {
        let sftp = self.create_sftp_session_with_retry().await.map_err(|e| {
            crate::Error::FileTransferError(format!(
                "Failed to create SFTP session for batch transfer: {}",
                e
            ))
        })?;

        self.ensure_transfer_helper(&sftp).await.map_err(|e| {
            crate::Error::FileTransferError(format!("Failed to ensure transfer helper: {}", e))
        })?;

        self.batch_transfer_file(file_contents, remote_dest)
            .await
            .map_err(|e| {
                crate::Error::FileTransferError(format!("Batch transfer failed: {}", e))
            })?;

        // Verify file exists after transfer
        match self.verify_file_exists(remote_dest).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(crate::Error::FileTransferError(
                "Failed to verify batch file transfer - file not found".into(),
            )),
            Err(e) => Err(crate::Error::FileTransferError(format!(
                "Failed to verify batch file transfer: {}",
                e
            ))),
        }
    }

    async fn verify_file_exists(&self, path: &str) -> crate::Result<bool> {
        // Windows paths need special handling
        let cmd = if path.starts_with("C:\\") || path.starts_with("c:\\") {
            format!("cmd.exe /c if exist {} echo TRUE", path)
        } else {
            format!("cmd.exe /c if exist \"{}\" echo TRUE", path)
        };

        match self.exec(&crate::cmd!(cmd)).await {
            Ok(output) => {
                // Windows command will output "1" if file exists
                let output_str = String::from_utf8_lossy(&output.stdout);
                if output_str.contains("TRUE") {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
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

    async fn verify_file_readiness(
        &self,
        sftp: &russh_sftp::client::SftpSession,
        path: &str,
    ) -> crate::Result<()> {
        const MAX_ATTEMPTS: u32 = 5;
        const RETRY_DELAY: Duration = Duration::from_millis(100);

        for attempt in 0..MAX_ATTEMPTS {
            // Check if file exists
            if !sftp.try_exists(path).await.unwrap_or(false) {
                if attempt == MAX_ATTEMPTS - 1 {
                    return Err(crate::Error::FileTransferError(
                        "File not found after retries".into(),
                    ));
                }
                tokio::time::sleep(RETRY_DELAY).await;
                continue;
            }

            // Try to open file to verify it's not locked
            match sftp.open(path).await {
                Ok(_) => return Ok(()),
                Err(e) if attempt < MAX_ATTEMPTS - 1 => {
                    warn!("File not ready on attempt {}: {}", attempt + 1, e);
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                Err(e) => {
                    return Err(crate::Error::FileTransferError(format!(
                        "File not ready after retries: {}",
                        e
                    )))
                }
            }
        }

        Err(crate::Error::FileTransferError(
            "File verification failed".into(),
        ))
    }

    async fn verify_transfer_helper_exists(&self) -> crate::Result<bool> {
        let output = self
            .exec(&crate::cmd!(
                "cmd.exe /c if exist C:\\Temp\\transfer_file.bat echo EXISTS"
            ))
            .await?;
        Ok(String::from_utf8_lossy(&output.stdout).contains("EXISTS"))
    }

    async fn verify_transfer_file(&self) -> crate::Result<(bool, bool)> {
        const EXPECTED_SIZE: u64 = 2544; // Expected size of transfer_file.bat

        let output = self
            .exec(&crate::cmd!(
                "cmd.exe /c dir C:\\Temp\\transfer_file.bat /a-d"
            ))
            .await?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        debug!("Dir output: {}", output_str);

        // Check file existence
        let exists = !output_str.is_empty()
            && !output_str.contains("File Not Found")
            && !output_str.contains("cannot find");

        // Parse size handling commas in the number
        let correct_size = if exists {
            output_str
                .lines()
                .filter(|line| line.contains("transfer_file.bat"))
                .find_map(|line| {
                    line.split_whitespace()
                        .find(|&part| part.contains(',') || part.chars().all(|c| c.is_digit(10)))
                        .map(|size| size.replace(",", ""))
                        .and_then(|size| size.parse::<u64>().ok())
                })
                .map(|size| {
                    debug!("Found file size: {}", size);
                    size == EXPECTED_SIZE
                })
                .unwrap_or(false)
        } else {
            false
        };

        debug!("File exists: {}, correct size: {}", exists, correct_size);

        Ok((exists, correct_size))
    }

    async fn ensure_transfer_helper(
        &self,
        sftp: &russh_sftp::client::SftpSession,
    ) -> crate::Result<()> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(100);

        for attempt in 0..MAX_RETRIES {
            // Check if file exists and has correct size
            let (exists, correct_size) = self.verify_transfer_file().await?;

            if exists && correct_size {
                debug!("transfer_file.bat exists and has correct size");
                return Ok(());
            }

            if exists && !correct_size {
                debug!("transfer_file.bat exists but has wrong size, recreating");
                let _ = sftp.remove_file("C:\\Temp\\transfer_file.bat").await;
            }

            // Create directory if needed
            if !sftp.try_exists("C:\\Temp").await.unwrap_or(false) {
                sftp.create_dir("C:\\Temp").await?;
            }

            // Create and write the file
            let mut helper = match sftp.create("C:\\Temp\\transfer_file.bat").await {
                Ok(file) => file,
                Err(e) => {
                    if attempt < MAX_RETRIES - 1 {
                        tokio::time::sleep(RETRY_DELAY).await;
                        continue;
                    }
                    return Err(e.into());
                }
            };

            helper.write_all(crate::TRANSFER_HELPER.as_bytes()).await?;
            helper.sync_all().await?;

            // Verify the newly created file
            let (exists, correct_size) = self.verify_transfer_file().await?;
            if exists && correct_size {
                return Ok(());
            }

            if attempt < MAX_RETRIES - 1 {
                tokio::time::sleep(RETRY_DELAY).await;
                continue;
            }
        }

        Err(crate::Error::FileTransferError(
            "Failed to ensure transfer_file.bat after retries".into(),
        ))
    }

    async fn verify_process_creation(&self, cmd: &str) -> crate::Result<()> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(100);

        for attempt in 0..MAX_RETRIES {
            let output = self.exec(&crate::cmd!(cmd)).await?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Check for specific error conditions
            if stderr.contains("not found") || stderr.contains("cannot find") {
                if attempt < MAX_RETRIES - 1 {
                    tokio::time::sleep(RETRY_DELAY).await;
                    continue;
                }
                return Err(crate::Error::FileTransferError("Process not found".into()));
            }

            if stderr.contains("being used by another process") {
                if attempt < MAX_RETRIES - 1 {
                    tokio::time::sleep(RETRY_DELAY).await;
                    continue;
                }
                return Err(crate::Error::FileTransferError("Resource busy".into()));
            }

            // For wmic process creation
            if stdout.contains("ReturnValue = 0") {
                return Ok(());
            }

            if attempt < MAX_RETRIES - 1 {
                tokio::time::sleep(RETRY_DELAY).await;
                continue;
            }
        }

        Err(crate::Error::FileTransferError(
            "Process creation verification failed after retries".into(),
        ))
    }

    async fn batch_transfer_file(
        &self,
        file_contents: Arc<Vec<u8>>,
        remote_destination: &str,
    ) -> crate::Result<()> {
        let port_number = 49152 + rand::random::<u16>() % 16384;

        // Add firewall rule
        let rule = format!(
            "cmd.exe /c netsh advfirewall firewall add rule name=\"Allow Port {}\" dir=in action=allow protocol=TCP localport={}",
            port_number, port_number
        );

        self.exec(&crate::cmd!(rule)).await?;

        // Start helper with process creation verification
        let start_helper = format!(
            "cmd.exe /c wmic process call create 'C:\\Temp\\transfer_file.bat {} 0.0.0.0 {} receive'",
            port_number, remote_destination
        );

        // Verify process creation
        self.verify_process_creation(&start_helper).await?;

        // Connect and transfer
        let result = match self.connect_with_retry(port_number).await {
            Ok(stream) => self.send_file_data(stream, &file_contents).await,
            Err(e) => {
                self.cleanup_firewall_rule(port_number).await;
                Err(e)
            }
        };

        // Always cleanup
        self.cleanup_firewall_rule(port_number).await;
        result
    }

    async fn cleanup_firewall_rule(&self, port_number: u16) {
        let cleanup_cmd = format!(
            "cmd.exe /c netsh advfirewall firewall delete rule name=\"Allow Port {}\"",
            port_number
        );
        if let Err(e) = self.exec(&crate::cmd!(cleanup_cmd)).await {
            eprintln!("Warning: Failed to cleanup firewall rule: {:?}", e);
        }
    }

    async fn connect_with_retry(&self, port_number: u16) -> crate::Result<TcpStream> {
        let socket = format!("{}:{}", self.config.ip(), port_number);

        tokio::time::sleep(Duration::from_secs(10)).await;

        // Reduce number of attempts and delay
        for attempt in 0..5 {
            match TcpStream::connect(&socket).await {
                Ok(stream) => return Ok(stream),
                Err(_) if attempt < 4 => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(_) => break,
            }
        }

        Err(crate::Error::FileTransferError(
            "Failed to connect after 5 attempts".to_string(),
        ))
    }

    async fn send_file_data(
        &self,
        mut stream: TcpStream,
        file_contents: &[u8],
    ) -> crate::Result<()> {
        let file_size = file_contents.len() as u64;
        let mut size_buffer = vec![];

        match WriteBytesExt::write_u64::<BigEndian>(&mut size_buffer, file_size) {
            Ok(_) => {}
            Err(e) => {
                return Err(crate::Error::FileTransferError(format!(
                    "Failed to write file size header: {:?}",
                    e
                )))
            }
        }

        if let Err(e) = stream.write_all(&size_buffer).await {
            return Err(crate::Error::FileTransferError(format!(
                "Failed to send file size header: {:?}",
                e
            )));
        }

        if let Err(e) = stream.write_all(file_contents).await {
            return Err(crate::Error::FileTransferError(format!(
                "Failed to send file contents: {:?} (sent {}/{})",
                e,
                size_buffer.len(),
                file_contents.len()
            )));
        }

        Ok(())
    }

    #[instrument(skip(self, remote_path, local_path))]
    async fn download_file(&self, remote_path: &str, local_path: &str) -> crate::Result<()> {
        info!(
            remote_path = %remote_path,
            local_path = %local_path,
            "Starting file download"
        );

        if let Some(parent) = Path::new(local_path).parent() {
            debug!(path = ?parent, "Creating parent directories");
            tokio::fs::create_dir_all(parent).await?;
        }

        let sftp = match self.create_sftp_session_with_retry().await {
            Ok(session) => session,
            Err(e) => {
                error!(error = ?e, "Failed to create SFTP session for download");
                return Err(e);
            }
        };

        let temp_path = format!("{}.tmp", local_path);
        debug!(temp_path = %temp_path, "Creating temporary file");

        let mut local_file = match tokio::fs::File::create(&temp_path).await {
            Ok(file) => file,
            Err(e) => {
                error!(error = ?e, "Failed to create local file");
                return Err(crate::Error::FileTransferError(format!(
                    "Failed to create local file: {}",
                    e
                )));
            }
        };

        debug!(remote_path = %remote_path, "Opening remote file");
        let mut remote_file = match sftp.open(remote_path).await {
            Ok(file) => file,
            Err(e) => {
                error!(error = ?e, "Failed to open remote file");
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(crate::Error::FileTransferError(format!(
                    "Failed to open remote file: {}",
                    e
                )));
            }
        };

        debug!("Starting file copy operation");
        match tokio::time::timeout(
            Duration::from_secs(300), // 5 minute timeout
            tokio::io::copy(&mut remote_file, &mut local_file),
        )
        .await
        {
            Ok(Ok(bytes)) => {
                debug!(bytes_copied = bytes, "File copy completed");
                local_file.sync_all().await?;
                debug!("Renaming temporary file to target");
                tokio::fs::rename(temp_path, local_path).await?;
                info!("File download completed successfully");
                Ok(())
            }
            Ok(Err(e)) => {
                error!(error = ?e, "Copy operation failed");
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(crate::Error::FileTransferError(format!(
                    "Copy failed: {}",
                    e
                )))
            }
            Err(_) => {
                error!("Download operation timed out");
                let _ = tokio::fs::remove_file(&temp_path).await;
                Err(crate::Error::FileTransferError("Download timed out".into()))
            }
        }
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
            } => {
                let mut session = get_handle(*socket, *inactivity_timeout).await?;

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
            } => {
                let mut session = get_handle(*socket, *inactivity_timeout).await?;
                let auth_res = session.authenticate_password(username, password).await?;

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

async fn get_handle<S: ToSocketAddrs>(
    socket: S,
    timeout: Duration,
) -> crate::Result<russh::client::Handle<Handler>> {
    let config = client::Config {
        inactivity_timeout: Some(timeout),
        ..Default::default()
    };

    let config = Arc::new(config);
    let sh = Handler {};
    Ok(client::connect(config, socket, sh).await?)
}

struct Handler {}

#[async_trait]
impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}
