use crate::{Error, Result, OS};
use futures::future::{join_all, BoxFuture};
use log::{debug, error, info, warn};
use rustrc::client::{Client, Command, CommandOutput, Config};
use rustrc::cmd;
use rustrc::ssh::SSHConfig;
use rustrc::winexe::WinexeConfig;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub enum Either<L, R> {
    Left(L),
    Right(R),
}

pub type WindowsConfig = Either<WinexeConfig, SSHConfig>;

pub enum OSConfig {
    Windows(WindowsConfig),
    Unix(SSHConfig),
    Unknown(SSHConfig),
}

// Generic result type for operations that need to track which host they're associated with
#[derive(Debug)]
pub struct HostOperationResult<T> {
    pub ip: String,
    pub os: OS,
    pub result: Result<T>,
}

pub trait ClientWrapper: Send + Sync {
    fn exec<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>>;
    fn disconnect(&self) -> BoxFuture<'_, Result<()>>;
    fn transfer_file(&self, file: Arc<Vec<u8>>, destination: String) -> BoxFuture<'_, Result<()>>;
    fn download_file(&self, remote_path: String, local_path: String) -> BoxFuture<'_, Result<()>>;
    fn get_ip(&self) -> IpAddr;
}

impl<C: Config + Send + Sync + 'static> ClientWrapper for Client<C>
where
    C::SessionType: Send + Sync + 'static,
{
    fn exec<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>> {
        Box::pin(async move { self.exec(cmd).await.map_err(Into::into) })
    }

    fn disconnect(&self) -> BoxFuture<'_, Result<()>> {
        // NOTE: Cannot call Client::disconnect() because it requires &mut self,
        // but ClientWrapper trait only provides &self. Connections will be closed
        // when the client is dropped. This prevents stack overflow from recursive calls.
        Box::pin(async move { Ok(()) })
    }

    fn transfer_file(&self, file: Arc<Vec<u8>>, destination: String) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.transfer_file(file, &destination)
                .await
                .map_err(Into::into)
        })
    }

    fn download_file(&self, remote_path: String, local_path: String) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.download_file(&remote_path, &local_path)
                .await
                .map_err(Into::into)
        })
    }

    fn get_ip(&self) -> IpAddr {
        // Note: IP address is tracked separately in Communicator.clients Vec<(OS, IpAddr, Arc<dyn ClientWrapper>)>
        // This method is not currently used, but must be implemented for the trait.
        // Return placeholder to prevent panic if ever called.
        warn!("get_ip() called on ClientWrapper - IP is tracked in Communicator, not Client");
        IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))
    }
}

impl OSConfig {
    pub fn os_type(&self) -> OS {
        match self {
            OSConfig::Windows(_) => OS::Windows,
            OSConfig::Unix(_) => OS::Unix,
            OSConfig::Unknown(_) => OS::Unknown,
        }
    }

    pub async fn connect(self, ip: IpAddr) -> Result<(OS, IpAddr, Arc<dyn ClientWrapper>)> {
        match self {
            OSConfig::Windows(config) => match config {
                Either::Left(winexe_config) => {
                    // Retry Winexe connections up to 2 times with fixed delay to avoid extending script runtime
                    let mut last_error = None;
                    for attempt in 0..2 {
                        if attempt > 0 {
                            let delay = Duration::from_secs(2); // Fixed 2-second delay
                            debug!("Retrying Winexe connection to {} (attempt {}/2) after 2s", ip, attempt + 1);
                            tokio::time::sleep(delay).await;
                        }

                        match Client::connect(winexe_config.clone()).await {
                            Ok(client) => {
                                if attempt > 0 {
                                    info!("Winexe connection to {} succeeded on attempt {}/2", ip, attempt + 1);
                                }
                                return Ok((OS::Windows, ip, Arc::new(client) as Arc<dyn ClientWrapper>));
                            }
                            Err(e) => {
                                last_error = Some(e);
                            }
                        }
                    }

                    Err(Error::CommunicatorError(format!(
                        "Winexe connection failed for {} after 2 attempts: {}",
                        ip, last_error.map(|e| e.to_string()).unwrap_or_else(|| "Unknown error".to_string())
                    )))
                },
                Either::Right(ssh_config) => {
                    // Try SSH first with retries, keeping config for potential Winexe fallback
                    let mut ssh_last_error = None;

                    for attempt in 0..2 {
                        if attempt > 0 {
                            let delay = Duration::from_secs(2);
                            debug!("Retrying SSH connection to Windows host {} (attempt {}/2)", ip, attempt + 1);
                            tokio::time::sleep(delay).await;
                        }

                        match Client::connect(ssh_config.clone()).await {
                            Ok(client) => {
                                drop(ssh_config);
                                if attempt > 0 {
                                    info!("SSH connection to Windows host {} succeeded on attempt {}/2", ip, attempt + 1);
                                }
                                return Ok((OS::Windows, ip, Arc::new(client) as Arc<dyn ClientWrapper>));
                            }
                            Err(e) => {
                                ssh_last_error = Some(e);
                            }
                        }
                    }

                    // SSH failed after retries, try Winexe fallback with original config
                    debug!("SSH failed for Windows host {} after 2 attempts, trying Winexe fallback", ip);
                    match ssh_to_winexe(ssh_config, ip).await {
                        Ok(winexe_config) => {
                            // Retry Winexe fallback up to 2 times
                            for attempt in 0..2 {
                                if attempt > 0 {
                                    let delay = Duration::from_secs(2);
                                    tokio::time::sleep(delay).await;
                                }

                                match Client::connect(winexe_config.clone()).await {
                                    Ok(client) => {
                                        if attempt > 0 {
                                            info!("Winexe fallback to {} succeeded on attempt {}/2", ip, attempt + 1);
                                        }
                                        return Ok((
                                            OS::Windows,
                                            ip,
                                            Arc::new(client) as Arc<dyn ClientWrapper>,
                                        ));
                                    }
                                    Err(e) if attempt == 1 => {
                                        return Err(Error::CommunicatorError(format!(
                                            "Both SSH and Winexe failed for {}: SSH error: {}, Winexe error: {}",
                                            ip, ssh_last_error.map(|e| e.to_string()).unwrap_or_else(|| "Unknown SSH error".to_string()), e
                                        )));
                                    }
                                    _ => {}
                                }
                            }

                            Err(Error::CommunicatorError(format!(
                                "Both SSH and Winexe failed for {}: SSH error: {}",
                                ip, ssh_last_error.map(|e| e.to_string()).unwrap_or_else(|| "Unknown SSH error".to_string())
                            )))
                        }
                        Err(e) => Err(Error::CommunicatorError(format!(
                            "SSH failed and could not create Winexe fallback for {}: {}",
                            ip, e
                        ))),
                    }
                }
            },
            OSConfig::Unix(config) => {
                // Retry Unix SSH connections up to 2 times with fixed delay to avoid extending script runtime
                let mut last_error = None;
                for attempt in 0..2 {
                    if attempt > 0 {
                        let delay = Duration::from_secs(2); // Fixed 2-second delay
                        debug!("Retrying SSH connection to Unix host {} (attempt {}/2) after 2s", ip, attempt + 1);
                        tokio::time::sleep(delay).await;
                    }

                    match Client::connect(config.clone()).await {
                        Ok(client) => {
                            if attempt > 0 {
                                info!("SSH connection to Unix host {} succeeded on attempt {}/2", ip, attempt + 1);
                            }
                            return Ok((OS::Unix, ip, Arc::new(client) as Arc<dyn ClientWrapper>));
                        }
                        Err(e) => {
                            last_error = Some(e);
                        }
                    }
                }

                Err(Error::CommunicatorError(format!(
                    "SSH connection failed for {} after 2 attempts: {}",
                    ip, last_error.map(|e| e.to_string()).unwrap_or_else(|| "Unknown error".to_string())
                )))
            },
            OSConfig::Unknown(config) => {
                // Retry unknown OS connections up to 2 times
                let mut last_error = None;
                for attempt in 0..2 {
                    if attempt > 0 {
                        let delay = Duration::from_secs(2);
                        debug!("Retrying connection to unknown OS at {} (attempt {}/2)", ip, attempt + 1);
                        tokio::time::sleep(delay).await;
                    }

                    match Client::connect(config.clone()).await {
                        Ok(client) => {
                            if attempt > 0 {
                                info!("Connection to unknown OS at {} succeeded on attempt {}/2", ip, attempt + 1);
                            }
                            return Ok((OS::Unknown, ip, Arc::new(client) as Arc<dyn ClientWrapper>));
                        }
                        Err(e) => {
                            last_error = Some(e);
                        }
                    }
                }

                Err(Error::CommunicatorError(format!(
                    "Connection failed for unknown OS at {} after 2 attempts: {}",
                    ip, last_error.map(|e| e.to_string()).unwrap_or_else(|| "Unknown error".to_string())
                )))
            },
        }
    }
}

pub struct Communicator {
    clients: Vec<(OS, IpAddr, Arc<dyn ClientWrapper>)>,
}

impl Communicator {
    pub async fn new(configs: Vec<(IpAddr, OSConfig)>) -> Result<Self> {
        let connection_results = join_all(configs.into_iter().map(|(ip, config)| async move {
            HostOperationResult {
                ip: ip.to_string(),
                os: config.os_type(),
                result: config.connect(ip).await,
            }
        }))
        .await;

        let mut clients = Vec::new();
        let mut errors = Vec::new();

        for result in connection_results {
            match result.result {
                Ok((os, ip, client)) => clients.push((os, ip, client)),
                Err(e) => {
                    let error_msg = format!("{}:{:?} - {}", result.ip, result.os, e);
                    error!("Connection failed: {}", error_msg);
                    errors.push(error_msg);
                }
            }
        }

        if clients.is_empty() {
            Err(Error::CommunicatorError(format!(
                "No successful connections established. Errors: {}",
                errors.join("; ")
            )))
        } else {
            if !errors.is_empty() {
                warn!("Some connections failed ({}/{}): {}", errors.len(), clients.len() + errors.len(), errors.join("; "));
            }
            Ok(Communicator { clients })
        }
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    pub fn get_clients_by_os(&self, os_type: OS) -> Vec<(OS, &IpAddr, &Arc<dyn ClientWrapper>)> {
        debug!("get_clients_by_os({:?}): Total clients = {}", os_type, self.clients.len());
        for (os, ip, _) in &self.clients {
            debug!("  Client: {} -> {:?}", ip, os);
        }
        let filtered: Vec<_> = self.clients
            .iter()
            .filter(|(client_os, _, _)| *client_os == os_type)
            .map(|(os, ip, client)| (*os, ip, client))
            .collect();
        debug!("get_clients_by_os({:?}): Filtered count = {}", os_type, filtered.len());
        filtered
    }

    pub async fn disconnect_all(&self) -> Vec<HostOperationResult<()>> {
        join_all(self.clients.iter().map(|(os, ip, client)| async move {
            HostOperationResult {
                ip: ip.to_string(),
                os: *os,
                result: client.disconnect().await,
            }
        }))
        .await
    }

    pub async fn exec_by_os(
        &self,
        cmd: &Command,
        os_type: OS,
    ) -> Vec<HostOperationResult<CommandOutput>> {
        // Removed unconditional 1-second delay for better performance
        // Network latency provides natural pacing for parallel operations

        join_all(
            self.clients
                .iter()
                .filter(|(client_os, _, _)| *client_os == os_type)
                .map(|(os, ip, client)| async move {
                    // Try command execution with retries for transient failures
                    let mut result = None;
                    let mut last_error = None;

                    for attempt in 0..2 {
                        if attempt > 0 {
                            debug!("Retrying command execution on {} (attempt {}/2)", ip, attempt + 1);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }

                        match client.exec(cmd).await {
                            Ok(output) => {
                                if attempt > 0 {
                                    info!("Command execution on {} succeeded on retry", ip);
                                }
                                result = Some(Ok(output));
                                break;
                            }
                            Err(e) => {
                                // Check if this is a permission error on Unix
                                if matches!(*os, OS::Unix)
                                    && !e.to_string().contains("timed out")
                                    && (e.to_string().contains("Permission denied")
                                        || e.to_string().contains("not permitted")) {

                                    debug!("Attempting command with sudo on {}", ip);
                                    // Wrap command in sh -c with proper quoting to preserve escaping
                                    let original_cmd = cmd.to_string();
                                    let sudo_cmd = format!("sudo sh -c '{}'", original_cmd.replace('\'', "'\\''"));
                                    let cmd = &cmd!(sudo_cmd);

                                    match client.exec(cmd).await {
                                        Ok(output) => {
                                            result = Some(Ok(output));
                                            break;
                                        }
                                        Err(sudo_err) => {
                                            last_error = Some(sudo_err);
                                        }
                                    }
                                } else {
                                    last_error = Some(e);
                                }
                            }
                        }
                    }

                    HostOperationResult {
                        ip: ip.to_string(),
                        os: *os,
                        result: result.unwrap_or_else(|| {
                            Err(last_error.unwrap_or_else(|| {
                                Error::CommunicatorError(
                                    format!("Command execution failed on {} with no error details", ip)
                                )
                            }))
                        }),
                    }
                }),
        )
        .await
    }

    pub async fn exec_all(&self, cmd: &Command) -> Vec<HostOperationResult<CommandOutput>> {
        join_all(self.clients.iter().map(|(os, ip, client)| async move {
            HostOperationResult {
                ip: ip.to_string(),
                os: *os,
                result: client.exec(cmd).await,
            }
        }))
        .await
    }

    pub async fn exec_on_hosts(
        &self,
        cmd: &Command,
        target_ips: &[String],
    ) -> Vec<HostOperationResult<CommandOutput>> {
        join_all(
            self.clients
                .iter()
                .filter(|(_, ip, _)| target_ips.contains(&ip.to_string()))
                .map(|(os, ip, client)| async move {
                    // Try command execution with retries for transient failures
                    let mut result = None;
                    let mut last_error = None;

                    for attempt in 0..2 {
                        if attempt > 0 {
                            debug!("Retrying command execution on {} (attempt {}/2)", ip, attempt + 1);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }

                        match client.exec(cmd).await {
                            Ok(output) => {
                                if attempt > 0 {
                                    info!("Command execution on {} succeeded on retry", ip);
                                }
                                result = Some(Ok(output));
                                break;
                            }
                            Err(e) => {
                                // Check if this is a permission error on Unix
                                if matches!(*os, OS::Unix)
                                    && !e.to_string().contains("timed out")
                                    && (e.to_string().contains("Permission denied")
                                        || e.to_string().contains("not permitted")) {

                                    debug!("Attempting command with sudo on {}", ip);
                                    // Wrap command in sh -c with proper quoting to preserve escaping
                                    let original_cmd = cmd.to_string();
                                    let sudo_cmd = format!("sudo sh -c '{}'", original_cmd.replace('\'', "'\\''"));
                                    let cmd = &cmd!(sudo_cmd);

                                    match client.exec(cmd).await {
                                        Ok(output) => {
                                            result = Some(Ok(output));
                                            break;
                                        }
                                        Err(sudo_err) => {
                                            last_error = Some(sudo_err);
                                        }
                                    }
                                } else {
                                    last_error = Some(e);
                                }
                            }
                        }
                    }

                    HostOperationResult {
                        ip: ip.to_string(),
                        os: *os,
                        result: result.unwrap_or_else(|| {
                            Err(last_error.unwrap_or_else(|| {
                                Error::CommunicatorError(
                                    format!("Command execution failed on {} with no error details", ip)
                                )
                            }))
                        }),
                    }
                }),
        )
        .await
    }

    pub async fn mass_file_download_by_os(
        &self,
        destination_path: String,
        local_path: String,
        os_type: OS,
    ) -> Vec<HostOperationResult<()>> {
        tokio::time::sleep(Duration::from_secs(1)).await;

        join_all(
            self.clients
                .iter()
                .filter(|(client_os, _, _)| *client_os == os_type)
                .map(|(os, ip, client)| {
                    let dest_clone = destination_path.clone();
                    let local_dir = local_path.clone();
                    async move {
                        let local_path = format!("{}{}", local_dir, ip);

                        // First verify the remote file with retries for consistency
                        let verify_cmd = match os {
                            OS::Windows => format!("cmd.exe /c dir \"{}\"", dest_clone),
                            OS::Unix => format!("ls -l \"{}\"", dest_clone),
                            OS::Unknown => {
                                return HostOperationResult {
                                    ip: ip.to_string(),
                                    os: *os,
                                    result: Err(Error::UnknownOS),
                                }
                            }
                        };

                        let mut verify_success = false;
                        for verify_attempt in 0..3 {
                            if verify_attempt > 0 {
                                let delay = Duration::from_secs(2);
                                debug!("Retrying file verification on {} (attempt {}/3) after {}s", ip, verify_attempt + 1, delay.as_secs());
                                tokio::time::sleep(delay).await;
                            }

                            match client.exec(&rustrc::cmd!(&verify_cmd)).await {
                                Ok(output) => {
                                    let output_str = match String::from_utf8(output.stdout.clone()) {
                                        Ok(s) => s,
                                        Err(_) => {
                                            warn!("File verification output contains invalid UTF-8 for {}", ip);
                                            String::from_utf8_lossy(&output.stdout).to_string()
                                        }
                                    };
                                    debug!("File verification output for {}: {}", ip, output_str);

                                    if output_str.contains("not found")
                                        || output_str.contains("No such file")
                                    {
                                        if verify_attempt >= 2 {
                                            error!("Remote file not found on {} after {} attempts: {}", ip, verify_attempt + 1, dest_clone);
                                            return HostOperationResult {
                                                ip: ip.to_string(),
                                                os: *os,
                                                result: Err(Error::FileTransferError(format!(
                                                    "Remote file not found on {}",
                                                    ip
                                                ))),
                                            };
                                        }
                                    } else {
                                        verify_success = true;
                                        break;
                                    }
                                }
                                Err(e) => {
                                    if verify_attempt >= 2 {
                                        error!("Failed to verify file on {} after {} attempts: {}", ip, verify_attempt + 1, e);
                                        return HostOperationResult {
                                            ip: ip.to_string(),
                                            os: *os,
                                            result: Err(e),
                                        };
                                    }
                                }
                            }
                        }

                        if !verify_success {
                            return HostOperationResult {
                                ip: ip.to_string(),
                                os: *os,
                                result: Err(Error::FileTransferError(format!(
                                    "Failed to verify file on {} after retries",
                                    ip
                                ))),
                            };
                        }

                        info!("Downloading from {} to {}", dest_clone, local_path);

                        // Try the download with retries up to 3 times
                        let mut result = None;
                        let mut last_error = None;

                        for attempt in 0..3 {
                            if attempt > 0 {
                                // Use checked_pow to prevent overflow for defensive coding
                                let delay_secs = 2u64.checked_pow(attempt).unwrap_or(60);
                                let delay = Duration::from_secs(delay_secs);
                                debug!("Retrying file download from {} (attempt {}/3) after {}s", ip, attempt + 1, delay.as_secs());
                                tokio::time::sleep(delay).await;
                            }

                            match client
                                .download_file(dest_clone.clone(), local_path.clone())
                                .await
                            {
                                Ok(_) => {
                                    // Verify the downloaded file
                                    match tokio::fs::metadata(&local_path).await {
                                        Ok(metadata) => {
                                            if metadata.len() == 0 {
                                                error!("Downloaded empty file for {} on attempt {}", ip, attempt + 1);
                                                last_error = Some(Error::FileTransferError(format!(
                                                    "Downloaded empty file from {}",
                                                    ip
                                                )));
                                            } else {
                                                info!(
                                                    "Successfully downloaded {}B from {}{}",
                                                    metadata.len(),
                                                    ip,
                                                    if attempt > 0 { format!(" on attempt {}/3", attempt + 1) } else { String::new() }
                                                );
                                                result = Some(Ok(()));
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "Failed to verify downloaded file for {} on attempt {}: {}",
                                                ip, attempt + 1, e
                                            );
                                            last_error = Some(Error::FileTransferError(format!(
                                                "Failed to verify downloaded file: {}",
                                                e
                                            )));
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Download failed for {} on attempt {}: {}", ip, attempt + 1, e);
                                    last_error = Some(e);
                                }
                            }
                        }

                        let result = result.unwrap_or_else(|| {
                            Err(last_error.unwrap_or_else(|| {
                                Error::FileTransferError(
                                    format!("File download failed on {} with no error details", ip)
                                )
                            }))
                        });

                        HostOperationResult {
                            ip: ip.to_string(),
                            os: *os,
                            result,
                        }
                    }
                }),
        )
        .await
    }

    pub async fn mass_file_transfer_by_os(
        &self,
        file: Arc<Vec<u8>>,
        destination: String,
        os_type: OS,
    ) -> Vec<HostOperationResult<()>> {
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Use join_all like exec_by_os for sequential processing
        join_all(
            self.clients
                .iter()
                .filter(|(client_os, _, _)| *client_os == os_type)
                .map(|(os, ip, client)| {
                    let file_clone = Arc::clone(&file);
                    let dest_clone = destination.clone();
                    async move {
                        debug!("Starting transfer for {}", ip);

                        // Retry file transfer up to 3 times with exponential backoff
                        let mut last_error = None;
                        for attempt in 0..3 {
                            if attempt > 0 {
                                let delay = Duration::from_secs(2u64.pow(attempt));
                                debug!("Retrying file transfer to {} (attempt {}/3) after {}s", ip, attempt + 1, delay.as_secs());
                                tokio::time::sleep(delay).await;
                            }

                            match client.transfer_file(Arc::clone(&file_clone), dest_clone.clone()).await {
                                Ok(_) => {
                                    if attempt > 0 {
                                        info!("File transfer to {} succeeded on attempt {}/3", ip, attempt + 1);
                                    }
                                    return HostOperationResult {
                                        ip: ip.to_string(),
                                        os: *os,
                                        result: Ok(()),
                                    };
                                }
                                Err(e) => {
                                    last_error = Some(e);
                                }
                            }
                        }

                        HostOperationResult {
                            ip: ip.to_string(),
                            os: *os,
                            result: Err(last_error.unwrap_or_else(|| {
                                Error::FileTransferError(
                                    format!("File transfer failed on {} with no error details", ip)
                                )
                            })),
                        }
                    }
                }),
        )
        .await
    }

    pub async fn mass_file_transfer_all(
        &self,
        file: Arc<Vec<u8>>,
        destination: String,
    ) -> Vec<HostOperationResult<()>> {
        join_all(self.clients.iter().map(|(os, ip, client)| {
            let file_clone = Arc::clone(&file);
            let dest_clone = destination.clone();
            async move {
                HostOperationResult {
                    ip: ip.to_string(),
                    os: *os,
                    result: client.transfer_file(file_clone, dest_clone).await,
                }
            }
        }))
        .await
    }
}

// Helper functions
pub fn windows_config(config: impl Into<WindowsConfig>) -> OSConfig {
    OSConfig::Windows(config.into())
}

impl From<WinexeConfig> for WindowsConfig {
    fn from(config: WinexeConfig) -> Self {
        WindowsConfig::Left(config)
    }
}

impl From<SSHConfig> for WindowsConfig {
    fn from(config: SSHConfig) -> Self {
        WindowsConfig::Right(config)
    }
}

async fn ssh_to_winexe(ssh_config: SSHConfig, ip: IpAddr) -> Result<WinexeConfig> {
    match ssh_config {
        SSHConfig::Password {
            username,
            password,
            inactivity_timeout,
            ..
        } => WinexeConfig::password(&username, &password, &ip.to_string(), inactivity_timeout)
            .await
            .map_err(|e| {
                Error::CommunicatorError(format!("Failed to create Winexe config: {}", e))
            }),
        SSHConfig::Key { .. } => Err(Error::CommunicatorError(
            "Cannot convert key-based SSH config to Winexe".into(),
        )),
    }
}

pub fn unix_config(config: SSHConfig) -> OSConfig {
    OSConfig::Unix(config)
}

pub fn unknown_config(config: SSHConfig) -> OSConfig {
    OSConfig::Unknown(config)
}
