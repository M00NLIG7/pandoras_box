use tokio::io::AsyncWriteExt;
use std::collections::HashMap;
use std::net::IpAddr;
use crate::communicator::{
    unix_config, windows_config, Communicator, HostOperationResult, OSConfig, ClientWrapper,
};
use crate::enumerator::{Enumerator, Subnet};
use crate::types::{Host, OS};
use crate::{Error, Result};
use base64::Engine;
use rustrc::client::CommandOutput;
use rustrc::cmd;
use rustrc::ssh::SSHConfig;
use rustrc::winexe::WinexeConfig;
use reqwest;
use futures::stream;
use futures::stream::StreamExt;

use futures::future::join_all;
use log::{error, info, warn};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::{log_failure, log_output, log_results, log_skipped, log_success, log_host_results};

//cmd.exe /c echo Dim xhr: Set xhr = CreateObject("MSXML2.XMLHTTP.6.0"): xhr.Open "GET", "https://raw.githubusercontent.com/M00NLIG7/pandoras_box/master/pandoras_box/resources/chimera", False: xhr.Send: Set stream = CreateObject("ADODB.Stream"): stream.Open: stream.Type = 1: stream.Write xhr.responseBody: stream.SaveToFile "C:\Temp\chimera.exe", 2: stream.Close > dl.vbs && cscript //B dl.vbs

static CHIMERA_URL_UNIX: &str = "https://github.com/M00NLIG7/pandoras_box/releases/download/v1.0.0/chimera";
static CHIMERA_URL_WIN: &str = "https://github.com/M00NLIG7/pandoras_box/releases/download/v1.0.0/chimera.exe";
static OUTPUT_PATH: &str = "/tmp/chimera";

// Define a struct for mode configuration
#[derive(Debug, Clone)]
struct ModeConfig<'a> {
    name: &'a str,
    args: Option<&'a str>,
}

// Define the available modes with their optional arguments
const CHIMERA_MODES: [ModeConfig; 3] = [
    ModeConfig {
        name: "inventory",
        args: None,
    },
    /*
    ModeConfig {
        name: "baseline",
        args: None,
    },
    */
    ModeConfig {
        name: "credentials",
        args: Some("-m 1234"),
    }, // Example magic number
    ModeConfig {
        name: "serve",
        args: None,
    },
];

pub struct NetworkManager {
    enumerator: Enumerator,
    communicator: Option<Communicator>,
}

impl NetworkManager {
    pub fn new(subnet: Subnet) -> Self {
        let enumerator = Enumerator::new(subnet);
        Self {
            enumerator,
            communicator: None,
        }
    }

    pub async fn enumerate(&self) -> Result<Vec<Arc<Host>>> {
        info!("Starting network enumeration");
        let hosts = self.enumerator.sweep().await?;
        for host in &hosts {
            info!(
                "Enumerated host: {} (OS: {:?}, Open ports: {:?})",
                host.ip, host.os, host.open_ports
            );
        }
        Ok(hosts)
    }
    pub fn get_communicator(&self) -> Option<&Communicator> {
        self.communicator.as_ref()
    }

    async fn create_single_config(
        &self,
        host: &Arc<Host>,
        password: &str,
    ) -> Result<(OSConfig, Option<Arc<Host>>)> {
        // Changed return type
        info!(
            "Creating config for host {} (OS: {:?}, Open ports: {:?})",
            host.ip, host.os, host.open_ports
        );

        let socket_addr = (host.ip.clone(), 22)
            .to_socket_addrs()
            .map_err(|e| Error::InvalidIP(e.to_string()))?
            .find(|addr| addr.is_ipv4())
            .ok_or_else(|| Error::InvalidIP("No valid IPv4 address found".into()))?;

        match host.os {
            OS::Unix | OS::Unknown => self.create_unix_config(host, password, socket_addr).await,
            OS::Windows => {
                // Windows config doesn't return updated host
                self.create_windows_config(host, password, socket_addr)
                    .await
                    .map(|config| (config, None))
            }
        }
    }

    async fn create_os_configs(
        &self,
        hosts: &[Arc<Host>],
        password: &str,
    ) -> Result<Vec<(Arc<Host>, Result<OSConfig>)>> {
        // Filter out Unix/Unknown hosts without port 22 first
        let filtered_hosts: Vec<Arc<Host>> = hosts
            .iter()
            .filter(|host| {
                if matches!(host.os, OS::Unix | OS::Unknown) && !host.open_ports.contains(&22) {
                    log_skipped("config creation", &host.ip, "port 22 not open");
                    false
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // Process the filtered hosts as before
        Ok(stream::iter(filtered_hosts)
            .map(|host| async move {
                match self.create_single_config(&host, password).await {
                    Ok((config, maybe_updated_host)) => (
                        maybe_updated_host.unwrap_or_else(|| Arc::clone(&host)),
                        Ok(config),
                    ),
                    Err(e) => (Arc::clone(&host), Err(e)),
                }
            })
            .buffer_unordered(32)
            .collect()
            .await)
    }

    pub async fn initialize_communication(
        &mut self,
        hosts: &[Arc<Host>],
        network_password: &str,
    ) -> Result<Vec<Arc<Host>>> {
        info!(
            "Starting communication initialization for {} hosts",
            hosts.len()
        );

        let config_results = self.create_os_configs(hosts, network_password).await?;

        let (successful_configs, successful_hosts): (Vec<_>, Vec<_>) = config_results
            .into_iter()
            .filter_map(|(host, config_result)| match config_result {
                Ok(config) => Some(((host.ip.parse().expect("Invalid IP"), config), host)), // Now includes IP in the tuple
                Err(e) => {
                    warn!("Failed to create config for {}: {}", host.ip, e);
                    None
                }
            })
            .unzip();

        if successful_configs.is_empty() {
            error!("No successful configurations created");
            return Err(Error::CommunicatorError(
                "No successful configurations".into(),
            ));
        }

        match Communicator::new(successful_configs).await {
            Ok(comm) => {
                self.communicator = Some(comm);
                info!(
                    "Successfully initialized communicator with {}/{} hosts",
                    successful_hosts.len(),
                    hosts.len()
                );
                Ok(successful_hosts)
            }
            Err(e) => {
                error!("Failed to initialize communicator: {}", e);
                Err(e)
            }
        }
    }

    async fn create_unix_config(
        &self,
        host: &Arc<Host>,
        password: &str,
        socket_addr: SocketAddr,
    ) -> Result<(OSConfig, Option<Arc<Host>>)> {
        // Now returns potential new host
        if !host.open_ports.contains(&22) {
            warn!("Skipping Unix/Unknown host without SSH: {}", host.ip);
            return Err(Error::NoSSHPort);
        }

        match SSHConfig::password("root", password, socket_addr, Duration::from_secs(300)).await {
            Ok(config) => {
                let updated_host = if host.os == OS::Unknown {
                    // Create new Host with Unix OS
                    let mut new_host = (**host).clone();
                    new_host.os = OS::Unix;
                    Some(Arc::new(new_host))
                } else {
                    None
                };
                Ok((unix_config(config), updated_host))
            }
            Err(e) => {
                warn!("Failed to create SSH config for {}: {}", host.ip, e);
                Err(e.into())
            }
        }
    }

    async fn create_windows_config(
        &self,
        host: &Arc<Host>,
        password: &str,
        socket_addr: SocketAddr,
    ) -> Result<OSConfig> {
        if host.open_ports.contains(&22) {
            info!("Attempting SSH connection for Windows host {}", host.ip);
            match self.try_windows_ssh(password, socket_addr).await {
                Ok(config) => Ok(config),
                Err(e) => {
                    warn!("SSH connection failed for {}: {}", host.ip, e);
                    info!("Initiating WinExe fallback for {}", host.ip);
                    self.try_windows_winexe(host, password).await
                }
            }
        } else {
            info!("No SSH port available, using WinExe for {}", host.ip);
            self.try_windows_winexe(host, password).await
        }
    }

    async fn try_windows_ssh(&self, password: &str, socket_addr: SocketAddr) -> Result<OSConfig> {
        SSHConfig::password(
            "Administrator",
            password,
            socket_addr,
            Duration::from_secs(300),
        )
        .await
        .map(windows_config)
        .map_err(Into::into)
    }

    async fn try_windows_winexe(&self, host: &Arc<Host>, password: &str) -> Result<OSConfig> {
        WinexeConfig::password(
            "Administrator",
            password,
            &host.ip,
            Duration::from_secs(300),
        )
        .await
        .map(windows_config)
        .map_err(|e| {
            warn!("Failed to create WinExe config for {}: {}", host.ip, e);
            e.into()
        })
    }
}

pub struct Orchestrator {
    network_manager: NetworkManager,
}

impl Orchestrator {
    pub fn new(subnet: Subnet) -> Self {
        info!("Initializing Orchestrator for subnet {}", subnet);
        let network_manager = NetworkManager::new(subnet);
        Self { network_manager }
    }

    // Generic function to fetch files from hosts on port 44372
    /// uri_path: The path part of the URI (e.g., "inventory.json")
    /// output_prefix: Prefix for the output filename (e.g., "chimera_inventory")
    async fn fetch_file(&self, hosts: &[Arc<Host>], uri_path: &str, output_prefix: &str) -> Result<()> {
        info!("Starting file fetch for {} hosts, uri: {}", hosts.len(), uri_path);
        
        let client = reqwest::Client::new();
        let futures: Vec<_> = hosts.iter().map(|host| {
            let ip = host.ip.to_string();
            let client = client.clone();
            let uri_path = uri_path.to_string();
            let output_prefix = output_prefix.to_string();
            
            async move {
                let url = format!("http://{}:44372/{}", ip, uri_path);
                let filename = format!("{}_{}.json", output_prefix, ip);
                
                info!("Fetching {} from {}", uri_path, url);
                match client.get(&url).send().await {
                    Ok(response) => {
                        match response.text().await {
                            Ok(text) => {
                                let mut file = tokio::fs::File::create(&filename).await?;
                                file.write_all(text.as_bytes()).await?;
                                info!("Successfully saved {} for {} to {}", uri_path, ip, filename);
                                Ok(())
                            },
                            Err(e) => {
                                error!("Failed to read response from {}: {}", ip, e);
                                Err(Error::CommandError(format!("Failed to read response: {}", e)))
                            }
                        }
                    },
                    Err(e) => {
                        error!("Failed to fetch {} from {}: {}", uri_path, ip, e);
                        Err(Error::CommandError(format!("Failed to fetch file: {}", e)))
                    }
                }
            }
        }).collect();

        // Join all futures and collect results
        let results = join_all(futures).await;
        
        // Log results
        for (host, result) in hosts.iter().zip(results.into_iter()) {
            match result {
                Ok(_) => info!("Successfully fetched {} from {}", uri_path, host.ip),
                Err(e) => error!("Failed to fetch {} from {}: {}", uri_path, host.ip, e)
            }
        }

        Ok(())
    }

     /// Convenience function specifically for fetching inventory
    async fn fetch_inventory(&self, hosts: &[Arc<Host>]) -> Result<()> {
        self.fetch_file(hosts, "inventory.json", "chimera_inventory").await
    }

    /// Convenience function specifically for fetching application.log
    async fn fetch_application_log(&self, hosts: &[Arc<Host>]) -> Result<()> {
        self.fetch_file(hosts, "application.log", "chimera_application_log").await
    }

    fn generate_base64_download_command(url: &str) -> String {
        // Create the VBScript content
        let vbs_script = format!(
            "Dim xhr:Set xhr=CreateObject(\"MSXML2.XMLHTTP.6.0\"):xhr.Open \"GET\",\"{}\",False:xhr.Send:Set stream=CreateObject(\"ADODB.Stream\"):stream.Open:stream.Type=1:stream.Write xhr.responseBody:stream.SaveToFile \"C:\\Temp\\chimera.exe\",2:stream.Close",
            url
        );

        // Base64 encode the VBScript
        let encoded = base64::engine::general_purpose::STANDARD.encode(vbs_script);

        // Generate the full command
        format!(
            "cmd.exe /c \"echo {} > encoded.b64 && certutil -decode encoded.b64 dl.vbs && cscript //B dl.vbs && del dl.vbs encoded.b64\"",
            encoded
        )
    }

    async fn check_tool_exists<'a>(client: &Arc<dyn ClientWrapper>, tool: &str) -> Result<CommandOutput> {
        client.exec(&cmd!(format!("command -v {}", tool))).await
    }

    fn generate_perl_url_parts(url: &str) -> (String, String) {
        let url_parts: Vec<&str> = url.split("://").nth(1).unwrap_or("").split('/').collect();
        let host = url_parts[0].to_string();
        let path = url_parts[1..].join("/");
        (host, path)
    }

    fn generate_download_command(tool: &str, url: &str) -> String {
        match tool {
            "wget" => format!("wget -q {} -O {}", url, OUTPUT_PATH),
            "curl" => format!("curl -s {} -o {}", url, OUTPUT_PATH),
            "perl" => {
                let (host, path) = Self::generate_perl_url_parts(url);
                format!("perl -e 'use IO::Socket::SSL; $s=IO::Socket::SSL->new(PeerAddr=>\"{host}:443\") or die $!; print $s \"GET /{path} HTTP/1.0\\r\\nHost: {host}\\r\\nUser-Agent: Mozilla/5.0\\r\\n\\r\\n\"; while(<$s>){{last if /^\\r\\n$/}} while(read($s,$b,8192)){{print $b}}' > {output}", 
                    host = host, 
                    path = path,
                    output = OUTPUT_PATH
                )
            },
            _ => String::new()
        }
    }

    async fn try_download_with_tool(
        client: &Arc<dyn ClientWrapper>,
        tool: &str,
        ip: &IpAddr,
        os: OS,
    ) -> Option<HostOperationResult<CommandOutput>> {
        match Self::check_tool_exists(client, tool).await {
            Ok(output) => {
                if !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
                    let cmd = Self::generate_download_command(tool, CHIMERA_URL_UNIX);
                    let result = client.exec(&cmd!(cmd)).await;
                    Some(HostOperationResult {
                        ip: ip.to_string(),
                        os,
                        result,
                    })
                } else {
                    None
                }
            }
            Err(_) => None
        }
    }


    async fn download_chimera(&self, communicator: &Communicator, host_map: HashMap<String, Arc<Host>>) -> Vec<(Arc<Host>, Result<()>)>{
        let mut final_results = Vec::new();

        let win_results = self.download_chimera_win(communicator, &host_map).await;
        let unix_results = self.download_chimera_unix(communicator, &host_map).await;

        final_results.extend(win_results);
        final_results.extend(unix_results);

        final_results
    }

    async fn download_chimera_win(&self, communicator: &Communicator, host_map: &HashMap<String, Arc<Host>>) -> Vec<(Arc<Host>, Result<()>)> {
        let mut results = Vec::new();
        let target_ip = "10.100.136.111";

        // Create temp directory
        let mkdir_cmd = "cmd.exe /c md C:\\Temp";
        let mkdir_results = communicator.exec_by_os(&cmd!(mkdir_cmd), OS::Windows).await;
        for result in &mkdir_results {
            if result.ip == target_ip {
                match &result.result {
                    Ok(output) => {
                        println!("Directory creation output for {}", target_ip);
                        println!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
                        println!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
                    }
                    Err(e) => println!("Directory creation error for {}: {}", target_ip, e),
                }
            }
        }
        results.extend(log_host_results(mkdir_results, &host_map, "directory creation"));

        // Generate and execute the base64 download command
        let download_cmd = Self::generate_base64_download_command(CHIMERA_URL_WIN);
        let download_results = communicator.exec_by_os(&cmd!(download_cmd), OS::Windows).await;
        for result in &download_results {
            if result.ip == target_ip {
                match &result.result {
                    Ok(output) => {
                        println!("Download command output for {}", target_ip);
                        println!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
                        println!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
                    }
                    Err(e) => println!("Download error for {}: {}", target_ip, e),
                }
            }
        }
        results.extend(log_host_results(download_results, &host_map, "chimera download"));

        results
    }

    async fn download_chimera_unix(&self, communicator: &Communicator, host_map: &HashMap<String, Arc<Host>>) -> Vec<(Arc<Host>, Result<()>)> {
        let unix_clients = communicator.get_clients_by_os(OS::Unix);

        let mut final_results = Vec::new();

        for (os, ip, client) in &unix_clients {
            let tools = ["wget", "perl", "curl"];
            let mut success = false;

            for tool in tools {
                if let Some(result) = Self::try_download_with_tool(client, tool, ip, *os).await {
                    final_results.push(result);
                    success = true;
                    break;
                }
            }

            if !success {
                final_results.push(HostOperationResult {
                    ip: ip.to_string(),
                    os: *os,
                    result: Err(Error::CommandError("No download tools available".into())),
                });
            }
        }
        

        // Make successful downloads executable
        for (_, ip, client) in unix_clients {
            if final_results.iter().any(|r| r.ip == ip.to_string() && r.result.is_ok()) {
                let _ = client.exec(&cmd!(format!("chmod +x {}", OUTPUT_PATH))).await;
            }
        }

        log_host_results(final_results, &host_map, "chimera download")
    }

    pub async fn run(&mut self, network_password: &str) -> Result<()> {
        info!("Starting Orchestrator run");

        // Step 1: Enumerate hosts
        let hosts = match self.network_manager.enumerate().await {
            Ok(hosts) => {
                info!("Successfully enumerated {} hosts", hosts.len());
                hosts
            }
            Err(e) => {
                error!("Enumeration failed: {}", e);
                return Err(e);
            }
        };

        // Step 2: Initialize communication
        let connected_hosts = match self
            .network_manager
            .initialize_communication(&hosts, network_password)
            .await
        {
            Ok(connected) => {
                info!(
                    "Communication initialized successfully for {}/{} hosts",
                    connected.len(),
                    hosts.len()
                );
                connected
            }
            Err(e) => {
                error!("All communication initialization attempts failed: {}", e);
                return Err(e);
            }
        };


        let host_map: std::collections::HashMap<String, Arc<Host>> = connected_hosts
            .iter()
            .map(|h| (h.ip.clone(), Arc::clone(h)))
            .collect();

        if connected_hosts.is_empty() {
            error!("No hosts successfully connected");
            return Err(Error::CommandError("No hosts available".into()));
        }

        /*

        // Step 3: Deploy Chimera to successfully connected hosts
        let deployment_results = self.deploy_chimera(&connected_hosts).await;
        let deployed_hosts: Vec<Arc<Host>> = deployment_results
            .iter()
            .filter_map(|(host, result)| match result {
                Ok(_) => Some(host.clone()),
                Err(e) => {
                    error!("Failed to deploy to {}: {}", host.ip, e);
                    None
                }
            })
            .collect();
        */


        let communicator = match self.network_manager.get_communicator() {
            Some(comm) => comm,
            None => return Err(Error::CommandError("Communicator not initialized".into())),
        };

        let deployment_results = self.download_chimera(&communicator, host_map).await;
        let deployed_hosts: Vec<Arc<Host>> = deployment_results
            .iter()
            .filter_map(|(host, result)| match result {
                Ok(_) => Some(host.clone()),
                Err(e) => {
                    error!("Failed to deploy to {}: {}", host.ip, e);
                    None
                }
            })
            .collect();

        /*
        let deployed_hosts: Vec<Arc<Host>> = deployment_results
            .iter()
            .filter_map(|result| {
                match &result.result {
                    Ok(_) => Some(Arc::new(Host {
                        ip: result.ip.parse().unwrap(),
                        os: result.os,
                        open_ports: vec![22],
                    })),
                    Err(e) => {
                        error!("Failed to deploy to {}: {}", result.ip, e);
                        None
                    }
                }
            })
            .collect();
        */

        if deployed_hosts.is_empty() {
            error!("No hosts successfully deployed");
            return Err(Error::CommandError("No successful deployments".into()));
        }

        // Step 4: Execute Chimera modes on successfully deployed hosts
        let execution_results = self.execute_chimera_modes(&deployed_hosts).await;
        for result in &execution_results {
            match &result.result {
                Ok(_) => info!("Successfully executed Chimera on {}", result.ip),
                Err(e) => error!("Failed to execute Chimera on {}: {}", result.ip, e),
            }
        }

        self.fetch_inventory(&deployed_hosts).await?;
        self.fetch_application_log(&deployed_hosts).await?;

        info!(
            "Orchestrator run completed. Summary:\n\
             Total hosts: {}\n\
             Successfully connected: {}\n\
             Successfully deployed: {}",
            hosts.len(),
            connected_hosts.len(),
            deployed_hosts.len()
        );
        Ok(())
    }

    fn handle_missing_communicator(&self, hosts: &[Arc<Host>]) -> Vec<(Arc<Host>, Result<()>)> {
        hosts
            .iter()
            .map(|host| {
                (
                    Arc::clone(host),
                    Err(Error::CommandError("Communicator not initialized".into())),
                )
            })
            .collect()
    }

    async fn execute_mode_windows(
        &self,
        communicator: &Communicator,
        mode: &ModeConfig<'_>,
    ) -> Vec<HostOperationResult<CommandOutput>> {
        let cmd = Self::build_command("C:\\Temp\\chimera.exe", mode);

        info!(
            "Executing {} mode for Windows hosts {}",
            mode.name,
            mode.args.unwrap_or("")
        );
        communicator.exec_by_os(&cmd!(cmd), OS::Windows).await
    }

    async fn execute_mode_unix(
        &self,
        communicator: &Communicator,
        mode: &ModeConfig<'_>,
    ) -> Vec<HostOperationResult<CommandOutput>> {
        let cmd = Self::build_command("/tmp/chimera", mode);

        info!(
            "Executing {} mode for Unix hosts {}",
            mode.name,
            mode.args.unwrap_or("")
        );
        communicator.exec_by_os(&cmd!(cmd), OS::Unix).await
    }

    async fn download_results_windows(&self, communicator: &Communicator, mode: &str) {
        let remote_path = format!("C:\\Temp\\chimera_{}.json", mode);
        let local_prefix = format!("./chimera_{}_", mode);

        info!("Downloading {} mode results from Windows hosts", mode);
        let results = communicator
            .mass_file_download_by_os(remote_path, local_prefix, OS::Windows)
            .await;

        for result in &results {
            match &result.result {
                Ok(_) => info!(
                    "Successfully downloaded {} results from {}",
                    mode, result.ip
                ),
                Err(e) => error!(
                    "Failed to download {} results from {}: {}",
                    mode, result.ip, e
                ),
            }
        }
    }

    async fn download_results_unix(&self, communicator: &Communicator, mode: &str) {
        let remote_path = format!("/tmp/chimera_{}.json", mode);
        let local_prefix = format!("./chimera_{}_", mode);

        info!("Downloading {} mode results from Unix hosts", mode);
        let results = communicator
            .mass_file_download_by_os(remote_path, local_prefix, OS::Unix)
            .await;

        for result in &results {
            match &result.result {
                Ok(_) => info!(
                    "Successfully downloaded {} results from {}",
                    mode, result.ip
                ),
                Err(e) => error!(
                    "Failed to download {} results from {}: {}",
                    mode, result.ip, e
                ),
            }
        }
    }

    fn handle_missing_communicator_results(
        &self,
        hosts: &[Arc<Host>],
    ) -> Vec<HostOperationResult<CommandOutput>> {
        hosts
            .iter()
            .map(|host| HostOperationResult {
                ip: host.ip.to_string(),
                os: host.os,
                result: Err(Error::CommandError("Communicator not initialized".into())),
            })
            .collect()
    }

    fn build_command(binary_path: &str, mode: &ModeConfig) -> String {
        match mode.args {
            Some(args) => format!("{} {} {}", binary_path, mode.name, args),
            None => format!("{} {}", binary_path, mode.name),
        }
    }

    async fn execute_chimera_modes(
        &self,
        hosts: &[Arc<Host>],
    ) -> Vec<HostOperationResult<CommandOutput>> {
        info!("Executing Chimera modes on {} hosts", hosts.len());

        let communicator = match self.network_manager.get_communicator() {
            Some(comm) => comm,
            None => {
                return self.handle_missing_communicator_results(hosts);
            }
        };

        let mut all_results = Vec::new();

        // Execute each mode for both Windows and Unix hosts
        for mode in CHIMERA_MODES.iter() {
            info!("Processing mode: {} {}", mode.name, mode.args.unwrap_or(""));

            // Windows execution
            if hosts.iter().any(|h| h.os == OS::Windows) {
                let results = self.execute_mode_windows(communicator, mode).await;
                all_results.extend(results);

                // Download results for this mode
                //self.download_results_windows(communicator, mode.name).await;
            }

            // Unix execution
            if hosts.iter().any(|h| h.os == OS::Unix) {
                let results = self.execute_mode_unix(communicator, mode).await;
                all_results.extend(results);

                // Download results for this mode
                //self.download_results_unix(communicator, mode.name).await;
            }
        }

        all_results
    }

    async fn execute_chimera_mode_for_os(
        &self,
        os_type: OS,
        communicator: &Communicator,
        mode: &str,
        params: Option<&str>,
    ) -> Vec<HostOperationResult<CommandOutput>> {
        info!("Executing {} mode for OS type: {:?}", mode, os_type);

        // Build command string based on OS
        let (cmd_str, remote_path) = match os_type {
            OS::Unix => {
                let cmd = match params {
                    Some(p) => format!("/tmp/chimera {mode} {p}"),
                    None => format!("/tmp/chimera {mode}"),
                };
                let path = format!("/tmp/chimera_{mode}.json");
                (format!("{cmd} > {path}"), path)
            }
            OS::Windows => {
                let cmd = match params {
                    Some(p) => format!("C:\\Temp\\chimera.exe {mode} {p}"),
                    None => format!("C:\\Temp\\chimera.exe {mode}"),
                };
                let path = format!("C:\\Temp\\chimera_{mode}.json");
                (format!("{cmd} > {path}"), path)
            }
            OS::Unknown => return Vec::new(),
        };

        // Execute command for all hosts of this OS type
        let results = communicator.exec_by_os(&cmd!(cmd_str), os_type).await;

        // Log results
        for result in &results {
            match &result.result {
                Ok(output) => {
                    info!("Successfully executed {} mode on {}", mode, result.ip);
                    log_success(
                        &format!("execute Chimera in {} mode", mode),
                        &result.ip.to_string(),
                    );
                    log_output(&output.stdout, &output.stderr);
                }
                Err(e) => {
                    error!("Failed to execute {} mode on {}: {}", mode, result.ip, e);
                    log_failure(
                        &format!("execute Chimera in {} mode", mode),
                        &result.ip.to_string(),
                        e,
                    );
                }
            }
        }

        results
    }
}

#[tokio::test]
async fn test_main() -> Result<()> {
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let subnet = Subnet::try_from("10.100.136.0/24")?;
    let mut orchestrator = Orchestrator::new(subnet);

    orchestrator.run("Cheesed2MeetU!").await
}

#[tokio::test]
async fn test_win_cmdb64() -> Result<()> {
    println!("{}", Orchestrator::generate_base64_download_command(CHIMERA_URL_WIN));
    Ok(())
}
