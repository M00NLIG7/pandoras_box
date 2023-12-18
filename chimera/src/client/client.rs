use serde::Deserialize;
use sysinfo::{CpuExt, DiskExt, Networks, System, SystemExt, UserExt};

#[derive(Debug)]
pub struct Disk {
    pub name: Box<str>,
    pub mount_point: Box<str>,
    pub filesystem: Box<str>,
    pub total_space: u64,
    pub available_space: u64,
}

#[derive(Debug)]
pub struct ContainerVolume {
    pub host_path: Box<str>,
    pub container_path: Box<str>,
    pub mode: Box<str>,
    pub name: Box<str>,
    pub rw: bool,
    pub v_type: Box<str>,
}

#[derive(Debug)]
pub struct ContainerNetwork {
    pub name: Box<str>,
    pub ip: Box<str>,
    pub gateway: Box<str>,
    pub mac_address: Box<str>,
}

#[derive(Debug)]
pub struct Container {
    pub id: Box<str>,
    pub name: Box<str>,
    // pub networks: Box<[ContainerNetwork]>,
    pub port_bindings: Box<[Box<str>]>,
    pub volumes: Box<[ContainerVolume]>,
    pub status: Box<str>,
    pub cmd: Box<str>,
}

#[derive(Debug)]
pub struct NetworkConnection {
    pub local_address: Box<str>,
    pub remote_address: Box<str>,
    pub state: Box<str>,
    pub protocol: Box<str>,
    pub pid: Option<i32>,
}

#[derive(Debug)]
pub struct User {
    pub name: Box<str>,
    // pub uid
    pub uid: Box<str>,
    pub gid: Box<str>,
    pub groups: Box<[Box<str>]>,
    pub shell: Option<Box<str>>,
}

#[derive(Debug)]
pub struct OpenPort {
    pub port: u16,
    pub protocol: Box<str>,
    pub pid: Option<i32>,
    pub version: Box<str>,
    pub state: Box<str>,
}

#[derive(Debug)]
pub struct Host {
    pub hostname: Box<str>,
    pub ip: Box<str>,
    // pub max_addr: Box<str>,
    pub os: Box<str>,
    pub cpu: Box<str>,
    pub memory: u64,
    // pub disk: u64,
    pub disks: Box<[Disk]>,
    pub network_adapters: String,
    pub ports: Box<[OpenPort]>,
    //pub firewall_rules: String,
    pub connections: Box<[NetworkConnection]>,
    pub services: Box<[Service]>,
    pub users: Box<[User]>,
    pub shares: Box<[Share]>,
    pub persistent_programs: String,
    //pub containers: Box<[Container]>,
}

// WMI Structs
#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Service")]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    name: String,
    start_mode: String,
    state: String,
    status: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Share")]
#[serde(rename_all = "PascalCase")]
pub struct Share {
    name: String,
    path: String,
    description: String,
}

impl Host {
    pub fn new() -> Host {
        let mut sys = System::new_all();
        // First we update all information of our `System` struct.
        sys.refresh_all();

        let disks: Box<[Disk]> = sys
            .disks()
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
            .collect();

        // println!("{:?}", sys.networks());
        // let storage: u64 = sys.disks().iter().map(|disk| disk.available_space()).sum();

        let mut users: Vec<_> = Vec::new();

        for user in sys.users() {
            users.push(User {
                name: user.name().into(),
                uid: user.id().to_string().into(),
                gid: user.group_id().to_string().into(),
                groups: user
                    .groups()
                    .iter()
                    .map(|group| group.clone().into_boxed_str())
                    .collect(),
                shell: None,
            });
        }

        let (connections, open_ports) = Host::net_info();

        Host {
            hostname: sys_info::hostname().unwrap_or(String::from("")).into(),
            ip: Host::ip(),
            // max_addr:
            os: std::env::consts::OS.into(),
            cpu: sys.cpus().first().unwrap().brand().into(),
            memory: sys.total_memory(),
            // disk: storage / 1024 / 1024 / 1024,
            disks: disks,
            network_adapters: String::from(""),
            ports: open_ports,
            connections: connections,
            //firewall_rules: String::from(""),
            services: Host::get_services(),
            users: users.into(),
            shares: Host::get_shares(),
            persistent_programs: String::from(""),
            //containers: Host::containers(),
        }
    }
}

pub trait NetworkInfo {
    fn net_info() -> (Box<[NetworkConnection]>, Box<[OpenPort]>);
    fn firewall_rules();
    fn ip() -> Box<str>;
    fn containers() -> Box<[Container]>;
}

pub trait Services {
    fn get_services() -> Box<[Service]>;
}

pub trait Shares {
    fn get_shares() -> Box<[Share]>;
}

pub trait Infect {
    fn init(&self, schema: &str);
}

fn calculate_resource_weight(cpu_cores: u32, memory_mb: u64) -> u64 {
    let cpu_cores_weight = 4;
    let memory_weight = 2;

    (cpu_cores as u64 * cpu_cores_weight as u64 * 1024) + (memory_mb as u64 * memory_weight)
}

pub fn evil_fetch() {
    // let cpu_cores: u32 = sys_info::cpu_num();
    let cpu_cores = match sys_info::cpu_num() {
        Ok(cpu_cores) => cpu_cores,
        _ => 1,
    };

    match sys_info::mem_info() {
        Ok(mem_info) => {
            let memory_mb: u64 = (mem_info.total / 1024).try_into().unwrap_or(0);
            let resource_weight = calculate_resource_weight(cpu_cores, memory_mb);
            println!("CPU Cores: {}", cpu_cores);
            println!("Memory: {} MB", memory_mb);
            println!("Resource Weight: {} units", resource_weight);
        }
        Err(e) => {
            println!("Failed to get memory info: {}", e);
        }
    }
}
