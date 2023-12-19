use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Service {
    pub(crate) name: Box<str>,            // The name of the service
    pub(crate) status: ServiceStatus,     // The current status of the service
    pub(crate) description: Box<str>,     // A brief description of the service
    pub(crate) exec_path: Option<String>, // Path to the executable or script
    pub(crate) enabled: bool,             // Whether the service is enabled to start on boot
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ServiceStatus {
    Active,   // The service is currently running
    Inactive, // The service is not running
    Failed,   // The service has failed
    Unknown,  // The status of the service is unknown
              // Additional statuses can be added as needed
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Disk {
    pub(crate) name: Box<str>,
    pub(crate) mount_point: Box<str>,
    pub(crate) filesystem: Box<str>,
    pub(crate) total_space: u64,
    pub(crate) available_space: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContainerVolume {
    pub(crate) host_path: Box<str>,
    pub(crate) container_path: Box<str>,
    pub(crate) mode: Box<str>,
    pub(crate) name: Box<str>,
    pub(crate) rw: bool,
    pub(crate) v_type: Box<str>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContainerNetwork {
    pub(crate) name: Box<str>,
    pub(crate) ip: Box<str>,
    pub(crate) gateway: Box<str>,
    pub(crate) mac_address: Box<str>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Container {
    pub(crate) id: Box<str>,
    pub(crate) name: Box<str>,
    pub(crate) networks: Box<[ContainerNetwork]>,
    pub(crate) port_bindings: Box<[Box<str>]>,
    pub(crate) volumes: Box<[ContainerVolume]>,
    pub(crate) status: Box<str>,
    pub(crate) cmd: Box<str>,
}

// NetworkConnection struct
// remote_address needs to be an option
// state needs to be an option
// pid should be a tuple containing the pid and process name
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
pub enum ConnectionState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Closed,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown,
}

impl ConnectionState {
    pub fn is_closed(&self) -> bool {
        match self {
            ConnectionState::Closed => true,
            _ => false,
        }
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Unknown
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Process {
    pub(crate) pid: i32,
    pub(crate) name: Box<str>,
}

impl Clone for Process {
    fn clone(&self) -> Self {
        Process {
            pid: self.pid,
            name: self.name.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkConnection {
    pub(crate) local_address: Box<str>,
    pub(crate) remote_address: Option<Box<str>>,
    pub(crate) state: Option<ConnectionState>,
    pub(crate) protocol: Box<str>,
    pub(crate) process: Option<Process>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub(crate) name: Box<str>,
    pub(crate) uid: Box<str>,
    pub(crate) gid: Box<str>,
    pub(crate) is_admin: bool,
    pub(crate) groups: Box<[Box<str>]>,
    pub(crate) is_local: bool,
    pub(crate) shell: Option<Box<str>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OpenPort {
    pub(crate) port: u16,
    pub(crate) protocol: Box<str>,
    pub(crate) process: Option<Process>,
    pub(crate) version: Box<str>,
    pub(crate) state: Option<ConnectionState>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ShareType {
    NFS,
    SMB,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Share {
    pub(crate) share_type: ShareType, // Type of the file share (NFS, SMB, etc.)
    pub(crate) network_path: Box<str>, // Network path or URL of the file share
}

pub trait OS {
    fn conn_info() -> (Box<[NetworkConnection]>, Box<[OpenPort]>);
    fn firewall_rules();
    fn ip() -> Box<str>;
    fn containers() -> Box<[Container]>;
    fn services() -> Box<[Service]>;
    fn shares() -> Box<[Share]>;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Host {
    pub(crate) hostname: Box<str>,
    pub(crate) ip: Box<str>,
    // pub(crate) max_addr: Box<str>,
    pub(crate) os: Box<str>,
    pub(crate) cpu: Box<str>,
    pub(crate) memory: u64,
    // pub(crate) disk: u64,
    pub(crate) disks: Box<[Disk]>,
    pub(crate) network_adapters: String,
    pub(crate) ports: Box<[OpenPort]>,
    pub(crate) firewall_rules: String,
    // pub(crate) processes: String,
    pub(crate) connections: Box<[NetworkConnection]>,
    pub(crate) services: Box<[Service]>,
    pub(crate) users: Box<[User]>,
    pub(crate) shares: Box<[Share]>,
    pub(crate) persistent_programs: String,
    pub(crate) containers: Box<[Container]>,
}

pub trait UserInfo {
    fn is_admin(&self) -> bool;
    fn is_local(&self) -> bool;
}

pub trait Infect {
    fn init(&self, schema: &str);
}
