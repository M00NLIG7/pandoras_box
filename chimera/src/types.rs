//! Types and structures for CCDC automation system
//! 
//! This module contains the core types used for system automation
//! across both Windows and Linux systems.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use log::{error, info};



#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;


/// Represents the different execution modes available for system
/// automation and configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionMode {
   /// Initial remote access configuration
   /// 
   /// # Tasks
   /// * Verify network connectivity
   /// * Establish remote connections (RDP/SSH)
   /// * Validate administrative access
   Remote,

   /// Credential and account security management
   /// 
   /// # Tasks
   /// * Change default passwords
   /// * Create backup administrative accounts
   /// * Disable unnecessary accounts
   Credentials,

   /// System inventory and asset discovery
   /// 
   /// # Tasks
   /// * List installed software/packages
   /// * Enumerate users and groups
   /// * Identify running services
   /// * Map network connections
   Inventory,

   /// System update and patch management
   /// 
   /// # Tasks
   /// * Configure update sources
   /// * Install pending updates
   /// * Validate system patch level
   Update,

   /// OS-specific configurations
   /// 
   /// # Windows Tasks
   /// * Disable SMBv1
   /// * Mitigate Zerologon vulnerability
   /// * Implement Kerberoasting protections
   /// * Harden LSA against Mimikatz
   /// * Enable Windows Defender
   ///
   /// # Linux Tasks
   /// * Install and configure rsyslog
   /// * Set up Auditd logging
   /// * Configure fail2ban
   Baseline,

   /// Serve inventory and log
   Serve,
}

/// Result of an execution operation
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
   /// Whether the operation completed successfully
   pub success: bool,
   /// The mode that was executed
   pub mode: ExecutionMode,
   /// Detailed message about the operation result
   pub message: String,
   /// Timestamp when the operation completed
   #[serde(with = "chrono::serde::ts_seconds")]
   pub timestamp: DateTime<Utc>,
}

impl ExecutionResult {
   pub fn new(mode: ExecutionMode, success: bool, message: String) -> Self {
       let result = Self {
           success,
           mode: mode.clone(),
           message: message.clone(),
           timestamp: Utc::now(),
       };

       // Log based on success/failure
       if success {
           info!("[{}] {}", mode.as_str(), message);
       } else {
           error!("[{}] {}", mode.as_str(), message);
       }

       result
   }
}

impl ExecutionMode {
   /// Gets a description of what the mode does
   /// 
   /// # Returns
   /// A static string describing the mode's purpose
   pub fn description(&self) -> &'static str {
       match self {
           ExecutionMode::Remote => "Establishes initial system access and remote connections",
           ExecutionMode::Credentials => "Manages system credentials and account security",
           ExecutionMode::Inventory => "Performs system inventory and asset discovery",
           ExecutionMode::Update => "Handles system updates and patch management",
           ExecutionMode::Baseline => "Implements OS-specific security configurations",
           ExecutionMode::Serve => "Serves inventory and log",
       }
   }

   /// Gets a short string representation of the mode
   pub fn as_str(&self) -> &'static str {
       match self {
           ExecutionMode::Remote => "REMOTE",
           ExecutionMode::Credentials => "CREDS",
           ExecutionMode::Inventory => "INVEN",
           ExecutionMode::Update => "UPDATE",
           ExecutionMode::Baseline => "BASELINE",
           ExecutionMode::Serve => "SERVE",
       }
   }
}

/// Represents the operational status of a system service.
///
/// This enum is used to indicate whether a service is currently running,
/// stopped, or in an error state.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub enum ServiceStatus {
    /// Service is running and operational
    Active,
    /// Service is not currently running
    Inactive,
    /// Service has encountered an error and failed to start/run
    Failed,
    /// Service status could not be determined
    Unknown,
}

/// Defines the startup behavior of a system service.
///
/// This enum determines whether a service will automatically start
/// when the system boots up.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum ServiceStartType {
    /// Service will start automatically on system boot
    Enabled,
    /// Service must be started manually
    Disabled,
}

/// Configuration and status information for a system service.
///
/// This struct contains all relevant information about a service,
/// including its current state and startup configuration.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Unique identifier for the service
    pub(crate) name: String,
    /// Current running state as a string
    pub(crate) state: String,
    /// Configuration for service startup behavior
    pub(crate) start_mode: Option<ServiceStartType>,
    /// Current operational status
    pub(crate) status: Option<ServiceStatus>,
}

/// Information about a physical or virtual disk in the system.
///
/// Contains details about the disk's capacity, mounting point,
/// and filesystem type.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Disk {
    /// Disk identifier or name
    pub(crate) name: String,
    /// Path where the disk is mounted in the filesystem
    pub(crate) mount_point: String,
    /// Type of filesystem (e.g., ext4, ntfs)
    pub(crate) filesystem: String,
    /// Total disk capacity in bytes
    pub(crate) total_space: u64,
    /// Currently available space in bytes
    pub(crate) available_space: u64,
}

/// Configuration for a container volume mount.
///
/// Defines how a filesystem path is mapped between the host
/// and container environments.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerVolume {
    /// Path on the host system
    pub(crate) host_path: String,
    /// Path inside the container
    pub(crate) container_path: String,
    /// Mount mode (e.g., "rw", "ro")
    pub(crate) mode: String,
    /// Name of the volume if named
    pub(crate) volume_name: String,
    /// Whether volume is writable
    pub(crate) rw: bool,
    /// Volume type specification
    pub(crate) v_type: String,
}

/// Network configuration for a container.
///
/// Contains all network-related settings and addresses
/// for a container instance.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerNetwork {
    /// Name of the network
    pub(crate) network_name: String,
    /// IP address assigned to the container
    pub(crate) ip: String,
    /// Gateway IP address for the network
    pub(crate) gateway: String,
    /// MAC address assigned to the container
    pub(crate) mac_address: String,
}

/// Complete configuration and status for a container instance.
///
/// Includes all network, volume, and runtime configuration
/// for a container.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Container {
    /// Unique container identifier
    pub(crate) container_id: String,
    /// User-assigned container name
    pub(crate) name: String,
    /// Network configurations
    pub(crate) networks: Vec<ContainerNetwork>,
    /// Port mappings between host and container
    pub(crate) port_bindings: Vec<String>,
    /// Volume mount configurations
    pub(crate) volumes: Vec<ContainerVolume>,
    /// Current container status
    pub(crate) status: String,
    /// Command being run in container
    pub(crate) cmd: String,
}

/// TCP connection states as defined in RFC 793.
///
/// Represents all possible states a TCP connection can be in
/// during its lifecycle.
#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq, Clone, Hash)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionState {
    /// Connection is established and operating normally
    Established,
    /// SYN sent, waiting for matching SYN+ACK
    SynSent,
    /// SYN received, waiting for matching ACK
    SynRecv,
    /// FIN sent, waiting for matching ACK
    FinWait1,
    /// FIN received, waiting for matching FIN
    FinWait2,
    /// Waiting for enough time to ensure remote TCP received connection termination
    TimeWait,
    /// Connection is fully terminated
    Close,
    /// Remote end has initiated a shutdown
    CloseWait,
    /// Waiting for last ACK after initiating shutdown
    LastAck,
    /// Socket is listening for incoming connections
    Listen,
    /// Both sides trying to close simultaneously
    Closing,
    /// State could not be determined
    #[default]
    Unknown,
}

impl ConnectionState {
    /// Checks if the connection is in a closed state.
    ///
    /// # Returns
    /// * `true` if the connection state is `Closed`
    /// * `false` for all other states
    pub fn is_closed(&self) -> bool {
        matches!(self, ConnectionState::Close)
    }
}

/// Information about a system process.
///
/// Contains the process identifier and name for tracking
/// system resources used by the process.
#[derive(Debug, Deserialize, Serialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    /// Process identifier
    pub(crate) pid: u32,
    /// Process name
    pub(crate) name: String,
}

impl Clone for Process {
    /// Creates a clone of the Process.
    ///
    /// # Returns
    /// * A new `Process` instance with the same pid and name
    fn clone(&self) -> Self {
        Process {
            pid: self.pid,
            name: self.name.clone(),
        }
    }
}

/// Details about a network connection.
///
/// Includes information about endpoints, state, and
/// associated process.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConnection {
    /// Local endpoint address
    pub(crate) local_address: String,
    /// Remote endpoint address if connected
    pub(crate) remote_address: Option<String>,
    /// Current connection state
    pub(crate) state: Option<ConnectionState>,
    /// Protocol in use (e.g., "TCP", "UDP")
    pub(crate) protocol: String,
    /// Process owning the connection
    pub(crate) process: Option<Process>,
}

/// Information about a system user account.
///
/// Contains user identification and privilege information.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// Username
    pub(crate) name: String,
    /// User ID
    pub(crate) uid: String,
    /// Primary group ID
    pub(crate) gid: String,
    /// Whether user has administrative privileges
    pub(crate) is_admin: bool,
    /// Group memberships
    pub(crate) groups: Vec<String>,
    /// Whether account is local or domain
    pub(crate) is_local: bool,
    /// User's login shell
    pub(crate) shell: Option<String>,
}

/// Information about an open network port.
///
/// Contains details about port number, protocol, and
/// associated process.
#[derive(Debug, Deserialize, Serialize, Eq, Hash, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OpenPort {
    /// Port number
    pub(crate) port: u16,
    /// Protocol in use
    pub(crate) protocol: String,
    /// Process using the port
    pub(crate) process: Option<Process>,
    /// Protocol version
    pub(crate) version: String,
    /// Current connection state
    pub(crate) state: Option<ConnectionState>,
}

/// Types of network file shares supported.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ShareType {
    /// Network File System
    NFS,
    /// Server Message Block
    SMB,
}

/// Configuration for a network file share.
///
/// Contains the share type and network path information.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    /// Type of share protocol
    pub(crate) share_type: ShareType,
    /// Network path to the share
    pub(crate) network_path: String,
}

/// Windows-specific server feature detection.
#[cfg(target_os = "windows")]
pub trait ServerFeatures {
    /// Lists enabled Windows server features.
    ///
    /// # Returns
    /// * Vector of feature names
    fn server_features() -> Vec<String>;
}

/// Comprehensive system information.
///
/// Contains all queryable information about the host system
/// including hardware, network, and service configurations.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    /// System hostname
    pub(crate) hostname: String,
    /// Primary IP address
    pub(crate) ip: String,
    /// OS version
    pub(crate) os: String,
    /// Number of CPU cores
    pub(crate) cores: u8,
    /// CPU model name
    pub(crate) cpu: String,
    /// Total memory in bytes
    pub(crate) memory: u64,
    /// Disk configurations
    pub(crate) disks: Vec<Disk>,
    /// Network adapter information
    pub(crate) network_adapters: String,
    /// Open ports
    pub(crate) ports: Vec<OpenPort>,
    /// Network connections
    pub(crate) connections: Vec<NetworkConnection>,
    /// System services
    pub(crate) services: Vec<Service>,
    /// User accounts
    pub(crate) users: Vec<User>,
    /// Network shares
    pub(crate) shares: Vec<Share>,
    /// Container configurations
    pub(crate) containers: Vec<Container>,
    /*
    /// Windows server features
    #[cfg(target_os = "windows")]
    pub(crate) server_features: Vec<String>,
    */
}

/// Interface for user information operations.
pub trait UserInfo {
    /// Checks if the user has administrative privileges.
    ///
    /// # Returns
    /// * `true` if user is an administrator
    /// * `false` otherwise
    fn is_admin(&self) -> bool;

    /// Checks if the user account is local.
    ///
    /// # Returns
    /// * `true` if user is a local account
    /// * `false` if domain account
    fn is_local(&self) -> bool;

    /// Gets the user's login shell.
    ///
    /// # Returns
    /// * The path to the user's login shell
    #[cfg(target_os = "linux")]
    fn shell(&self) -> String;
}

