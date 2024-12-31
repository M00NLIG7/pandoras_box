use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::process::Command;

pub mod error;
pub mod client;

pub mod traits;
pub use traits::*;

static TRANSFER_HELPER: &str = include_str!("../resources/transfer_file.bat");

/// Gate behind ssh feature
#[cfg(feature = "ssh")]
pub mod ssh;

pub mod stateful_process;

/// Gate behind telnet feature
#[cfg(feature = "telnet")]
pub mod telnet;

/// Gate behind winexe feature
#[cfg(feature = "winexe")]
pub mod winexe;
#[cfg(feature = "winexe")]
pub mod smb;

/// Gate behind winrm feature
#[cfg(feature = "winrm")]
pub mod winrm;

pub use error::*;

pub mod macros {
    #[macro_export]
    macro_rules! cmd {
        ($cmd:expr $(,$arg:expr)*) => {
            {
                let mut cmd = $crate::client::Command::new($cmd);
                $(
                    cmd = cmd.arg($arg);
                )*

                cmd
            }
        };
    }
}


pub fn get_local_ip() -> String {
    // Read and parse /proc/net/route
    let default_route = match get_default_route() {
        Some(route) => route,
        None => return "0.0.0.0".to_string(),
    };

    // Get IP addresses for the interface
    match get_interface_ip(&default_route.interface) {
        Some(ip) => ip.to_string(),
        None => "0.0.0.0".to_string(),
    }
}

struct RouteEntry {
    interface: String,
    destination: u32,
}

fn get_default_route() -> Option<RouteEntry> {
    let file = File::open("/proc/net/route").ok()?;
    let reader = BufReader::new(file);
    
    for line in reader.lines().skip(1) { // Skip header
        let line = line.ok()?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 2 {
            let interface = fields[0].to_string();
            let destination = u32::from_str_radix(fields[1], 16).ok()?;
            if destination == 0 { // 0.0.0.0 is the default route
                return Some(RouteEntry { interface, destination });
            }
        }
    }
    None
}

fn get_interface_ip(interface: &str) -> Option<Ipv4Addr> {
    let output = Command::new("ip")
        .args(&["addr", "show", interface])
        .output()
        .ok()?;
    
    let output = String::from_utf8_lossy(&output.stdout);
    for line in output.lines() {
        if line.contains("inet ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > 1 {
                if let Some(ip_str) = parts[1].split('/').next() {
                    return ip_str.parse().ok();
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::cmd;

    #[test]
    fn test_macro() {
        let cmd = cmd!("ls", "-l","-a");
        assert_eq!(cmd.get_cmd(), "ls");
        assert_eq!(cmd.get_args(), &vec!["-l", "-a"]);
    }
}
