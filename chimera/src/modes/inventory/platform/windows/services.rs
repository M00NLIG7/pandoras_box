use std::sync::Arc;
use futures::future::join_all;
use crate::utils::CommandExecutor;
use crate::types::{Service, ServiceStatus, ServiceStartType};
use crate::error::{Error, Result};
use std::collections::HashMap;
use wmi::{COMLibrary, Variant, WMIConnection};

pub async fn services() -> Vec<Service> {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        _ => return Vec::new(), // or handle the error as appropriate
    };

    let wmi_con = match WMIConnection::new(com_lib) {
        Ok(con) => con,
        _ => return Vec::new(), // or handle the error as appropriate
    };

    let results: Vec<HashMap<String, Variant>> =
        wmi_con.raw_query("SELECT * FROM Win32_Service").unwrap();
    let mut services = Vec::new();
    for os in results {
        services.push(Service {
            name: match os.get("Name").unwrap() {
                Variant::String(s) => s.clone(),
                _ => "".to_string(),
            },
            status: match os.get("State").unwrap() {
                Variant::String(s) => match s.as_str() {
                    "Running" => Some(ServiceStatus::Active),
                    "Stopped" => Some(ServiceStatus::Inactive),
                    "Paused" => Some(ServiceStatus::Inactive),
                    "Start Pending" => Some(ServiceStatus::Inactive),
                    "Stop Pending" => Some(ServiceStatus::Inactive),
                    "Continue Pending" => Some(ServiceStatus::Inactive),
                    "Pause Pending" => Some(ServiceStatus::Inactive),
                    "Unknown" => Some(ServiceStatus::Unknown),
                    _ => Some(ServiceStatus::Failed),
                },
                _ => None,
            },

            start_mode: match os.get("StartMode").unwrap() {
                Variant::String(s) => {
                    if s == "Auto" {
                        Some(ServiceStartType::Enabled)
                    } else {
                        Some(ServiceStartType::Disabled)
                    }
                }
                _ => panic!("Unexpected type for StartMode"),
            },

            state: match os.get("Status").unwrap() {
                Variant::String(s) => {
                    if s == "OK" {
                        s.to_string()
                    } else {
                        s.to_string()
                    }
                }
                _ => "".to_string(),
            },
        });
    }

    services
}

