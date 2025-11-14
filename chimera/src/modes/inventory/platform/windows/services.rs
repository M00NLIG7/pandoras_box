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

    // Only collect services that are BOTH running AND auto-start
    // This significantly reduces output on Domain Controllers (from 200+ to ~15-25 critical services)
    // Similar to Linux showing only active services (not all enabled services)
    let results: Vec<HashMap<String, Variant>> = match wmi_con
        .raw_query("SELECT * FROM Win32_Service WHERE State='Running' AND StartMode='Auto'") {
        Ok(results) => results,
        Err(_) => return Vec::new(),
    };
    let mut services = Vec::new();
    for os in results {
        // Skip services with missing required fields instead of panicking
        let name = match os.get("Name") {
            Some(Variant::String(s)) => s.clone(),
            _ => continue, // Skip services without names
        };

        let status = match os.get("State") {
            Some(Variant::String(s)) => match s.as_str() {
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
        };

        let start_mode = match os.get("StartMode") {
            Some(Variant::String(s)) => {
                if s == "Auto" {
                    Some(ServiceStartType::Enabled)
                } else {
                    Some(ServiceStartType::Disabled)
                }
            }
            _ => None, // Don't panic, just return None
        };

        let state = match os.get("Status") {
            Some(Variant::String(s)) => s.to_string(),
            _ => "Unknown".to_string(),
        };

        services.push(Service {
            name,
            status,
            start_mode,
            state,
        });
    }

    services
}

