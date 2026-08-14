use crate::types::{Share, ShareType};
use std::collections::HashMap;
use wmi::{COMLibrary, Variant, WMIConnection};

pub fn shares() -> (Vec<Share>, Vec<String>) {
    match query_shares() {
        Ok(shares) => (shares, Vec::new()),
        Err(error) => (Vec::new(), vec![error]),
    }
}

fn query_shares() -> Result<Vec<Share>, String> {
    let com_lib =
        COMLibrary::new().map_err(|error| format!("failed to initialize COM: {error}"))?;
    let wmi_con = WMIConnection::new(com_lib)
        .map_err(|error| format!("failed to connect to WMI: {error}"))?;
    let results: Vec<HashMap<String, Variant>> = wmi_con
        .raw_query("SELECT Name FROM Win32_Share")
        .map_err(|error| format!("share WMI query failed: {error}"))?;

    Ok(results
        .into_iter()
        .filter_map(|share| match share.get("Name") {
            Some(Variant::String(name)) if !name.is_empty() => Some(Share {
                share_type: ShareType::SMB,
                network_path: format!(r"\\localhost\{name}"),
            }),
            _ => None,
        })
        .collect())
}
