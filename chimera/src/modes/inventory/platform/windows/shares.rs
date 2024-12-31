use crate::types::Share;
use wmi::{Variant, WMIConnection};
use crate::types::ShareType;
use std::collections::HashMap;
use wmi::COMLibrary;



pub fn shares() -> Vec<Share> {
    let com_lib = match COMLibrary::new() {
        Ok(lib) => lib,
        _ => return Vec::new(), // or handle the error as appropriate
    };

    let wmi_con = match WMIConnection::new(com_lib) {
        Ok(con) => con,
        _ => return Vec::new(), // or handle the error as appropriate
    };

    let results: Vec<HashMap<String, Variant>> =
        wmi_con.raw_query("SELECT * FROM Win32_Share").unwrap();
    let mut shares: Vec<Share> = Vec::new();
    for os in results {
        shares.push(Share {
            share_type: ShareType::SMB,
            network_path: match os.get("Path").unwrap() {
                Variant::String(s) => s.to_string(),
                _ => "".to_string(),
            },
        });
    }

    shares
}

