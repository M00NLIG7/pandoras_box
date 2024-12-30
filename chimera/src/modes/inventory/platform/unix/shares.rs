use std::fs::File;
use std::io::{self, BufRead, BufReader};
use serde::{Deserialize, Serialize};
use crate::types::{Share, ShareType};

pub fn read_smb_shares() -> io::Result<Vec<Share>> {
    let config_paths = [
        "/etc/samba/smb.conf",
        "/usr/local/samba/lib/smb.conf",
        "/usr/local/etc/smb.conf",
        "/opt/samba/etc/smb.conf"
    ];

    // Try each possible config location
    let mut config_file = None;
    for path in config_paths {
        if let Ok(file) = File::open(path) {
            config_file = Some(file);
            break;
        }
    }

    let file = config_file.ok_or_else(|| 
        io::Error::new(io::ErrorKind::NotFound, "SMB configuration file not found")
    )?;

    let reader = BufReader::new(file);
    let mut shares = Vec::new();
    let mut current_share: Option<String> = None;
    let mut current_path: Option<String> = None;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        
        // Skip comments and empty lines
        if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
            continue;
        }

        // Check for share definition
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            // Save previous share if it exists and has a path
            if let (Some(share_name), Some(path)) = (current_share.take(), current_path.take()) {
                shares.push(Share {
                    share_type: ShareType::SMB,
                    network_path: format!("//{}/{}", "localhost", share_name),
                });
            }

            let share_name = trimmed[1..trimmed.len()-1].to_string();
            // Skip [global] and [printers] sections
            if share_name != "global" && share_name != "printers" {
                current_share = Some(share_name);
            }
            continue;
        }

        // Parse path for current share
        if current_share.is_some() {
            if let Some((key, value)) = trimmed.split_once('=') {
                let key = key.trim().to_lowercase();
                let value = value.trim();
                
                if key == "path" {
                    current_path = Some(value.to_string());
                }
            }
        }
    }

    // Don't forget to add the last share
    if let (Some(share_name), Some(_)) = (current_share, current_path) {
        shares.push(Share {
            share_type: ShareType::SMB,
            network_path: format!("//{}/{}", "localhost", share_name),
        });
    }

    Ok(shares)
}

pub fn read_nfs_shares() -> io::Result<Vec<Share>> {
    let export_paths = [
        "/etc/exports",
        "/usr/local/etc/exports",
        "/etc/nfs.conf/exports"
    ];

    // Try each possible exports location
    let mut exports_file = None;
    for path in export_paths {
        if let Ok(file) = File::open(path) {
            exports_file = Some(file);
            break;
        }
    }

    let file = exports_file.ok_or_else(|| 
        io::Error::new(io::ErrorKind::NotFound, "NFS exports file not found")
    )?;

    let reader = BufReader::new(file);
    let mut shares = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        
        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Split the line into path and clients/options
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let path = parts[0];

        // Skip non-absolute paths and invalid entries
        if !path.starts_with('/') || path.contains('*') {
            continue;
        }

        // Clean the path (remove any quotes if present)
        let clean_path = path.trim_matches('"').trim_matches('\'');

        // Verify path exists
        if let Ok(metadata) = std::fs::metadata(clean_path) {
            if metadata.is_dir() {
                shares.push(Share {
                    share_type: ShareType::NFS,
                    // Format as nfs://hostname/path
                    network_path: format!("nfs://localhost{}", clean_path),
                });
            }
        }
    }

    Ok(shares)
}

pub fn shares() -> Vec<Share> {
    let mut shares = Vec::new();
    if let Ok(smb_shares) = read_smb_shares() {
        shares.extend(smb_shares);
    }
    if let Ok(nfs_shares) = read_nfs_shares() {
        shares.extend(nfs_shares);
    }
    shares
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_smb_shares() {
        let shares = read_smb_shares().unwrap();
        assert!(!shares.is_empty());
        for share in shares {
            println!("{:?}", share);
        }
    }

    #[tokio::test]
    async fn test_read_nfs_shares() {
        let shares = read_nfs_shares().unwrap();
        assert!(!shares.is_empty());
        for share in shares {
            println!("{:?}", share);
        }
    }
}


