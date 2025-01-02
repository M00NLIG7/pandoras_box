use crate::error::{Error, Result};
use reqwest::Client;
use std::{env, path::Path, ptr};
use tokio::process::Command;
use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, HANDLE, TRUE},
    Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
    System::{
        Registry::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        },
        SystemInformation::{GetSystemInfo, GetVersionExW, OSVERSIONINFOW, SYSTEM_INFO},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};


fn get_powershell_registry_version() -> Result<Option<String>> {
    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let subkey = "SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine\0"
            .encode_utf16()
            .collect::<Vec<u16>>();
            
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        ) == 0 {
            let value_name = "PowerShellVersion\0"
                .encode_utf16()
                .collect::<Vec<u16>>();
            let mut buf_len: u32 = 256;
            let mut buf_type: u32 = 0;
            let mut buffer = vec![0u8; buf_len as usize];

            let result = RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut buf_type,
                buffer.as_mut_ptr(),
                &mut buf_len,
            );
            
            RegCloseKey(hkey);
            
            if result == 0 {
                // Convert buffer to string, removing null terminators
                let version = String::from_utf16_lossy(
                    &buffer[..buf_len as usize - 2]  // Remove null terminator
                        .chunks_exact(2)
                        .map(|chunk| u16::from_ne_bytes([chunk[0], chunk[1]]))
                        .collect::<Vec<u16>>()
                )
                .trim()
                .to_string();
                
                println!("PowerShell version from registry: {}", version);
                return Ok(Some(version));
            }
        }
        
        println!("Could not read PowerShell version from registry");
        Ok(None)
    }
}

fn version_needs_update(version: &str) -> bool {
    // Parse version string like "5.1.14393.3866" to check major.minor
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>()) {
            // Return true if version is less than 5.1
            return major < 5 || (major == 5 && minor < 1);
        }
    }
    // If we can't parse the version, assume update is needed
    true
}

#[derive(Debug)]
struct UpdateUrls {
    win_server_2012_r2: &'static str,
    win_server_2012: &'static str,
    win_server_2008_r2: &'static str,
    win_8: &'static str,
    win_7: &'static str,
}

impl UpdateUrls {
    fn new() -> Self {
        Self {
            win_server_2012_r2: "https://go.microsoft.com/fwlink/?linkid=839516",
            win_server_2012: "https://go.microsoft.com/fwlink/?linkid=839513",
            win_server_2008_r2: "https://go.microsoft.com/fwlink/?linkid=839523",
            win_8: "https://go.microsoft.com/fwlink/?linkid=839521",
            win_7: "https://go.microsoft.com/fwlink/?linkid=839522",
        }
    }
}

#[derive(Debug)]
struct PrerequisiteUrls {
    win_7: &'static str,
    win_server_2008_r2: &'static str,
}

impl PrerequisiteUrls {
    fn new() -> Self {
        Self {
            win_7: "https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe",
            win_server_2008_r2: "https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe",
        }
    }
}

fn is_admin() -> bool {
    println!("Checking for administrative privileges");
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == FALSE {
            println!("Failed to open process token");
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let elevation_ptr = &mut elevation as *mut _ as *mut std::ffi::c_void;

        let result = GetTokenInformation(token, TokenElevation, elevation_ptr, size, &mut size);

        CloseHandle(token);

        let is_elevated = result == TRUE && elevation.TokenIsElevated != 0;
        println!("Administrative privileges check result: {}", is_elevated);
        is_elevated
    }
}

fn get_os_info() -> Result<(String, bool)> {
    println!("Retrieving OS information");
    unsafe {
        let mut system_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut system_info);

        let mut osvi: OSVERSIONINFOW = std::mem::zeroed();
        osvi.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

        if GetVersionExW(&mut osvi) == TRUE {
            let is_server = system_info.Anonymous.Anonymous.wProcessorArchitecture == 9;

            // Handle version numbers and compatibility
            let version = match (osvi.dwMajorVersion, osvi.dwMinorVersion) {
                (10, _) => "10.0".to_string(),
                (6, 3) => "8.1".to_string(),
                (6, 2) => "8.0".to_string(),
                (6, 1) => "7.0".to_string(),
                (v1, v2) => format!("{}.{}", v1, v2),
            };

            println!(
                "Detected OS version: Windows {}, Server: {}",
                version, is_server
            );
            Ok((format!("Windows {}", version), is_server))
        } else {
            println!("Failed to get Windows version information, assuming modern Windows");
            Ok(("Windows 10.0".to_string(), false))
        }
    }
}

async fn download_file(url: &str, path: &Path) -> Result<()> {
    println!("Starting file download from: {}", url);
    println!("Download target path: {:?}", path);

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| {
            println!("Failed to build HTTP client: {}", e);
            Error::ModuleError(e.to_string())
        })?;

    match client.get(url).send().await {
        Ok(response) => match response.bytes().await {
            Ok(bytes) => {
                println!("Writing {} bytes to file", bytes.len());
                if let Err(e) = tokio::fs::write(path, bytes).await {
                    println!("Failed to write file: {}", e);
                }
            }
            Err(e) => println!("Failed to read response bytes: {}", e),
        },
        Err(e) => println!("Failed to download file: {}", e),
    }

    Ok(())
}

async fn install_update(path: &Path) -> Result<()> {
    println!("Starting update installation from: {:?}", path);

    if !path.exists() {
        println!("Update file not found, skipping installation");
        return Ok(());
    }

    match path.to_str() {
        Some(path_str) => {
            let output = Command::new("wusa.exe")
                .args(&[path_str, "/quiet", "/norestart"])
                .output()
                .await;

            match output {
                Ok(output) => {
                    if !output.status.success() {
                        let error = String::from_utf8_lossy(&output.stderr);
                        println!("Update installation returned non-success: {}", error);
                    }
                }
                Err(e) => println!("Failed to execute wusa.exe: {}", e),
            }
        }
        None => println!("Invalid path format, skipping installation"),
    }

    println!("Update installation process completed");
    Ok(())
}

async fn install_prerequisites(os_version: &str) -> Result<()> {
    println!("Checking prerequisites for OS version: {}", os_version);

    let prereq_urls = PrerequisiteUrls::new();

    let url = match os_version {
        v if v.contains("7") => {
            println!("Windows 7 prerequisites selected");
            Some(prereq_urls.win_7)
        }
        v if v.contains("2008 R2") => {
            println!("Windows Server 2008 R2 prerequisites selected");
            Some(prereq_urls.win_server_2008_r2)
        }
        _ => {
            println!("No prerequisites needed for this OS version");
            None
        }
    };

    if let Some(prereq_url) = url {
        println!("Installing prerequisites");
        let temp_dir = env::temp_dir();
        let prereq_path = temp_dir.join("prereq.exe");
        println!("Prerequisites installer path: {:?}", prereq_path);

        download_file(prereq_url, &prereq_path).await?;

        println!("Executing prerequisites installer");
        match Command::new(&prereq_path)
            .args(&["/quiet", "/norestart"])
            .output()
            .await
        {
            Ok(output) => {
                if !output.status.success() {
                    let error = String::from_utf8_lossy(&output.stderr);
                    println!("Prerequisites installation returned non-success: {}", error);
                }
            }
            Err(e) => println!("Failed to execute prerequisites installer: {}", e),
        }

        if let Err(e) = tokio::fs::remove_file(&prereq_path).await {
            println!("Failed to cleanup prerequisites installer: {}", e);
        }

        println!("Prerequisites installation process completed");
    }

    Ok(())
}

pub async fn update_powershell() -> Result<()> {
    println!("Starting PowerShell update process");

    // Check current PowerShell version first
    if let Ok(Some(current_version)) = get_powershell_registry_version() {
        if !version_needs_update(&current_version) {
            println!(
                "PowerShell 5.1 or later is already installed (Current version: {})",
                current_version
            );
            return Ok(());
        }
        println!(
            "PowerShell update needed. Current version: {}",
            current_version
        );
    } else {
        println!("Unable to determine PowerShell version, will attempt update");
    }

    if !is_admin() {
        println!("Administrative privileges not available, skipping update");
        return Ok(());
    }

    let (os_version, is_server) = get_os_info()?;
    println!("Detected OS: {}, Server: {}", os_version, is_server);

    if os_version.contains("10.") {
        println!("Modern Windows version detected, no PowerShell update needed");
        return Ok(());
    }

    let urls = UpdateUrls::new();
    let temp_dir = env::temp_dir();
    println!("Using temporary directory: {:?}", temp_dir);

    match os_version.as_str() {
        v if v.contains("8.1") || (v.contains("2012") && v.contains("R2")) => {
            println!("Windows 8.1/2012 R2 detected");
            let update_path = temp_dir.join("Win2012R2-PSUpdate.msu");
            download_file(urls.win_server_2012_r2, &update_path).await?;
            install_update(&update_path).await?;
            if let Err(e) = tokio::fs::remove_file(&update_path).await {
                println!("Failed to cleanup update file: {}", e);
            }
        }

        v if v.contains("8.0") || v.contains("2012") => {
            println!("Windows 8/2012 detected");
            let update_path = temp_dir.join("Win2012-PSUpdate.msu");
            download_file(urls.win_server_2012, &update_path).await?;
            install_update(&update_path).await?;
            if let Err(e) = tokio::fs::remove_file(&update_path).await {
                println!("Failed to cleanup update file: {}", e);
            }
        }

        v if v.contains("7") || v.contains("2008 R2") => {
            println!("Windows 7/2008 R2 detected");
            install_prerequisites(&os_version).await?;
            let update_path = temp_dir.join("Win7-PSUpdate.msu");
            download_file(urls.win_7, &update_path).await?;
            install_update(&update_path).await?;
            if let Err(e) = tokio::fs::remove_file(&update_path).await {
                println!("Failed to cleanup update file: {}", e);
            }
        }

        _ => println!(
            "Unsupported or unrecognized Windows version: {}",
            os_version
        ),
    }

    println!("PowerShell update process completed");
    Ok(())
}
