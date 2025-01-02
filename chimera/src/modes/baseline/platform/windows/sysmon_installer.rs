use std::{path::Path, process::Command, ptr};
use crate::error::{Error, Result};
use tokio::{fs::{self, File}, io::AsyncWriteExt};
use reqwest;
use zip::ZipArchive;
use windows_sys::Win32::{
    System::Services::{
        OpenSCManagerW, OpenServiceW, QueryServiceStatus,
        SC_MANAGER_CONNECT, SC_MANAGER_ALL_ACCESS, 
        SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOP,
        SERVICE_STATUS, SERVICE_RUNNING,
        CloseServiceHandle,
    },
    Foundation::{HANDLE, FALSE},
};

const SYSMON_URL: &str = "https://download.sysinternals.com/files/Sysmon.zip";
const SYSMON_CONFIG_URL: &str = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml";
const INSTALL_PATH: &str = r"C:\Program Files\Sysmon";

async fn create_install_directory() -> Result<()> {
    fs::create_dir_all(INSTALL_PATH).await?;
    Ok(())
}

async fn download_file(client: &reqwest::Client, url: &str, path: &str) -> Result<()> {
    let response = client.get(url).send().await?;
    let bytes = response.bytes().await?.to_vec();
    let mut file = File::create(path).await?;
    file.write_all(&bytes).await?;
    Ok(())
}

async fn extract_zip(zip_path: &str) -> Result<()> {
    let zip_file = std::fs::File::open(zip_path)?;
    let mut archive = ZipArchive::new(zip_file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = Path::new(INSTALL_PATH).join(file.name());

        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath).await?;
        } else {
            if let Some(p) = outpath.parent() {
                fs::create_dir_all(p).await?;
            }
            let mut outfile = File::create(&outpath).await?;
            let mut buffer = Vec::new();
            std::io::copy(&mut file, &mut buffer)?;
            outfile.write_all(&buffer).await?;
        }
    }
    Ok(())
}

fn check_existing_service() -> Result<bool> {
    unsafe {
        let sc_manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if sc_manager == 0 as HANDLE {
            return Ok(false);
        }

        let service_name = "Sysmon64\0".encode_utf16().collect::<Vec<u16>>();
        let service = OpenServiceW(
            sc_manager,
            service_name.as_ptr(),
            SERVICE_QUERY_STATUS
        );

        let exists = service != 0 as HANDLE;

        if service != 0 as HANDLE {
            CloseServiceHandle(service);
        }
        CloseServiceHandle(sc_manager);

        Ok(exists)
    }
}

fn verify_service_status() -> Result<bool> {
    unsafe {
        let sc_manager = OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_ALL_ACCESS
        );

        if sc_manager == 0 as HANDLE {
            return Ok(false);
        }

        let service_name = "Sysmon64\0".encode_utf16().collect::<Vec<u16>>();
        let service = OpenServiceW(
            sc_manager,
            service_name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP
        );

        if service == 0 as HANDLE {
            CloseServiceHandle(sc_manager);
            return Ok(false);
        }

        let mut service_status: SERVICE_STATUS = std::mem::zeroed();
        let result = QueryServiceStatus(service, &mut service_status);

        let is_running = if result != FALSE {
            service_status.dwCurrentState == SERVICE_RUNNING
        } else {
            false
        };

        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);

        Ok(is_running)
    }
}

async fn uninstall_existing() -> Result<()> {
    let sysmon_exe = format!("{}\\Sysmon64.exe", INSTALL_PATH);
    let output = Command::new(&sysmon_exe).arg("-u").output()?;

    if !output.status.success() {
        return Err(Error::ModuleError("Failed to uninstall existing Sysmon".to_string()));
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    Ok(())
}

async fn install_new_sysmon() -> Result<()> {
    let sysmon_exe = format!("{}\\Sysmon64.exe", INSTALL_PATH);
    let config_path = format!("{}\\sysmonconfig.xml", INSTALL_PATH);
    
    let output = Command::new(&sysmon_exe)
        .args(&["-accepteula", "-i", &config_path])
        .output()?;

    if !output.status.success() {
        return Err(Error::ModuleError("Failed to install Sysmon".to_string()));
    }
    Ok(())
}

async fn cleanup(zip_path: &str) -> Result<()> {
    if Path::new(zip_path).exists() {
        fs::remove_file(zip_path).await?;
    }
    Ok(())
}

pub async fn install_sysmon() -> Result<()> {
    let client = reqwest::Client::new();

    create_install_directory().await?;

    let zip_path = format!("{}\\Sysmon.zip", INSTALL_PATH);
    let config_path = format!("{}\\sysmonconfig.xml", INSTALL_PATH);
    
    download_file(&client, SYSMON_URL, &zip_path).await?;
    download_file(&client, SYSMON_CONFIG_URL, &config_path).await?;

    extract_zip(&zip_path).await?;

    if check_existing_service()? {
        uninstall_existing().await?;
    }

    install_new_sysmon().await?;
    
    if !verify_service_status()? {
        return Err(Error::ModuleError("Failed to start Sysmon service".to_string()));
    }
    
    cleanup(&zip_path).await?;

    Ok(())
}
