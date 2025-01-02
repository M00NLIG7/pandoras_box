mod sysmon_installer;
mod pwsh_update;

pub async fn establish_baseline() -> crate::error::Result<()> {
    match sysmon_installer::install_sysmon().await {
        Ok(_) => (),
        Err(e) => {
            log::error!("Failed to install Sysmon: {}", e);
        }
    }

    match pwsh_update::update_powershell().await {
        Ok(_) => (),
        Err(e) => {
            log::error!("Failed to update PowerShell: {}", e);
        }
    }

    Ok(())
}
