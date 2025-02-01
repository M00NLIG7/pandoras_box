use log::{info, error};

mod sysmon_installer;
mod pwsh_update;
mod harden;


pub async fn establish_baseline() -> crate::error::Result<()> {
    match harden::harden_zerologon().await {
        Ok(_) => info!("Zero logon hardened successfully"),
        Err(e) => {
            error!("Failed to harden Zero logon: {}", e);
        }
    }


    match harden::harden_php().await {
        Ok(_) => info!("PHP hardened successfully"),
        Err(e) => {
            error!("Failed to harden PHP: {}", e);
        }
    }

    match harden::harden_lanman().await {
        Ok(_) => info!("Lanman hardened successfully"),
        Err(e) => {
            error!("Failed to harden Lanman: {}", e);
        }
    }

    match harden::configure_null_session_shares().await {
        Ok(_) => info!("Null session shares configured successfully"),
        Err(e) => {
            error!("Failed to configure null session shares: {}", e);
        }
    }

    match harden::configure_null_session_pipes().await {
        Ok(_) => info!("Null session pipes configured successfully"),
        Err(e) => {
            error!("Failed to configure null session pipes: {}", e);
        }
    }

    match harden::setup_logging().await {
        Ok(_) => info!("Logging setup successfully"),
        Err(e) => {
            error!("Failed to setup logging: {}", e);
        }
    }

    match harden::harden_smb_system().await {
        Ok(_) => info!("SMB hardened successfully"),
        Err(e) => {
            error!("Failed to harden SMB: {}", e);
        }
    }

    match harden::fix_ccdc_bs().await {
        Ok(_) => info!("CCDC BS fixed successfully"),
        Err(e) => {
            error!("Failed to fix CCDC BS: {}", e);
        }
    }

    match harden::disable_misc().await {
        Ok(_) => info!("Miscellaneous hardening completed successfully"),
        Err(e) => {
            error!("Failed to complete miscellaneous hardening: {}", e);
        }
    }

    match harden::disable_default_accounts().await {
        Ok(_) => info!("Default accounts disabled successfully"),
        Err(e) => {
            error!("Failed to disable default accounts: {}", e);
        }
    }

    match sysmon_installer::install_sysmon().await {
        Ok(_) => info!("Sysmon installed successfully"),
        Err(e) => {
            error!("Failed to install Sysmon: {}", e);
        }
    }

    match pwsh_update::update_powershell().await {
        Ok(_) => info!("PowerShell updated successfully"),
        Err(e) => {
            error!("Failed to update PowerShell: {}", e);
        }
    }

    Ok(())
}
