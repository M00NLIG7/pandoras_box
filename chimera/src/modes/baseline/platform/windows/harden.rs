use crate::error::Result;
use crate::utils::find_files;
use ignore::WalkBuilder;
use log::error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io;
use tokio::process::Command;
use tokio::{self, sync::mpsc};

async fn run_cmd(args: &[&str]) -> io::Result<String> {
    let output = Command::new("cmd")
        .args(["/C", &args.join(" ")])
        .output()
        .await?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub async fn harden_php() -> Result<()> {
    // Find PHP configuration files
    let php_configs = find_php_configs().await?;

    // PHP security configurations
    let disable_functions = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source\n";
    let file_uploads = "file_uploads=off\n";

    // Apply configurations to each PHP config file
    for config_file in php_configs {
        match fs::OpenOptions::new().append(true).open(&config_file) {
            Ok(mut file) => {
                file.write_all(disable_functions.as_bytes())?;
                file.write_all(file_uploads.as_bytes())?;
            }
            Err(e) => {
                error!("Error writing to {}: {}", config_file, e);
            }
        }
    }

    Ok(())
}

async fn find_php_configs() -> Result<Vec<String>> {
    let php_exes = find_files("php.exe".to_string(), "/".to_string()).await;
    let mut config_files = Vec::new();

    for php_exe in php_exes {
        let output = match Command::new(&php_exe).arg("--ini").output().await {
            Ok(output) => output,
            Err(e) => {
                error!("Failed to execute {}: {}", php_exe, e);
                continue;
            }
        };

        let output_str = match String::from_utf8(output.stdout) {
            Ok(str) => str,
            Err(_) => continue,
        };

        for line in output_str.lines() {
            if !line.contains("Loaded") {
                continue;
            }

            let config_path = match line.split_whitespace().last() {
                Some(path) => path,
                None => continue,
            };

            config_files.push(config_path.to_string());
        }
    }

    Ok(config_files)
}

pub async fn harden_lanman() -> io::Result<()> {
    run_cmd(&[
        "reg",
        "add",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        "/v",
        "RestrictNullSessAccess",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ])
    .await?;
    Ok(())
}

async fn get_shares() -> io::Result<Vec<String>> {
    let shares = run_cmd(&["net", "share"]).await?;
    let mut share_list = Vec::new();

    for line in shares.lines() {
        if let Some(share_name) = line.split_whitespace().next() {
            if !share_name.ends_with('$') {
                share_list.push(share_name.to_string());
            }
        }
    }
    Ok(share_list)
}

pub async fn configure_null_session_shares() -> io::Result<()> {
    let shares = get_shares().await?;
    let null_shares = shares.join("\\0");
    run_cmd(&[
        "reg",
        "add",
        "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        "/v",
        "NullSessionShares",
        "/t",
        "REG_MULTI_SZ",
        "/d",
        &null_shares,
        "/f",
    ])
    .await?;
    Ok(())
}

pub async fn configure_null_session_pipes() -> io::Result<()> {
    run_cmd(&[
        "reg",
        "add",
        "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        "/v",
        "NullSessionPipes",
        "/t",
        "REG_MULTI_SZ",
        "/d",
        "MS-IPAMM2\\0MS-NCNBI\\0MS-WSUSAR\\0BITS-samr\\0",
        "/f",
    ])
    .await?;
    Ok(())
}

pub async fn setup_logging() -> Result<()> {
    // Enable all audit policies
    run_cmd(&[
        "auditpol",
        "/set",
        "/category:*",
        "/success:enable",
        "/failure:enable",
    ])
    .await?;

    // Process Creation Command Line Logging
    run_cmd(&[
        "reg",
        "add",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
        "/v",
        "ProcessCreationIncludeCmdLine_Enabled",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ])
    .await?;

    // PowerShell Transcription
    let user_profile =
        std::env::var("USERPROFILE").unwrap_or_else(|_| String::from("C:\\Users\\Default"));
    let ps_trans_path = format!("{}\\Desktop\\PSLogs", user_profile);

    let registry_commands = vec![
        vec![
            "reg",
            "add",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
            "/v",
            "EnableTranscripting",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
        vec![
            "reg",
            "add",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
            "/v",
            "EnableInvocationHeader",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
        vec![
            "reg",
            "add",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
            "/v",
            "OutputDirectory",
            "/t",
            "REG_SZ",
            "/d",
            &ps_trans_path,
            "/f",
        ],
        vec![
            "reg",
            "add",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
            "/v",
            "EnableScriptBlockLogging",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
        vec![
            "reg",
            "add",
            "HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
            "/v",
            "EnableModuleLogging",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
        vec![
            "reg",
            "add",
            "HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging\\ModuleNames",
            "/v",
            "*",
            "/t",
            "REG_SZ",
            "/d",
            "*",
            "/f",
        ],
    ];

    for cmd in registry_commands {
        run_cmd(&cmd).await?;
    }

    let computer_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| String::from("UNKNOWN"));

    // IIS Logging
    let _ = run_cmd(&[
        "C:\\Windows\\System32\\inetsrv\\appcmd.exe",
        "set",
        "config",
        "/section:httpLogging",
        "/dontLog:False",
    ])
    .await;

    Ok(())
}

async fn restore_segoe_fonts() -> io::Result<()> {
    let font_entries = [
        ("Segoe UI (TrueType)", "segoeui.ttf"),
        ("Segoe UI Black (TrueType)", "seguibl.ttf"),
        ("Segoe UI Black Italic (TrueType)", "seguibli.ttf"),
        ("Segoe UI Bold (TrueType)", "segoeuib.ttf"),
        ("Segoe UI Bold Italic (TrueType)", "segoeuiz.ttf"),
        ("Segoe UI Emoji (TrueType)", "seguiemj.ttf"),
        ("Segoe UI Historic (TrueType)", "seguihis.ttf"),
        ("Segoe UI Italic (TrueType)", "segoeuii.ttf"),
        ("Segoe UI Light (TrueType)", "segoeuil.ttf"),
        ("Segoe UI Light Italic (TrueType)", "seguili.ttf"),
        ("Segoe UI Semibold (TrueType)", "seguisb.ttf"),
        ("Segoe UI Semibold Italic (TrueType)", "seguisbi.ttf"),
        ("Segoe UI Semilight (TrueType)", "seguisli.ttf"),
        ("Segoe UI Semilight Italic (TrueType)", "seguisl.ttf"),
        ("Segoe UI Symbol (TrueType)", "seguisym.ttf"),
        ("Segoe UI Variable (TrueType)", "segoeui.ttf"),
        ("Segoe MDL2 Assets (TrueType)", "segmdl2.ttf"),
        ("Segoe Print (TrueType)", "segoepr.ttf"),
        ("Segoe Print Bold (TrueType)", "segoeprb.ttf"),
        ("Segoe Script (TrueType)", "segoesc.ttf"),
        ("Segoe Script Bold (TrueType)", "segoescb.ttf"),
    ];

    for (name, file) in font_entries.iter() {
        run_cmd(&[
            "reg",
            "add",
            "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Fonts",
            "/v",
            name,
            "/t",
            "REG_SZ",
            "/d",
            file,
            "/f",
        ])
        .await?;
    }

    // Delete font substitutes
    run_cmd(&[
        "reg",
        "delete",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes",
        "/v",
        "Segoe UI",
        "/f",
    ])
    .await?;

    Ok(())
}

async fn configure_font_management() -> io::Result<()> {
    // Configure font management settings
    run_cmd(&[
        "reg",
        "add",
        "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Font Management",
        "/v",
        "Auto Activation Mode",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ])
    .await?;

    run_cmd(&[
        "reg",
        "add",
        "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Font Management",
        "/v",
        "InstallAsLink",
        "/t",
        "REG_DWORD",
        "/d",
        "0",
        "/f",
    ])
    .await?;

    // Delete unnecessary entries
    for key in ["Inactive Fonts", "Active Languages"].iter() {
        run_cmd(&[
            "reg",
            "delete",
            "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Font Management",
            "/v",
            key,
            "/f",
        ])
        .await?;
    }

    Ok(())
}

async fn set_system_language() -> io::Result<()> {
    // Clear existing keyboard layouts
    run_cmd(&[
        "reg",
        "delete",
        "HKCU\\Keyboard Layout\\Preload",
        "/va",
        "/f",
    ])
    .await?;

    // Set English keyboard
    run_cmd(&[
        "reg",
        "add",
        "HKCU\\Keyboard Layout\\Preload",
        "/v",
        "1",
        "/t",
        "REG_SZ",
        "/d",
        "00000409",
        "/f",
    ])
    .await?;

    // Set UI language
    let lang_entries = [
        (
            "HKCU\\Control Panel\\Desktop",
            "PreferredUILanguages",
            "en-US",
        ),
        (
            "HKLM\\Software\\Policies\\Microsoft\\MUI\\Settings",
            "PreferredUILanguages",
            "en-US",
        ),
        (
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language",
            "InstallLanguage",
            "0409",
        ),
        (
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language",
            "Default",
            "0409",
        ),
    ];

    for (path, key, value) in lang_entries.iter() {
        run_cmd(&[
            "reg", "add", path, "/v", key, "/t", "REG_SZ", "/d", value, "/f",
        ])
        .await?;
    }

    Ok(())
}

async fn configure_explorer_settings() -> io::Result<()> {
    let settings = [
        ("Hidden", "1"),
        ("HideFileExt", "0"),
        ("ShowSuperHidden", "1"),
    ];

    for (setting, value) in settings.iter() {
        run_cmd(&[
            "reg",
            "add",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
            "/v",
            setting,
            "/t",
            "REG_DWORD",
            "/d",
            value,
            "/f",
        ])
        .await?;
    }

    Ok(())
}

pub async fn configure_smb_security() -> io::Result<()> {
    // Disable SMB1
    run_cmd(&[
        "reg",
        "add",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        "/v",
        "SMB1",
        "/t",
        "REG_DWORD",
        "/d",
        "0",
        "/f",
    ])
    .await?;

    // Configure LanManWorkstation security settings
    let lanman_workstation_settings = [
        ("RequireSecuritySignature", "1"),
        ("EnableSecuritySignature", "1"),
    ];

    for (setting, value) in lanman_workstation_settings.iter() {
        run_cmd(&[
            "reg",
            "add",
            "HKLM\\System\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters",
            "/v",
            setting,
            "/t",
            "REG_DWORD",
            "/d",
            value,
            "/f",
        ])
        .await?;
    }

    // Configure LanmanServer security settings
    let lanman_server_settings = [
        ("RequireSecuritySignature", "1"),
        ("EnableSecuritySignature", "1"),
        // Commented out as in original script
        // ("AutoShareServer", "0"),
        // ("AutoShareWks", "0"),
    ];

    for (setting, value) in lanman_server_settings.iter() {
        run_cmd(&[
            "reg",
            "add",
            "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
            "/v",
            setting,
            "/t",
            "REG_DWORD",
            "/d",
            value,
            "/f",
        ])
        .await?;
    }

    Ok(())
}

pub async fn harden_smb_shares() -> io::Result<()> {
    let exempt_shares = vec![
        "NETLOGON",
        "SYSVOL",
        "ADMIN$",
        "C$",
        "IPC$",
        "AdminUIContentPayload",
        "EasySetupPayload",
        "SCCMContentLib$",
        "SMS_CPSC$",
        "SMS_DP$",
        "SMS_OCM_DATACACHE",
        "SMS_SITE",
        "SMS_SUIAgent",
        "SMS_WWW",
        "SMSPKGC$",
        "SMSSIG$",
    ];

    // Get all shares
    let shares_output = run_cmd(&[
        "powershell",
        "-Command",
        "Get-SmbShare | Select-Object Name",
    ])
    .await?;

    for line in shares_output.lines() {
        let share_name = line.trim();
        if share_name.is_empty() || share_name == "Name" || share_name == "--" {
            continue;
        }

        if !exempt_shares.contains(&share_name) {
            // Get current share access
            let access_output = run_cmd(&[
                "powershell",
                "-Command",
                &format!(
                    "Get-SmbShareAccess -Name '{}' | Select-Object AccountName",
                    share_name
                ),
            ])
            .await?;

            // Process each account
            for account_line in access_output.lines() {
                let account = account_line.trim();
                if account.is_empty() || account == "AccountName" || account == "--" {
                    continue;
                }

                // Set read-only access
                run_cmd(&["powershell", "-Command", 
                    &format!("Grant-SmbShareAccess -Name '{}' -AccountName '{}' -AccessRight Read -Force",
                        share_name, account)
                ]).await?;
            }
        }
    }

    Ok(())
}

pub async fn verify_smb_hardening() -> io::Result<()> {
    // Verify SMB1 is disabled
    let smb1_status = run_cmd(&[
        "reg",
        "query",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
        "/v",
        "SMB1",
    ])
    .await?;

    // Verify security signatures
    let security_settings = [
        ("LanManWorkstation", "RequireSecuritySignature"),
        ("LanManWorkstation", "EnableSecuritySignature"),
        ("LanmanServer", "RequireSecuritySignature"),
        ("LanmanServer", "EnableSecuritySignature"),
    ];

    for (service, setting) in security_settings.iter() {
        run_cmd(&[
            "reg",
            "query",
            &format!(
                "HKLM\\System\\CurrentControlSet\\Services\\{}\\Parameters",
                service
            ),
            "/v",
            setting,
        ])
        .await?;
    }

    Ok(())
}

pub async fn harden_smb_system() -> Result<()> {
    configure_smb_security().await?;
    harden_smb_shares().await?;
    verify_smb_hardening().await?;
    Ok(())
}

// Yoink
pub async fn fix_ccdc_bs() -> io::Result<()> {
    restore_segoe_fonts().await?;
    configure_font_management().await?;
    set_system_language().await?;
    configure_explorer_settings().await?;
    Ok(())
}

pub async fn disable_bits() -> Result<()> {
    run_cmd(&[
        "reg",
        "add",
        "HKLM\\Software\\Policies\\Microsoft\\Windows\\BITS",
        "/v",
        "EnableBITSMaxBandwidth",
        "/t",
        "REG_DWORD",
        "/d",
        "0",
        "/f",
    ])
    .await?;

    run_cmd(&[
        "reg",
        "add",
        "HKLM\\Software\\Policies\\Microsoft\\Windows\\BITS",
        "/v",
        "MaxDownloadTime",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ])
    .await?;
    Ok(())
}

async fn disable_floppy_remoting() -> Result<()> {
    run_cmd(&[
        "reg",
        "add",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "/v",
        "AllocateFloppies",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ])
    .await?;

    Ok(())
}

async fn disable_accessibility_features() -> Result<()> {
    let settings = [
        (
            "HKCU\\Control Panel\\Accessibility\\StickyKeys",
            "Flags",
            "506",
        ),
        (
            "HKCU\\Control Panel\\Accessibility\\ToggleKeys",
            "Flags",
            "58",
        ),
        (
            "HKCU\\Control Panel\\Accessibility\\Keyboard Response",
            "Flags",
            "122",
        ),
        (
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI",
            "ShowTabletKeyboard",
            "0",
        ),
    ];

    for (path, key, value) in settings.iter() {
        run_cmd(&[
            "reg", "add", path, "/v", key, "/t", "REG_SZ", "/d", value, "/f",
        ])
        .await?;
    }

    Ok(())
}

async fn disable_run_once() -> Result<()> {
    run_cmd(&[
        "reg",
        "add",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "/v",
        "DisableLocalMachineRunOnce",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ])
    .await?;

    run_cmd(&[
        "reg",
        "add",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
        "/v",
        "DisableLocalMachineRunOnce",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ])
    .await?;

    Ok(())
}

pub async fn disable_misc() -> Result<()> {
    disable_bits().await?;
    disable_floppy_remoting().await?;
    disable_accessibility_features().await?;
    disable_run_once().await?;
    Ok(())
}

pub async fn disable_default_accounts() -> Result<()> {
    run_cmd(&["net", "user", "Guest", "/active:no"]).await?;
    run_cmd(&["net", "user", "DefaultAccount", "/active:no"]).await?;
    Ok(())
}
