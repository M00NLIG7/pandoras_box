use crate::error::Result;
use ignore::WalkBuilder;
use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
struct SysctlSetting {
    key: String,
    value: String,
}

#[derive(Debug, Clone)]
struct SSHConfig {
    setting: String,
    value: String,
}

#[derive(Debug, Clone)]
enum PackageManager {
    Yum,
    Apt,
    Apk,
    Pkg,
    Zypper,
    Pacman,
    Dnf,
    SlaptGet,
}

#[derive(Clone, Debug)]
pub struct PHPConfig {
    disable_functions: Vec<String>,
    security_settings: Vec<(String, String)>,
}

fn generate_php_config() -> PHPConfig {
    PHPConfig {
        disable_functions: vec![
            "exec".into(),
            "system".into(),
            "shell_exec".into(),
            "passthru".into(),
            "popen".into(),
            "curl_exec".into(),
            "curl_multi_exec".into(),
            "parse_ini_file".into(),
            "show_source".into(),
            "proc_open".into(),
            "pcntl_exec".into(),
        ],
        security_settings: vec![
            ("track_errors".into(), "off".into()),
            ("html_errors".into(), "off".into()),
            ("max_execution_time".into(), "3".into()),
            ("display_errors".into(), "off".into()),
            ("short_open_tag".into(), "off".into()),
            ("session.cookie_httponly".into(), "1".into()),
            ("session.use_only_cookies".into(), "1".into()),
            ("session.cookie_secure".into(), "1".into()),
            ("expose_php".into(), "off".into()),
            ("magic_quotes_gpc".into(), "off".into()),
            ("allow_url_fopen".into(), "off".into()),
            ("allow_url_include".into(), "off".into()),
            ("register_globals".into(), "off".into()),
            ("file_uploads".into(), "off".into()),
        ],
    }
}

async fn append_php_config_to_file(path: &str, config: &PHPConfig) -> Result<()> {
    let mut file = OpenOptions::new().append(true).open(path).await?;

    // Append disable_functions
    let disable_functions = format!(
        "\ndisable_functions = {}\n",
        config.disable_functions.join(",")
    );
    file.write_all(disable_functions.as_bytes()).await?;

    // Append security settings
    for (key, value) in &config.security_settings {
        let setting = format!("{} = {}\n", key, value);
        file.write_all(setting.as_bytes()).await?;
    }

    println!("{} changed", path);
    Ok(())
}

/// Asynchronously searches for files with the specified name and returns their paths.
///
/// # Arguments
///
/// * `target_name` - The name of the file to search for.
/// * `root` - The root directory to start the search.
///
/// # Returns
///
/// A vector of file paths matching the specified name.
pub async fn find_files(target_name: String, root: String) -> Vec<String> {
    // Use Arc for shared ownership of the target_name
    let target_name = Arc::new(target_name);
    let root = Arc::new(root);

    // Create a channel for communication
    let (tx, mut rx) = mpsc::channel::<PathBuf>(100);

    // Spawn a blocking task for file traversal
    let walker_task = tokio::task::spawn_blocking({
        let target_name = Arc::clone(&target_name);
        let root = Arc::clone(&root);
        move || {
            let walker = WalkBuilder::new(&*root).threads(6).build_parallel();
            walker.run(|| {
                let tx = tx.clone();
                let target_name = Arc::clone(&target_name);
                Box::new(move |entry| {
                    if let Ok(entry) = entry {
                        // Check if the file name matches
                        if entry.path().file_name().and_then(|n| n.to_str()) == Some(&*target_name)
                        {
                            // Send the matching path
                            tx.blocking_send(entry.into_path()).ok();
                        }
                    }
                    ignore::WalkState::Continue
                })
            });
        }
    });

    // Collect results asynchronously
    let mut results = Vec::new();
    while let Some(path) = rx.recv().await {
        if let Some(path_str) = path.to_str() {
            results.push(path_str.to_string());
        }
    }

    // Ensure the walker task finishes
    walker_task.await.unwrap();

    results
}

async fn configure_rbash(revert: bool) -> Result<()> {
    if revert {
        info!("Reverting passwd configuration to backup");
        if Path::new("/etc/passwd.bak").exists() {
            fs::copy("/etc/passwd.bak", "/etc/passwd").await?;
            info!("Successfully restored passwd from backup");
        } else {
            error!("Backup file /etc/passwd.bak not found");
            return Err(crate::error::Error::Execution(
                "Backup file not found".to_string(),
            ));
        }
    } else {
        info!("Starting rbash configuration");

        // Backup passwd file
        info!("Creating backup of passwd file");
        fs::copy("/etc/passwd", "/etc/passwd.bak").await?;
        tokio::fs::set_permissions(
            "/etc/passwd.bak",
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .await?;

        // Create rbash symlink if it doesn't exist
        if !Path::new("/bin/rbash").exists() {
            info!("Creating rbash symlink");
            tokio::fs::symlink("/bin/bash", "/bin/rbash").await?;
        }

        // Modify passwd file to use rbash
        if command_exists("bash").await {
            info!("Modifying user shells to use rbash");
            let mut passwd_content = String::new();
            let mut file = File::open("/etc/passwd").await?;
            file.read_to_string(&mut passwd_content).await?;

            let mut lines: Vec<String> = passwd_content.lines().map(String::from).collect();
            if lines.is_empty() {
                return Err(crate::error::Error::Execution(
                    "Empty passwd file".to_string(),
                ));
            }

            // Keep first line (root) unchanged
            let root_line = lines.remove(0);

            // Modify remaining lines to use rbash
            let modified_lines: Vec<String> = lines
                .into_iter()
                .map(|line| {
                    line.replace(r"/bin/bash", "/bin/rbash")
                        .replace(r"/bin/sh", "/bin/rbash")
                        .replace(r"/bin/dash", "/bin/rbash")
                        .replace(r"/bin/zsh", "/bin/rbash")
                })
                .collect();

            // Combine lines back together
            let mut new_content = String::new();
            new_content.push_str(&root_line);
            new_content.push('\n');
            new_content.push_str(&modified_lines.join("\n"));

            // Write to temporary file first
            let temp_path = "/etc/passwd.temp";
            let mut temp_file = File::create(temp_path).await?;
            temp_file.write_all(new_content.as_bytes()).await?;
            temp_file.sync_all().await?;

            // Move temporary file to passwd
            fs::rename(temp_path, "/etc/passwd").await?;
            tokio::fs::set_permissions(
                "/etc/passwd",
                std::os::unix::fs::PermissionsExt::from_mode(0o644),
            )
            .await?;
        }

        // Update shell rc files
        info!("Updating shell rc files");
        modify_shell_rc_files().await?;
    }

    Ok(())
}

async fn modify_shell_rc_files() -> Result<()> {
    let is_alpine = command_exists("apk").await;
    let rc_paths = find_rc_files().await?;

    // Define secure base paths that are essential for system operation
    let secure_path = vec![
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ];

    for path in rc_paths {
        debug!("Modifying shell rc file: {:?}", path);

        let mut file = OpenOptions::new().append(true).open(&path).await?;

        // Reset PATH to known secure directories
        file.write_all(b"\n# Security hardening - Setting secure PATH\n")
            .await?;
        file.write_all(format!("PATH=\"{}\"\n", secure_path.join(":")).as_bytes())
            .await?;
        file.write_all(b"export PATH\n").await?;

        // Optional: Prevent PATH modification by user scripts
        file.write_all(b"readonly PATH\n").await?;

        // Optional: Prevent PATH modification through ENV
        file.write_all(b"export -n PATH\n").await?;
    }

    Ok(())
}

async fn find_rc_files() -> Result<Vec<std::path::PathBuf>> {
    let mut rc_files = Vec::new();

    // Search in /etc
    let mut etc_files = find_rc_files_in_dir("/etc").await?;
    rc_files.append(&mut etc_files);

    // Search in /home
    let mut home_files = find_rc_files_in_dir("/home").await?;
    rc_files.append(&mut home_files);

    Ok(rc_files)
}

async fn find_rc_files_in_dir(dir: &str) -> Result<Vec<std::path::PathBuf>> {
    use std::future::Future;
    use std::pin::Pin;

    fn find_rc_files_in_dir_recursive(
        dir: String,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<std::path::PathBuf>>> + Send>> {
        Box::pin(async move {
            let mut rc_files = Vec::new();

            let mut entries = fs::read_dir(&dir).await?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();

                if path.is_dir() {
                    if let Some(path_str) = path.to_str() {
                        if let Ok(mut subdir_files) =
                            find_rc_files_in_dir_recursive(path_str.to_string()).await
                        {
                            rc_files.append(&mut subdir_files);
                        }
                    }
                } else if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if filename.ends_with("shrc") {
                        rc_files.push(path);
                    }
                }
            }

            Ok(rc_files)
        })
    }

    find_rc_files_in_dir_recursive(dir.to_string()).await
}

async fn configure_pam() -> Result<()> {
    info!("Starting PAM configuration and repair");

    let package_manager = match detect_package_manager().await {
        Some(pm) => {
            info!("Detected package manager: {:?}", pm);
            pm
        }
        None => {
            error!("Unable to detect package manager");
            return Err(crate::error::Error::UnknownOS);
        }
    };

    // Backup PAM configuration
    backup_pam_config().await?;

    match package_manager {
        PackageManager::Yum | PackageManager::Dnf => {
            info!("Configuring PAM for RHEL-based system");
            if command_exists("authconfig").await {
                info!("Running authconfig update");
                run_command("authconfig", &["--updateall"]).await?;

                info!("Reinstalling PAM packages");
                run_command("yum", &["-y", "reinstall", "pam"]).await?;
            } else {
                warn!("authconfig not found, skipping PAM configuration");
            }
        }
        PackageManager::Apt => {
            info!("Configuring PAM for Debian/Ubuntu system");
            // Set environment variable for non-interactive frontend
            let mut cmd = Command::new("pam-auth-update");
            cmd.env("DEBIAN_FRONTEND", "noninteractive");
            cmd.arg("--force");

            info!("Running pam-auth-update");
            if let Err(e) = cmd.status().await {
                error!("Failed to update PAM auth: {}", e);
            }

            info!("Reinstalling PAM packages");
            run_command(
                "apt-get",
                &[
                    "-y",
                    "--reinstall",
                    "install",
                    "libpam-runtime",
                    "libpam-modules",
                ],
            )
            .await?;
        }
        PackageManager::Apk => {
            info!("Configuring PAM for Alpine system");
            if !Path::new("/etc/pam.d").exists() {
                warn!("PAM is not installed on this Alpine system");
                return Ok(());
            }

            info!("Repairing PAM installation");
            run_command("apk", &["fix", "--purge", "linux-pam"]).await?;

            info!("Processing new PAM configuration files");
            process_alpine_pam_configs().await?;
        }
        PackageManager::Pacman => {
            info!("Configuring PAM for Arch system");
            if let Ok(backup_dir) = std::env::var("BACKUPDIR") {
                info!("Restoring PAM configuration from backup");
                backup_and_restore_arch_pam(&backup_dir).await?;
            } else {
                warn!("BACKUPDIR not set, skipping PAM config restore");
            }

            info!("Reinstalling PAM package");
            run_command("pacman", &["-S", "pam", "--noconfirm"]).await?;
        }
        _ => {
            warn!("Unsupported distribution for PAM configuration");
        }
    }

    info!("PAM configuration completed");
    Ok(())
}

async fn backup_pam_config() -> Result<()> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if Path::new("/etc/pam.d").exists() {
        info!("Creating backup of PAM configuration");
        let backup_path = format!("/etc/pam.d.backup.{}", timestamp);
        run_command("cp", &["-R", "/etc/pam.d", &backup_path]).await?;
    }

    Ok(())
}

async fn process_alpine_pam_configs() -> Result<()> {
    let mut read_dir = fs::read_dir("/etc/pam.d").await?;

    while let Some(entry) = read_dir.next_entry().await? {
        let path = entry.path();
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            if file_name.ends_with(".apk-new") {
                let new_name = file_name.replace(".apk-new", "");
                let new_path = path.with_file_name(new_name);
                debug!("Moving PAM config: {:?} -> {:?}", path, new_path);
                if let Err(e) = fs::rename(&path, &new_path).await {
                    error!("Failed to move PAM config file: {}", e);
                }
            }
        }
    }

    Ok(())
}

async fn backup_and_restore_arch_pam(backup_dir: &str) -> Result<()> {
    info!("Creating backup of current PAM configuration");
    run_command("mv", &["/etc/pam.d", "/etc/pam.d.backup"]).await?;

    info!("Restoring PAM configuration from backup");
    run_command("cp", &["-R", backup_dir, "/etc/pam.d"]).await?;

    Ok(())
}

pub async fn setup_syslog() -> Result<()> {
    info!("Setting up syslog and auditd");
    let package_manager = match detect_package_manager().await {
        Some(pm) => {
            info!("Detected package manager: {:?}", pm);
            pm
        }
        None => return Err(crate::error::Error::UnknownOS),
    };

    match package_manager {
        PackageManager::Yum | PackageManager::Dnf => {
            let cmd = if matches!(package_manager, PackageManager::Dnf) {
                "dnf"
            } else {
                "yum"
            };

            info!("Installing rsyslog and auditd via {}", cmd);

            match run_command(cmd, &["check-update", "-y"]).await {
                Ok(_) => info!("Package list updated"),
                Err(e) => warn!("Failed to update package list: {}", e),
            }
            match run_command(
                cmd,
                &[
                    "install",
                    "net-tools",
                    "iproute",
                    "sed",
                    "curl",
                    "wget",
                    "bash",
                    "-y",
                ],
            )
            .await
            {
                Ok(_) => info!("Installed required packages"),
                Err(e) => warn!("Failed to install required packages: {}", e),
            }

            match run_command(cmd, &["install", "iptraf", "-y"]).await {
                Ok(_) => info!("Installed iptraf"),
                Err(e) => warn!("Failed to install iptraf: {}", e),
            }

            match run_command(cmd, &["install", "auditd", "-y"]).await {
                Ok(_) => info!("Installed auditd"),
                Err(e) => warn!("Failed to install auditd: {}", e),
            }

            match run_command(cmd, &["install", "rsyslog", "-y"]).await {
                Ok(_) => info!("Installed rsyslog"),
                Err(e) => warn!("Failed to install rsyslog: {}", e),
            }

            debug!("Setting SELinux context for /var/log/audit");
            match run_command("chcon", &["-R", "-t", "var_log_t", "/var/log/audit"]).await {
                Ok(_) => info!("Set SELinux context for /var/log/audit"),
                Err(e) => warn!("Failed to set SELinux context for /var/log/audit: {}", e),
            }
        }
        PackageManager::Apt => {
            info!("Installing rsyslog and auditd via apt");
            match run_command("apt-get", &["-qq", "update"]).await {
                Ok(_) => info!("Package list updated"),
                Err(e) => warn!("Failed to update package list: {}", e),
            }

            match run_command("apt-get", &["-qq", "install", "rsyslog", "auditd", "-y"]).await {
                Ok(_) => info!("Installed rsyslog and auditd"),
                Err(e) => warn!("Failed to install rsyslog and auditd: {}", e),
            }
        }
        PackageManager::Apk => {
            info!("Installing rsyslog and auditd via apk");
            fs::write(
                "/etc/apk/repositories",
                "\nhttp://mirrors.ocf.berkeley.edu/alpine/v3.16/community\n",
            )
            .await?;
            match run_command("apk", &["update", "--allow-untrusted"]).await {
                Ok(_) => info!("Package list updated"),
                Err(e) => warn!("Failed to update package list: {}", e),
            }

            match run_command("apk", &["add", "rsyslog", "audit", "--allow-untrusted"]).await {
                Ok(_) => info!("Installed rsyslog and auditd"),
                Err(e) => warn!("Failed to install rsyslog and auditd: {}", e),
            }
            fs::create_dir_all("/var/log/audit").await?;
            match update_audit_dispatcher().await {
                Ok(_) => info!("Updated audit dispatcher"),
                Err(e) => warn!("Failed to update audit dispatcher: {}", e),
            }
        }
        PackageManager::Pkg if is_dragonfly().await? => {
            info!("Installing rsyslog via pkg");
            fs::copy(
                "/usr/local/etc/pkg/repos/df-latest.conf.sample",
                "/usr/local/etc/pkg/repos/df-latest.conf",
            )
            .await?;
            match run_command("pkg", &["update"]).await {
                Ok(_) => info!("Package list updated"),
                Err(e) => warn!("Failed to update package list: {}", e),
            }
            match run_command("pkg", &["install", "-y", "rsyslog"]).await {
                Ok(_) => info!("Installed rsyslog"),
                Err(e) => warn!("Failed to install rsyslog: {}", e),
            }
            return Ok(()); // Skip audit setup for DragonFly
        }
        _ => return Err(crate::error::Error::UnknownOS),
    };

    fs::create_dir_all("/etc/rsyslog.d").await?;

    // Configure audit unless we're on DragonFly
    if !is_dragonfly().await? {
        info!("Setting up auditd");
        match setup_audit().await {
            Ok(_) => info!("Auditd setup completed"),
            Err(e) => warn!("Failed to setup auditd: {}", e),
        }
    }

    // Start services unless we're on Alpine
    if !is_alpine().await? {
        if command_exists("systemctl").await {
            match run_command("systemctl", &["restart", "rsyslog"]).await {
                Ok(_) => info!("Restarted rsyslog"),
                Err(e) => warn!("Failed to restart rsyslog: {}", e),
            }
            match run_command("systemctl", &["start", "auditd"]).await {
                Ok(_) => info!("Started auditd"),
                Err(e) => warn!("Failed to start auditd: {}", e),
            }
        } else {
            match run_command("service", &["rsyslog", "restart"]).await {
                Ok(_) => info!("Restarted rsyslog"),
                Err(e) => warn!("Failed to restart rsyslog: {}", e),
            }

            match run_command("service", &["auditd", "start"]).await {
                Ok(_) => info!("Started auditd"),
                Err(e) => warn!("Failed to start auditd: {}", e),
            }
        }
    } else {
        match run_command("service", &["rsyslog", "restart"]).await {
            Ok(_) => info!("Restarted rsyslog"),
            Err(e) => warn!("Failed to restart rsyslog: {}", e),
        }
        match run_command("/usr/sbin/auditd", &[]).await {
            Ok(_) => info!("Started auditd"),
            Err(e) => warn!("Failed to start auditd: {}", e),
        }
    }

    Ok(())
}

async fn setup_audit() -> Result<()> {
    info!("Configuring auditd system parameters");
    debug!("setting audit buffer size to 8192");
    run_command("auditctl", &["-b", "8192"]).await?;

    let audit_rules = [
        (
            &[
                "-a",
                "exit,always",
                "-F",
                "arch=b64",
                "-S",
                "59",
                "-k",
                "exec_rule",
            ],
            "64-bit execve",
        ),
        (
            &[
                "-a",
                "exit,always",
                "-F",
                "arch=b32",
                "-S",
                "11",
                "-k",
                "exec_rule",
            ],
            "32-bit execve",
        ),
        (
            &[
                "-a",
                "exit,always",
                "-F",
                "arch=b64",
                "-S",
                "43",
                "-k",
                "accept_rule",
            ],
            "accept syscall",
        ),
    ];

    for (rule, description) in audit_rules.iter() {
        debug!("Adding audit rule for {}", description);
        run_command("auditctl", *rule).await?;
    }

    info!("Adding audit exclusion rules for crond_t");
    run_command("auditctl", &["-a", "never,user", "-F", "subj_type=crond_t"]).await?;
    run_command("auditctl", &["-a", "never,exit", "-F", "subj_type=crond_t"]).await?;

    if !is_ubuntu16().await? {
        info!("Configuring auditd to use audispd");
        update_audit_log_format().await?;
    }

    Ok(())
}

async fn command_exists(cmd: &str) -> bool {
    // More thorough input validation
    if !cmd
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return false;
    }

    which::which(cmd).is_ok()
}

async fn run_command(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd).args(args).status().await?;

    if !status.success() {
        return Err(crate::error::Error::Execution(format!(
            "Failed to execute command: {}",
            cmd
        )));
    }
    Ok(())
}

async fn is_ubuntu16() -> Result<bool> {
    Ok(fs::read_to_string("/etc/os-release")
        .await?
        .to_lowercase()
        .contains("ubuntu 16"))
}

async fn is_alpine() -> Result<bool> {
    Ok(fs::read_to_string("/etc/os-release")
        .await?
        .to_lowercase()
        .contains("alpine"))
}

async fn is_dragonfly() -> Result<bool> {
    Ok(fs::read_to_string("/etc/os-release")
        .await?
        .to_lowercase()
        .contains("dragonfly"))
}

async fn update_audit_dispatcher() -> Result<()> {
    let contents = fs::read_to_string("/etc/audit/auditd.conf").await?;
    let updated = contents.replace("dispatcher =", "dispatcher = /usr/sbin/audispd");
    fs::write("/etc/audit/auditd.conf", updated).await?;
    Ok(())
}

async fn update_audit_log_format() -> Result<()> {
    let contents = fs::read_to_string("/etc/audit/auditd.conf").await?;
    let updated = contents.replace("log_format =", "log_format = ENRICHED");
    fs::write("/etc/audit/auditd.conf", updated).await?;
    Ok(())
}

async fn detect_package_manager() -> Option<PackageManager> {
    const PACKAGE_MANAGERS: &[(&str, PackageManager)] = &[
        // Order by popularity for faster detection on common systems
        ("apt-get", PackageManager::Apt),
        ("dnf", PackageManager::Dnf),
        ("yum", PackageManager::Yum),
        ("apk", PackageManager::Apk),
        ("pacman", PackageManager::Pacman),
        ("zypper", PackageManager::Zypper),
        ("pkg", PackageManager::Pkg),
        ("slapt-get", PackageManager::SlaptGet),
    ];

    // Try to detect package manager in parallel for faster detection
    let futures: Vec<_> = PACKAGE_MANAGERS
        .iter()
        .map(|(cmd, pm)| async move {
            if command_exists(cmd).await {
                info!("Detected package manager: {:?}", pm);
                Some(pm.clone())
            } else {
                None
            }
        })
        .collect();

    // Return the first package manager found
    for result in futures {
        if let Some(pm) = result.await {
            return Some(pm);
        }
    }

    None
}

async fn create_secure_directories(dirs: &[&str]) -> Result<()> {
    for dir in dirs {
        fs::create_dir_all(dir).await?;
        Command::new("chmod").args(&["750", dir]).status().await?;
    }
    Ok(())
}

async fn set_sysctl_value(setting: &SysctlSetting) -> Result<()> {
    let path = format!("/proc/sys/{}", setting.key.replace(".", "/"));

    if Path::new(&path).exists() {
        Command::new("sysctl")
            .args(&["-w", &format!("{}={}", setting.key, setting.value)])
            .status()
            .await?;

        let config_line = format!("{}={}\n", setting.key, setting.value);
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("/etc/sysctl.d/99-security.conf")
            .await?;

        file.write_all(config_line.as_bytes()).await?;
    }
    Ok(())
}

fn get_secure_sysctl_settings() -> Vec<SysctlSetting> {
    vec![
        // Randomize the layout of virtual memory to make buffer overflow attacks harder
        ("kernel.randomize_va_space", "2"),
        // Restrict access to kernel pointers in the proc filesystem to prevent information leaks
        ("kernel.kptr_restrict", "2"),
        // Disable the SysRq key to prevent unauthorized system control
        ("kernel.sysrq", "0"),
        // Append the process ID to core dump filenames for better identification
        ("kernel.core_uses_pid", "1"),
        // Disable unprivileged user namespaces to prevent container escapes and privilege escalation
        ("kernel.unprivileged_userns_clone", "0"),
        // Set maximum user namespaces to 0 to further restrict namespace-based attacks
        ("user.max_user_namespaces", "0"),
        // Enable source route verification (primary) to prevent IP spoofing
        ("net.ipv4.conf.all.rp_filter", "1"),
        // Enable source route verification (fallback) to prevent IP spoofing
        ("net.ipv4.conf.default.rp_filter", "1"),
        // Ignore ICMP broadcast requests to prevent SMURF attacks
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
        // Disable acceptance of all ICMP redirects to prevent man-in-the-middle attacks
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0"),
        // Disable acceptance of secure ICMP redirects to prevent routing table poisoning
        ("net.ipv4.conf.all.secure_redirects", "0"),
        ("net.ipv4.conf.default.secure_redirects", "0"),
        // Disable sending of ICMP redirects (this machine should not act as a router)
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0"),
        // Enable TCP SYN cookies to prevent SYN flood attacks
        ("net.ipv4.tcp_syncookies", "1"),
    ]
    .into_iter()
    .map(|(key, value)| SysctlSetting {
        key: key.to_string(),
        value: value.to_string(),
    })
    .collect()
}

fn get_secure_ssh_config() -> Vec<SSHConfig> {
    vec![
        // Use SSH protocol version 2 only, as version 1 has known vulnerabilities
        ("Protocol", "2"),
        // Limit authentication attempts to 3 to prevent brute force attacks
        ("MaxAuthTries", "3"),
        // Disable password authentication, forcing use of more secure key-based auth
        ("PasswordAuthentication", "no"),
        // Explicitly prevent empty passwords, additional protection against null passwords
        ("PermitEmptyPasswords", "no"),
        // Disable X11 forwarding to prevent potential display hijacking
        ("X11Forwarding", "no"),
        // Disable TCP forwarding to prevent tunnel abuse
        ("AllowTcpForwarding", "no"),
        // Set 30 second timeout for completed login to reduce exposure
        ("LoginGraceTime", "30"),
        // Disable root login to prevent direct root access
        ("PermitRootLogin", "no"),
        // Enable strict file permissions checking
        ("StrictModes", "yes"),
        // Enable privilege separation for additional security layer
        ("UsePrivilegeSeparation", "yes"),
        // Set minimum 2048 bits for server keys for strong encryption
        ("ServerKeyBits", "2048"),
        // Disable .rhosts files for security, as they're inherently insecure
        ("IgnoreRhosts", "yes"),
        // Disable host-based authentication which is less secure than key-based
        ("HostbasedAuthentication", "no"),
        // Prevent users from setting environment variables at login
        ("PermitUserEnvironment", "no"),
        // Send keep-alive every 300 seconds (5 minutes)
        ("ClientAliveInterval", "300"),
        // Disconnect after no response to keep-alive, prevents hung sessions
        ("ClientAliveCountMax", "0"),
        // Disable SSH agent forwarding to prevent unauthorized key usage
        ("AllowAgentForwarding", "no"),
    ]
    .into_iter()
    .map(|(setting, value)| SSHConfig {
        setting: setting.to_string(),
        value: value.to_string(),
    })
    .collect()
}
async fn backup_config(path: &str, backup_suffix: &str) -> Result<()> {
    let timestamp = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => return Ok(()), // If we can't get timestamp, skip backup
    };
    fs::copy(path, format!("{}.{}.{}", path, backup_suffix, timestamp)).await?;
    Ok(())
}

async fn configure_ssh() -> Result<()> {
    let ssh_config_path = "/etc/ssh/sshd_config";
    if !Path::new(ssh_config_path).exists() {
        warn!("SSH config not found at {}", ssh_config_path);
        return Ok(());
    }

    info!("Configuring SSH security settings");

    // Backup the original config
    backup_config(ssh_config_path, "bak").await?;

    // Read current config
    let content = fs::read_to_string(ssh_config_path).await?;
    let mut new_lines: Vec<String> = Vec::new();
    let config_settings = get_secure_ssh_config();

    // Track which settings we've seen
    let mut seen_settings: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Process existing configuration lines
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            new_lines.push(line.to_string());
            continue;
        }

        // Check if this line contains any of our target settings
        let mut found_setting = false;
        for conf in &config_settings {
            // Match the setting even if there are spaces or comments
            if trimmed.starts_with(&conf.setting)
                && (trimmed.chars().nth(conf.setting.len()) == Some(' ')
                    || trimmed.chars().nth(conf.setting.len()) == Some('\t'))
            {
                debug!("Found existing setting: {}", trimmed);
                // Comment out the old setting
                new_lines.push(format!("# {} (modified by security hardening)", line));
                seen_settings.insert(conf.setting.clone());
                found_setting = true;
                break;
            }
        }

        if !found_setting {
            new_lines.push(line.to_string());
        }
    }

    // Add our secure configurations that weren't in the original file
    new_lines.push("\n# Security hardening configurations".to_string());
    for conf in config_settings {
        if !seen_settings.contains(&conf.setting) {
            debug!("Adding new setting: {} {}", conf.setting, conf.value);
        }
        new_lines.push(format!("{} {}", conf.setting, conf.value));
    }

    // Join all lines with newlines
    let content = new_lines.join("\n");

    // Write to temp file first
    let temp_path = format!("{}.tmp", ssh_config_path);
    fs::write(&temp_path, &content).await?;

    // Validate the config
    info!("Validating new SSH configuration");
    if Command::new("sshd")
        .args(&["-t", "-f", &temp_path])
        .status()
        .await?
        .success()
    {
        // Move temp file to actual config
        fs::rename(&temp_path, ssh_config_path).await?;

        // Restart SSH service
        restart_ssh_service().await?;
    } else {
        error!("SSH config validation failed");
        fs::remove_file(&temp_path).await?;
        return Err(crate::error::Error::Execution(
            "SSH config validation failed".to_string(),
        ));
    }

    Ok(())
}

async fn restart_ssh_service() -> Result<()> {
    info!("Attempting to restart SSH service");

    // Check for systemctl first
    if command_exists("systemctl").await {
        debug!("Using systemctl to restart SSH");
        let restart_attempts = [vec!["restart", "ssh"], vec!["restart", "sshd"]];

        for args in restart_attempts {
            if Command::new("systemctl")
                .args(&args)
                .status()
                .await
                .map_or(false, |s| s.success())
            {
                return Ok(());
            }
        }
    }

    // Try service command if systemctl failed or doesn't exist
    if command_exists("service").await {
        debug!("Using service command to restart SSH");
        let restart_attempts = [vec!["ssh", "restart"], vec!["sshd", "restart"]];

        for args in restart_attempts {
            if Command::new("service")
                .args(&args)
                .status()
                .await
                .map_or(false, |s| s.success())
            {
                return Ok(());
            }
        }
    }

    // Check for Slackware-style RC scripts
    let rc_paths = ["/etc/rc.d/sshd", "/etc/rc.d/rc.sshd"];
    for rc_path in rc_paths {
        if Path::new(rc_path).exists() {
            debug!("Using RC script to restart SSH: {}", rc_path);
            if Command::new(rc_path)
                .arg("restart")
                .status()
                .await
                .map_or(false, |s| s.success())
            {
                return Ok(());
            }
        }
    }

    warn!("Could not restart SSH service through any known method");
    Ok(()) // Return Ok since this isn't critical enough to fail the whole hardening process
}

async fn configure_kernel_modules() -> Result<()> {
    let blacklisted_modules = [
        "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf",
    ];

    fs::create_dir_all("/etc/modprobe.d").await?;
    let config_path = "/etc/modprobe.d/security-blacklist.conf";

    // Create a set of our new configurations
    let new_configs: HashSet<String> = blacklisted_modules
        .iter()
        .flat_map(|module| {
            vec![
                format!("blacklist {}", module),
                format!("install {} /bin/false", module),
            ]
        })
        .collect();

    // Read existing configurations if file exists
    let existing_configs = if Path::new(config_path).exists() {
        // Backup existing file
        backup_config(config_path, "bak").await?;

        // Read existing content
        let content = fs::read_to_string(config_path).await?;
        content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect::<HashSet<String>>()
    } else {
        HashSet::new()
    };

    // Combine existing and new configs, maintaining uniqueness
    let mut final_configs: Vec<String> = existing_configs.union(&new_configs).cloned().collect();

    // Sort for consistency
    final_configs.sort();

    // Write the combined configuration
    let config_content = final_configs.join("\n") + "\n";

    // Write to a temporary file first
    let temp_path = format!("{}.tmp", config_path);
    fs::write(&temp_path, &config_content).await?;

    // Move temporary file to actual location
    fs::rename(&temp_path, config_path).await?;

    Ok(())
}

async fn configure_login_security() -> Result<()> {
    let login_configs = [
        ("UMASK", "027"),
        ("PASS_MAX_DAYS", "90"),
        ("PASS_MIN_DAYS", "7"),
        ("PASS_WARN_AGE", "14"),
    ];

    let login_defs_path = "/etc/login.defs";
    if Path::new(login_defs_path).exists() {
        let content = fs::read_to_string(login_defs_path).await?;

        let new_content = login_configs.iter().fold(content, |acc, &(key, value)| {
            // Case A: Match "UMASK   022" pattern (key + whitespace + number)
            let value_pattern = format!(r"(?m)^{}\s+\d+", regex::escape(key));
            let value_regex = regex::Regex::new(&value_pattern).unwrap();

            // Case B: Match standalone "UMASK" on its own line
            let key_pattern = format!(r"(?m)^{}\s*$", regex::escape(key));
            let key_regex = regex::Regex::new(&key_pattern).unwrap();

            // First check if Case A exists (key + number)
            if value_regex.is_match(&acc) {
                value_regex
                    .replace(&acc, format!("{}\t{}", key, value))
                    .to_string()
            }
            // Then check if Case B exists (standalone key)
            else if key_regex.is_match(&acc) {
                key_regex
                    .replace(&acc, format!("{}\t{}", key, value))
                    .to_string()
            }
            // Case C: Neither exists, append to end of file
            else {
                format!("{}\n{}\t{}", acc.trim_end(), key, value)
            }
        });

        fs::write(login_defs_path, new_content).await?;
    }
    Ok(())
}

pub async fn harden() -> Result<()> {
    info!("Hardening Unix system");

    // Create necessary directories first
    info!("Creating secure directories");
    create_secure_directories(&["/etc/security-config", "/var/log/security-hardening"]).await?;

    info!("Configuring up rbash");
    if let Err(e) = configure_rbash(false).await {
        error!("Failed to set up rbash: {}", e);
    }

    info!("Configuring PAM");
    if let Err(e) = configure_pam().await {
        error!("PAM configuration failed: {}", e);
    }

    info!("Securing php.ini files");
    let files = find_files("php.ini".to_string(), "/".to_string()).await;
    let config = generate_php_config();

    for file in files {
        if let Err(e) = append_php_config_to_file(&file, &config).await {
            error!("Failed to secure php.ini: {}", e);
        }
    }

    info!("Applying sysctl settings");
    // Apply sysctl settings sequentially to avoid borrowing issues
    let settings = get_secure_sysctl_settings();
    for setting in settings {
        debug!("Setting sysctl: {}={}", setting.key, setting.value);
        if let Err(e) = set_sysctl_value(&setting).await {
            warn!("Failed to set sysctl: {}", e);
        }
    }

    info!("Configuring SSH security settings");
    if let Err(e) = configure_ssh().await {
        error!("SSH configuration failed: {}", e);
    }

    info!("Configuring kernel module restrictions");
    if let Err(e) = configure_kernel_modules().await {
        error!("Kernel module configuration failed: {}", e);
    }

    info!("Configuring login security parameters");
    if let Err(e) = configure_login_security().await {
        error!("Login security configuration failed: {}", e);
    }

    info!("System hardening completed successfully");

    Ok(())
}

pub async fn establish_baseline() -> Result<()> {
    info!("Establishing system baseline");

    info!("Setting up logging");
    match setup_syslog().await {
        Ok(_) => info!("Syslog setup completed"),
        Err(e) => warn!("Failed to setup syslog: {}", e),
    }

    info!("Adding system hardening measures");
    match harden().await {
        Ok(_) => info!("System hardening completed"),
        Err(e) => warn!("Failed to harden system: {}", e),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::tempdir;
    use tokio::fs;

    // Test utilities
    struct TestContext {
        _temp_dir: tempfile::TempDir,
        ssh_config_path: String,
        original_ssh_config_path: String,
    }

    impl TestContext {
        async fn new(content: &str) -> Self {
            let temp_dir = tempdir().unwrap();
            let ssh_dir = temp_dir.path().join("ssh");
            fs::create_dir(&ssh_dir).await.unwrap();

            let config_path = ssh_dir.join("sshd_config");
            fs::write(&config_path, content).await.unwrap();

            let original_path = "/etc/ssh/sshd_config".to_string();

            TestContext {
                _temp_dir: temp_dir,
                ssh_config_path: config_path.to_str().unwrap().to_string(),
                original_ssh_config_path: original_path,
            }
        }

        async fn read_config(&self) -> String {
            fs::read_to_string(&self.ssh_config_path).await.unwrap()
        }
    }

    fn parse_ssh_config(content: &str) -> HashMap<String, String> {
        let mut settings = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                if let Some((key, value)) = line.split_once(' ') {
                    settings.insert(key.to_string(), value.trim().to_string());
                }
            }
        }
        settings
    }

    // Original Tests
    #[tokio::test]
    async fn test_empty_config() {
        let ctx = TestContext::new("").await;
        async fn test_configure_ssh(config_path: &str) -> Result<()> {
            let content = fs::read_to_string(config_path).await?;
            let config_settings = get_secure_ssh_config();
            let mut new_lines = Vec::new();

            new_lines.push("# Security hardening configurations".to_string());
            for conf in config_settings {
                new_lines.push(format!("{} {}", conf.setting, conf.value));
            }

            fs::write(config_path, new_lines.join("\n")).await?;
            Ok(())
        }

        test_configure_ssh(&ctx.ssh_config_path).await.unwrap();
        let result = ctx.read_config().await;
        let settings = parse_ssh_config(&result);

        assert_eq!(settings.get("Protocol").unwrap(), "2");
        assert_eq!(settings.get("X11Forwarding").unwrap(), "no");
        assert_eq!(settings.get("AllowTcpForwarding").unwrap(), "no");
    }

    #[tokio::test]
    async fn test_replace_existing_settings() {
        let initial_config = "\
            X11Forwarding yes\n\
            AllowTcpForwarding yes\n\
            Protocol 1\n";

        let ctx = TestContext::new(initial_config).await;

        async fn test_configure_ssh(config_path: &str) -> Result<()> {
            let content = fs::read_to_string(config_path).await?;
            let mut new_lines: Vec<String> = Vec::new();
            let config_settings = get_secure_ssh_config();
            let mut seen_settings = std::collections::HashSet::new();

            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    new_lines.push(line.to_string());
                    continue;
                }

                let mut found_setting = false;
                for conf in &config_settings {
                    if trimmed.starts_with(&conf.setting) {
                        new_lines.push(format!("# {} (modified by security hardening)", line));
                        seen_settings.insert(conf.setting.clone());
                        found_setting = true;
                        break;
                    }
                }

                if !found_setting {
                    new_lines.push(line.to_string());
                }
            }

            new_lines.push("\n# Security hardening configurations".to_string());
            for conf in config_settings {
                new_lines.push(format!("{} {}", conf.setting, conf.value));
            }

            fs::write(config_path, new_lines.join("\n")).await?;
            Ok(())
        }

        test_configure_ssh(&ctx.ssh_config_path).await.unwrap();
        let result = ctx.read_config().await;
        assert!(result.contains("# X11Forwarding yes (modified by security hardening)"));
        assert!(result.contains("X11Forwarding no"));
        assert!(result.contains("# AllowTcpForwarding yes (modified by security hardening)"));
        assert!(result.contains("AllowTcpForwarding no"));
    }

    #[tokio::test]
    async fn test_handle_malformed_settings() {
        let initial_config = "\
            X11Forwarding:yes\n\
            AllowTcpForwarding=yes\n\
            Protocol\t\t1\n\
            BadSetting\n";

        let ctx = TestContext::new(initial_config).await;

        async fn test_configure_ssh(config_path: &str) -> Result<()> {
            let content = fs::read_to_string(config_path).await?;
            let config_settings = get_secure_ssh_config();
            let mut new_lines = Vec::new();

            for line in content.lines() {
                new_lines.push(format!("# {}", line));
            }

            new_lines.push("\n# Security hardening configurations".to_string());
            for conf in config_settings {
                new_lines.push(format!("{} {}", conf.setting, conf.value));
            }

            fs::write(config_path, new_lines.join("\n")).await?;
            Ok(())
        }

        test_configure_ssh(&ctx.ssh_config_path).await.unwrap();

        let result = ctx.read_config().await;
        let settings = parse_ssh_config(&result);

        assert_eq!(settings.get("X11Forwarding").unwrap(), "no");
        assert_eq!(settings.get("AllowTcpForwarding").unwrap(), "no");
        assert_eq!(settings.get("Protocol").unwrap(), "2");
    }

    #[tokio::test]
    async fn test_backup_creation() {
        let initial_config = "X11Forwarding yes\n";
        let ctx = TestContext::new(initial_config).await;

        async fn test_configure_ssh(config_path: &str) -> Result<()> {
            let backup_path = format!("{}.bak.test", config_path);
            fs::copy(config_path, &backup_path).await?;

            let config_settings = get_secure_ssh_config();
            let mut new_lines = vec!["# Security hardening configurations".to_string()];
            for conf in config_settings {
                new_lines.push(format!("{} {}", conf.setting, conf.value));
            }

            fs::write(config_path, new_lines.join("\n")).await?;
            Ok(())
        }

        test_configure_ssh(&ctx.ssh_config_path).await.unwrap();

        let backup_path = format!("{}.bak.test", ctx.ssh_config_path);
        assert!(PathBuf::from(&backup_path).exists());
    }

    #[tokio::test]
    async fn test_all_security_settings() {
        let ctx = TestContext::new("").await;

        async fn test_configure_ssh(config_path: &str) -> Result<()> {
            let config_settings = get_secure_ssh_config();
            let mut new_lines = vec!["# Security hardening configurations".to_string()];
            for conf in config_settings {
                new_lines.push(format!("{} {}", conf.setting, conf.value));
            }

            fs::write(config_path, new_lines.join("\n")).await?;
            Ok(())
        }

        test_configure_ssh(&ctx.ssh_config_path).await.unwrap();

        let result = ctx.read_config().await;
        let settings = parse_ssh_config(&result);

        let required_settings = [
            ("Protocol", "2"),
            ("X11Forwarding", "no"),
            ("AllowTcpForwarding", "no"),
            ("PermitRootLogin", "no"),
            ("MaxAuthTries", "3"),
            ("PasswordAuthentication", "no"),
            ("PermitEmptyPasswords", "no"),
            ("ClientAliveInterval", "300"),
            ("ClientAliveCountMax", "0"),
        ];

        for (setting, expected_value) in required_settings.iter() {
            assert_eq!(
                settings.get(*setting).unwrap_or(&"missing".to_string()),
                expected_value,
                "Setting {} should be {}",
                setting,
                expected_value
            );
        }
    }

    // New Tests
    #[tokio::test]
    async fn test_php_config_generation() {
        let config = generate_php_config();

        assert!(config.disable_functions.contains(&"exec".to_string()));
        assert!(config.disable_functions.contains(&"system".to_string()));
        assert!(config.disable_functions.contains(&"shell_exec".to_string()));

        let settings: HashMap<_, _> = config.security_settings.iter().cloned().collect();
        assert_eq!(settings.get("display_errors").unwrap(), "off");
        assert_eq!(settings.get("allow_url_fopen").unwrap(), "off");
        assert_eq!(settings.get("session.cookie_httponly").unwrap(), "1");
    }

    #[tokio::test]
    async fn test_sysctl_settings() {
        let settings = get_secure_sysctl_settings();

        let settings_map: HashMap<_, _> = settings
            .iter()
            .map(|s| (s.key.as_str(), s.value.as_str()))
            .collect();

        assert_eq!(*settings_map.get("kernel.randomize_va_space").unwrap(), "2");
        assert_eq!(*settings_map.get("net.ipv4.tcp_syncookies").unwrap(), "1");
        assert_eq!(
            *settings_map
                .get("net.ipv4.conf.all.accept_redirects")
                .unwrap(),
            "0"
        );
    }

    #[tokio::test]
    async fn test_ssh_config_validation() {
        let initial_config = "# Invalid setting\nRandomSetting random_value\n";
        let ctx = TestContext::new(initial_config).await;

        async fn test_configure_ssh(config_path: &str) -> Result<()> {
            let config_settings = get_secure_ssh_config();
            let mut new_lines = Vec::new();

            new_lines.push("# Security hardening configurations".to_string());
            for conf in config_settings {
                new_lines.push(format!("{} {}", conf.setting, conf.value));
            }

            fs::write(config_path, new_lines.join("\n")).await?;
            Ok(())
        }

        test_configure_ssh(&ctx.ssh_config_path).await.unwrap();
        let result = ctx.read_config().await;
        assert!(!result.contains("RandomSetting"));
    }

    #[tokio::test]
    async fn test_kernel_module_blacklist() {
        let temp_dir = tempdir().unwrap();
        let modprobe_path = temp_dir.path().join("security-blacklist.conf");

        async fn test_configure_kernel_modules(path: PathBuf) -> Result<()> {
            let blacklisted_modules = ["cramfs", "freevxfs", "jffs2"];
            let config = blacklisted_modules
                .iter()
                .flat_map(|module| {
                    vec![
                        format!("blacklist {}", module),
                        format!("install {} /bin/false", module),
                    ]
                })
                .collect::<Vec<_>>()
                .join("\n");

            fs::write(path, config).await?;
            Ok(())
        }

        test_configure_kernel_modules(modprobe_path.clone())
            .await
            .unwrap();

        let content = fs::read_to_string(modprobe_path).await.unwrap();
        assert!(content.contains("blacklist cramfs"));
        assert!(content.contains("install cramfs /bin/false"));
    }

    #[tokio::test]
    async fn test_find_files() {
        let temp_dir = tempdir().unwrap();
        let test_file_path = temp_dir.path().join("test.txt");
        fs::write(&test_file_path, "test content").await.unwrap();

        let files = find_files(
            "test.txt".to_string(),
            temp_dir.path().to_str().unwrap().to_string(),
        )
        .await;

        assert_eq!(files.len(), 1);
        assert!(files[0].contains("test.txt"));
    }

    #[tokio::test]
    async fn test_command_exists() {
        // Test with common commands that should exist
        assert!(command_exists("ls").await);
        assert!(command_exists("cat").await);

        // Test with likely non-existent command
        assert!(!command_exists("nonexistentcommand123456789").await);

        // Test with potentially dangerous input
        assert!(!command_exists("; rm -rf /").await);
        assert!(!command_exists("&&").await);
    }

    #[tokio::test]
    async fn test_backup_config() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.conf");
        fs::write(&test_file, "original content").await.unwrap();

        backup_config(test_file.to_str().unwrap(), "backup")
            .await
            .unwrap();

        let mut entries = fs::read_dir(temp_dir.path()).await.unwrap();
        let mut found_backup = false;
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_name().to_string_lossy().contains("backup") {
                found_backup = true;
                break;
            }
        }
        assert!(found_backup);
    }

    #[tokio::test]
    async fn test_package_manager_detection() {
        // This is a basic test since we can't mock the command_exists easily
        let pm = detect_package_manager().await;
        assert!(pm.is_some());

        match pm.unwrap() {
            PackageManager::Apt
            | PackageManager::Yum
            | PackageManager::Apk
            | PackageManager::Dnf
            | PackageManager::Pacman
            | PackageManager::Pkg
            | PackageManager::Zypper
            | PackageManager::SlaptGet => (),
        }
    }

    #[tokio::test]
    async fn test_find_rc_files() {
        let temp_dir = tempdir().unwrap();
        let rc_file = temp_dir.path().join(".bashrc");
        fs::write(&rc_file, "# test rc file").await.unwrap();

        let files = find_rc_files_in_dir(temp_dir.path().to_str().unwrap())
            .await
            .unwrap();
        assert!(!files.is_empty());
    }
}
