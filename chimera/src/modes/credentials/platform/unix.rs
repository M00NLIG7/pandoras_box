use std::process::{Command, Stdio};
use std::io::Write;
use zeroize::Zeroize;
use crate::error::Error;
use crate::error::Result;

pub fn change_password(username: &str, new_password: &mut str) -> Result<()> {
    if username.is_empty() || new_password.is_empty() {
        let err = Error::PasswordChange("Username and password cannot be empty".into());
        err.log();
        return Err(err);
    }

    // Check if Kerberos is configured by checking for krb5.conf
    if std::path::Path::new("/etc/krb5.conf").exists() {
        log::warn!("Kerberos configuration detected, password change may fail");
    }

    // Try chpasswd first (works without prompting, requires root)
    let chpasswd_result = Command::new("chpasswd")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    if let Ok(mut child) = chpasswd_result {
        if let Some(mut stdin) = child.stdin.take() {
            // chpasswd format: username:password
            let _ = stdin.write_all(format!("{}:{}\n", username, new_password).as_bytes());
        }

        match child.wait() {
            Ok(status) if status.success() => {
                new_password.zeroize();
                log::info!("Successfully changed password for user: {} using chpasswd", username);
                return Ok(());
            }
            _ => {
                log::debug!("chpasswd failed, falling back to passwd command");
            }
        }
    }

    // Fallback to passwd command (interactive)
    let mut child = Command::new("passwd")
        .arg(username)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        // Some systems ask for old password (current user), some don't (root changing others)
        // Send password 3 times to cover all cases: old (if asked), new, confirm
        let _ = stdin.write_all(format!("{}\n{}\n{}\n", new_password, new_password, new_password).as_bytes());
    }

    let output = child.wait_with_output()?;
    let combined_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    new_password.zeroize();

    if output.status.success() {
        log::info!("Successfully changed password for user: {}", username);
        Ok(())
    } else {
        let err = if combined_output.to_lowercase().contains("kerberos") {
            Error::PasswordChange("Cannot change Kerberos-linked passwords".into())
        } else {
            Error::PasswordChange(format!("Password change failed: {}", combined_output))
        };
        err.log();
        Err(err)
    }
}
