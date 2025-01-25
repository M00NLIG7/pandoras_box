use std::process::{Command, Stdio};
use std::io::Write;
use zeroize::Zeroize;
use crate::error::Error;
use crate::error::Result;

pub fn change_password(username: &str, new_password: &mut str) -> Result<()> {
    log::info!("Password changing to {} for user: {}", new_password, username);

    if username.is_empty() || new_password.is_empty() {
        let err = Error::PasswordChange("Username and password cannot be empty".into());
        err.log();
        return Err(err);
    }

    // Quick check for Kerberos using .output() which won't hang
    let output = Command::new("passwd")
        .arg(username)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    let combined_output = format!(
        "{}{}", 
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ).to_lowercase();
    
    if combined_output.contains("kerberos") {
        let err = Error::PasswordChange("Cannot change Kerberos-linked passwords".into());
        err.log();
        println!("Error: {:?}", err);
        return Err(err);
    }

    // Regular password change
    let mut child = Command::new("passwd")
        .arg(username)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(format!("{}\n{}\n", new_password, new_password).as_bytes())?;
    }

    let status = child.wait()?;
    new_password.zeroize();

    if !status.success() {
        let err = Error::PasswordChange("Password change failed".into());
        err.log();
        println!("Error: {:?}", err);
        Err(err)
    } else {
        log::info!("Successfully changed password for user: {}", username);
        Ok(())
    }
}
