mod platform;

use super::ModeExecutor;
use crate::error::Result;
use crate::types::{ExecutionMode, ExecutionResult};
use include_crypt::{include_crypt, EncryptedFile};
use local_ip_address::local_ip;
use log::{debug, error};
use std::net::IpAddr;

const PASSWORD_SCHEMA: EncryptedFile = include_crypt!(".password");

const PRIVILEGED_USER: &str = match cfg!(target_os = "windows") {
    true => "Administrator",
    false => "root",
};

pub struct Magic(pub u32);

pub struct CredentialsMode;

impl ModeExecutor for CredentialsMode {
    type Args = Magic;
    type ArgRequirement = super::Required; // This executor requires args

    async fn execute(&self, args: Self::Args) -> ExecutionResult {
        debug!("Managing system credentials...");

        match PASSWORD_SCHEMA.decrypt_str() {
            Ok(mut password) => {
                password = password.trim().replace("\r", "").replace("\n", "");

                let ip = match local_ip() {
                    Ok(ip) => ip,
                    Err(e) => {
                        return ExecutionResult::new(
                            ExecutionMode::Credentials,
                            false,
                            format!("Failed to get local IP address: {e}"),
                        );
                    }
                };

                let last_octet = match ip {
                    IpAddr::V4(ip) => {
                        let octets = ip.octets();
                        octets[3]
                    }
                    _ => {
                        return ExecutionResult::new(
                            ExecutionMode::Credentials,
                            false,
                            "IPv6 is not supported".to_string(),
                        );
                    }
                } as u32;

                let magic = args.0;

                password = format!("{}{}", password, last_octet * magic);

                if let Err(e) = platform::change_password(PRIVILEGED_USER, password.as_mut_str()) {
                    error!("Failed to change password: {}", e);
                    return ExecutionResult::new(
                        ExecutionMode::Credentials,
                        false,
                        format!("Password change failed: {}", e),
                    );
                }

                ExecutionResult::new(
                    ExecutionMode::Credentials,
                    true,
                    "Credentials managed successfully".to_string(),
                )
            }
            Err(e) => {
                error!("Failed to decrypt password: {}", e);
                ExecutionResult::new(
                    ExecutionMode::Credentials,
                    false,
                    "Failed to decrypt password schema".to_string(),
                )
            }
        }
    }
}

impl CredentialsMode {
    pub fn new() -> Self {
        Self
    }

    async fn manage_credentials(&self) -> Result<()> {
        self.change_default_passwords().await?;
        self.create_admin_accounts().await?;
        self.disable_unused_accounts().await?;
        Ok(())
    }

    async fn change_default_passwords(&self) -> Result<()> {
        todo!("Implement password changes")
    }

    async fn create_admin_accounts(&self) -> Result<()> {
        todo!("Implement admin account creation")
    }

    async fn disable_unused_accounts(&self) -> Result<()> {
        todo!("Implement account disable")
    }
}
