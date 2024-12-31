mod platform;

use super::ModeExecutor;
use crate::error::Result;
use crate::types::{ExecutionMode, ExecutionResult};
use include_crypt::{include_crypt, EncryptedFile};
use log::{debug, error, info};

const PASSWORD_SCHEMA: EncryptedFile = include_crypt!(".password");

pub struct CredentialsMode;

impl ModeExecutor for CredentialsMode {
    async fn execute(&self) -> ExecutionResult {
        debug!("Managing system credentials...");
        
        match PASSWORD_SCHEMA.decrypt_str() {
            Ok(mut password) => {
                if let Err(e) = platform::change_password("testuser", password.as_mut_str()) {
                    error!("Failed to change password: {}", e);
                    return ExecutionResult::new(
                        ExecutionMode::Credentials,
                        false,
                        format!("Password change failed: {}", e)
                    );
                }
                
                ExecutionResult::new(
                    ExecutionMode::Credentials,
                    true,
                    "Credentials managed successfully".to_string()
                )
            }
            Err(e) => {
                error!("Failed to decrypt password: {}", e);
                ExecutionResult::new(
                    ExecutionMode::Credentials,
                    false,
                    "Failed to decrypt password schema".to_string()
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
