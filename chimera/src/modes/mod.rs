pub mod inventory;
pub mod credentials;

use crate::error::{Result, Error};

use crate::types::{ExecutionMode, ExecutionResult};
use log::{debug, error, info};

pub trait ModeExecutor {
    async fn execute(&self) -> ExecutionResult;
}

