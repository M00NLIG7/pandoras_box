pub mod ssh;

use std::path::PathBuf;

use async_trait::async_trait;

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub command: String,
}

impl ExecRequest {
    #[must_use]
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResponse {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status_code: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTransfer {
    pub local_path: PathBuf,
    pub remote_path: String,
}

#[async_trait]
pub trait HostSession: Send {
    async fn exec(&mut self, request: ExecRequest) -> Result<ExecResponse>;
    async fn put(&mut self, transfer: &FileTransfer) -> Result<()>;
    async fn get(&mut self, transfer: &FileTransfer) -> Result<()>;
    async fn ensure_dir(&mut self, remote_dir: &str) -> Result<()>;
    async fn cleanup(&mut self) -> Result<()>;
}
