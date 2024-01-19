use async_trait::async_trait;

#[async_trait]
pub trait Session: Send + Sync {
    async fn close(&self) -> Result<(), std::io::Error>;

    async fn transfer_file(&self, local_path: &str, remote_path: &str) -> anyhow::Result<()>; 

    fn get_ip(&self) -> &Box<str>;

    async fn execute_command(&self, command: &str) -> Result<Option<String>, std::io::Error>;
}

#[derive(Clone, Debug)]
pub struct Credentials {
    pub username: Box<str>,
    pub password: Option<String>,
    pub key: Option<bool>,
}
