use async_trait::async_trait;

#[async_trait]
pub trait Session: Send + Sync {
    async fn close(&self) -> Result<(), std::io::Error>;

    async fn execute_command(&self, command: &str) -> Result<Option<String>, std::io::Error>;
}

pub struct Credentials<'a> {
    pub username: &'a str,
    pub password: Option<String>,
    pub key: Option<bool>,
}
