use super::communicator::{Credentials, Session};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use russh::*;
use russh_keys::*;
use russh_sftp::client::SftpSession;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::ToSocketAddrs;
use tokio::sync::Mutex;

// Simplified SSH Handler

#[async_trait]
impl client::Handler for SSHHandler {
    type Error = russh::Error;

    async fn check_server_key(
        self,
        _server_public_key: &key::PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        Ok((self, true))
    }

    async fn data(
        self,
        channel: ChannelId,
        data: &[u8],
        session: client::Session,
    ) -> Result<(Self, client::Session), Self::Error> {
        Ok((self, session))
    }
}

struct SSHHandler {}

// SSH Session struct
pub struct SSHSession {
    session: Arc<tokio::sync::Mutex<russh::client::Handle<SSHHandler>>>,
    key: Option<String>,
    creds: Credentials,
    ip: Box<str>,
    port: Box<str>,
    retry_count: Arc<tokio::sync::Mutex<u32>>,
}

impl SSHSession {
    async fn establish_connection(
        addr: impl tokio::net::ToSocketAddrs,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<client::Handle<SSHHandler>, russh::Error> {
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..<_>::default()
        };

        let sh = SSHHandler {};

        let config = Arc::new(config);

        let mut session = client::connect(config, addr, sh).await?;
        let auth_res = session.authenticate_password(user, password).await;

        let _auth_res = auth_res?;

        Ok(session)
    }

    async fn try_call(&self, command: &str) -> Result<CommandResult, russh::Error> {
        let session = self.session.lock().await;
        let mut channel = session.channel_open_session().await?;

        channel.exec(true, command).await?;

        let mut output = Vec::new();
        let mut code = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    output.write_all(data).await?;
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                }
                _ => {}
            }
        }

        Ok(CommandResult { output, code })
    }

    async fn call(&self, command: &str) -> Result<CommandResult> {
        loop {
            let result = self.try_call(command).await;

            match result {
                Ok(command_result) => return Ok(command_result),
                Err(e) => {
                    println!("Error during SSH call: {:?}", e);

                    let mut retry_count = self.retry_count.lock().await;
                    if *retry_count >= 5 {
                        // If retry count is 5 or more, return the error without retrying
                        return Err(e.into());
                    }

                    // Increment the retry counter
                    *retry_count += 1;

                    // Attempt to reconnect
                    if let Err(reconnect_error) = self.reconnect().await {
                        println!("Reconnect failed: {:?}", reconnect_error);
                        // If reconnect fails, return the original error
                        return Err(e.into());
                    }
                    // If reconnect succeeds, loop will retry the command
                }
            }
        }
    }

    async fn reconnect(&self) -> Result<(), russh::Error> {
        // Re-establish the connection
        let new_session = SSHSession::establish_connection(
            format!("{}:{}", self.ip, self.port),
            &self.creds.username.to_string(),
            &self
                .creds
                .password
                .clone()
                .expect("No password supplied")
                .to_string(),
        )
        .await?;

        // Update the session in your SSHSession struct
        let mut session_guard = self.session.lock().await;
        *session_guard = new_session;

        Ok(())
    }

    pub async fn transfer_file(&self, local_path: &str, remote_path: &str) -> anyhow::Result<()> {
        let session = self.session.lock().await;
        let channel = session.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await;

        match sftp {
            Ok(sftp) => {
                let mut file = sftp.create(remote_path).await?;

                let mut local_file = tokio::fs::File::open(local_path).await?;

                // Read the file into a buffer then write it to the remote file using write_all
                let mut buffer = Vec::new();

                local_file.read_to_end(&mut buffer).await?;

                file.write_all(&buffer).await?;
                file.shutdown().await?;

                Ok(())
            }
            _ => return Err(anyhow!("Error creating SFTP session")),
        }
    }
}

#[derive(Clone)]
pub struct SSHClient {
    ip: Option<String>,
    port: Option<String>,
    key: Option<String>,
}

impl SSHClient {
    pub fn new() -> Self {
        Self {
            ip: None,
            port: Some("22".to_string()),
            key: None,
        }
    }

    pub fn ip(&mut self, ip: &str) -> &mut Self {
        self.ip = Some(ip.to_string());
        self
    }

    pub fn port(&mut self, port: &str) -> &mut Self {
        self.port = Some(port.to_string());
        self
    }

    pub fn key(&mut self, key: &str) -> &mut Self {
        self.key = Some(key.to_string());
        self
    }

    pub async fn connect(
        &self,
        creds: &Credentials,
    ) -> Result<SSHSession, Box<dyn std::error::Error>> {
        if self.ip.is_none() {
            return Err("Please configure ip()".into());
        }

        let addr = format!(
            "{}:{}",
            self.ip.clone().unwrap_or_default(),
            self.port.clone().unwrap_or_default()
        );

        let session = SSHSession::establish_connection(
            addr,
            creds.username.clone(),
            creds.password.clone().unwrap_or_default(),
        )
        .await?;

        Ok(SSHSession {
            key: self.key.clone(),
            session: Arc::new(Mutex::new(session)),
            creds: creds.clone(),
            ip: self.ip.clone().unwrap().into_boxed_str(),
            port: self.port.clone().unwrap().into_boxed_str(),
            retry_count: Arc::new(Mutex::new(0)),
        })
    }
}

struct CommandResult {
    output: Vec<u8>,
    code: Option<u32>,
}

impl CommandResult {
    fn output(&self) -> String {
        String::from_utf8_lossy(&self.output).into()
    }

    fn success(&self) -> bool {
        self.code == Some(0)
    }
}

#[async_trait]
impl Session for SSHSession {
    async fn execute_command(&self, command: &str) -> Result<Option<String>, std::io::Error> {
        match self.call(command).await {
            Ok(r) => {
                println!("{}: {}", r.success(), r.output());
                Ok(Some(r.output()))
            }
            Err(e) => {
                println!("Error executing command: {:?}", e);
                Err(std::io::Error::new(std::io::ErrorKind::Other, e))
            }
        }
    }

    // Close the session
    async fn close(&self) -> Result<(), std::io::Error> {
        let session = self.session.lock().await;
        match session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
        {
            Ok(_) => {}
            Err(e) => {
                println!("Error closing SSH session: {:?}", e)
            }
        };

        Ok(())
    }
}
