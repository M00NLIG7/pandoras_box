use crate::net::communicator::{Credentials, Session};
use anyhow::Result;
use async_trait::async_trait;
use std::io::Write;
use std::sync::Arc;
use thrussh::*;
use thrussh_keys::*;
use tokio::sync::Mutex;

struct SSHHandler {}

impl client::Handler for SSHHandler {
    type Error = thrussh::Error;
    type FutureUnit = futures::future::Ready<Result<(Self, client::Session), Self::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, bool), Self::Error>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        futures::future::ready(Ok((self, b)))
    }
    fn finished(self, session: client::Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, session)))
    }
    fn check_server_key(self, _server_public_key: &key::PublicKey) -> Self::FutureBool {
        self.finished_bool(true)
    }
}

pub struct SSHSession {
    key: Option<String>,
    // session: thrussh::client::Handle<SSHHandler>,
    session: Arc<Mutex<thrussh::client::Handle<SSHHandler>>>,
}

pub struct SSHClient {
    // credentials: Option<Credentials<'static>>,
    ip: Option<String>,
    port: Option<String>,
    key: Option<String>,
}

impl SSHClient {
    pub fn new() -> Self {
        SSHClient {
            // credentials: None,
            ip: None,
            port: Some("22".to_string()),
            key: None,
        }
    }

    pub fn ip(&mut self, ip: String) -> &mut Self {
        self.ip = Some(ip);
        self
    }

    pub fn port(&mut self, port: String) -> &mut Self {
        self.port = Some(port);
        self
    }

    pub fn key(&mut self, key: String) -> &mut Self {
        self.key = Some(key);
        self
    }

    pub async fn connect<'a>(
        &mut self,
        creds: &Credentials<'a>,
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
            creds.username.to_string(),
            creds.password.clone().unwrap_or_default(),
        )
        .await?;

        Ok(SSHSession {
            key: self.key.clone(),
            session: Arc::new(Mutex::new(session)),
        })
    }
}
impl SSHSession {
    async fn establish_connection(
        addr: impl std::net::ToSocketAddrs,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<thrussh::client::Handle<SSHHandler>, thrussh::Error> {
        let config = client::Config::default();
        let config = Arc::new(config);
        let sh = SSHHandler {};

        let mut session = client::connect(config, addr, sh).await?;

        let auth_res = session.authenticate_password(user, password).await;

        let _auth_res = auth_res?;
        Ok(session)
    }

    async fn call(&self, command: &str) -> Result<CommandResult> {
        let mut session = self.session.lock().await;
        let mut channel: client::Channel = session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut output = Vec::new();
        let mut code = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                thrussh::ChannelMsg::Data { ref data } => {
                    output.write_all(&data).unwrap();
                }
                thrussh::ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                }
                _ => {}
            }
        }
        Ok(CommandResult { output, code })
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
        println!("HERE");
        let r = self.call(command).await.unwrap();
        println!("{}: {}", r.success(), r.output());
        Ok(Some(r.output()))
    }

    async fn close(&self) -> Result<(), std::io::Error> {
        todo!()
    }
}
