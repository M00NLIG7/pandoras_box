use crate::enumerator::Host;
use crate::error::Error;
use crate::Result;
use crate::OS;
use std::sync::Arc;
use rustrc::client::{Client, Command, CommandOutput, Config};
use rustrc::ssh::SSHConfig;
use rustrc::winexe::WinexeConfig;

pub enum DynamicClient {
    Windows(Client<WinexeConfig>),
    Unix(Client<SSHConfig>),
    Unknown(Client<SSHConfig>),
}

impl DynamicClient {
    async fn new(host: Host) -> Result<Self> {
        match host.os {
            OS::Windows => {
                // TODO: Implement Windows client creation
                todo!("Implement Windows client creation")
            }
            OS::Unix => {
                // TODO: Implement Unix client creation
                todo!("Implement Unix client creation")
            }
            OS::Unknown => {
                // TODO: Handle unknown OS type
                todo!("Handle unknown OS type")
            }
        }
    }

    async fn disconnect(&mut self) -> Result<()> {
        match self {
            DynamicClient::Windows(client) => client.disconnect().await,
            DynamicClient::Unix(client) => client.disconnect().await,
            DynamicClient::Unknown(client) => client.disconnect().await,
        }
        .map_err(Error::from)
    }

    async fn exec(&self, cmd: &Command) -> Result<CommandOutput> {
        match self {
            DynamicClient::Windows(client) => client.exec(cmd).await,
            DynamicClient::Unix(client) => client.exec(cmd).await,
            DynamicClient::Unknown(client) => client.exec(cmd).await,
        }
        .map_err(Error::from)
    }
}

pub struct Communicator {
    clients: Vec<DynamicClient>,
}

impl Communicator {
    pub async fn new(hosts: Vec<Host>) -> Result<Self> {
        let mut clients = Vec::new();

        for host in hosts {
            let client = DynamicClient::new(host).await?;
            clients.push(client);
        }

        Ok(Communicator { clients })
    }

    pub async fn disconnect_all(&mut self) -> Result<()> {
        for client in &mut self.clients {
            client.disconnect().await?;
        }
        Ok(())
    }

    pub async fn exec_by_os(&self, cmd: &Command, os: OS) -> Vec<Result<CommandOutput>> {
        let results = self.clients.iter().filter(|client| match client {
            DynamicClient::Windows(_) if os == OS::Windows => true,
            DynamicClient::Unix(_) if os == OS::Unix => true,
            _ => false,
        }).map(|client| client.exec(cmd)).collect::<Vec<_>>();

        futures::future::join_all(results).await
    }

    pub async fn exec_all(&self, cmd: &Command) -> Vec<Result<CommandOutput>> {
        let mut results = Vec::new();
        for client in &self.clients {
            results.push(client.exec(cmd));
        }

        futures::future::join_all(results).await
    }
}

// TODO: Implement specific client types (e.g., WindowsClient, UnixClient)
// TODO: Implement corresponding Config types for each client type

/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::cmd;
    use std::time::Duration;

    #[tokio::test]
    async fn test_winexe_container() {
        let socket = "139.182.180.178";
        let config =
            WinexeConfig::password("sfs15-ultron", socket, "sfs15", Duration::from_secs(10))
                .await
                .unwrap();

        let client = Client::connect(config).await.unwrap();

        let output = client.exec(cmd!("echo", "TESTING")).await.unwrap();

        let str_output = String::from_utf8_lossy(&output.stdout);

        dbg!(str_output);
    }
}
*/
