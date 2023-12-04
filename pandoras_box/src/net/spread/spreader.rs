use crate::net::communicator::{Credentials, Session};
// use crate::net::enumeration::ping::Enumerator;
use crate::net::enumeration::ping::Enumerator;
use crate::net::session_pool::SessionPool;
use crate::net::ssh::{SSHClient, SSHSession};
use crate::net::winexe::{WinexeClient, WinexeSession};
use futures::future::join_all;
use libc::passwd;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug)]
pub enum OS {
    Unix,
    Windows,
    Unknown,
}

pub struct Spreader {
    linux_hosts: Mutex<Vec<(String, Arc<dyn Session>)>>,
    windows_hosts: SessionPool,
    password: String,
}

impl Spreader {
    pub fn new(password: String) -> Self {
        Spreader {
            linux_hosts: Mutex::new(Vec::new()),
            windows_hosts: SessionPool::new(),
            password: password,
        }
    }

    pub async fn enumerate_hosts(&mut self, subnet: &str) {
        // let hosts
        println!("Enumerating hosts in subnet: {}", subnet);
        let mut enumerator = Enumerator::new(subnet.to_string());
        let _ = enumerator.ping_sweep().await;

        for host in enumerator.hosts {
            match host.os {
                OS::Unix => {
                    let session = match SSHClient::new()
                        .ip(host.ip.clone())
                        .connect(&Credentials {
                            username: "root",
                            password: Some(self.password.clone()),
                            key: None,
                        })
                        .await
                    {
                        Ok(session) => {
                            println!("{}", host.ip);
                            self.linux_hosts
                                .lock()
                                .await
                                .push((host.ip, Arc::new(session)))
                        }
                        _ => (),
                    };
                }
                OS::Unknown => (),
                _ => (),
            }
        }
    }

    async fn spread_unix(&mut self) {
        let mut handles = vec![];
        let hosts = self.linux_hosts.lock().await;

        hosts.iter().for_each(|host| {
            // let (ip, session) = Arc::clone(host);
            let session: Arc<dyn Session> = Arc::clone(&host.1);
            let ip = host.0.clone();

            handles.push(tokio::spawn(async move {
                let mut magic: u16 = 0;
                if let Some(last_segment) = ip.split('.').last() {
                    if let Ok(last_octet) = last_segment.parse::<u16>() {
                        magic = last_octet * 69;
                    } else {
                        println!("Failed to parse the last segment as u8");
                    }
                } else {
                    println!("No segments found in IP address");
                    return;
                }

                // Echo change password and pipe it to passwd command to change password
                let passwd = format!("GoblinoMunchers{}!", magic);
                let command = format!("echo '{}' | passwd --stdin root", passwd);

                let _ = session.execute_command(&command).await;
            }));
        });

        join_all(handles).await;
        // return handles;
    }

    pub async fn spread(&mut self) {
        return self.spread_unix().await;
    }
}
