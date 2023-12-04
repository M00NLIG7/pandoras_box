// use crate::net::spread::OS;
use crate::net::spread::spreader::OS;
use futures::future::join_all;
use std::net::IpAddr;
use std::time::Duration;
use surge_ping::{Client, Config, IcmpPacket, ICMP};
use tokio::time;

// use surge_ping::{Client, Config, IcmpPacket, ICMP};
// use tokio::time;
#[derive(Debug)]
pub struct Host {
    pub ip: String,
    pub os: OS,
}

pub struct Enumerator {
    subnet: String,
    pub hosts: Vec<Host>,
}

impl Enumerator {
    pub fn new(subnet: String) -> Self {
        Enumerator {
            subnet: subnet,
            hosts: Vec::new(),
        }
    }

    pub async fn ping_sweep(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut tasks = Vec::new();
        let client_v4 = Client::new(&Config::default()).await?;
        // let client_v6 = Client::new(&Config::builder().kind(ICMP::V6).build()).await?;

        for i in 1..255 {
            let ip = format!("{}.{}", self.subnet, i);
            // println!("{}", ip);
            match ip.parse() {
                Ok(IpAddr::V4(addr)) => tasks.push(tokio::spawn(Self::ping(
                    client_v4.clone(),
                    IpAddr::V4(addr),
                ))),
                Ok(IpAddr::V6(addr)) => {
                    // self.hosts.push(Host {
                    //     ip: ip,
                    //     os: OS::Windows,
                    // });
                    todo!()
                }
                Err(e) => println!("{} parse to ipaddr error: {}", ip, e),
            }

            // let result = Self::ping(ip);
        }
        let results: Vec<Option<Host>> = join_all(tasks)
            .await
            .into_iter()
            .map(|result| result.unwrap_or_default())
            .collect();

        // match results? {}
        for item in results {
            if item.is_some() {
                // println!("{:?}", item);
                self.hosts.push(item.unwrap());
            }
        }
        Ok(())
    }

    // Ping an address 5 times， and print output message（interval 1s）
    async fn ping(client: Client, addr: IpAddr) -> Option<Host> {
        let mut result: Option<Host> = None;
        let mut pinger = client.pinger(addr).await;

        pinger.size(56).timeout(Duration::from_secs(1));
        let mut interval = time::interval(Duration::from_secs(1));
        for idx in 0..5 {
            interval.tick().await;
            match pinger.ping(idx).await {
                Ok((IcmpPacket::V4(packet), _)) => {
                    // println!("test");
                    println!("IP: {}, TTL: {}", addr.to_string(), packet.get_ttl());
                    result = Some(Host {
                        ip: addr.to_string(),
                        os: match packet.get_ttl() {
                            60..=64 => OS::Unix,
                            120..=128 => OS::Windows,
                            _ => OS::Unknown,
                        },
                    });
                }
                _ => continue,
            };
        }
        result
        // println!("[+] {} done.", pinger.destination);
    }
}

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // test same url 114.114.114.114
//     let ips = [
//         "114.114.114.114",
//         "8.8.8.8",
//         "39.156.69.79",
//         "172.217.26.142",
//         "240c::6666",
//         "2a02:930::ff76",
//         "114.114.114.114",
//     ];

// let client_v4 = Client::new(&Config::default()).await?;
//     let client_v6 = Client::new(&Config::builder().kind(ICMP::V6).build()).await?;
//     let mut tasks = Vec::new();
//     for ip in &ips {
//         match ip.parse() {
// Ok(IpAddr::V4(addr)) => {
//     tasks.push(tokio::spawn(ping(client_v4.clone(), IpAddr::V4(addr))))
// }
//             Ok(IpAddr::V6(addr)) => {
//                 tasks.push(tokio::spawn(ping(client_v6.clone(), IpAddr::V6(addr))))
//             }
//             Err(e) => println!("{} parse to ipaddr error: {}", ip, e),
//         }
//     }

//     join_all(tasks).await;
//     Ok(())
// }
