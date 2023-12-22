// mod enumeration;
mod api;
mod init;
mod net;

use std::sync::{Arc, Mutex};

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

    // Fetch srv_handle and srv from api::run_server
    let (srv, srv_handle) = api::start_server(golden_node.clone()).await;

    // Start API server in background
    tokio::spawn(srv);

    loop {
        // sleep one second\
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    // Main loop
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
    // Complex password (typables)
    // Encrypt database

    // net::spread::spreader::Spreader::new()
    // let mut hosts = net::enumeration::ping::Enumerator::new("192.168.1".to_string());
    // let results = hosts.ping_sweep().await;
    // println!("Hosts: {:?}", hosts.hosts.len());

    srv_handle.stop(true).await;

    // let creds: Credentials = Credentials {
    //     username: "cm03".into(),
    //     password: Some("@11272003Cm!".to_string()),
    //     key: None,
    // };

    // let ssh_client = SSHClient::new()
    //     .ip("10.123.40.102".to_string())
    //     .connect(&creds)
    //     .await
    //     .unwrap();

    // let mut decompresser = GzDecoder::new(CHIMERA);
    // let mut decompressed_data = Vec::new();
    // decompresser
    //     .read_to_end(&mut decompressed_data)
    //     .expect("Failed to decompress data");d ..
    // let base64_str = String::from_utf8(decompressed_data).expect("Unable to parse UTF-8");

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
    println!("DONE CHUNKING");
    // .for_each(|chunk| {
    //     let chunk_str = chunk.iter().collect::<String>();

    //     let command = format!("echo \"{}\" >> /tmp/chimera64", chunk_str);

    //     ssh_client.execute_command(&command).await.unwrap();
    // });

    // let command = format!("base64 -d /tmp/chimera64 > /tmp/chimera");
    // ssh_client.execute_command(&command).await.unwrap();

    let _memory_report = MemoryReport;
}
