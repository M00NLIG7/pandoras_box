use clap::{arg as carg, command, value_parser};

use std::collections::BinaryHeap;
use std::sync::{Arc, Mutex};
use std::io::Read;
// use enumeration::ping;
//use std::future::Future;
// use crate::net::spread::spreader::Spreader;
// use crate::net::spread::spreader::ConnectionPool;
use tokio::sync::watch;
use flate2::read::ZlibDecoder;
use std::process::Command;

// const CHIMERA: &[u8] = include_bytes!("../bin/chimera64.zlib");
//const COMPRESSED_CHIMERA: &[u8] = include_bytes!("../bin/chimera_win.zlib");

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
}

