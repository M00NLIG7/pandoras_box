use clap::{arg as carg, command, value_parser};
use pandoras_box::*;
use std::collections::BinaryHeap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use flate2::read::ZlibDecoder;
use std::process::Command;
use tokio::sync::watch;
use log::{info, warn, error, debug, LevelFilter};
use env_logger::{Builder, Target, WriteStyle};
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;

struct MemoryReport;

impl Drop for MemoryReport {
    fn drop(&mut self) {
        let output = Command::new("ps")
            .arg("-o")
            .arg("rss=")
            .arg("-p")
            .arg(std::process::id().to_string())
            .output()
            .expect("Failed to execute command");

        let memory_usage = String::from_utf8_lossy(&output.stdout);
        info!("Memory Usage at Exit: {} KB", memory_usage.trim());
    }
}

fn setup_logging() -> Result<()> {
    // Create log file with timestamp
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let log_path = format!("./pandoras_box{}.log", timestamp);
    
    // Open file in append mode and create if it doesn't exist
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(&log_path)?;

    // Initialize env_logger with custom configuration
    Builder::new()
        .target(Target::Pipe(Box::new(file)))
        .filter_level(LevelFilter::Info) // Capture all logs by default
        .write_style(WriteStyle::Always)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{:>5}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();

    // Create a console output handler as well
    let stderr = Builder::new()
        .filter_level(LevelFilter::Info)
        .write_style(WriteStyle::Always)
        .build();

    info!("Logging initialized to {}", log_path);
    Ok(())
}

fn decompress_data(compressed_data: &[u8]) -> Vec<u8> {
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data).unwrap();
    decompressed_data
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging first
    setup_logging()?;
    
    let matches = command!()
        .arg(
            carg!(-r --range <IP_RANGE>)
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            carg!(-p --password <PASSWORD>)
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .get_matches();

    let range = matches.get_one::<String>("range").unwrap();
    let password = matches.get_one::<String>("password").unwrap();
    
    info!("Starting application with range: {}", range);
    debug!("Password length: {}", password.len());

    let subnet = match enumerator::Subnet::try_from("10.100.136.0/24") {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse subnet: {}", e);
            return Err(e.into());
        }
    };
    
    info!("Created subnet: {}", "10.100.136.0/24");
    let mut orchestrator = orchestrator::Orchestrator::new(subnet);

    match orchestrator.run("Cheesed2MeetU!").await {
        Ok(_) => {
            info!("Orchestrator completed successfully");
            Ok(())
        },
        Err(e) => {
            error!("Orchestrator failed: {}", e);
            Err(e.into())
        }
    }
}
