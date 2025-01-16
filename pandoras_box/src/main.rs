use chrono::Local;
use clap::{arg as carg, command, value_parser};
use log::{debug, error, info, warn};
use pandoras_box::*;
use std::fs::OpenOptions;
use std::process::Command;
use std::sync::Once;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

static INIT: Once = Once::new();

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

pub fn setup_tracing() -> Result<()> {
    let mut result = Ok(());

    INIT.call_once(|| {
        if std::env::var("RUST_LOG").is_err() {
            std::env::set_var("RUST_LOG", "info,rustrc=debug");
        }

        // Create log file
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let log_path = format!("./pandoras_box{}.log", timestamp);

        // Create file appender
        let file = match OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&log_path)
        {
            Ok(file) => file,
            Err(e) => {
                result = Err(Error::InvalidSubnet(e.to_string()));
                return;
            }
        };

        // Set up the file layer
        let file_layer = tracing_subscriber::fmt::layer()
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true)
            .with_writer(file);

        // Set up the console layer
        let console_layer = tracing_subscriber::fmt::layer()
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_file(true)
            .with_line_number(true);

        // Set up the filter
        let filter_layer = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,rustrc=debug,test=debug"));

        // Combine everything and initialize
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(console_layer)
            .with(file_layer)
            .init();

        println!("Logging initialized to {}", log_path);
    });

    result
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing()?;

    let _memory_report = MemoryReport;

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

    let subnet = match enumerator::Subnet::try_from(range) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse subnet: {}", e);
            return Err(Error::InvalidSubnet(e.to_string()));
        }
    };

    info!("Created subnet: {}", range);
    let mut orchestrator = orchestrator::Orchestrator::new(subnet);

    match orchestrator.run(password).await {
        Ok(_) => {
            info!("Orchestrator completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Orchestrator failed: {}", e);
            Err(e)
        }
    }
}
