use crate::utils::{get_default_output_dir, APPLICATION_LOG_FILENAME};
use chrono::Local;
use std::io::Write;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogFileMode {
    Append,
    Truncate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoggingConfig {
    pub file_mode: LogFileMode,
}

impl LoggingConfig {
    pub fn append_file() -> Self {
        Self {
            file_mode: LogFileMode::Append,
        }
    }

    pub fn truncate_file() -> Self {
        Self {
            file_mode: LogFileMode::Truncate,
        }
    }
}

pub struct MultiWriter {
    writers: Vec<Box<dyn Write + Send + Sync>>,
}

impl Write for MultiWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for writer in &mut self.writers {
            writer.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        for writer in &mut self.writers {
            writer.flush()?;
        }
        Ok(())
    }
}

pub fn init_logging(config: LoggingConfig) -> Result<(), Box<dyn std::error::Error>> {
    let default_output = get_default_output_dir();
    let mut writers: Vec<Box<dyn Write + Send + Sync>> = vec![Box::new(std::io::stderr())];

    std::fs::create_dir_all(&default_output)?;

    let mut file = std::fs::OpenOptions::new();
    file.create(true).write(true);
    match config.file_mode {
        LogFileMode::Append => {
            file.append(true);
        }
        LogFileMode::Truncate => {
            file.truncate(true);
        }
    }

    writers.push(Box::new(
        file.open(default_output.join(APPLICATION_LOG_FILENAME))?,
    ));

    let env = env_logger::Env::default().default_filter_or("info");

    env_logger::Builder::from_env(env)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {} - {}",
                Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .target(env_logger::Target::Pipe(Box::new(MultiWriter { writers })))
        .try_init()?;
    Ok(())
}
