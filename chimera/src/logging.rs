use std::io::Write;
use log::SetLoggerError;
use chrono::Local;

const DEFAULT_LOG_FILE: &str = "application.log";

pub struct MultiWriter {
    writers: Vec<Box<dyn Write + Send + Sync>>
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

pub fn init_logging() -> Result<(), SetLoggerError> {
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
        .target(env_logger::Target::Pipe(Box::new(MultiWriter {
            writers: vec![
                Box::new(std::io::stderr()),
                Box::new(std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(DEFAULT_LOG_FILE)
                    .expect("Failed to open log file"))
            ]
        })))
        .init();
    Ok(())
}

