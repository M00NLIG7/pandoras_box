use std::io::Write;
use log::SetLoggerError;
use crate::utils::get_default_output_dir;
use chrono::Local;

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
    let default_output = get_default_output_dir();

    // Create ./output directory if it doesn't exist
    std::fs::create_dir_all(&default_output).expect("Failed to create output directory");

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
                    .open(default_output.join("application.log"))
                    .expect("Failed to open log file"))
            ]
        })))
        .init();
    Ok(())
}

