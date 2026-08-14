use log;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Execution error: {0}")]
    Execution(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Module error: {0}")]
    ModuleError(String),

    #[error("Unknown OS")]
    UnknownOS,
}

impl Error {
    pub fn log(&self) {
        match self {
            Error::Execution(msg) => log::error!("Execution failed: {}", msg),
            Error::Io(err) => log::error!("IO error: {}", err),
            Error::ModuleError(msg) => log::error!("Module error: {}", msg),
            Error::UnknownOS => log::error!("Attempted operation on unknown OS"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
