use thiserror::Error;
use std::io;
use log;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Execution error: {0}")]
    Execution(String),
    
    #[error("Password change error: {0}")]
    PasswordChange(String),
    
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Unknown OS")]
    UnknownOS,
}

impl Error {
    pub fn log(&self) {
        match self {
            Error::Execution(msg) => log::error!("Execution failed: {}", msg),
            Error::PasswordChange(msg) => log::error!("Password change failed: {}", msg),
            Error::Io(err) => log::error!("IO error: {}", err),
            Error::UnknownOS => log::error!("Attempted operation on unknown OS"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
