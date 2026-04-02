use log;
use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Execution error: {0}")]
    Execution(String),

    #[error("Password change error: {0}")]
    PasswordChange(String),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[cfg(feature = "legacy-modes")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[cfg(feature = "legacy-modes")]
    #[error("Decompression error: {0}")]
    Decompression(#[from] zip::result::ZipError),

    #[cfg(feature = "legacy-modes")]
    #[error("Conversion error: {0}")]
    Conversion(#[from] reqwest::header::ToStrError),

    #[error("Module error: {0}")]
    ModuleError(String),

    #[error("Unknown OS")]
    UnknownOS,
}

impl Error {
    pub fn log(&self) {
        match self {
            Error::Execution(msg) => log::error!("Execution failed: {}", msg),
            Error::PasswordChange(msg) => log::error!("Password change failed: {}", msg),
            Error::Io(err) => log::error!("IO error: {}", err),
            Error::ModuleError(msg) => log::error!("Module error: {}", msg),
            #[cfg(feature = "legacy-modes")]
            Error::Decompression(err) => log::error!("Decompression error: {}", err),
            #[cfg(feature = "legacy-modes")]
            Error::Http(err) => log::error!("HTTP error: {}", err),
            #[cfg(feature = "legacy-modes")]
            Error::Conversion(err) => log::error!("Conversion error: {}", err),
            Error::UnknownOS => log::error!("Attempted operation on unknown OS"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
