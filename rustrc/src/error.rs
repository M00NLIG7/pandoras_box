use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Config error: {0}")]
    ConfigError(String),
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Command error: {0}")]
    CommandError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("Socket Error: {0}")]
    SocketError(#[from] std::io::Error),
    #[error("JSON Error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("File Transfer Error: {0}")]
    FileTransferError(String),
}

impl From<russh::Error> for Error {
    fn from(err: russh::Error) -> Self {
        match err {
            _ => Error::ConnectionError(err.to_string()),
        }
    }
}

impl From<russh_keys::Error> for Error {
    fn from(err: russh_keys::Error) -> Self {
        match err {
            _ => Error::ConnectionError(err.to_string()),
        }
    }
}

/// A custom `Result` type for our client operations.
pub type Result<T> = std::result::Result<T, Error>;

