use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to create ping client")]
    ClientCreationError(#[from] std::io::Error),

    #[error("Parsing error: {0}")]
    ParsingError(#[from] std::num::ParseIntError),

    #[error("Address parsing error: {0}")]
    AddressParsingError(#[from] std::net::AddrParseError),

    #[error("Argument error: {0}")]
    ArgumentError(String),

    #[error("Failed to create client")]
    RemoteConnectionError(#[from] rustrc::Error),

    #[error("Command error: {0}")]
    CommandError(String),

    #[error("Unknown OS")]
    UnknownOS,
}

pub type Result<T> = std::result::Result<T, Error>;
