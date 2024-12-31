use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to create ping client")]
    ClientCreationError(#[from] std::io::Error),
    
    #[error("Parsing error: {0}")]
    ParsingError(#[from] std::num::ParseIntError),
    
    #[error("Address parsing error: {0}")]
    AddressParsingError(#[from] std::net::AddrParseError),
    
    #[error("Invalid IP address: {0}")]
    InvalidIP(String),
    
    #[error("No SSH port (22) available")]
    NoSSHPort,
    
    #[error("Unknown OS")]
    UnknownOS,
    
    #[error("Argument error: {0}")]
    ArgumentError(String),
    
    #[error("Failed to create client: {0}")]
    RemoteConnectionError(#[from] rustrc::Error),
    
    #[error("Failed to create communicator: {0}")]
    CommunicatorError(String),
    
    #[error("Command error: {0}")]
    CommandError(String),

    #[error("Deployment error: {0}")]
    DeploymentError(String),

}

pub type Result<T> = std::result::Result<T, Error>;
