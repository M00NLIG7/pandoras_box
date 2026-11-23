use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

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

    #[error("Authentication failed: {0}")]
    AuthenticationFailure(String),

    #[error("Credential profile error: {0}")]
    CredentialProfileFailure(String),

    #[error("Host identity verification failed: {0}")]
    HostIdentityFailure(String),

    #[error("Operation timed out: {0}")]
    DeadlineExceeded(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("Unsupported target: {0}")]
    UnsupportedTarget(String),

    #[error("Unsafe workspace: {0}")]
    UnsafeWorkspace(String),

    #[error("Command error: {0}")]
    CommandError(String),

    #[error("Deployment error: {0}")]
    DeploymentError(String),

    #[error("File Transfer error: {0}")]
    FileTransferError(String),

    #[error("Invalid Subnet: {0}")]
    InvalidSubnet(String),

    #[error("Mission failed: {0}")]
    MissionFailure(String),
}

impl Error {
    #[must_use]
    pub fn is_authentication_failure(&self) -> bool {
        if matches!(self, Self::AuthenticationFailure(_))
            || matches!(
                self,
                Self::RemoteConnectionError(rustrc::Error::AuthenticationError(_))
            )
        {
            return true;
        }
        let rendered = self.to_string().to_ascii_lowercase();
        [
            "auth failed",
            "authentication failed",
            "authentication error",
            "failed to authenticate",
            "logon failure",
            "account locked",
        ]
        .iter()
        .any(|needle| rendered.contains(needle))
    }

    #[must_use]
    pub fn is_host_identity_failure(&self) -> bool {
        if matches!(self, Self::HostIdentityFailure(_)) {
            return true;
        }
        let rendered = self.to_string().to_ascii_lowercase();
        rendered.contains("host key verification failed")
            || rendered.contains("host key for")
            || rendered.contains("unknown server key")
            || rendered.contains("unknown host key")
    }

    #[must_use]
    pub fn blocks_retry_or_fallback(&self) -> bool {
        self.is_authentication_failure()
            || self.is_host_identity_failure()
            || matches!(
                self,
                Self::CredentialProfileFailure(_)
                    | Self::UnsupportedTarget(_)
                    | Self::UnsafeWorkspace(_)
                    | Self::ResourceLimit(_)
            )
    }
}

pub type Result<T> = std::result::Result<T, Error>;
