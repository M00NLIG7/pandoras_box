use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to create ping client")]
    ClientCreationError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
