mod enumerator;
mod error;
mod orchestrator;
mod propagator;
mod config;
mod communicator;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OS {
    Unix,
    Windows,
    Unknown,
}

pub use error::Error;
pub use error::Result;
