#[cfg(target_os = "linux")]
pub mod connections;
#[cfg(not(target_os = "linux"))]
pub mod connections_stub;

#[cfg(target_os = "linux")]
pub use connections::*;
#[cfg(not(target_os = "linux"))]
pub use connections_stub::*;

pub mod user;

pub mod shares;
pub use shares::*;

pub mod services;
pub use services::*;
