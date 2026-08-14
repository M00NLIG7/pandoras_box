//! Audited SSH client primitives used by Pandora's Box.

pub mod client;
pub mod error;
pub mod ssh;

pub use error::*;

#[macro_export]
macro_rules! cmd {
    ($cmd:expr $(,$arg:expr)*) => {
        $crate::client::Command::new($cmd)$(.arg($arg))*
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn command_macro_adds_arguments() {
        let command = cmd!("ls", "-l", "-a");
        assert_eq!(command.get_cmd(), "ls");
        assert_eq!(command.get_args(), &["-l", "-a"]);
    }
}
