pub mod error;
pub mod client;

pub mod traits;
pub use traits::*;

/// Gate behind ssh feature
#[cfg(feature = "ssh")]
pub mod ssh;

pub mod stateful_process;

/// Gate behind telnet feature
#[cfg(feature = "telnet")]
pub mod telnet;

/// Gate behind winexe feature
#[cfg(feature = "winexe")]
pub mod winexe;
#[cfg(feature = "winexe")]
pub mod smb;

/// Gate behind winrm feature
#[cfg(feature = "winrm")]
pub mod winrm;

pub use error::*;

pub mod macros {
    #[macro_export]
    macro_rules! cmd {
        ($cmd:expr $(,$arg:expr)*) => {
            {
                let mut cmd = $crate::client::Command::new($cmd);
                $(
                    cmd = cmd.arg($arg);
                )*

                cmd
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::cmd;

    #[test]
    fn test_macro() {
        let cmd = cmd!("ls", "-l","-a");
        assert_eq!(cmd.get_cmd(), "ls");
        assert_eq!(cmd.get_args(), &vec!["-l", "-a"]);
    }
}
