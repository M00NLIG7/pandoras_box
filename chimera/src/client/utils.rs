use std::io::Write;
use std::process::{Command, Output, Stdio};

pub(crate) struct CommandExecutor;

impl CommandExecutor {
    pub fn execute_command(
        command: &str,
        args: Option<&[&str]>,
        stdin_inputs: Option<&[&str]>,
    ) -> std::io::Result<Output> {
        let mut command = Command::new(command);

        if let Some(args) = args {
            command.args(args);
        }

        let mut child = command
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        if let Some(inputs) = stdin_inputs {
            if let Some(mut stdin) = child.stdin.take() {
                for input in inputs {
                    stdin.write_all(input.as_bytes())?;
                    stdin.write_all(b"\n")?;
                }
            }
        }

        let output = child.wait_with_output()?;

        if output.status.success() {
            Ok(output)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{:?} failed with exit code: {}",
                    command,
                    output.status.code().unwrap_or(0)
                ),
            ))
        }
    }
}
