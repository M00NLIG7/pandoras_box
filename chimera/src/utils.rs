use tokio::process::{Command, Child};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::process::Stdio;
use std::io;
use std::path::PathBuf;

pub fn get_default_output_dir() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\Temp\output")
    }
    #[cfg(unix)]
    {
        PathBuf::from("/tmp/output")
    }
}

pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(crate) struct CommandExecutor;

impl CommandExecutor {
    pub async fn execute_command(
        command: &str,
        args: Option<&[&str]>,
        stdin_inputs: Option<&[&str]>,
    ) -> io::Result<CommandOutput> {
        // Build the command
        let mut cmd = Command::new(command);
        if let Some(args) = args {
            cmd.args(args);
        }

        // Configure stdio
        cmd.stdin(Stdio::piped())
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        // Spawn the command
        let mut child = cmd.spawn()?;

        // Handle stdin if provided
        if let Some(inputs) = stdin_inputs {
            if let Some(mut stdin) = child.stdin.take() {
                for input in inputs {
                    stdin.write_all(input.as_bytes()).await?;
                    stdin.write_all(b"\n").await?;
                }
                // Explicitly close stdin
                drop(stdin);
            }
        }

        // Wait for the command to complete and collect output
        let output = Self::collect_output(child).await?;

        if output.status == 0 {
            Ok(output)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Command {:?} failed with exit code: {}",
                    command, output.status
                ),
            ))
        }
    }

    async fn collect_output(mut child: Child) -> io::Result<CommandOutput> {
        // Take ownership of the stdout and stderr handles
        let mut stdout = child.stdout.take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Could not capture stdout"))?;
        let mut stderr = child.stderr.take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Could not capture stderr"))?;

        // Create buffers for stdout and stderr
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        // Concurrently read stdout and stderr
        let (stdout_res, stderr_res) = tokio::join!(
            stdout.read_to_end(&mut stdout_buf),
            stderr.read_to_end(&mut stderr_buf)
        );

        // Check for read errors
        stdout_res?;
        stderr_res?;

        // Wait for the child process to complete
        let status = child.wait().await?;

        Ok(CommandOutput {
            status: status.code().unwrap_or(-1),
            stdout: stdout_buf,
            stderr: stderr_buf,
        })
    }
}

// Add test module
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_execute_command_success() {
        let result = CommandExecutor::execute_command("echo", Some(&["hello"]), None).await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.status, 0);
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
    }

    #[tokio::test]
    async fn test_execute_command_failure() {
        let result = CommandExecutor::execute_command("nonexistentcommand", None, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_command_with_stdin() {
        let result = CommandExecutor::execute_command(
            "cat",
            None,
            Some(&["test input"]),
        ).await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.status, 0);
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "test input");
    }
}
