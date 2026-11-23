use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::{timeout_at, Instant};

pub const APPLICATION_LOG_FILENAME: &str = "application.log";
pub const INVENTORY_FILENAME: &str = "inventory.json";
const OUTPUT_ROOT_ENV_VAR: &str = "CHIMERA_OUTPUT_ROOT";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_COMMAND_INPUT_BYTES: usize = 64 * 1024;

pub fn get_default_output_dir() -> PathBuf {
    if let Some(path) = std::env::var_os(OUTPUT_ROOT_ENV_VAR) {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }

    #[cfg(windows)]
    {
        PathBuf::from(r"C:\Temp\output")
    }
    #[cfg(unix)]
    {
        PathBuf::from("/tmp/output")
    }
}

pub fn set_output_root(path: &str) {
    std::env::set_var(OUTPUT_ROOT_ENV_VAR, path);
}

#[derive(Debug)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
}

#[derive(Clone, Copy)]
struct CommandLimits {
    timeout: Duration,
    max_output_bytes: usize,
    max_input_bytes: usize,
}

impl Default for CommandLimits {
    fn default() -> Self {
        Self {
            timeout: COMMAND_TIMEOUT,
            max_output_bytes: MAX_COMMAND_OUTPUT_BYTES,
            max_input_bytes: MAX_COMMAND_INPUT_BYTES,
        }
    }
}

pub(crate) struct CommandExecutor;

impl CommandExecutor {
    pub async fn execute_command(
        command: &str,
        args: Option<&[&str]>,
        stdin_inputs: Option<&[&str]>,
    ) -> io::Result<CommandOutput> {
        Self::execute_with_limits(command, args, stdin_inputs, CommandLimits::default()).await
    }

    async fn execute_with_limits(
        command: &str,
        args: Option<&[&str]>,
        stdin_inputs: Option<&[&str]>,
        limits: CommandLimits,
    ) -> io::Result<CommandOutput> {
        validate_input_size(stdin_inputs, limits.max_input_bytes)?;

        let mut cmd = Command::new(command);
        if let Some(args) = args {
            cmd.args(args);
        }
        cmd.kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()?;
        let deadline = Instant::now() + limits.timeout;

        if let Err(error) = write_stdin(&mut child, stdin_inputs, deadline).await {
            terminate(&mut child).await;
            return Err(error);
        }

        let output = Self::collect_output(&mut child, limits.max_output_bytes, deadline).await?;
        if output.status == 0 {
            Ok(output)
        } else {
            Err(io::Error::other(format!(
                "command {command:?} failed with exit code {}",
                output.status
            )))
        }
    }

    async fn collect_output(
        child: &mut Child,
        max_output_bytes: usize,
        deadline: Instant,
    ) -> io::Result<CommandOutput> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("could not capture stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("could not capture stderr"))?;

        let reads = async {
            tokio::try_join!(
                read_bounded(stdout, max_output_bytes, "stdout"),
                read_bounded(stderr, max_output_bytes, "stderr")
            )
        };

        let (stdout, _stderr) = match timeout_at(deadline, reads).await {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                terminate(child).await;
                return Err(error);
            }
            Err(_) => {
                terminate(child).await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "command exceeded its execution deadline",
                ));
            }
        };

        let status = match timeout_at(deadline, child.wait()).await {
            Ok(result) => result?,
            Err(_) => {
                terminate(child).await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "command exceeded its execution deadline",
                ));
            }
        };

        Ok(CommandOutput {
            status: status.code().unwrap_or(-1),
            stdout,
        })
    }
}

fn validate_input_size(inputs: Option<&[&str]>, max_bytes: usize) -> io::Result<()> {
    let total_bytes = inputs
        .unwrap_or_default()
        .iter()
        .try_fold(0usize, |total, input| {
            input
                .len()
                .checked_add(1)
                .and_then(|input_bytes| total.checked_add(input_bytes))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "stdin size overflow"))
        })?;

    if total_bytes > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("command stdin exceeds the {max_bytes}-byte limit"),
        ));
    }
    Ok(())
}

async fn write_stdin(
    child: &mut Child,
    inputs: Option<&[&str]>,
    deadline: Instant,
) -> io::Result<()> {
    let Some(mut stdin) = child.stdin.take() else {
        return Err(io::Error::other("could not open command stdin"));
    };

    let write = async {
        for input in inputs.unwrap_or_default() {
            stdin.write_all(input.as_bytes()).await?;
            stdin.write_all(b"\n").await?;
        }
        stdin.shutdown().await
    };

    timeout_at(deadline, write).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "command exceeded its execution deadline while reading stdin",
        )
    })?
}

async fn read_bounded(
    reader: impl AsyncRead + Unpin,
    max_bytes: usize,
    stream_name: &str,
) -> io::Result<Vec<u8>> {
    let read_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut reader = reader.take(read_limit);
    let mut bytes = Vec::with_capacity(max_bytes.min(8192));
    reader.read_to_end(&mut bytes).await?;

    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("command {stream_name} exceeds the {max_bytes}-byte limit"),
        ));
    }
    Ok(bytes)
}

async fn terminate(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const SHELL: &str = "sh";
    #[cfg(unix)]
    fn shell_args(script: &str) -> [&str; 2] {
        ["-c", script]
    }

    #[cfg(windows)]
    const SHELL: &str = "cmd";
    #[cfg(windows)]
    fn shell_args(script: &str) -> [&str; 2] {
        ["/C", script]
    }

    #[tokio::test]
    async fn executes_a_successful_command() {
        #[cfg(unix)]
        let args = shell_args("printf hello");
        #[cfg(windows)]
        let args = shell_args("<nul set /p =hello");

        let output = CommandExecutor::execute_command(SHELL, Some(&args), None)
            .await
            .expect("command should succeed");
        assert_eq!(output.status, 0);
        assert_eq!(output.stdout, b"hello");
    }

    #[tokio::test]
    async fn reports_a_missing_command() {
        let result = CommandExecutor::execute_command("nonexistentcommand", None, None).await;
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn supplies_bounded_stdin() {
        let args = shell_args("cat");
        let output = CommandExecutor::execute_command(SHELL, Some(&args), Some(&["test input"]))
            .await
            .expect("command should succeed");
        assert_eq!(output.stdout, b"test input\n");
    }

    #[tokio::test]
    async fn terminates_a_command_at_its_deadline() {
        #[cfg(unix)]
        let args = shell_args("sleep 5");
        #[cfg(windows)]
        let args = shell_args("ping -n 6 127.0.0.1 >NUL");
        let limits = CommandLimits {
            timeout: Duration::from_millis(100),
            ..CommandLimits::default()
        };

        let error = CommandExecutor::execute_with_limits(SHELL, Some(&args), None, limits)
            .await
            .expect_err("long-running command should time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn rejects_output_over_the_configured_limit() {
        #[cfg(unix)]
        let args = shell_args("printf 123456789");
        #[cfg(windows)]
        let args = shell_args("<nul set /p =123456789");
        let limits = CommandLimits {
            max_output_bytes: 4,
            ..CommandLimits::default()
        };

        let error = CommandExecutor::execute_with_limits(SHELL, Some(&args), None, limits)
            .await
            .expect_err("oversized output should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
