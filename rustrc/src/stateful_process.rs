use nix::sys::signal::{kill, Signal};
use nix::unistd::{getpgid, setpgid, Pid};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::mpsc;

const BUFFER_SIZE: usize = 1024;

#[derive(Debug)]
pub enum Message {
    Exec(Vec<u8>),
    Data(Vec<u8>),
    Error(Vec<u8>), // New variant for errors
}

#[derive(Debug, Clone)]
pub struct StatefulProcess {
    sender: mpsc::Sender<Message>,
    pub(crate) pgid: Pid,
}

impl StatefulProcess {
    pub async fn new(
        command: &str,
        cmd_args: Vec<&str>,
        external_sender: mpsc::UnboundedSender<Message>,
    ) -> crate::Result<Self> {
        let mut child = unsafe {
            tokio::process::Command::new(command)
                .args(cmd_args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .pre_exec(|| {
                    setpgid(Pid::this(), Pid::from_raw(0))
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                    Ok(())
                })
                .spawn()?
        };

        let pid = Pid::from_raw(
            child
                .id()
                .ok_or_else(|| crate::Error::CommandError("Failed to get PID".into()))?
                as i32,
        );
        let pgid = getpgid(Some(pid))
            .map_err(|e| crate::Error::CommandError(format!("Failed to get PGID: {:?}", e)))?;

        let (sender, receiver) = mpsc::channel(32);

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| crate::Error::CommandError("Failed to get stdin handle".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| crate::Error::CommandError("Failed to get stdout handle".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| crate::Error::CommandError("Failed to get stderr handle".into()))?;

        Self::manage_process(stdin, stdout, stderr, receiver, external_sender).await;

        Ok(StatefulProcess { sender, pgid })
    }

    async fn manage_process(
        stdin: ChildStdin,
        stdout: ChildStdout,
        stderr: ChildStderr,
        mut receiver: mpsc::Receiver<Message>,
        external_sender: mpsc::UnboundedSender<Message>,
    ) {
        let mut stdin_writer = BufWriter::new(stdin);
        let mut stdout_reader = BufReader::new(stdout);
        let mut stderr_reader = BufReader::new(stderr);

        tokio::spawn(async move {
            let mut stdout_buffer = vec![0; BUFFER_SIZE];
            let mut stderr_buffer = vec![0; BUFFER_SIZE];
            loop {
                tokio::select! {
                    result = stdout_reader.read(&mut stdout_buffer) => {
                        match result {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                let _ = external_sender.send(Message::Data(stdout_buffer[..n].to_vec()));
                            }
                            Err(e) => eprintln!("Failed to read from stdout: {:?}", e),
                        }
                    }
                    result = stderr_reader.read(&mut stderr_buffer) => {
                        match result {
                            Ok(0) => {}, // EOF, but don't break loop
                            Ok(n) => {
                                let error_data = stderr_buffer[..n].to_vec();
                                eprintln!("Stderr: {}", String::from_utf8_lossy(&error_data));
                                let _ = external_sender.send(Message::Error(error_data));
                            }
                            Err(e) => eprintln!("Failed to read from stderr: {:?}", e),
                        }
                    }
                    cmd = receiver.recv() => {
                        match cmd {
                            Some(Message::Exec(data)) => {
                                if let Err(e) = Self::write_to_stdin(&mut stdin_writer, &data).await {
                                    eprintln!("Failed to execute command: {:?}", e);
                                }
                            }
                            Some(Message::Data(data)) => {
                                if let Err(e) = Self::write_to_stdin(&mut stdin_writer, &data).await {
                                    eprintln!("Failed to write data: {:?}", e);
                                }
                            }
                            Some(Message::Error(_)) | None => break,
                        }
                    }
                }
            }
        });
    }

    pub async fn shutdown(&self) -> crate::Result<()> {
        kill(self.pgid, Signal::SIGTERM)
            .map_err(|e| crate::Error::CommandError(format!("Failed to send SIGTERM: {:?}", e)))
    }

    pub async fn exec(&self, cmd: Vec<u8>) -> crate::Result<()> {
        self.sender
            .send(Message::Exec(cmd))
            .await
            .map_err(|e| crate::Error::CommandError(format!("Failed to send command: {:?}", e)))?;
        self.sender
            .send(Message::Data(b"\n".to_vec()))
            .await
            .map_err(|e| crate::Error::CommandError(format!("Failed to send newline: {:?}", e)))
    }

    async fn write_to_stdin(writer: &mut BufWriter<ChildStdin>, data: &[u8]) -> crate::Result<()> {
        writer.write_all(data).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    async fn collect_output(rx: &mut mpsc::UnboundedReceiver<Message>) -> String {
        let mut output = String::new();
        while let Ok(Some(Message::Data(data))) = timeout(Duration::from_secs(1), rx.recv()).await {
            output.push_str(&String::from_utf8_lossy(&data));
        }
        output
    }

    #[tokio::test]
    async fn test_container_echo() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let stateful_process = StatefulProcess::new("sh", vec![], tx)
            .await
            .expect("Failed to create stateful_process");

        stateful_process
            .exec("echo 'Hello, World!'".as_bytes().to_vec())
            .await
            .expect("Failed to execute echo command");

        let output = collect_output(&mut rx).await;
        assert_eq!(output.trim(), "Hello, World!");
    }

    #[tokio::test]
    async fn test_container_arithmetic() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let stateful_process = StatefulProcess::new("bash", vec![], tx)
            .await
            .expect("Failed to create stateful_process");

        stateful_process
            .exec("echo '2 + 2' | bc".as_bytes().to_vec())
            .await
            .expect("Failed to execute bc command");

        let output = collect_output(&mut rx).await;
        assert_eq!(output.trim(), "4");
    }

    #[tokio::test]
    async fn test_multiple_commands() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let stateful_process = StatefulProcess::new("bash", vec![], tx)
            .await
            .expect("Failed to create stateful_process");

        stateful_process
            .exec("echo 'First command'".as_bytes().to_vec())
            .await
            .expect("Failed to execute first command");
        stateful_process
            .exec("echo 'Second command'".as_bytes().to_vec())
            .await
            .expect("Failed to execute second command");

        let output = collect_output(&mut rx).await;
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines, vec!["First command", "Second command"]);
    }

    #[tokio::test]
    async fn test_large_output() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        let stateful_process = StatefulProcess::new("bash", vec![], tx)
            .await
            .expect("Failed to create stateful_process");

        stateful_process
            .exec("for i in {1..1000}; do echo $i; done".as_bytes().to_vec())
            .await
            .expect("Failed to execute large output command");

        let output = collect_output(&mut rx).await;
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1000);
        assert_eq!(lines[0], "1");
        assert_eq!(lines[999], "1000");
    }
}
