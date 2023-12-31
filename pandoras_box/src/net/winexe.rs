use crate::net::communicator::{Credentials, Session};
use async_trait::async_trait;
use flate2::read::ZlibDecoder;
use rand::Rng;
use std::{
    env, fs,
    io::{Read, Write},
    option::Option,
    os::unix::fs::PermissionsExt,
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::{mpsc, Mutex},
    time::sleep,
};

const RUNC: &[u8] = include_bytes!("../../bin/runc.zlib");

impl Drop for WinexeSession {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.output_file_name);
    }
}
// use fs2::FileExt;
pub struct WinexeSession {
    child_process: Arc<Mutex<Child>>, // Used to keep track of actual winexe process
    output_file_name: String,         // tmp file to store stdout
    command_sender: Option<mpsc::Sender<(String, tokio::sync::oneshot::Sender<()>)>>, // Channel to send commands to winexe session
    ready_receiver: Option<tokio::sync::oneshot::Receiver<()>>, // Add ready_receiver here
    output_file: Arc<Mutex<File>>,
    ip: Box<str>,
}

// Struct to keep track of winexe session
impl WinexeSession {
    // Sends any data(bytes) to stdin
    pub async fn write_to_stdin(
        mut child: tokio::sync::MutexGuard<'_, Child>,
        data: &[u8],
    ) -> Result<(), std::io::Error> {
        // let mut child = .lock().await;

        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(data).await?;
            println!("{:?}", data);
            stdin.flush().await?;
        }

        Ok(())
    }

    async fn start_receiver(&mut self) -> &mut Self {
        let (command_sender, mut command_receiver) =
            mpsc::channel::<(String, tokio::sync::oneshot::Sender<()>)>(32);

        // Open channel to send ready signal to winexe session
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();

        let child = Arc::clone(&self.child_process);
        let file_path = self.output_file_name.clone();

        // Clone session to be used in tokio::spawn in background
        tokio::spawn(async move {
            let _ = ready_sender.send(());

            // Waits for command to be sent to channel and then sends it to winexe session
            while let Some((command, completion_sender)) = command_receiver.recv().await {
                let child: tokio::sync::MutexGuard<'_, Child> = child.lock().await;
                let _ = Self::write_to_stdin(child, command.as_bytes()).await;

                loop {
                    // Sleep for a short interval (e.g., 1 second) before checking again
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    if Self::is_finished(&file_path, 5).await {
                        // println!("GOOOD CONTENTS {}", contents);
                        break;
                    }
                }
                let _ = completion_sender.send(());
            }
        });

        let _ = ready_receiver.await;

        self.command_sender = Some(command_sender);
        self
    }

    async fn is_finished(file_path: &str, num_lines: usize) -> bool {
        let mut file = File::open(&file_path).await.unwrap();

        let mut contents = String::new();

        file.read_to_string(&mut contents).await.unwrap();

        let lines: Vec<_> = contents
            .lines()
            .rev()
            .take(num_lines)
            .filter(|line| line.contains(">") && line.contains("C:\\"))
            .collect();

        !lines.is_empty()
    }
}

// Define Winexe Client (subject behind)
pub struct WinexeClient {
    // session: Option<Arc<Mutex<Session>>>, // Winexe Session
    container_path: Option<String>, // Path to winexe container
    // credentials: Option<Credentials<'static>>, // Credentials to connect to winexe session
    ip: Option<String>, // Ip to connect to winexe session
}

// Winexe implementation
impl WinexeClient {
    pub fn new() -> Self {
        WinexeClient {
            // session: None,
            // command_sender: None,
            container_path: None,
            // credentials: None,
            ip: None,
        }
    }

    pub async fn connect(
        &mut self,
        creds: &Credentials,
    ) -> Result<WinexeSession, Box<dyn std::error::Error>> {
        if self.ip.is_none() {
            return Err("Please configure ip()".into());
        }

        if self.container_path.is_some() {
            Self::install_runc().await?;

            if !Self::is_container_running().await? {
                Self::start_winexe_container(self.container_path.clone().unwrap()).await?;
            }

            while !Self::is_container_running().await? {
                sleep(Duration::from_secs(1)).await;
            }
        }

        let mut session = Self::establish_connection(
            self.ip.clone().unwrap(),
            creds.username.to_string(),
            creds.password.clone(),
            self.container_path.is_some(),
        )
        .await?;

        session.start_receiver().await;

        Ok(session)
    }

    // Builder methods that modify the fields
    pub fn container_path(&mut self, path: String) -> &mut Self {
        self.container_path = Some(path);
        self
    }

    pub fn ip(&mut self, ip: &str) -> &mut Self {
        self.ip = Some(ip.to_string());
        self
    }

    // Checks if winexe container is running
    async fn is_container_running() -> Result<bool, std::io::Error> {
        let runc_path = if WinexeClient::is_runc_in_path()? {
            "runc"
        } else {
            "/tmp/runc"
        };

        // Checks runc list command to see if winexe is in the output
        let output = Command::new(runc_path).arg("list").output().await?;

        // Check if the command execution was successful
        if !output.status.success() {
            eprintln!("Command failed to execute");
            return Ok(false);
        }

        // Convert the output to a string
        let output_str = String::from_utf8_lossy(&output.stdout);

        // Check if the output contains the specified substring
        Ok(output_str.contains("winexe-container"))
    }

    // Creates winexe session
    async fn establish_connection(
        ip: String,
        user: String,
        password: Option<String>,
        needs_container: bool,
    ) -> Result<WinexeSession, std::io::Error> {
        let file_name = format!("/tmp/{}", rand::thread_rng().gen::<u64>());
        let output_file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&file_name)
            .await?;

        let runc_path = if WinexeClient::is_runc_in_path()? {
            "runc"
        } else {
            "/tmp/runc"
        };

        // Establish a connection to the remote host using winexe or winexe-container
        let mut cmd = Command::new(if needs_container { runc_path } else { "winexe" });

        // Container specific arguments
        if needs_container {
            cmd.arg("exec").arg("winexe-container").arg("winexe");
        }

        // User flag
        cmd.arg("-U");

        // User authentication
        let user_auth = match password {
            Some(password) => format!("{}%{}", user, password),
            None => user,
        };

        // Add authentication
        cmd.arg(user_auth)
            .arg(format!("//{}", ip))
            .arg("cmd.exe")
            .stdin(std::process::Stdio::piped()) // Bind stdin
            .stdout(std::process::Stdio::from(output_file.into_std().await)) // Bind stdout
            .stderr(std::process::Stdio::piped());

        println!("Establishing Connection{:?}", cmd);
        // Spawn the child process but do not wait for it here
        let child = cmd.spawn()?;

        // Return session
        Ok(WinexeSession {
            child_process: Arc::new(Mutex::new(child)),
            output_file_name: file_name.clone(),
            command_sender: None,
            ready_receiver: None,
            output_file: Arc::new(Mutex::new(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&file_name)
                    .await?,
            )),
            ip: ip.clone().into(),
        })
    }

    // Starts winexe container
    async fn start_winexe_container(container_path: String) -> Result<(), std::io::Error> {
        let runc_path = if WinexeClient::is_runc_in_path()? {
            "runc"
        } else {
            "/tmp/runc"
        };

        let mut cmd = Command::new(runc_path);
        cmd.arg("run")
            .arg("-d")
            .arg("--bundle")
            .arg(container_path)
            .arg("winexe-container");
        let mut child = cmd.spawn()?;
        let _ = child.wait().await?;

        Ok(())
    }

    // Installs low level container runtime
    async fn install_runc() -> Result<(), Box<dyn std::error::Error>> {
        // Check if runc is already installed
        if WinexeClient::is_runc_in_path()? {
            return Ok(());
        }

        // Decompress CHIMERA
        let mut decoder = ZlibDecoder::new(&RUNC[..]);
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data)?;

        let mut file = File::create("/tmp/runc").await?;

        file.write_all(&decompressed_data).await?;
        let mut perms = file.metadata().await?.permissions();
        perms.set_mode(0o744); // User can read, write, and execute. Others can only read.
        fs::set_permissions("/tmp/runc", perms)?;

        Ok(())
    }

    // Destroys winexe container
    fn destroy_winexe_container(&self) -> Result<(), std::io::Error> {
        // if runc not installed set runc path to /tmp/runc else use runc
        let runc_path = if WinexeClient::is_runc_in_path()? {
            "runc"
        } else {
            "/tmp/runc"
        };

        // First, try to stop the container
        let stop_output = std::process::Command::new(runc_path)
            .arg("kill")
            .arg("winexe-container")
            .arg("SIGKILL") // Send a SIGTERM signal to gracefully stop the container
            .output()?;

        if !stop_output.status.success() {
            eprintln!("Failed to stop winexe-container.");
            eprintln!("Stdout: {}", String::from_utf8_lossy(&stop_output.stdout));
            eprintln!("Stderr: {}", String::from_utf8_lossy(&stop_output.stderr));
        }

        // Then, destroy the container
        let destroy_output = std::process::Command::new(runc_path)
            .arg("delete")
            .arg("winexe-container")
            .output()?;

        if destroy_output.status.success() {
            println!("Successfully destroyed winexe-container.");
        } else {
            eprintln!("Failed to destroy winexe-container.");
            eprintln!(
                "Stdout: {}",
                String::from_utf8_lossy(&destroy_output.stdout)
            );
            eprintln!(
                "Stderr: {}",
                String::from_utf8_lossy(&destroy_output.stderr)
            );
        }

        Ok(())
    }

    // Checks if runc is installed
    fn is_runc_in_path() -> Result<bool, std::io::Error> {
        if let Ok(path) = env::var("PATH") {
            for p in env::split_paths(&path) {
                if p.join("runc").exists() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

#[async_trait]
impl Session for WinexeSession {
    // Exectues command on winexe session
    async fn execute_command(&self, command: &str) -> Result<Option<String>, std::io::Error> {
        // Send the command
        if let Some(sender) = &self.command_sender {
            let (completion_sender, completion_receiver) = tokio::sync::oneshot::channel();

            sender
                .send((command.to_string(), completion_sender))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Failed to send command")
                })?;

            completion_receiver.await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Command execution did not complete",
                )
            })?;
        }

        let mut dst = String::new();

        let mut output = self.output_file.lock().await;

        let _ = output.read_to_string(&mut dst).await;

        let parsed = dst
            .split(command)
            .last()
            .and_then(|line| line.split_once("\r\n\r\nC:\\"))
            .map(|(output, _)| output)
            .unwrap_or_default(); // or handle the error case as you need

        Ok(Some(parsed.to_string()))
    }

    fn get_ip(&self) -> &Box<str> {
        &self.ip
    }

    async fn close(&self) -> Result<(), std::io::Error> {
        // // Get output files

        // Locks and closes winexe session
        let mut child = self.child_process.lock().await;
        let _ = child.kill().await;

        println!("File size is now 1 byte, so the command has finished executing");
        Ok(())
    }
}
