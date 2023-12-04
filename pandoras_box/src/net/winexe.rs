use crate::net::communicator::{Credentials, Session};
use async_trait::async_trait;
use rand::Rng;
use reqwest;
use reqwest::Url;
use std::env;
use std::fs;
use std::fs::File;
use std::io::copy;
use std::option::Option;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, ChildStdout, Command as AsyncCommand};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::sleep;
// use tokio::io::
use tokio::fs::File as AsyncFile;
use tokio::fs::OpenOptions;
use tokio::io::AsyncReadExt;

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
    output_file: Arc<Mutex<AsyncFile>>,
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
        let mut file = AsyncFile::open(&file_path).await.unwrap();

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

    pub async fn connect<'a>(
        &mut self,
        creds: &Credentials<'a>,
    ) -> Result<WinexeSession, Box<dyn std::error::Error>> {
        if self.ip.is_none() {
            return Err("Please configure ip()".into());
        }

        if self.container_path.is_some() {
            Self::install_runc().await?;

            if !Self::is_container_running().await? {
                Self::start_winexe_container(self.container_path.clone().unwrap())?;
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

    pub fn ip(&mut self, ip: String) -> &mut Self {
        self.ip = Some(ip);
        self
    }

    // Checks if winexe container is running
    async fn is_container_running() -> Result<bool, std::io::Error> {
        // Checks runc list command to see if winexe is in the output
        let output = AsyncCommand::new("runc").arg("list").output().await?;

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

        // Establish a connection to the remote host using winexe or winexe-container
        let mut cmd = AsyncCommand::new(if needs_container { "runc" } else { "winexe" });

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
        })
    }

    // Starts winexe container
    fn start_winexe_container(container_path: String) -> Result<(), std::io::Error> {
        let mut cmd = Command::new("runc");
        cmd.arg("run")
            .arg("-d")
            .arg("--bundle")
            .arg(container_path)
            .arg("winexe-container");
        let mut child = cmd.spawn()?;
        let _ = child.wait()?;

        Ok(())
    }

    // Installs low level container runtime
    async fn install_runc() -> Result<(), Box<dyn std::error::Error>> {
        const BASE_URL: &str = "https://github.com/opencontainers/runc/releases/download/v1.1.9/";

        let architecture: &str = if cfg!(target_arch = "x86_64") {
            "runc.amd64"
        } else if cfg!(target_arch = "aarch64") {
            "runc.arm64"
        } else if cfg!(target_arch = "arm") && cfg!(target_endian = "little") {
            "runc.armel"
        } else if cfg!(target_arch = "arm") {
            "runc.armhf"
        } else if cfg!(target_arch = "powerpc64le") {
            "runc.ppc64le"
        } else if cfg!(target_arch = "riscv64") {
            "runc.riscv64"
        } else if cfg!(target_arch = "s390x") {
            "runc.s390x"
        } else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Unsupported architecture",
            )));
        };

        // Check if runc is already installed
        if WinexeClient::is_runc_in_path()? {
            return Ok(());
        }

        let download_url = format!("{}{}", BASE_URL, architecture);
        let response = reqwest::get(Url::parse(&download_url)?).await?;

        // Make sure the download was successful
        if !response.status().is_success() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Download failed",
            )));
        }

        // Create a file to write the runc binary into it
        let mut dest = {
            let fname = "/usr/local/bin/runc";
            let file = File::create(fname)?;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o744); // User can read, write, and execute. Others can only read.
            fs::set_permissions(fname, perms)?;
            file
        };

        // Asynchronously copy the data from the response to the file
        let content = response.bytes().await?;
        copy(&mut content.as_ref(), &mut dest)?;

        // Add the runc binary to the system's PATH
        let path_var = env::var_os("PATH").unwrap_or_default();
        let mut paths = env::split_paths(&path_var).collect::<Vec<_>>();
        paths.push("/usr/local/bin".into());
        let new_path = env::join_paths(paths)?;

        env::set_var("PATH", &new_path);

        Ok(())
    }

    // Destroys winexe container
    fn destroy_winexe_container(&self) -> Result<(), std::io::Error> {
        // First, try to stop the container
        let stop_output = std::process::Command::new("runc")
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
        let destroy_output = std::process::Command::new("runc")
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

    async fn close(&self) -> Result<(), std::io::Error> {
        // // Get output files

        // Locks and closes winexe session
        let mut child = self.child_process.lock().await;
        let _ = child.kill().await;

        println!("File size is now 1 byte, so the command has finished executing");
        Ok(())
    }
}
