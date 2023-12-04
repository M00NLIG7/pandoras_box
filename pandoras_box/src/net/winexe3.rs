use std::env;
use std::fmt::format;
use std::process::{Command, ExitStatus};
use rand::Rng;
use std::time::Duration;
use futures::future::ok;
use tokio::process::{Command as AsyncCommand, Child, ChildStdout, ChildStdin};
use reqwest;
use tokio::time::sleep;
use tokio::time::Instant;
use tokio::time::interval;
use tokio::io;
use std::fs::File;
use reqwest::Url;
use std::io::{copy, SeekFrom};
use std::os::unix::fs::PermissionsExt;
use std::fs;
use crate::connection::communicator::{Communicator, Credentials};
use std::option::Option;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::io::BufReader;
use tokio::io::AsyncSeekExt;
use tokio::sync::oneshot;
use tokio::sync::mpsc;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncBufReadExt;
use async_trait::async_trait;
// use tokio::io::  
use std::io::Write;
use tokio::io::AsyncReadExt;
use tokio::fs::OpenOptions; 
use tokio::fs::File as AsyncFile; 
struct Session {
    child_process: Arc<Mutex<Child>>, // Used to keep track of actual winexe process 
    output_file: String, // tmp file to store stdout 
}

// Struct to keep track of winexe session
impl Session {

    // Kills the child process
    pub async fn close(&self) -> Result<(), std::io::Error> {
        let mut child = self.child_process.lock().await;
        println!("child {:?}", child.id());
        child.kill().await
    }

    // Sends any data(bytes) to stdin
    pub async fn write_to_stdin(&self, data: &[u8]) -> Result<(), std::io::Error> {
        let mut child = self.child_process.lock().await;

        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(data).await?;
            stdin.flush().await?;
        }

        Ok(())
    }
}

// Define Winexe Client (subject behind)
pub struct WinexeClient {
    session: Arc<Mutex<Session>>, // Winexe Session
    command_sender: mpsc::Sender<String>, // Channel to send commands to winexe session
}

// Winexe implementation
impl WinexeClient {
    pub async fn new<'a>(container_path: Option<String>, credentials: &Credentials<'a>, ip: String) -> Result<Self, Box<dyn std::error::Error>> {
        // Ensures low level contianer runtime is installed and that the winexe container is running if needed
        if let Some(path) = &container_path {
            Self::install_runc().await?;
            println!("Starting container");
            if !Self::is_container_running().await? {
                let _ = Self::start_winexe_container(path.to_string());  // Using cloned path
            }
        }

        // Define session for initializtion later
        let session: Arc<Mutex<Session>>;
        loop { // Keep looping until the container is running
           if Self::is_container_running().await? {
                // Create session based on credemtials and ip given 
                session = Arc::new(Mutex::new(
                    Self::create_session(
                            ip,
                            credentials.username.to_string(),
                            credentials.password.clone(),
                            container_path.is_some()
                        ).await?
                    )
                );
                break;
           } 
        } 

        // Open channel to send commands to winexe session
        let (command_sender, mut command_receiver) = mpsc::channel::<String>(32);

        // Open channel to send ready signal to winexe session
        let (ready_sender, ready_receiver) = oneshot::channel();

        // Clone session to be used in tokio::spawn in background
        let session_clone = Arc::clone(&session);
        tokio::spawn(async move {
            let _ = ready_sender.send(());

            // Waits for command to be sent to channel and then sends it to winexe session 
            while let Some(command) = command_receiver.recv().await {
                // Lock session to avoid race conditions
                let session = session_clone.lock().await;

                // Send command to winexe session 
                let _ = session.write_to_stdin(command.as_bytes()).await;
                println!("Executing commadn inside of my channel {}", command);
            }
        }); 

        // Wait for ready signal to be sent to winexe session
        let _ = ready_receiver.await;

        // Return winexe client 
        Ok(WinexeClient { 
                session: session, 
                command_sender: command_sender, 
            }
        )

    } 

    pub fn build() {

    }

    // Setter for container_path
    pub fn container_path(mut self, path: String) -> Self {
        self.container_path = Some(path);
        self
    }

    // Setter for credentials
    pub fn credentials(mut self, credentials: Credentials<'a>) -> Self {
        self.credentials = Some(credentials);
        self
    }

    // Setter for IP address
    pub fn ip(mut self, ip: String) -> Self {
        self.ip = Some(ip);
        self
    } 

    async fn set_file_length(file_path: &str, length: u64) -> Result<(), std::io::Error> {
        let file = AsyncFile::create(file_path).await?;
        file.set_len(length).await?;
        Ok(())
    }

    async fn read_file_from_end(file_path: &str, offset: i64) -> Result<String, std::io::Error> {
        // Read the file's contents into a string
        let mut file = AsyncFile::open(&file_path).await?;
        file.seek(SeekFrom::End(offset)).await?;

        let mut contents = String::new();

        file.read_to_string(&mut contents).await?;
        
        Ok(contents)
    }

    fn is_finished(contents: &str, num_lines: usize) -> bool {
        let lines: Vec<_> = contents
            .lines()
            .rev()
            .take(num_lines)
            .filter(|line| line.contains(">") && line.contains("C:\\"))
            .collect();
        
        !lines.is_empty()
    }

 
 
    // Closes winexe session when called, ensures that in progress command has finished executing
    pub async fn close(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Get output files
        let file_path = self.session.lock().await.output_file.clone();
        let metadata = tokio::fs::metadata(&file_path).await?;
        let size: i64 = metadata.len() as i64;
        let offset: i64 = -std::cmp::min(size, 500);

        loop {
            // Sleep for a short interval (e.g., 1 second) before checking again
            tokio::time::sleep(Duration::from_secs(1)).await;

            let contents = Self::read_file_from_end(&file_path, offset).await?; 

            if Self::is_finished(&contents, 5) {
                break;
            }
        }

        // Locks and closes winexe session
        self.session.lock().await.close().await?;
        println!("File size is now 1 byte, so the command has finished executing");
        Ok(())
    }

    // Checks if winexe container is running
    async fn is_container_running() -> Result<bool, std::io::Error> {
        // Checks runc list command to see if winexe is in the output
        // let cmdo = AsyncCommand::new("runc").arg("list").spawn(); 
        let output = AsyncCommand::new("runc")
            .arg("list")
            .output()
            .await?;
        // println!("{:?}", cmd.unwrap().stdout);
        // cmd.unwrap().stdouttake().

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
    async fn create_session(ip: String, user: String, password: Option<String>, needs_container: bool) -> Result<Session, std::io::Error> {
        println!("Establishing Conn");
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

        println!("Establishing Connection{:?}",cmd);
        // Spawn the child process but do not wait for it here
        let child = cmd.spawn()?;

        // Create the output file 
        let _ = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&file_name)
        .await?;

        // Return session
        Ok(Session {
                child_process: Arc::new(Mutex::new(child)),
                output_file: file_name,
            })
    }

    // Starts winexe container
    fn start_winexe_container(container_path: String) -> Result<(), std::io::Error> {
        let mut cmd = Command::new("runc");
        cmd.arg("run").arg("-d").arg("--bundle").arg(container_path).arg("winexe-container");
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
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Unsupported architecture")));
        };

        // Check if runc is already installed
        if WinexeClient::is_runc_in_path()? {
            return Ok(());
        }

        let download_url = format!("{}{}", BASE_URL, architecture);
        let response = reqwest::get(Url::parse(&download_url)?).await?;

        // Make sure the download was successful
        if !response.status().is_success() {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Download failed")));
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

    // Sends command to winexe session
    async fn call(&self, command: String) -> Result<String, std::io::Error> {
        let file_path = self.session.lock().await.output_file.clone();
    
        // Send the command
        self.command_sender.send(command.clone()).await.expect("Failed to send command");
        
        let one_second = Duration::from_secs(1);

        let mut file_size = 0; // Track the previous file size

        loop {
            // Wait for one second
            sleep(one_second).await;
            
            // Check the file's size
            let metadata = tokio::fs::metadata(&file_path).await;
            
            match metadata {
                Ok(new_metadata) => {
                    let new_size = new_metadata.len();
                    if new_size == 0 {
                        println!("File is empty.");
                    } else {
                        println!("File size has changed to {} bytes.", new_size);
                    }
                    
                    // If the file size hasn't changed in the last second, set its length to 1 and exit the loop
                    if new_size == file_size {
                        
                        break;
                    }
                    
                    file_size = new_size; // Update the previous file size
                }
                Err(err) => {
                    eprintln!("Error getting file metadata: {}", err);
                }
            }
        }
        let output = tokio::fs::OpenOptions::new()
            .write(true)
            // .truncate(true)
            .open(&file_path)
            .await?;
                    
        let file_contents = fs::read_to_string(file_path)?;    

        output.set_len(0).await?; // Set len to magic length 1 to signal command has finished executing
        Ok(file_contents) 
    }
}

#[async_trait]
impl Communicator for WinexeClient {
    // Exectues command on winexe session
    async fn execute_command(
        &self,
        command: &str,
    ) -> Result<Option<String>, std::io::Error> {
        let output = self.call(format!("{}\n", command)).await?;

        Ok(Some(output))
    }
}
