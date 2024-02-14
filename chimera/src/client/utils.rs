use std::fs::File;
use std::fs::Permissions;
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const DOCKER_INSTALLER: &[u8] = include_bytes!("../../includes/install_docker.sh");
const DOCKER_COMPOSE: &[u8] = include_bytes!("../../includes/docker-compose.yml");

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

#[cfg(target_os = "linux")]
// Install docker
pub fn install_docker() -> anyhow::Result<()> {
    // Check if Docker is already installed
    if Command::new("docker").output().is_ok() {
        println!("Docker is already installed.");
        return Ok(());
    }

    // Create a temporary file to store the script
    let script_path = "/tmp/install_docker.sh";
    {
        let mut file = File::create(script_path)?;
        file.write_all(DOCKER_INSTALLER)?;
        file.flush()?;

        // Make the script executable
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o755);
        file.set_permissions(permissions)?;
    }

    // Execute the script
    let output = Command::new(script_path).output()?;

    if !output.status.success() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "Failed to install Docker: {}",
            error_message
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn install_serial_scripter(api_key: &str, lifetime: u8) -> anyhow::Result<()> {
    // Write docker-compose to file at /tmp and execute it detatched
    let mut file = File::create("/tmp/docker-compose.yml")?;
    file.write_all(DOCKER_COMPOSE)?;

    let docker_compose_prefix = if which::which("docker-compose").is_ok() {
        "docker-compose"
    } else {
        "docker compose"
    };

    let mut command = Command::new("sh");

    command.arg("-c").arg(format!(
        "{} -f /tmp/docker-compose.yml up -d",
        docker_compose_prefix
    ));

    // docker-compose up -d
    command.env("API_KEY", api_key);
    command.env("API_KEY_LIFETIME", lifetime.to_string());

    match command.output() {
        Ok(output) => {
            println!("output: {}", String::from_utf8_lossy(&output.stdout));
            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "Failed to install serial-scripter: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
        Err(e) => {
            println!("Failed to install serial-scripter: {}", e);
            return Err(anyhow::anyhow!("Failed to install serial-scripter: {}", e));
        }
    }
    //
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn is_docker_compatabile() -> bool {
    if which::which("docker").is_ok() {
        return true;
    }
    // delete the script if it exists
    let script_path = Path::new("/tmp/install_docker.sh");
    if script_path.exists() {
        std::fs::remove_file(script_path).unwrap();
    }

    match write_docker_script() {
        Ok(_) => {
            let output = Command::new("/tmp/install_docker.sh")
                .arg("--dryrun")
                .output()
                .unwrap();

            if !output.status.success() {
                return false;
            }

            let output_string = String::from_utf8_lossy(&output.stdout);

            return !output_string.contains("end-of-life");
        }
        Err(e) => {
            println!("Failed to install Docker: {}", e);
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn write_docker_script() -> anyhow::Result<()> {
    let script_path = Path::new("/tmp/install_docker.sh");

    if !script_path.exists() {
        // Create a temporary file to store the script
        let mut file = File::create(script_path)?;
        file.write_all(DOCKER_INSTALLER)?;
        file.flush()?;

        // Make the script executable
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o755);
        file.set_permissions(permissions)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
// Install docker
pub fn install_docker() -> anyhow::Result<()> {
    // Check if Docker is already installed
    if which::which("docker").is_ok() {
        return Ok(());
    }

    write_docker_script()?;

    // Execute the script
    let output = Command::new("/tmp/install_docker.sh").output()?;

    if !output.status.success() {
        let error_message = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "Failed to install Docker: {}",
            error_message
        ));
    }

    Ok(())
}
