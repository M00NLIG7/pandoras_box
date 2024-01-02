// Slackware Service Status
// ------------------------

// Network Services:
//   rc.inet1          [  started  ]
//   rc.inet2          [  started  ]
//   rc.sshd           [  started  ]
//   rc.httpd          [  stopped  ]
//   rc.nfsd           [  started  ]
//   rc.smbd           [  stopped  ]

// System Services:
//   rc.syslog         [  started  ]
//   rc.cupsd          [  started  ]
//   rc.crond          [  started  ]
//   rc.atd            [  stopped  ]
//   rc.hald           [  started  ]
//   rc.messagebus     [  started  ]

// Hardware Services:
//   rc.udev           [  started  ]
//   rc.bluetooth      [  stopped  ]
//   rc.pcmcia         [  started  ]
//   rc.acpid          [  started  ]
//   rc.lvm2           [  started  ]
//   rc.mdadm          [  started  ]

// Miscellaneous:
//   rc.local          [  started  ]
//   rc.mysqld         [  stopped  ]
//   rc.apache2        [  stopped  ]
//   rc.bind           [  started  ]
//   rc.ntpd           [  started  ]
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::thread;
use std::time::Duration;

const DOCKER_INSTALLER: &[u8] = include_bytes!("../includes/install_docker.sh");

fn main() -> anyhow::Result<()> {
    // If docker is already installed, return
    if Command::new("docker").output().is_ok() {
        println!("Docker is already installed");
        return Ok(());
    }

    // Create a temporary file to store the script
    let script_path = "/tmp/install_docker.sh";
    {
        let mut file = File::create(script_path)?;
        file.write_all(DOCKER_INSTALLER)?;
        file.flush()?; // Ensure all data is written

        // Make the script executable
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o755);
        file.set_permissions(permissions)?;
    } // File is closed here as it goes out of scope

    // Execute the script
    let output = Command::new(script_path).output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to install docker: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    } else if String::from_utf8_lossy(&output.stdout).contains("Unsupported distribution") {
        return Err(anyhow::anyhow!(
            "Failed to install docker: {}",
            String::from_utf8_lossy(&output.stdout)
        ));
    }

    Ok(())
}

