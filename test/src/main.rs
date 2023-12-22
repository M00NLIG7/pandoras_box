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
use std::collections::HashMap;
use std::process::Command;

fn fetch_service_statuses() -> HashMap<String, String> {
    let output = Command::new("systemctl")
        .arg("list-unit-files")
        .arg("--type=service")
        .output()
        .expect("Failed to execute systemctl");

    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut service_statuses = HashMap::new();

    for line in output_str.lines() {
        if let Some((service, status)) = line.split_once(' ') {
            service_statuses.insert(
                service.to_string(),
                status.trim().split_whitespace().next().unwrap().to_string(),
            );
        }
    }

    service_statuses
}

fn main() {
    println!("{:?}", fetch_service_statuses().len());
    for (service, status) in fetch_service_statuses() {
        println!("service {} Status {}", service, status);
    }
}
