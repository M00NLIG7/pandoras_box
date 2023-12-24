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
use std::io::{self, Read};
use std::net::TcpStream;
use std::str;
fn ssh_is_open(ip: &str) -> Result<bool, io::Error> {
    let target = format!("{}:22", ip); // Replace with your target IP or hostname
    let mut stream = TcpStream::connect(target)?;

    let mut buffer = [0; 1024];
    let bytes_read = stream.read(&mut buffer)?;

    let banner = str::from_utf8(&buffer[..bytes_read]).unwrap_or_else(|_| "<Invalid UTF-8 data>");

    Ok(banner.contains("OpenSSH"))
}
fn main() -> io::Result<()> {
    let ip = "localhost";
    let is_open = ssh_is_open(ip)?;
    println!("Is port 22 open on {}? {}", ip, is_open);

    Ok(())
}
