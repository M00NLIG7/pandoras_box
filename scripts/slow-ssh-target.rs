use std::env;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn usage() -> ! {
    eprintln!("usage: slow-ssh-target <listen-host> <listen-port>");
    std::process::exit(1);
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(listen_host) = args.next() else {
        usage();
    };
    let Some(listen_port_raw) = args.next() else {
        usage();
    };

    if args.next().is_some() {
        usage();
    }

    let listen_port: u16 = listen_port_raw
        .parse()
        .unwrap_or_else(|_| panic!("invalid listen port: {}", listen_port_raw));
    let listen_addr = format!("{listen_host}:{listen_port}");
    let listener = TcpListener::bind(&listen_addr)
        .unwrap_or_else(|err| panic!("failed to bind {}: {}", listen_addr, err));

    for incoming in listener.incoming() {
        match incoming {
            Ok(socket) => {
                eprintln!("accepted slow SSH connection");
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(30));
                    drop(socket);
                });
            }
            Err(err) => {
                eprintln!("slow SSH accept error: {err}");
            }
        }
    }
}
