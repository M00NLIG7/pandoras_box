use std::env;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;

fn usage() -> ! {
    eprintln!("usage: tcp-port-proxy <listen-host> <listen-port> <target-host> <target-port>");
    std::process::exit(1);
}

fn copy_loop(mut reader: TcpStream, mut writer: TcpStream) {
    let result = io::copy(&mut reader, &mut writer);
    if let Err(err) = writer.shutdown(Shutdown::Write) {
        eprintln!("proxy shutdown error: {err}");
    }
    if let Err(err) = result {
        eprintln!("proxy copy error: {err}");
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(listen_host) = args.next() else {
        usage();
    };
    let Some(listen_port_raw) = args.next() else {
        usage();
    };
    let Some(target_host) = args.next() else {
        usage();
    };
    let Some(target_port_raw) = args.next() else {
        usage();
    };

    if args.next().is_some() {
        usage();
    }

    let listen_port: u16 = listen_port_raw
        .parse()
        .unwrap_or_else(|_| panic!("invalid listen port: {}", listen_port_raw));
    let target_port: u16 = target_port_raw
        .parse()
        .unwrap_or_else(|_| panic!("invalid target port: {}", target_port_raw));

    let listen_addr = format!("{listen_host}:{listen_port}");
    let target_addr = format!("{target_host}:{target_port}");
    let listener = TcpListener::bind(&listen_addr)
        .unwrap_or_else(|err| panic!("failed to bind {}: {}", listen_addr, err));

    for incoming in listener.incoming() {
        let client = match incoming {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("proxy accept error: {err}");
                continue;
            }
        };

        let upstream_addr = target_addr.clone();
        thread::spawn(move || {
            let upstream_target = upstream_addr
                .to_socket_addrs()
                .unwrap_or_else(|err| panic!("failed to resolve {}: {}", upstream_addr, err))
                .next()
                .unwrap_or_else(|| panic!("no target address resolved for {}", upstream_addr));
            let upstream = match TcpStream::connect(upstream_target) {
                Ok(stream) => stream,
                Err(err) => {
                    eprintln!("proxy connect error to {upstream_addr}: {err}");
                    return;
                }
            };

            if let Err(err) = client.set_nodelay(true) {
                eprintln!("proxy client nodelay error: {err}");
            }
            if let Err(err) = upstream.set_nodelay(true) {
                eprintln!("proxy upstream nodelay error: {err}");
            }

            let client_reader = client
                .try_clone()
                .unwrap_or_else(|err| panic!("failed to clone client socket: {}", err));
            let upstream_reader = upstream
                .try_clone()
                .unwrap_or_else(|err| panic!("failed to clone upstream socket: {}", err));

            let copy_upstream = thread::spawn(move || copy_loop(client_reader, upstream));
            let copy_client = thread::spawn(move || copy_loop(upstream_reader, client));

            let _ = copy_upstream.join();
            let _ = copy_client.join();
        });
    }
}
