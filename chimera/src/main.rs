pub mod client;

use crate::client::client::Host;
use crate::client::client::NetworkInfo;

fn main() {
    let c = Host::new();
    // println!("Ports: {:?}", c.ports);
    println!("{:?}", c.shares);
    // println!("{:?}", c.containers);
    // NetworkInfo::ports();
}
