pub mod client;

// use crate::client::client::Host;
// use crate::client::client::OS;
use crate::client::types::Host;

fn main() {
    let c = Host::new();
    let serialized = serde_json::to_string(&c).unwrap();
    // println!("Serialized Client to JSON: {}", serialized);
    println!("{:?}", c.services);
    // println!("{}", c.);
    // println!("{:?}", c.shares);
    // println!("Ports: {:?}", c.ports);
}
