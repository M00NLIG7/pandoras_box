use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};
#[derive(Default, Clone, Copy)]
struct Tag;
impl Tag {
    fn as_str(&self) -> &str {
        "example"
    }
}
struct Target {
    ip: String,
    open_ports: Vec<u16>,
}
struct Contract {
    operating_system: Tag,
    architecture: Tag,
}
struct Payload {
    version: String,
    sha256: String,
}
struct Plan {
    target: Target,
    contract: Contract,
    payload: Option<Payload>,
    transport_chain: Vec<Tag>,
}
struct HostExecutionReport {
    plan: Plan,
    error: Option<String>,
    final_state: Tag,
    selected_transport: Option<Tag>,
    failure_phase: Option<Tag>,
    failure_disposition: Option<Tag>,
    cleanup_outcome: Tag,
    residue_present: bool,
    partial_collection: bool,
}
fn context() -> HostExecutionReport {
    HostExecutionReport {
        plan: Plan {
            target: Target {
                ip: "192.0.2.41".into(),
                open_ports: vec![],
            },
            contract: Contract {
                operating_system: Tag,
                architecture: Tag,
            },
            payload: None,
            transport_chain: vec![],
        },
        error: None,
        final_state: Tag,
        selected_transport: None,
        failure_phase: None,
        failure_disposition: None,
        cleanup_outcome: Tag,
        residue_present: false,
        partial_collection: false,
    }
}

use serde::{Deserialize, Serialize};
use std::io::Read;
include!("report_items.rs");

fn main() {
    let mut document = String::new();
    std::io::stdin().read_to_string(&mut document).unwrap();
    let inventory: InventoryArtifact = serde_json::from_str(&document).unwrap();
    let host = record_from_report(&context(), Ok(inventory)).host;
    let bundle = AssetInventoryBundle {
        mission_id: "example".into(),
        requested_targets: 1,
        reachable_targets: 1,
        unreachable_targets: 0,
        skipped_targets: 0,
        attempted_targets: 1,
        discovered_hosts: 1,
        completed_hosts: 1,
        failed_hosts: 0,
        partial_hosts: 0,
        hosts: vec![host],
    };
    print!("{}", render_asset_inventory_csv(&bundle));
}
