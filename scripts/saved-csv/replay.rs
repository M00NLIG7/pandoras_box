#![allow(dead_code)]

mod host_types {
    use serde::{Deserialize, Serialize};
    include!("host_items.rs");
}

mod report {
    include!("csv_probe.rs");

    pub(super) fn replay() {
        let mut document = String::new();
        std::io::stdin().read_to_string(&mut document).unwrap();
        let typed = serde_json::from_str::<super::host_types::Host>(&document)
            .map(|host| serde_json::to_value(host).unwrap())
            .map_err(|error| error.to_string());
        let inventory =
            serde_json::from_str::<InventoryArtifact>(&document).map_err(|error| error.to_string());
        let saved_error = inventory.as_ref().err().cloned();
        let record = record_from_report(&context(), inventory);
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
            hosts: vec![record.host],
        };
        println!(
            "{}",
            serde_json::json!({
                "typed": typed,
                "saved_error": saved_error,
                "host": bundle.hosts[0],
                "peers": record.observed_peer_ips,
                "markdown": render_asset_inventory_markdown(&bundle),
            })
        );
    }
}

fn main() {
    report::replay();
}
