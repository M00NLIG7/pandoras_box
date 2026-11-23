use crate::types::{NetworkConnection, OpenPort};

pub async fn conn_info() -> (Vec<NetworkConnection>, Vec<OpenPort>, Vec<String>) {
    (
        Vec::new(),
        Vec::new(),
        vec![format!(
            "network connection inventory is not implemented for {}",
            std::env::consts::OS
        )],
    )
}
