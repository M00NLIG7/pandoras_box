use std::path::{Path, PathBuf};

pub(crate) fn inventory_path(directory: &Path, host_name: Option<&str>) -> PathBuf {
    match host_name {
        Some(host) => directory.join(format!("{}.json", host)),
        None => directory.join("inventory.json"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_directory_uses_inventory_filename() {
        let dir = Path::new("default-output");
        assert_eq!(inventory_path(dir, None), dir.join("inventory.json"));
    }

    #[test]
    fn custom_directory_uses_host_filename() {
        let dir = Path::new("custom-output");
        assert_eq!(
            inventory_path(dir, Some("sample-node")),
            dir.join("sample-node.json")
        );
    }
}
