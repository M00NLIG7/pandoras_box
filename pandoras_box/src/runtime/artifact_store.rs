use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveMissionRecord {
    pub mission_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactStore {
    root: PathBuf,
    mission_id: String,
}

impl ArtifactStore {
    #[must_use]
    pub fn active_mission_path(root: impl AsRef<Path>) -> PathBuf {
        root.as_ref().join(".active_mission.json")
    }

    #[must_use]
    pub fn new(root: impl Into<PathBuf>, mission_id: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            mission_id: mission_id.into(),
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn mission_dir(&self) -> PathBuf {
        self.root.join(&self.mission_id)
    }

    #[must_use]
    pub fn mission_manifest_path(&self) -> PathBuf {
        self.mission_dir().join("mission.json")
    }

    #[must_use]
    pub fn summary_path(&self) -> PathBuf {
        self.mission_dir().join("summary.json")
    }

    #[must_use]
    pub fn asset_inventory_json_path(&self) -> PathBuf {
        self.mission_dir().join("asset_inventory.json")
    }

    #[must_use]
    pub fn asset_inventory_markdown_path(&self) -> PathBuf {
        self.mission_dir().join("asset_inventory.md")
    }

    #[must_use]
    pub fn asset_inventory_csv_path(&self) -> PathBuf {
        self.mission_dir().join("asset_inventory.csv")
    }

    #[must_use]
    pub fn asset_inventory_pdf_path(&self) -> PathBuf {
        self.mission_dir().join("asset_inventory.pdf")
    }

    #[must_use]
    pub fn network_topology_markdown_path(&self) -> PathBuf {
        self.mission_dir().join("network_topology.md")
    }

    #[must_use]
    pub fn network_topology_mermaid_path(&self) -> PathBuf {
        self.mission_dir().join("network_topology.mmd")
    }

    #[must_use]
    pub fn network_topology_excalidraw_path(&self) -> PathBuf {
        self.mission_dir().join("network_topology.excalidraw")
    }

    #[must_use]
    pub fn network_topology_png_path(&self) -> PathBuf {
        self.mission_dir().join("network_topology.png")
    }

    #[must_use]
    pub fn embedded_payload_dir(&self) -> PathBuf {
        self.mission_dir().join("payloads")
    }

    #[must_use]
    pub fn hosts_dir(&self) -> PathBuf {
        self.mission_dir().join("hosts")
    }

    #[must_use]
    pub fn host_dir(&self, ip: IpAddr) -> PathBuf {
        self.hosts_dir().join(ip.to_string())
    }

    #[must_use]
    pub fn host_plan_path(&self, ip: IpAddr) -> PathBuf {
        self.host_dir(ip).join("plan.json")
    }

    #[must_use]
    pub fn host_status_path(&self, ip: IpAddr) -> PathBuf {
        self.host_dir(ip).join("status.json")
    }

    #[must_use]
    pub fn host_exec_dir(&self, ip: IpAddr) -> PathBuf {
        self.host_dir(ip).join("exec")
    }

    #[must_use]
    pub fn host_files_dir(&self, ip: IpAddr) -> PathBuf {
        self.host_dir(ip).join("files")
    }

    #[must_use]
    pub fn host_logs_dir(&self, ip: IpAddr) -> PathBuf {
        self.host_dir(ip).join("logs")
    }

    #[must_use]
    pub fn host_inventory_path(&self, ip: IpAddr) -> PathBuf {
        self.host_files_dir(ip).join("inventory.json")
    }

    #[must_use]
    pub fn host_application_log_path(&self, ip: IpAddr) -> PathBuf {
        self.host_logs_dir(ip).join("application.log")
    }

    pub async fn ensure_layout<I>(&self, hosts: I) -> io::Result<()>
    where
        I: IntoIterator<Item = IpAddr>,
    {
        tokio::fs::create_dir_all(self.hosts_dir()).await?;

        for host in hosts {
            tokio::fs::create_dir_all(self.host_exec_dir(host)).await?;
            tokio::fs::create_dir_all(self.host_files_dir(host)).await?;
            tokio::fs::create_dir_all(self.host_logs_dir(host)).await?;
        }

        Ok(())
    }

    pub async fn write_mission_manifest(&self, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.mission_manifest_path(), contents).await
    }

    pub async fn write_summary(&self, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.summary_path(), contents).await
    }

    pub async fn write_asset_inventory_json(&self, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.asset_inventory_json_path(), contents).await
    }

    pub async fn write_asset_inventory_markdown(&self, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.asset_inventory_markdown_path(), contents).await
    }

    pub async fn write_asset_inventory_csv(&self, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.asset_inventory_csv_path(), contents).await
    }

    pub async fn write_asset_inventory_pdf(&self, contents: &[u8]) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.asset_inventory_pdf_path(), contents).await
    }

    pub async fn write_network_topology_markdown(&self, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.network_topology_markdown_path(), contents).await
    }

    pub async fn write_network_topology_mermaid(&self, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.network_topology_mermaid_path(), contents).await
    }

    pub async fn write_network_topology_excalidraw(&self, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.network_topology_excalidraw_path(), contents).await
    }

    pub async fn write_network_topology_png(&self, contents: &[u8]) -> io::Result<()> {
        tokio::fs::create_dir_all(self.mission_dir()).await?;
        tokio::fs::write(self.network_topology_png_path(), contents).await
    }

    pub async fn write_host_plan(&self, ip: IpAddr, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.host_dir(ip)).await?;
        tokio::fs::write(self.host_plan_path(ip), contents).await
    }

    pub async fn write_host_status(&self, ip: IpAddr, contents: &str) -> io::Result<()> {
        tokio::fs::create_dir_all(self.host_dir(ip)).await?;
        tokio::fs::write(self.host_status_path(ip), contents).await
    }

    pub async fn read_host_status(&self, ip: IpAddr) -> io::Result<String> {
        tokio::fs::read_to_string(self.host_status_path(ip)).await
    }

    pub async fn read_active_mission(
        root: impl AsRef<Path>,
    ) -> io::Result<Option<ActiveMissionRecord>> {
        let path = Self::active_mission_path(root);
        match tokio::fs::read_to_string(&path).await {
            Ok(raw) => serde_json::from_str(&raw)
                .map(Some)
                .map_err(io::Error::other),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn write_active_mission(
        root: impl AsRef<Path>,
        record: &ActiveMissionRecord,
    ) -> io::Result<()> {
        tokio::fs::create_dir_all(root.as_ref()).await?;
        let payload = serde_json::to_string_pretty(record).map_err(io::Error::other)?;
        tokio::fs::write(Self::active_mission_path(root), format!("{payload}\n")).await
    }

    pub async fn clear_active_mission(root: impl AsRef<Path>) -> io::Result<()> {
        match tokio::fs::remove_file(Self::active_mission_path(root)).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub async fn clear_active_mission_if_matches(
        root: impl AsRef<Path>,
        mission_id: &str,
    ) -> io::Result<()> {
        let root = root.as_ref();
        let Some(record) = Self::read_active_mission(root).await? else {
            return Ok(());
        };
        if record.mission_id == mission_id {
            Self::clear_active_mission(root).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ArtifactStore;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn artifact_store_plans_deterministic_paths() {
        let store = ArtifactStore::new("/tmp/pandoras-box", "mission-123");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8));

        assert_eq!(
            store.host_plan_path(ip),
            PathBuf::from("/tmp/pandoras-box/mission-123/hosts/10.0.0.8/plan.json")
        );
        assert_eq!(
            store.summary_path(),
            PathBuf::from("/tmp/pandoras-box/mission-123/summary.json")
        );
        assert_eq!(
            store.asset_inventory_json_path(),
            PathBuf::from("/tmp/pandoras-box/mission-123/asset_inventory.json")
        );
        assert_eq!(
            store.asset_inventory_pdf_path(),
            PathBuf::from("/tmp/pandoras-box/mission-123/asset_inventory.pdf")
        );
        assert_eq!(
            store.network_topology_mermaid_path(),
            PathBuf::from("/tmp/pandoras-box/mission-123/network_topology.mmd")
        );
        assert_eq!(
            store.network_topology_excalidraw_path(),
            PathBuf::from("/tmp/pandoras-box/mission-123/network_topology.excalidraw")
        );
        assert_eq!(
            store.network_topology_png_path(),
            PathBuf::from("/tmp/pandoras-box/mission-123/network_topology.png")
        );
    }

    #[tokio::test]
    async fn artifact_store_creates_host_layout() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pandoras-box-artifacts-{unique}"));
        let store = ArtifactStore::new(&root, "mission-123");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8));

        store
            .ensure_layout(vec![ip])
            .await
            .expect("layout should be created");

        assert!(tokio::fs::metadata(store.host_exec_dir(ip)).await.is_ok());
        assert!(tokio::fs::metadata(store.host_files_dir(ip)).await.is_ok());
        assert!(tokio::fs::metadata(store.host_logs_dir(ip)).await.is_ok());

        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
