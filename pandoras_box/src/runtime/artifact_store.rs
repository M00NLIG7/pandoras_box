use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

static ATOMIC_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveMissionRecord {
    pub mission_id: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ArtifactRootLock {
    root: PathBuf,
    _file: Arc<File>,
}

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
    mission_id: String,
    root_lock: Option<ArtifactRootLock>,
}

impl PartialEq for ArtifactStore {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.mission_id == other.mission_id
    }
}

impl Eq for ArtifactStore {}

impl ArtifactStore {
    #[must_use]
    pub fn active_mission_path(root: impl AsRef<Path>) -> PathBuf {
        root.as_ref().join(".active_mission.json")
    }

    pub fn new(root: impl Into<PathBuf>, mission_id: impl Into<String>) -> io::Result<Self> {
        let mission_id = mission_id.into();
        validate_mission_id(&mission_id)?;
        Ok(Self {
            root: root.into(),
            mission_id,
            root_lock: None,
        })
    }

    pub(crate) fn new_locked(
        root: impl Into<PathBuf>,
        mission_id: impl Into<String>,
        root_lock: &ArtifactRootLock,
    ) -> io::Result<Self> {
        let root = root.into();
        if root != root_lock.root {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact root does not match the held mission lock",
            ));
        }
        let mut store = Self::new(root, mission_id)?;
        store.root_lock = Some(root_lock.clone());
        Ok(store)
    }

    pub(crate) async fn acquire_root_lock(
        root: impl Into<PathBuf>,
    ) -> io::Result<ArtifactRootLock> {
        let root = root.into();
        tokio::fs::create_dir_all(&root).await?;
        let lock_path = root.join(".pandoras_box.lock");
        let file = tokio::task::spawn_blocking(move || {
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&lock_path)?;
            file.try_lock().map_err(|err| match err {
                std::fs::TryLockError::WouldBlock => io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "another Pandora mission is active in this artifact root",
                ),
                std::fs::TryLockError::Error(err) => err,
            })?;
            Ok::<File, io::Error>(file)
        })
        .await
        .map_err(|err| io::Error::other(format!("artifact lock task failed: {err}")))??;

        Ok(ArtifactRootLock {
            root,
            _file: Arc::new(file),
        })
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
        atomic_write(self.mission_manifest_path(), contents.as_bytes()).await
    }

    pub async fn write_summary(&self, contents: &str) -> io::Result<()> {
        atomic_write(self.summary_path(), contents.as_bytes()).await
    }

    pub async fn write_asset_inventory_json(&self, contents: &str) -> io::Result<()> {
        atomic_write(self.asset_inventory_json_path(), contents.as_bytes()).await
    }

    pub async fn write_asset_inventory_markdown(&self, contents: &str) -> io::Result<()> {
        atomic_write(self.asset_inventory_markdown_path(), contents.as_bytes()).await
    }

    pub async fn write_asset_inventory_csv(&self, contents: &str) -> io::Result<()> {
        atomic_write(self.asset_inventory_csv_path(), contents.as_bytes()).await
    }

    pub async fn write_asset_inventory_pdf(&self, contents: &[u8]) -> io::Result<()> {
        atomic_write(self.asset_inventory_pdf_path(), contents).await
    }

    pub async fn write_network_topology_markdown(&self, contents: &str) -> io::Result<()> {
        atomic_write(self.network_topology_markdown_path(), contents.as_bytes()).await
    }

    pub async fn write_network_topology_mermaid(&self, contents: &str) -> io::Result<()> {
        atomic_write(self.network_topology_mermaid_path(), contents.as_bytes()).await
    }

    pub async fn write_network_topology_excalidraw(&self, contents: &str) -> io::Result<()> {
        atomic_write(self.network_topology_excalidraw_path(), contents.as_bytes()).await
    }

    pub async fn write_network_topology_png(&self, contents: &[u8]) -> io::Result<()> {
        atomic_write(self.network_topology_png_path(), contents).await
    }

    pub async fn write_host_plan(&self, ip: IpAddr, contents: &str) -> io::Result<()> {
        atomic_write(self.host_plan_path(ip), contents.as_bytes()).await
    }

    pub async fn write_host_status(&self, ip: IpAddr, contents: &str) -> io::Result<()> {
        atomic_write(self.host_status_path(ip), contents.as_bytes()).await
    }

    pub async fn read_host_status(&self, ip: IpAddr) -> io::Result<String> {
        tokio::fs::read_to_string(self.host_status_path(ip)).await
    }

    pub(crate) async fn read_active_mission(
        root_lock: &ArtifactRootLock,
    ) -> io::Result<Option<ActiveMissionRecord>> {
        let path = Self::active_mission_path(&root_lock.root);
        match tokio::fs::read_to_string(&path).await {
            Ok(raw) => {
                let record: ActiveMissionRecord =
                    serde_json::from_str(&raw).map_err(io::Error::other)?;
                validate_mission_id(&record.mission_id)?;
                Ok(Some(record))
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub(crate) async fn write_active_mission(
        root_lock: &ArtifactRootLock,
        record: &ActiveMissionRecord,
    ) -> io::Result<()> {
        validate_mission_id(&record.mission_id)?;
        let payload = serde_json::to_string_pretty(record).map_err(io::Error::other)? + "\n";
        atomic_write(
            Self::active_mission_path(&root_lock.root),
            payload.as_bytes(),
        )
        .await
    }

    async fn clear_active_mission(root_lock: &ArtifactRootLock) -> io::Result<()> {
        match tokio::fs::remove_file(Self::active_mission_path(&root_lock.root)).await {
            Ok(()) => sync_parent_directory(&root_lock.root).await,
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub(crate) async fn clear_active_mission_if_matches(&self, mission_id: &str) -> io::Result<()> {
        let root_lock = self.root_lock.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "active mission state requires the artifact root lock",
            )
        })?;
        let Some(record) = Self::read_active_mission(root_lock).await? else {
            return Ok(());
        };
        if record.mission_id == mission_id {
            Self::clear_active_mission(root_lock).await?;
        }
        Ok(())
    }
}

pub fn validate_mission_id(mission_id: &str) -> io::Result<()> {
    let valid_length = !mission_id.is_empty() && mission_id.len() <= 128;
    let valid_characters = mission_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    let valid_edges = mission_id
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && mission_id
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));

    if valid_length && valid_characters && valid_edges {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mission identifier must be one portable path component (1-128 ASCII letters, digits, '.', '_', or '-', beginning with a letter or digit and not ending with '.')",
        ))
    }
}

async fn atomic_write(path: PathBuf, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("atomic write path has no parent: {}", path.display()),
        )
    })?;
    tokio::fs::create_dir_all(parent).await?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "atomic write path has no UTF-8 file name: {}",
                    path.display()
                ),
            )
        })?;
    let mut temporary_path;
    let mut temporary_file;
    loop {
        let sequence = ATOMIC_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        temporary_path = parent.join(format!(
            ".{file_name}.tmp-{}-{sequence}",
            std::process::id()
        ));
        match tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)
            .await
        {
            Ok(file) => {
                temporary_file = file;
                break;
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    let write_result = async {
        temporary_file.write_all(contents).await?;
        temporary_file.flush().await?;
        temporary_file.sync_all().await?;
        drop(temporary_file);
        replace_file(&temporary_path, &path).await?;
        sync_parent_directory(parent).await
    }
    .await;

    if write_result.is_err() {
        let _ = tokio::fs::remove_file(&temporary_path).await;
    }
    write_result
}

#[cfg(not(windows))]
async fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    tokio::fs::rename(source, destination).await
}

#[cfg(windows)]
async fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
async fn sync_parent_directory(directory: &Path) -> io::Result<()> {
    let directory = directory.to_owned();
    tokio::task::spawn_blocking(move || File::open(directory)?.sync_all())
        .await
        .map_err(|err| io::Error::other(format!("directory sync task failed: {err}")))?
}

#[cfg(not(unix))]
async fn sync_parent_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_mission_id, ArtifactStore};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn artifact_store_plans_deterministic_paths() {
        let store = ArtifactStore::new("/tmp/pandoras-box", "mission-123")
            .expect("mission identifier should be valid");
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

    #[test]
    fn artifact_store_rejects_non_portable_mission_components() {
        for mission_id in [
            "",
            ".",
            "..",
            "../escape",
            "/tmp/escape",
            r"..\escape",
            "two/components",
            "line\nbreak",
            ".hidden",
            "trailing.",
        ] {
            assert!(
                validate_mission_id(mission_id).is_err(),
                "{mission_id:?} should be rejected"
            );
            assert!(ArtifactStore::new("/tmp/pandoras-box", mission_id).is_err());
        }

        for mission_id in ["mission-123", "20260814", "lab.alpha_2"] {
            validate_mission_id(mission_id).expect("portable mission identifier should be valid");
        }
    }

    #[tokio::test]
    async fn artifact_root_lock_rejects_concurrent_active_missions() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pandoras-box-lock-{unique}"));

        let first = ArtifactStore::acquire_root_lock(root.clone())
            .await
            .expect("first mission should acquire the root lock");
        let error = ArtifactStore::acquire_root_lock(root.clone())
            .await
            .expect_err("concurrent mission should not acquire the same root lock");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(error
            .to_string()
            .contains("another Pandora mission is active"));

        drop(first);
        let second = ArtifactStore::acquire_root_lock(root.clone())
            .await
            .expect("root lock should become available after the mission ends");
        drop(second);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn active_mission_reader_rejects_escaped_identifiers() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pandoras-box-active-input-{unique}"));
        let root_lock = ArtifactStore::acquire_root_lock(root.clone())
            .await
            .expect("artifact root lock should be available");
        tokio::fs::write(
            ArtifactStore::active_mission_path(&root),
            r#"{"mission_id":"../escape","signature":"fixture"}"#,
        )
        .await
        .expect("malicious fixture should be written");

        let error = ArtifactStore::read_active_mission(&root_lock)
            .await
            .expect_err("escaped active mission should be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

        drop(root_lock);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn durable_state_writes_replace_complete_files_without_temp_residue() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pandoras-box-atomic-{unique}"));
        let store =
            ArtifactStore::new(&root, "mission-123").expect("mission identifier should be valid");
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let mut tasks = tokio::task::JoinSet::new();

        for sequence in 0..32 {
            let store = store.clone();
            tasks.spawn(async move {
                store
                    .write_host_status(ip, &format!(r#"{{"sequence":{sequence}}}"#))
                    .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            result
                .expect("atomic writer task should not panic")
                .expect("atomic writer should succeed");
        }

        let status = store
            .read_host_status(ip)
            .await
            .expect("one complete status file should remain");
        let parsed: serde_json::Value =
            serde_json::from_str(&status).expect("atomic result should be complete JSON");
        assert!(parsed["sequence"].as_u64().is_some());
        let mut entries = tokio::fs::read_dir(store.host_dir(ip))
            .await
            .expect("host directory should exist");
        while let Some(entry) = entries
            .next_entry()
            .await
            .expect("host directory should be readable")
        {
            assert!(
                !entry.file_name().to_string_lossy().contains(".tmp-"),
                "atomic temporary files must not remain"
            );
        }

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn artifact_store_creates_host_layout() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pandoras-box-artifacts-{unique}"));
        let store =
            ArtifactStore::new(&root, "mission-123").expect("mission identifier should be valid");
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
