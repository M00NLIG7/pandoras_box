use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use super::mission::{
    CpuArchitecture, OperatingSystem, PayloadQualification, PayloadSpec, ResolvedPayload,
    TargetContract,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PayloadKey {
    pub operating_system: OperatingSystem,
    pub architecture: CpuArchitecture,
}

impl PayloadKey {
    #[must_use]
    pub fn new(operating_system: OperatingSystem, architecture: CpuArchitecture) -> Self {
        Self {
            operating_system,
            architecture,
        }
    }
}

impl fmt::Display for PayloadKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/{}",
            self.operating_system.as_str(),
            self.architecture.as_str()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadSelectionError {
    UnknownTarget,
    Missing { key: PayloadKey },
    Ambiguous { key: PayloadKey },
    Invalid { key: PayloadKey, reason: String },
    NotLiveQualified { key: PayloadKey, version: String },
}

impl fmt::Display for PayloadSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTarget => formatter.write_str(
                "target has no explicit operating-system/architecture contract; authentication was not attempted",
            ),
            Self::Missing { key } => write!(
                formatter,
                "no exact payload is packaged for {key}; authentication was not attempted"
            ),
            Self::Ambiguous { key } => write!(
                formatter,
                "multiple payload entries exist for {key}; authentication was not attempted"
            ),
            Self::Invalid { key, reason } => write!(
                formatter,
                "payload preflight failed for {key}: {reason}; authentication was not attempted"
            ),
            Self::NotLiveQualified { key, version } => write!(
                formatter,
                "payload {key} version {version} is contract-only and has no exact live qualification; authentication was not attempted"
            ),
        }
    }
}

impl std::error::Error for PayloadSelectionError {}

#[derive(Debug, Clone, Default)]
pub struct PayloadPreflight {
    payloads: BTreeMap<PayloadKey, Result<ResolvedPayload, String>>,
    ambiguous: BTreeSet<PayloadKey>,
}

impl PayloadPreflight {
    pub async fn build(catalog: &[PayloadSpec], max_payload_bytes: u64) -> Self {
        let mut payloads = BTreeMap::new();
        let mut ambiguous = BTreeSet::new();

        for payload in catalog {
            let key = PayloadKey::new(payload.operating_system, payload.architecture);
            if payloads.contains_key(&key) {
                ambiguous.insert(key);
                continue;
            }
            payloads.insert(key, preflight_payload(payload, max_payload_bytes).await);
        }

        Self {
            payloads,
            ambiguous,
        }
    }

    pub fn select(
        &self,
        contract: &TargetContract,
    ) -> Result<ResolvedPayload, PayloadSelectionError> {
        if !contract.is_explicit() {
            return Err(PayloadSelectionError::UnknownTarget);
        }

        let key = PayloadKey::new(contract.operating_system, contract.architecture);
        if self.ambiguous.contains(&key) {
            return Err(PayloadSelectionError::Ambiguous { key });
        }
        let payload = self
            .payloads
            .get(&key)
            .ok_or(PayloadSelectionError::Missing { key })?
            .as_ref()
            .map_err(|reason| PayloadSelectionError::Invalid {
                key,
                reason: reason.clone(),
            })?
            .clone();

        if payload.qualification != PayloadQualification::LiveQualified {
            return Err(PayloadSelectionError::NotLiveQualified {
                key,
                version: payload.version,
            });
        }

        Ok(payload)
    }
}

async fn preflight_payload(
    payload: &PayloadSpec,
    max_payload_bytes: u64,
) -> Result<ResolvedPayload, String> {
    if payload.operating_system == OperatingSystem::Unknown
        || payload.architecture == CpuArchitecture::Unknown
    {
        return Err("payload entries require an exact operating system and architecture".into());
    }
    if payload.version.trim().is_empty() {
        return Err("payload version cannot be empty".into());
    }
    let expected_digest = normalize_sha256(&payload.sha256)?;
    if payload.qualification == PayloadQualification::LiveQualified && payload.evidence.is_empty() {
        return Err(
            "live-qualified payloads require at least one exact evidence identifier".into(),
        );
    }

    let metadata = tokio::fs::symlink_metadata(&payload.path)
        .await
        .map_err(|error| format!("{} is unavailable: {error}", payload.path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is a symbolic link; payloads must be regular packaged files",
            payload.path.display()
        ));
    }
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "{} must be a non-empty regular file",
            payload.path.display()
        ));
    }
    if metadata.len() > max_payload_bytes {
        return Err(format!(
            "{} is {} bytes, exceeding the {} byte payload bound",
            payload.path.display(),
            metadata.len(),
            max_payload_bytes
        ));
    }

    let actual_digest = sha256_file_bounded(&payload.path, max_payload_bytes).await?;
    if actual_digest != expected_digest {
        return Err(format!(
            "{} digest mismatch: expected {}, got {}",
            payload.path.display(),
            expected_digest,
            actual_digest
        ));
    }

    Ok(ResolvedPayload {
        operating_system: payload.operating_system,
        architecture: payload.architecture,
        path: payload.path.clone(),
        version: payload.version.clone(),
        sha256: actual_digest,
        qualification: payload.qualification,
        evidence: payload.evidence.clone(),
        size_bytes: metadata.len(),
    })
}

pub(crate) fn normalize_sha256(value: &str) -> Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("SHA-256 must contain exactly 64 hexadecimal characters".into());
    }
    Ok(normalized)
}

pub(crate) async fn sha256_file_bounded(path: &Path, maximum: u64) -> Result<String, String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;

    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| "payload length overflowed u64".to_string())?;
        if total > maximum {
            return Err(format!(
                "{} exceeded the {} byte bound while hashing",
                path.display(),
                maximum
            ));
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{sha256_file_bounded, PayloadPreflight, PayloadSelectionError};
    use crate::runtime::mission::{
        CpuArchitecture, OperatingSystem, PayloadQualification, PayloadSpec, TargetContract,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_root(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    async fn payload_spec(
        path: std::path::PathBuf,
        operating_system: OperatingSystem,
        architecture: CpuArchitecture,
        qualification: PayloadQualification,
    ) -> PayloadSpec {
        let sha256 = sha256_file_bounded(&path, 1024)
            .await
            .expect("fixture should hash");
        PayloadSpec {
            operating_system,
            architecture,
            path,
            version: "test-1".into(),
            sha256,
            qualification,
            evidence: if qualification == PayloadQualification::LiveQualified {
                vec!["offline-test-fixture".into()]
            } else {
                Vec::new()
            },
        }
    }

    #[tokio::test]
    async fn missing_payload_is_an_isolated_selection_error() {
        let preflight = PayloadPreflight::build(&[], 1024).await;
        let error = preflight
            .select(&TargetContract::ssh(
                OperatingSystem::FreeBsd,
                CpuArchitecture::X86_64,
            ))
            .expect_err("missing payload should be reported");

        assert!(matches!(error, PayloadSelectionError::Missing { .. }));
        assert!(error
            .to_string()
            .contains("authentication was not attempted"));
    }

    #[tokio::test]
    async fn payload_selection_is_exact_by_os_and_architecture() {
        let root = unique_root("pandora-exact-payload");
        tokio::fs::create_dir_all(&root).await.expect("root");
        let linux = root.join("chimera-linux");
        let windows = root.join("chimera.exe");
        tokio::fs::write(&linux, b"linux-x86_64")
            .await
            .expect("linux");
        tokio::fs::write(&windows, b"windows-x86_64")
            .await
            .expect("windows");
        let catalog = vec![
            payload_spec(
                linux.clone(),
                OperatingSystem::Linux,
                CpuArchitecture::X86_64,
                PayloadQualification::LiveQualified,
            )
            .await,
            payload_spec(
                windows.clone(),
                OperatingSystem::Windows,
                CpuArchitecture::X86_64,
                PayloadQualification::LiveQualified,
            )
            .await,
        ];
        let preflight = PayloadPreflight::build(&catalog, 1024).await;

        assert_eq!(
            preflight
                .select(&TargetContract::windows(CpuArchitecture::X86_64, false))
                .expect("Windows payload should select")
                .path,
            windows
        );
        assert_eq!(
            preflight
                .select(&TargetContract::ssh(
                    OperatingSystem::Linux,
                    CpuArchitecture::X86_64,
                ))
                .expect("Linux payload should select")
                .path,
            linux
        );
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn contract_only_payload_cannot_reach_authentication() {
        let root = unique_root("pandora-unqualified-payload");
        tokio::fs::create_dir_all(&root).await.expect("root");
        let path = root.join("chimera");
        tokio::fs::write(&path, b"candidate")
            .await
            .expect("fixture");
        let catalog = vec![
            payload_spec(
                path,
                OperatingSystem::PfSense,
                CpuArchitecture::X86_64,
                PayloadQualification::ContractOnly,
            )
            .await,
        ];
        let preflight = PayloadPreflight::build(&catalog, 1024).await;
        let error = preflight
            .select(&TargetContract::ssh(
                OperatingSystem::PfSense,
                CpuArchitecture::X86_64,
            ))
            .expect_err("unqualified payload must fail closed");

        assert!(matches!(
            error,
            PayloadSelectionError::NotLiveQualified { .. }
        ));
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
