use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::mission::{OperatingSystem, SshHostKeyPolicy, TransportKind};
use super::secret::SecretString;
use crate::{Error, Result};

pub const MAX_EXTERNAL_SECRET_BYTES: u64 = 4096;
const MAX_PRIVATE_KEY_BYTES: u64 = 1024 * 1024;
const MAX_CREDENTIAL_PROFILES: usize = 256;
const MAX_CREDENTIAL_BINDINGS: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalSecretSource {
    Environment {
        variable: String,
    },
    File {
        path: PathBuf,
    },
    #[serde(skip)]
    Provided,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticationSpec {
    Password {
        source: ExternalSecretSource,
    },
    SshKey {
        private_key: PathBuf,
        public_key_sha256: String,
    },
    SshAgent {
        public_key_sha256: String,
    },
}

impl AuthenticationSpec {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password { .. } => "password",
            Self::SshKey { .. } => "ssh_key",
            Self::SshAgent { .. } => "ssh_agent",
        }
    }
}

fn default_ssh_port() -> u16 {
    22
}

fn default_smb_port() -> u16 {
    445
}

fn default_host_key_policy() -> SshHostKeyPolicy {
    SshHostKeyPolicy::RequireKnown
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfile {
    pub name: String,
    pub operating_systems: Vec<OperatingSystem>,
    pub username: String,
    pub authentication: AuthenticationSpec,
    pub transports: Vec<TransportKind>,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default = "default_smb_port")]
    pub smb_port: u16,
    #[serde(default)]
    pub windows_domain: Option<String>,
    #[serde(default)]
    pub windows_workstation: Option<String>,
    #[serde(default = "default_host_key_policy")]
    pub ssh_host_key_policy: SshHostKeyPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatingSystemDefault {
    operating_system: OperatingSystem,
    profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostProfileOverride {
    target: IpAddr,
    profile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialProfileManifest {
    version: u32,
    #[serde(default)]
    default_profile: Option<String>,
    #[serde(default)]
    operating_system_defaults: Vec<OperatingSystemDefault>,
    #[serde(default)]
    host_overrides: Vec<HostProfileOverride>,
    profiles: Vec<CredentialProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProfileBinding {
    Selected(String),
    Ambiguous(Vec<String>),
}

impl ProfileBinding {
    fn selected(&self, scope: &str) -> Result<&str> {
        match self {
            Self::Selected(profile) => Ok(profile),
            Self::Ambiguous(profiles) => Err(Error::CredentialProfileFailure(format!(
                "ambiguous {scope} credential profile bindings: {}",
                profiles.join(", ")
            ))),
        }
    }
}

fn merge_binding<K: Ord + Copy>(map: &mut BTreeMap<K, ProfileBinding>, key: K, profile: String) {
    use std::collections::btree_map::Entry;
    match map.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(ProfileBinding::Selected(profile));
        }
        Entry::Occupied(mut entry) => match entry.get_mut() {
            ProfileBinding::Selected(existing) => {
                let first = existing.clone();
                *entry.get_mut() = ProfileBinding::Ambiguous(vec![first, profile]);
            }
            ProfileBinding::Ambiguous(profiles) => profiles.push(profile),
        },
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialProfileCatalog {
    configured: bool,
    default_profile: Option<String>,
    operating_system_defaults: BTreeMap<OperatingSystem, ProfileBinding>,
    host_overrides: BTreeMap<IpAddr, ProfileBinding>,
    profiles: BTreeMap<String, CredentialProfile>,
    ambiguous_profiles: BTreeSet<String>,
    provided_secrets: BTreeMap<String, SecretString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCredentialPolicy {
    pub name: String,
    pub operating_system: OperatingSystem,
    pub username: String,
    pub authentication: AuthenticationSpec,
    pub transports: Vec<TransportKind>,
    pub ssh_port: u16,
    pub smb_port: u16,
    pub windows_domain: Option<String>,
    pub windows_workstation: Option<String>,
    pub ssh_host_key_policy: SshHostKeyPolicy,
    pub policy_sha256: String,
}

impl ResolvedCredentialPolicy {
    #[must_use]
    pub fn allows_transport(&self, transport: TransportKind) -> bool {
        self.transports.contains(&transport)
    }

    #[must_use]
    pub fn port_for(&self, transport: TransportKind) -> u16 {
        match transport {
            TransportKind::SshSftp => self.ssh_port,
            TransportKind::WindowsSmb => self.smb_port,
        }
    }

    pub fn ssh_username(&self) -> Result<String> {
        if self.operating_system == OperatingSystem::Windows {
            if let Some(domain) = &self.windows_domain {
                if self.username.contains(['\\', '@']) {
                    return Err(Error::CredentialProfileFailure(format!(
                        "credential profile '{}' sets windows_domain but its username is already domain-qualified",
                        self.name
                    )));
                }
                return Ok(format!(r"{domain}\{}", self.username));
            }
        }
        Ok(self.username.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedAuthentication {
    Password(SecretString),
    SshKey {
        private_key: PathBuf,
        public_key_sha256: String,
    },
    SshAgent {
        public_key_sha256: String,
    },
}

impl CredentialProfileCatalog {
    pub fn from_json(raw: &str, base_directory: &Path) -> Result<Self> {
        let manifest: CredentialProfileManifest = serde_json::from_str(raw).map_err(|error| {
            Error::ArgumentError(format!(
                "failed to parse credential profile manifest: {error}"
            ))
        })?;
        if manifest.version != 1 {
            return Err(Error::ArgumentError(format!(
                "credential profile manifest version {} is unsupported; expected version 1",
                manifest.version
            )));
        }
        if manifest.profiles.len() > MAX_CREDENTIAL_PROFILES {
            return Err(Error::ArgumentError(format!(
                "credential profile manifest exceeds the {MAX_CREDENTIAL_PROFILES}-profile bound"
            )));
        }
        if manifest.operating_system_defaults.len() > MAX_CREDENTIAL_BINDINGS
            || manifest.host_overrides.len() > MAX_CREDENTIAL_BINDINGS
        {
            return Err(Error::ArgumentError(format!(
                "credential profile manifest exceeds the {MAX_CREDENTIAL_BINDINGS}-binding bound"
            )));
        }

        if let Some(profile) = &manifest.default_profile {
            validate_profile_name(profile)?;
        }

        let mut catalog = Self {
            configured: true,
            default_profile: manifest.default_profile,
            ..Self::default()
        };

        for default in manifest.operating_system_defaults {
            validate_executable_operating_system(default.operating_system)
                .map_err(Error::ArgumentError)?;
            validate_profile_name(&default.profile)?;
            merge_binding(
                &mut catalog.operating_system_defaults,
                default.operating_system,
                default.profile,
            );
        }
        for host in manifest.host_overrides {
            validate_profile_name(&host.profile)?;
            merge_binding(&mut catalog.host_overrides, host.target, host.profile);
        }
        for mut profile in manifest.profiles {
            validate_profile(&mut profile, base_directory, false)?;
            if catalog.profiles.contains_key(&profile.name) {
                catalog.ambiguous_profiles.insert(profile.name.clone());
            } else {
                catalog.profiles.insert(profile.name.clone(), profile);
            }
        }

        Ok(catalog)
    }

    #[must_use]
    pub fn legacy(
        unix_username: impl Into<String>,
        windows_username: impl Into<String>,
        password: Option<SecretString>,
        ssh_port: u16,
        ssh_host_key_policy: SshHostKeyPolicy,
        allow_smb: bool,
        smb_port: u16,
    ) -> Self {
        let unix_name = "legacy-unix-default".to_string();
        let windows_name = "legacy-windows-default".to_string();
        let mut profiles = BTreeMap::new();
        profiles.insert(
            unix_name.clone(),
            CredentialProfile {
                name: unix_name.clone(),
                operating_systems: vec![
                    OperatingSystem::Linux,
                    OperatingSystem::FreeBsd,
                    OperatingSystem::OpenBsd,
                    OperatingSystem::NetBsd,
                    OperatingSystem::DragonFlyBsd,
                    OperatingSystem::PfSense,
                ],
                username: unix_username.into(),
                authentication: AuthenticationSpec::Password {
                    source: ExternalSecretSource::Provided,
                },
                transports: vec![TransportKind::SshSftp],
                ssh_port,
                smb_port,
                windows_domain: None,
                windows_workstation: None,
                ssh_host_key_policy,
            },
        );
        let mut windows_transports = vec![TransportKind::SshSftp];
        if allow_smb {
            windows_transports.push(TransportKind::WindowsSmb);
        }
        profiles.insert(
            windows_name.clone(),
            CredentialProfile {
                name: windows_name.clone(),
                operating_systems: vec![OperatingSystem::Windows],
                username: windows_username.into(),
                authentication: AuthenticationSpec::Password {
                    source: ExternalSecretSource::Provided,
                },
                transports: windows_transports,
                ssh_port,
                smb_port,
                windows_domain: None,
                windows_workstation: None,
                ssh_host_key_policy,
            },
        );

        let mut operating_system_defaults = BTreeMap::new();
        for operating_system in [
            OperatingSystem::Linux,
            OperatingSystem::FreeBsd,
            OperatingSystem::OpenBsd,
            OperatingSystem::NetBsd,
            OperatingSystem::DragonFlyBsd,
            OperatingSystem::PfSense,
        ] {
            operating_system_defaults.insert(
                operating_system,
                ProfileBinding::Selected(unix_name.clone()),
            );
        }
        operating_system_defaults.insert(
            OperatingSystem::Windows,
            ProfileBinding::Selected(windows_name.clone()),
        );

        let mut provided_secrets = BTreeMap::new();
        if let Some(password) = password {
            provided_secrets.insert(unix_name, password.clone());
            provided_secrets.insert(windows_name, password);
        }

        Self {
            configured: true,
            default_profile: None,
            operating_system_defaults,
            host_overrides: BTreeMap::new(),
            profiles,
            ambiguous_profiles: BTreeSet::new(),
            provided_secrets,
        }
    }

    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.configured
    }

    pub fn resolve_policy(
        &self,
        target: IpAddr,
        operating_system: OperatingSystem,
        contracted_transports: &[TransportKind],
    ) -> Result<ResolvedCredentialPolicy> {
        validate_executable_operating_system(operating_system)
            .map_err(Error::CredentialProfileFailure)?;
        if contracted_transports.is_empty() {
            return Err(Error::CredentialProfileFailure(format!(
                "target {target} has no authenticated transport contract"
            )));
        }

        let profile_name = if let Some(binding) = self.host_overrides.get(&target) {
            binding.selected(&format!("host override for {target}"))?
        } else if let Some(binding) = self.operating_system_defaults.get(&operating_system) {
            binding.selected(&format!(
                "{} operating-system default",
                operating_system.as_str()
            ))?
        } else {
            self.default_profile.as_deref().ok_or_else(|| {
                Error::CredentialProfileFailure(format!(
                    "no credential profile is selected for {target} ({})",
                    operating_system.as_str()
                ))
            })?
        };

        if self.ambiguous_profiles.contains(profile_name) {
            return Err(Error::CredentialProfileFailure(format!(
                "credential profile name '{profile_name}' is ambiguous"
            )));
        }
        let profile = self.profiles.get(profile_name).ok_or_else(|| {
            Error::CredentialProfileFailure(format!(
                "selected credential profile '{profile_name}' is missing for {target}"
            ))
        })?;
        if !profile.operating_systems.contains(&operating_system) {
            return Err(Error::CredentialProfileFailure(format!(
                "credential profile '{profile_name}' is not valid for {} target {target}",
                operating_system.as_str()
            )));
        }
        if !profile
            .transports
            .iter()
            .any(|transport| contracted_transports.contains(transport))
        {
            return Err(Error::CredentialProfileFailure(format!(
                "credential profile '{profile_name}' transport policy is incompatible with the target contract for {target}"
            )));
        }

        let policy_sha256 = profile_fingerprint(profile);
        Ok(ResolvedCredentialPolicy {
            name: profile.name.clone(),
            operating_system,
            username: profile.username.clone(),
            authentication: profile.authentication.clone(),
            transports: profile.transports.clone(),
            ssh_port: profile.ssh_port,
            smb_port: profile.smb_port,
            windows_domain: profile.windows_domain.clone(),
            windows_workstation: profile.windows_workstation.clone(),
            ssh_host_key_policy: profile.ssh_host_key_policy,
            policy_sha256,
        })
    }

    pub fn resolve_authentication(
        &self,
        policy: &ResolvedCredentialPolicy,
    ) -> Result<ResolvedAuthentication> {
        match &policy.authentication {
            AuthenticationSpec::Password { source } => {
                let secret = match source {
                    ExternalSecretSource::Environment { variable } => {
                        let value = std::env::var(variable).map_err(|_| {
                            Error::CredentialProfileFailure(format!(
                                "credential profile '{}' requires unavailable environment secret {variable}",
                                policy.name
                            ))
                        })?;
                        normalize_external_secret(value, &format!("environment secret {variable}"))?
                    }
                    ExternalSecretSource::File { path } => read_external_secret_file(path)?,
                    ExternalSecretSource::Provided => self
                        .provided_secrets
                        .get(&policy.name)
                        .filter(|secret| !secret.is_empty())
                        .cloned()
                        .ok_or_else(|| {
                            Error::CredentialProfileFailure(format!(
                                "credential profile '{}' has no externally supplied password",
                                policy.name
                            ))
                        })?,
                };
                Ok(ResolvedAuthentication::Password(secret))
            }
            AuthenticationSpec::SshKey {
                private_key,
                public_key_sha256,
            } => {
                validate_private_regular_file(
                    private_key,
                    MAX_PRIVATE_KEY_BYTES,
                    "SSH private key",
                )?;
                Ok(ResolvedAuthentication::SshKey {
                    private_key: private_key.clone(),
                    public_key_sha256: public_key_sha256.clone(),
                })
            }
            AuthenticationSpec::SshAgent { public_key_sha256 } => {
                Ok(ResolvedAuthentication::SshAgent {
                    public_key_sha256: public_key_sha256.clone(),
                })
            }
        }
    }

    #[must_use]
    pub fn policy_identity(
        &self,
        target: IpAddr,
        operating_system: OperatingSystem,
        contracted_transports: &[TransportKind],
    ) -> (Option<String>, String) {
        match self.resolve_policy(target, operating_system, contracted_transports) {
            Ok(policy) => (
                Some(policy.name.clone()),
                hash_text(&format!(
                    "selected={};policy={}",
                    policy.name, policy.policy_sha256
                )),
            ),
            Err(error) => (None, hash_text(&format!("unresolved={error}"))),
        }
    }
}

fn validate_profile(
    profile: &mut CredentialProfile,
    base_directory: &Path,
    allow_provided_secret: bool,
) -> Result<()> {
    validate_profile_name(&profile.name)?;
    validate_nonempty_text("credential username", &profile.username, 256)?;
    if profile.operating_systems.is_empty() {
        return Err(Error::ArgumentError(format!(
            "credential profile '{}' must name at least one operating system",
            profile.name
        )));
    }
    let operating_systems = profile
        .operating_systems
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if operating_systems.len() != profile.operating_systems.len() {
        return Err(Error::ArgumentError(format!(
            "credential profile '{}' contains duplicate operating systems",
            profile.name
        )));
    }
    for operating_system in &profile.operating_systems {
        validate_executable_operating_system(*operating_system).map_err(Error::ArgumentError)?;
    }
    if profile.transports.is_empty() {
        return Err(Error::ArgumentError(format!(
            "credential profile '{}' must allow at least one transport",
            profile.name
        )));
    }
    if profile
        .transports
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        != profile.transports.len()
    {
        return Err(Error::ArgumentError(format!(
            "credential profile '{}' contains duplicate transports",
            profile.name
        )));
    }
    if profile.ssh_port == 0 || profile.smb_port == 0 {
        return Err(Error::ArgumentError(format!(
            "credential profile '{}' ports must be between 1 and 65535",
            profile.name
        )));
    }

    if let Some(domain) = &profile.windows_domain {
        validate_nonempty_text("Windows domain", domain, 256)?;
        if profile.username.contains(['\\', '@']) {
            return Err(Error::ArgumentError(format!(
                "credential profile '{}' sets windows_domain but its username is already domain-qualified",
                profile.name
            )));
        }
    }
    if let Some(workstation) = &profile.windows_workstation {
        validate_nonempty_text("Windows workstation", workstation, 256)?;
    }
    if (profile.windows_domain.is_some() || profile.windows_workstation.is_some())
        && profile.operating_systems != [OperatingSystem::Windows]
    {
        return Err(Error::ArgumentError(format!(
            "credential profile '{}' may use Windows domain/workstation fields only for Windows",
            profile.name
        )));
    }

    let allows_ssh = profile.transports.contains(&TransportKind::SshSftp);
    let allows_smb = profile.transports.contains(&TransportKind::WindowsSmb);
    if allows_smb
        && (profile.operating_systems != [OperatingSystem::Windows]
            || !matches!(&profile.authentication, AuthenticationSpec::Password { .. }))
    {
        return Err(Error::ArgumentError(format!(
            "credential profile '{}' may use encrypted Windows SMB only with password authentication on Windows",
            profile.name
        )));
    }

    match &mut profile.authentication {
        AuthenticationSpec::Password { source } => match source {
            ExternalSecretSource::Environment { variable } => {
                validate_environment_variable(variable)?;
            }
            ExternalSecretSource::File { path } => resolve_relative_path(path, base_directory),
            ExternalSecretSource::Provided if !allow_provided_secret => {
                return Err(Error::ArgumentError(format!(
                    "credential profile '{}' cannot request an in-manifest provided secret",
                    profile.name
                )));
            }
            ExternalSecretSource::Provided => {}
        },
        AuthenticationSpec::SshKey {
            private_key,
            public_key_sha256,
        } => {
            if !allows_ssh || allows_smb {
                return Err(Error::ArgumentError(format!(
                    "credential profile '{}' SSH key authentication is valid only for SSH/SFTP",
                    profile.name
                )));
            }
            resolve_relative_path(private_key, base_directory);
            *public_key_sha256 = normalize_public_key_fingerprint(public_key_sha256)?;
        }
        AuthenticationSpec::SshAgent { public_key_sha256 } => {
            if !allows_ssh || allows_smb {
                return Err(Error::ArgumentError(format!(
                    "credential profile '{}' SSH agent authentication is valid only for SSH/SFTP",
                    profile.name
                )));
            }
            *public_key_sha256 = normalize_public_key_fingerprint(public_key_sha256)?;
        }
    }

    Ok(())
}

fn validate_executable_operating_system(
    operating_system: OperatingSystem,
) -> std::result::Result<(), String> {
    if matches!(
        operating_system,
        OperatingSystem::Unknown | OperatingSystem::Bsd
    ) {
        return Err(format!(
            "{} is not an executable credential-profile operating system",
            operating_system.as_str()
        ));
    }
    Ok(())
}

fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::ArgumentError(format!(
            "credential profile name '{name}' must be 1-64 portable [A-Za-z0-9._-] characters"
        )));
    }
    Ok(())
}

fn validate_nonempty_text(label: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.contains(['\0', '\r', '\n']) {
        return Err(Error::ArgumentError(format!(
            "{label} must be nonempty, at most {maximum} bytes, and contain no NUL or newline"
        )));
    }
    Ok(())
}

fn validate_environment_variable(variable: &str) -> Result<()> {
    if variable.is_empty()
        || variable.len() > 128
        || !variable
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || variable.as_bytes()[0].is_ascii_digit()
    {
        return Err(Error::ArgumentError(format!(
            "external secret environment variable '{variable}' is not a portable variable name"
        )));
    }
    Ok(())
}

fn normalize_public_key_fingerprint(value: &str) -> Result<String> {
    let value = value.trim();
    let Some(encoded) = value.strip_prefix("SHA256:") else {
        return Err(Error::ArgumentError(
            "SSH public-key fingerprint must use OpenSSH SHA256:<base64> form".into(),
        ));
    };
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
    {
        return Err(Error::ArgumentError(
            "SSH public-key fingerprint must contain an unpadded 43-character SHA-256 base64 digest"
                .into(),
        ));
    }
    Ok(value.to_string())
}

fn resolve_relative_path(path: &mut PathBuf, base_directory: &Path) {
    if path.is_relative() {
        *path = base_directory.join(&*path);
    }
}

pub fn normalize_external_secret(mut value: String, source: &str) -> Result<SecretString> {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') {
        value.pop();
    }
    if value.is_empty() {
        return Err(Error::CredentialProfileFailure(format!(
            "{source} is empty"
        )));
    }
    if value.len() > MAX_EXTERNAL_SECRET_BYTES as usize {
        return Err(Error::CredentialProfileFailure(format!(
            "{source} exceeds {MAX_EXTERNAL_SECRET_BYTES} bytes"
        )));
    }
    if value.contains(['\r', '\n']) {
        return Err(Error::CredentialProfileFailure(format!(
            "{source} must contain exactly one line"
        )));
    }
    Ok(SecretString::new(value))
}

pub fn read_external_secret_file(path: &Path) -> Result<SecretString> {
    validate_private_regular_file(path, MAX_EXTERNAL_SECRET_BYTES, "external secret file")?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|error| {
        Error::CredentialProfileFailure(format!(
            "external secret file {} is unavailable: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        Error::CredentialProfileFailure(format!(
            "cannot inspect external secret file {}: {error}",
            path.display()
        ))
    })?;
    validate_private_metadata(
        path,
        &metadata,
        MAX_EXTERNAL_SECRET_BYTES,
        "external secret file",
    )?;

    let mut value = String::new();
    file.take(MAX_EXTERNAL_SECRET_BYTES + 2)
        .read_to_string(&mut value)
        .map_err(|error| {
            Error::CredentialProfileFailure(format!(
                "cannot read external secret file {}: {error}",
                path.display()
            ))
        })?;
    normalize_external_secret(value, &format!("external secret file {}", path.display()))
}

fn validate_private_regular_file(path: &Path, maximum: u64, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        Error::CredentialProfileFailure(format!(
            "{label} {} is unavailable: {error}",
            path.display()
        ))
    })?;
    validate_private_metadata(path, &metadata, maximum, label)
}

fn validate_private_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
    maximum: u64,
    label: &str,
) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::CredentialProfileFailure(format!(
            "{label} must be a regular non-link file: {}",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(Error::CredentialProfileFailure(format!(
            "{label} {} is {} bytes, exceeding the {maximum} byte bound",
            path.display(),
            metadata.len()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::CredentialProfileFailure(format!(
                "{label} has unsafe ownership or permissions: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn profile_fingerprint(profile: &CredentialProfile) -> String {
    let mut identity = String::new();
    append_identity_field(&mut identity, "name", &profile.name);
    for operating_system in &profile.operating_systems {
        append_identity_field(&mut identity, "os", operating_system.as_str());
    }
    append_identity_field(&mut identity, "username", &profile.username);
    match &profile.authentication {
        AuthenticationSpec::Password { source } => match source {
            ExternalSecretSource::Environment { variable } => {
                append_identity_field(&mut identity, "auth", "password_environment");
                append_identity_field(&mut identity, "secret_variable", variable);
            }
            ExternalSecretSource::File { path } => {
                append_identity_field(&mut identity, "auth", "password_file");
                append_identity_field(&mut identity, "secret_file", &path.to_string_lossy());
            }
            ExternalSecretSource::Provided => {
                append_identity_field(&mut identity, "auth", "password_provided");
            }
        },
        AuthenticationSpec::SshKey {
            private_key,
            public_key_sha256,
        } => {
            append_identity_field(&mut identity, "auth", "ssh_key");
            append_identity_field(&mut identity, "private_key", &private_key.to_string_lossy());
            append_identity_field(&mut identity, "public_key_sha256", public_key_sha256);
        }
        AuthenticationSpec::SshAgent { public_key_sha256 } => {
            append_identity_field(&mut identity, "auth", "ssh_agent");
            append_identity_field(&mut identity, "public_key_sha256", public_key_sha256);
        }
    }
    for transport in &profile.transports {
        append_identity_field(&mut identity, "transport", transport.as_str());
    }
    append_identity_field(&mut identity, "ssh_port", &profile.ssh_port.to_string());
    append_identity_field(&mut identity, "smb_port", &profile.smb_port.to_string());
    append_identity_field(
        &mut identity,
        "domain",
        profile.windows_domain.as_deref().unwrap_or(""),
    );
    append_identity_field(
        &mut identity,
        "workstation",
        profile.windows_workstation.as_deref().unwrap_or(""),
    );
    append_identity_field(
        &mut identity,
        "host_key_policy",
        profile.ssh_host_key_policy.as_str(),
    );
    hash_text(&identity)
}

fn append_identity_field(identity: &mut String, label: &str, value: &str) {
    use std::fmt::Write;
    write!(
        identity,
        "{}:{label}={}:{};",
        label.len(),
        value.len(),
        value
    )
    .expect("writing to a String cannot fail");
}

#[must_use]
pub fn hash_text(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::CredentialProfileCatalog;
    use crate::runtime::mission::{OperatingSystem, TransportKind};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;

    const FINGERPRINT: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn target(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn manifest(overrides: &str) -> String {
        format!(
            r#"{{
  "version": 1,
  "default_profile": "unix-default",
  "operating_system_defaults": [
    {{"operating_system":"windows","profile":"windows-default"}}
  ],
  "host_overrides": [{overrides}],
  "profiles": [
    {{
      "name":"unix-default",
      "operating_systems":["linux","freebsd","openbsd","netbsd","dragonflybsd","pfsense"],
      "username":"root",
      "authentication":{{"type":"ssh_agent","public_key_sha256":"{FINGERPRINT}"}},
      "transports":["ssh_sftp"]
    }},
    {{
      "name":"windows-default",
      "operating_systems":["windows"],
      "username":"Administrator",
      "authentication":{{"type":"password","source":{{"type":"environment","variable":"PANDORA_WINDOWS_PASSWORD"}}}},
      "transports":["ssh_sftp","windows_smb"],
      "windows_domain":"BLUE"
    }},
    {{
      "name":"host-key",
      "operating_systems":["linux"],
      "username":"operator",
      "authentication":{{"type":"ssh_key","private_key":"keys/id_ed25519","public_key_sha256":"{FINGERPRINT}"}},
      "transports":["ssh_sftp"],
      "ssh_port":2222
    }}
  ]
}}"#
        )
    }

    #[test]
    fn global_os_defaults_and_host_overrides_resolve_without_prompts() {
        let catalog = CredentialProfileCatalog::from_json(
            &manifest(r#"{"target":"10.0.0.8","profile":"host-key"}"#),
            Path::new("/bundle"),
        )
        .expect("profile catalog");

        let linux_default = catalog
            .resolve_policy(target(7), OperatingSystem::Linux, &[TransportKind::SshSftp])
            .expect("global default");
        let override_policy = catalog
            .resolve_policy(target(8), OperatingSystem::Linux, &[TransportKind::SshSftp])
            .expect("host override");
        let windows_default = catalog
            .resolve_policy(
                target(9),
                OperatingSystem::Windows,
                &[TransportKind::SshSftp, TransportKind::WindowsSmb],
            )
            .expect("OS default");

        assert_eq!(linux_default.name, "unix-default");
        assert_eq!(override_policy.name, "host-key");
        assert_eq!(override_policy.ssh_port, 2222);
        assert_eq!(windows_default.name, "windows-default");
        assert_eq!(
            windows_default.ssh_username().expect("domain username"),
            r"BLUE\Administrator"
        );
    }

    #[test]
    fn duplicate_host_bindings_are_ambiguous_and_fail_closed() {
        let catalog = CredentialProfileCatalog::from_json(
            &manifest(
                r#"{"target":"10.0.0.8","profile":"host-key"},{"target":"10.0.0.8","profile":"unix-default"}"#,
            ),
            Path::new("/bundle"),
        )
        .expect("structurally valid catalog");

        let error = catalog
            .resolve_policy(target(8), OperatingSystem::Linux, &[TransportKind::SshSftp])
            .expect_err("ambiguous override must fail");
        assert!(error.to_string().contains("ambiguous host override"));
    }

    #[test]
    fn missing_and_policy_incompatible_profiles_fail_only_resolution() {
        let missing = manifest(r#"{"target":"10.0.0.8","profile":"does-not-exist"}"#);
        let catalog = CredentialProfileCatalog::from_json(&missing, Path::new("/bundle"))
            .expect("missing reference is isolated at resolution");
        assert!(catalog
            .resolve_policy(target(8), OperatingSystem::Linux, &[TransportKind::SshSftp])
            .expect_err("missing profile")
            .to_string()
            .contains("is missing"));
        assert!(catalog
            .resolve_policy(
                target(7),
                OperatingSystem::Linux,
                &[TransportKind::WindowsSmb]
            )
            .expect_err("transport mismatch")
            .to_string()
            .contains("transport policy is incompatible"));
    }

    #[cfg(unix)]
    #[test]
    fn external_secret_file_is_bounded_private_and_redacted() {
        use super::{ResolvedAuthentication, MAX_EXTERNAL_SECRET_BYTES};
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("pandora-profile-secret-{unique}"));
        fs::create_dir_all(&root).expect("fixture root");
        let secret_path = root.join("secret");
        fs::write(&secret_path, "profile-secret-value\n").expect("secret fixture");
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).expect("private");
        let raw = r#"{"version":1,"default_profile":"file-profile","profiles":[{"name":"file-profile","operating_systems":["linux"],"username":"root","authentication":{"type":"password","source":{"type":"file","path":"secret"}},"transports":["ssh_sftp"]}]}"#;
        let catalog = CredentialProfileCatalog::from_json(raw, &root).expect("catalog");
        let policy = catalog
            .resolve_policy(target(8), OperatingSystem::Linux, &[TransportKind::SshSftp])
            .expect("policy");
        let auth = catalog
            .resolve_authentication(&policy)
            .expect("external secret");
        let ResolvedAuthentication::Password(secret) = auth else {
            panic!("expected password")
        };
        assert_eq!(secret.expose_secret(), "profile-secret-value");
        assert!(!format!("{secret:?}").contains("profile-secret-value"));

        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644)).expect("public");
        let error = catalog
            .resolve_authentication(&policy)
            .expect_err("public secret file must fail");
        assert!(error
            .to_string()
            .contains("unsafe ownership or permissions"));

        fs::write(
            &secret_path,
            vec![b'x'; MAX_EXTERNAL_SECRET_BYTES as usize + 1],
        )
        .expect("large fixture");
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).expect("private");
        assert!(catalog.resolve_authentication(&policy).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn secret_values_never_change_persistable_policy_identity() {
        let first = CredentialProfileCatalog::legacy(
            "root",
            "Administrator",
            Some("first-secret".into()),
            22,
            crate::runtime::mission::SshHostKeyPolicy::RequireKnown,
            false,
            445,
        );
        let second = CredentialProfileCatalog::legacy(
            "root",
            "Administrator",
            Some("second-secret".into()),
            22,
            crate::runtime::mission::SshHostKeyPolicy::RequireKnown,
            false,
            445,
        );
        let first_identity =
            first.policy_identity(target(8), OperatingSystem::Linux, &[TransportKind::SshSftp]);
        let second_identity =
            second.policy_identity(target(8), OperatingSystem::Linux, &[TransportKind::SshSftp]);

        assert_eq!(first_identity, second_identity);
        assert!(!format!("{first:?}").contains("first-secret"));
    }
}
