use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::mission::{CpuArchitecture, HostPlan, MissionSpec, OperatingSystem, TargetContract};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteShell {
    Posix,
    PowerShell,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWorkspace {
    pub shell: RemoteShell,
    pub collector_source_path: PathBuf,
    pub staged_local_name: String,
    pub remote_temp_dir: String,
    pub remote_binary_path: String,
    pub remote_output_root: String,
    pub inventory_path: String,
    pub log_path: String,
    payload_sha256: String,
    workspace_token: String,
}

impl RemoteWorkspace {
    #[must_use]
    pub fn ensure_directories_command(&self) -> String {
        match self.shell {
            RemoteShell::Posix => self.posix_create_and_validate_command(),
            RemoteShell::PowerShell => self.windows_create_and_validate_command(),
        }
    }

    #[must_use]
    pub fn post_stage_commands(&self) -> Vec<String> {
        match self.shell {
            RemoteShell::Posix => vec![format!(
                concat!(
                    "chmod 700 '{binary}' || exit 90; ",
                    "if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum '{binary}' | awk '{{print $1}}'); ",
                    "elif command -v sha256 >/dev/null 2>&1; then actual=$(sha256 -q '{binary}'); else exit 91; fi; ",
                    "[ \"$actual\" = '{digest}' ]"
                ),
                binary = escape_posix_path(&self.remote_binary_path),
                digest = self.payload_sha256,
            )],
            RemoteShell::PowerShell => vec![format!(
                concat!(
                    "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"",
                    "$p='{binary}'; $v=Get-Item -LiteralPath $p -Force; ",
                    "if(($v.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){{exit 91}}; ",
                    "if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -ne '{digest}'){{exit 92}}\""
                ),
                binary = escape_powershell_literal(&self.remote_binary_path),
                digest = self.payload_sha256,
            )],
        }
    }

    #[must_use]
    pub fn collector_command(&self) -> String {
        match self.shell {
            RemoteShell::Posix => format!(
                "'{}' --output-root '{}' collector",
                escape_posix_path(&self.remote_binary_path),
                escape_posix_path(&self.remote_output_root)
            ),
            RemoteShell::PowerShell => format!(
                "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"& '{}' --output-root '{}' collector\"",
                escape_powershell_literal(&self.remote_binary_path),
                escape_powershell_literal(&self.remote_output_root),
            ),
        }
    }

    #[must_use]
    pub fn cleanup_command(&self) -> String {
        match self.shell {
            RemoteShell::Posix => self.posix_cleanup_command(),
            RemoteShell::PowerShell => self.windows_cleanup_command(),
        }
    }

    pub fn validate_for_plan(&self, plan: &HostPlan) -> Result<(), String> {
        if self.workspace_token.len() != 48
            || !self
                .workspace_token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("workspace token is not a 192-bit hexadecimal nonce".into());
        }
        let expected = workspace_for_token(plan, self.workspace_token.clone())?;
        if &expected != self {
            return Err(
                "persisted workspace does not match the exact target and payload contract".into(),
            );
        }
        Ok(())
    }

    fn posix_create_and_validate_command(&self) -> String {
        let path = escape_posix_path(&self.remote_temp_dir);
        let output = escape_posix_path(&self.remote_output_root);
        let binary = escape_posix_path(&self.remote_binary_path);
        let inventory = escape_posix_path(&self.inventory_path);
        let log = escape_posix_path(&self.log_path);
        let token = escape_posix_path(&self.workspace_token);
        format!(
            concat!(
                "umask 077; p='{path}'; o='{output}'; b='{binary}'; i='{inventory}'; l='{log}'; m=\"$p/.pandora-owner\"; t='{token}'; ",
                "owner_of() {{ stat -c %u \"$1\" 2>/dev/null || stat -f %u \"$1\" 2>/dev/null; }}; ",
                "mode_of() {{ stat -c %a \"$1\" 2>/dev/null || stat -f %Lp \"$1\" 2>/dev/null; }}; ",
                "u=$(id -u) || exit 70; ",
                "if [ -e \"$p\" ] || [ -L \"$p\" ]; then ",
                "[ -d \"$p\" ] && [ ! -L \"$p\" ] && [ -f \"$m\" ] && [ ! -L \"$m\" ] || exit 73; ",
                "[ \"$(cat \"$m\")\" = \"$t\" ] || exit 74; ",
                "else mkdir -m 700 \"$p\" || exit 73; printf '%s\\n' \"$t\" >\"$m\" || exit 74; chmod 600 \"$m\" || exit 74; fi; ",
                "[ \"$(owner_of \"$p\")\" = \"$u\" ] && [ \"$(owner_of \"$m\")\" = \"$u\" ] || exit 75; ",
                "[ \"$(mode_of \"$p\")\" = 700 ] && [ \"$(mode_of \"$m\")\" = 600 ] || exit 76; ",
                "if [ -e \"$o\" ] || [ -L \"$o\" ]; then [ -d \"$o\" ] && [ ! -L \"$o\" ] || exit 77; else mkdir -m 700 \"$o\" || exit 77; fi; ",
                "[ \"$(owner_of \"$o\")\" = \"$u\" ] && [ \"$(mode_of \"$o\")\" = 700 ] || exit 78; ",
                "for f in \"$b\" \"$i\" \"$l\"; do if [ -e \"$f\" ] || [ -L \"$f\" ]; then [ -f \"$f\" ] && [ ! -L \"$f\" ] && [ \"$(owner_of \"$f\")\" = \"$u\" ] || exit 79; fi; done"
            ),
            path = path,
            output = output,
            binary = binary,
            inventory = inventory,
            log = log,
            token = token,
        )
    }

    fn posix_cleanup_command(&self) -> String {
        let path = escape_posix_path(&self.remote_temp_dir);
        let output = escape_posix_path(&self.remote_output_root);
        let binary = escape_posix_path(&self.remote_binary_path);
        let inventory = escape_posix_path(&self.inventory_path);
        let log = escape_posix_path(&self.log_path);
        let token = escape_posix_path(&self.workspace_token);
        format!(
            concat!(
                "p='{path}'; o='{output}'; b='{binary}'; i='{inventory}'; l='{log}'; m=\"$p/.pandora-owner\"; t='{token}'; ",
                "[ ! -e \"$p\" ] && [ ! -L \"$p\" ] && exit 0; ",
                "owner_of() {{ stat -c %u \"$1\" 2>/dev/null || stat -f %u \"$1\" 2>/dev/null; }}; u=$(id -u) || exit 70; ",
                "[ -d \"$p\" ] && [ ! -L \"$p\" ] && [ -f \"$m\" ] && [ ! -L \"$m\" ] || exit 81; ",
                "[ \"$(owner_of \"$p\")\" = \"$u\" ] && [ \"$(owner_of \"$m\")\" = \"$u\" ] && [ \"$(cat \"$m\")\" = \"$t\" ] || exit 82; ",
                "[ -d \"$o\" ] && [ ! -L \"$o\" ] && [ \"$(owner_of \"$o\")\" = \"$u\" ] || exit 83; for f in \"$b\" \"$i\" \"$l\"; do if [ -e \"$f\" ] || [ -L \"$f\" ]; then [ -f \"$f\" ] && [ ! -L \"$f\" ] && [ \"$(owner_of \"$f\")\" = \"$u\" ] || exit 83; fi; done; ",
                "rm -f \"$b\" \"$i\" \"$l\" || exit 84; rm -f \"$m\" || exit 84; ",
                "if [ -d \"$o\" ]; then rmdir \"$o\" || exit 85; fi; rmdir \"$p\" || exit 86"
            ),
            path = path,
            output = output,
            binary = binary,
            inventory = inventory,
            log = log,
            token = token,
        )
    }

    fn windows_create_and_validate_command(&self) -> String {
        let path = escape_powershell_literal(&self.remote_temp_dir);
        let output = escape_powershell_literal(&self.remote_output_root);
        let binary = escape_powershell_literal(&self.remote_binary_path);
        let inventory = escape_powershell_literal(&self.inventory_path);
        let log = escape_powershell_literal(&self.log_path);
        let token = escape_powershell_literal(&self.workspace_token);
        format!(
            concat!(
                "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"",
                "$ErrorActionPreference='Stop'; $p='{path}'; $o='{output}'; $b='{binary}'; $i='{inventory}'; $l='{log}'; $m=Join-Path $p '.pandora-owner'; $t='{token}'; ",
                "$me=[Security.Principal.WindowsIdentity]::GetCurrent().Name; ",
                "function Assert-Safe([string]$x,[bool]$dir) {{ $v=Get-Item -LiteralPath $x -Force; if(($v.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){{exit 73}}; if($dir -and -not $v.PSIsContainer){{exit 74}}; if((-not $dir) -and $v.PSIsContainer){{exit 74}}; $owner=(Get-Acl -LiteralPath $x).Owner; if($owner -ne $me -and $owner -notmatch '\\\\Administrators$' -and $owner -ne 'NT AUTHORITY\\SYSTEM'){{exit 75}} }}; ",
                "if(Test-Path -LiteralPath $p){{Assert-Safe $p $true; Assert-Safe $m $false; if((Get-Content -LiteralPath $m -Raw).Trim() -ne $t){{exit 76}}}}else{{New-Item -ItemType Directory -Path $p | Out-Null; Set-Content -LiteralPath $m -Value $t -NoNewline}}; ",
                "if(Test-Path -LiteralPath $o){{Assert-Safe $o $true}}else{{New-Item -ItemType Directory -Path $o | Out-Null}}; foreach($f in @($b,$i,$l)){{if(Test-Path -LiteralPath $f){{Assert-Safe $f $false}}}}; ",
                "foreach($d in @($p,$o)){{& icacls.exe $d /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null; if($LASTEXITCODE -ne 0){{exit 77}}}}; & icacls.exe $m /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null; if($LASTEXITCODE -ne 0){{exit 77}}; Assert-Safe $p $true; Assert-Safe $m $false; Assert-Safe $o $true\""
            ),
            path = path,
            output = output,
            binary = binary,
            inventory = inventory,
            log = log,
            token = token,
        )
    }

    fn windows_cleanup_command(&self) -> String {
        let path = escape_powershell_literal(&self.remote_temp_dir);
        let output = escape_powershell_literal(&self.remote_output_root);
        let binary = escape_powershell_literal(&self.remote_binary_path);
        let inventory = escape_powershell_literal(&self.inventory_path);
        let log = escape_powershell_literal(&self.log_path);
        let token = escape_powershell_literal(&self.workspace_token);
        format!(
            concat!(
                "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"",
                "$ErrorActionPreference='Stop'; $p='{path}'; if(-not (Test-Path -LiteralPath $p)){{exit 0}}; $o='{output}'; $m=Join-Path $p '.pandora-owner'; $t='{token}'; $me=[Security.Principal.WindowsIdentity]::GetCurrent().Name; ",
                "function Assert-Safe([string]$x,[bool]$dir) {{ if(-not (Test-Path -LiteralPath $x)){{return}}; $v=Get-Item -LiteralPath $x -Force; if(($v.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){{exit 81}}; if($dir -and -not $v.PSIsContainer){{exit 82}}; $owner=(Get-Acl -LiteralPath $x).Owner; if($owner -ne $me -and $owner -notmatch '\\\\Administrators$' -and $owner -ne 'NT AUTHORITY\\SYSTEM'){{exit 83}} }}; ",
                "Assert-Safe $p $true; Assert-Safe $m $false; Assert-Safe $o $true; if((Get-Content -LiteralPath $m -Raw).Trim() -ne $t){{exit 84}}; ",
                "foreach($f in @('{binary}','{inventory}','{log}')){{Assert-Safe $f $false; if(Test-Path -LiteralPath $f){{Remove-Item -LiteralPath $f -Force}}}}; Remove-Item -LiteralPath $m -Force; if(Test-Path -LiteralPath $o){{Remove-Item -LiteralPath $o -Force}}; Remove-Item -LiteralPath $p -Force\""
            ),
            path = path,
            output = output,
            binary = binary,
            inventory = inventory,
            log = log,
            token = token,
        )
    }
}

fn escape_posix_path(path: &str) -> String {
    path.replace('\'', r#"'\''"#)
}

fn escape_powershell_literal(path: &str) -> String {
    path.replace('\'', "''")
}

fn random_workspace_token() -> Result<String, String> {
    let mut bytes = [0_u8; 24];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| format!("secure workspace randomness unavailable: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn workspace_for_token(plan: &HostPlan, token: String) -> Result<RemoteWorkspace, String> {
    let payload = plan
        .payload
        .as_ref()
        .ok_or_else(|| "cannot build a workspace without a preflighted payload".to_string())?;

    if plan.contract.operating_system.uses_windows_shell() {
        let remote_temp_dir = format!(r"C:\Windows\Temp\.pandora-{token}");
        let remote_binary_path = format!(r"{remote_temp_dir}\chimera.exe");
        let remote_output_root = format!(r"{remote_temp_dir}\output");
        return Ok(RemoteWorkspace {
            shell: RemoteShell::PowerShell,
            collector_source_path: payload.path.clone(),
            staged_local_name: "chimera.exe".to_string(),
            remote_temp_dir,
            remote_binary_path,
            inventory_path: format!(r"{remote_output_root}\inventory.json"),
            log_path: format!(r"{remote_output_root}\application.log"),
            remote_output_root,
            payload_sha256: payload.sha256.clone(),
            workspace_token: token,
        });
    }

    if !plan.contract.operating_system.uses_posix_shell() {
        return Err("unknown targets cannot receive a remote workspace".into());
    }
    let remote_temp_dir = format!("/tmp/.pandora-{token}");
    let remote_binary_path = format!("{remote_temp_dir}/chimera");
    let remote_output_root = format!("{remote_temp_dir}/output");

    Ok(RemoteWorkspace {
        shell: RemoteShell::Posix,
        collector_source_path: payload.path.clone(),
        staged_local_name: "chimera".to_string(),
        remote_temp_dir,
        remote_binary_path,
        inventory_path: format!("{remote_output_root}/inventory.json"),
        log_path: format!("{remote_output_root}/application.log"),
        remote_output_root,
        payload_sha256: payload.sha256.clone(),
        workspace_token: token,
    })
}

pub fn remote_workspace(_spec: &MissionSpec, plan: &HostPlan) -> Result<RemoteWorkspace, String> {
    workspace_for_token(plan, random_workspace_token()?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectorPlan {
    Preview,
    Chimera { workspace: Box<RemoteWorkspace> },
}

pub fn collector_plan(spec: &MissionSpec, plan: &HostPlan) -> Result<CollectorPlan, String> {
    if spec.dry_run {
        return Ok(CollectorPlan::Preview);
    }
    Ok(CollectorPlan::Chimera {
        workspace: Box::new(remote_workspace(spec, plan)?),
    })
}

#[must_use]
pub fn capability_probe_command(contract: &TargetContract) -> String {
    if contract.operating_system == OperatingSystem::Windows {
        return concat!(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"",
            "Write-Output 'pandora_os=windows'; ",
            "Write-Output ('pandora_arch=' + $env:PROCESSOR_ARCHITECTURE)\""
        )
        .to_string();
    }

    "sh -c 'printf \"pandora_os=%s\\npandora_arch=%s\\n\" \"$(uname -s)\" \"$(uname -m)\"'"
        .to_string()
}

pub fn validate_capability_capture(capture: &str, contract: &TargetContract) -> Result<(), String> {
    let os = capture
        .lines()
        .find_map(|line| line.trim().strip_prefix("pandora_os="))
        .map(str::trim)
        .ok_or_else(|| "capability probe omitted pandora_os".to_string())?;
    let architecture = capture
        .lines()
        .find_map(|line| line.trim().strip_prefix("pandora_arch="))
        .map(str::trim)
        .ok_or_else(|| "capability probe omitted pandora_arch".to_string())?;

    let os_matches = match contract.operating_system {
        OperatingSystem::Linux => os.eq_ignore_ascii_case("linux"),
        OperatingSystem::Windows => os.eq_ignore_ascii_case("windows"),
        OperatingSystem::FreeBsd | OperatingSystem::PfSense => os.eq_ignore_ascii_case("freebsd"),
        OperatingSystem::OpenBsd => os.eq_ignore_ascii_case("openbsd"),
        OperatingSystem::NetBsd => os.eq_ignore_ascii_case("netbsd"),
        OperatingSystem::DragonFlyBsd => os.eq_ignore_ascii_case("dragonfly"),
        OperatingSystem::Bsd => false,
        OperatingSystem::Unknown => false,
    };
    let architecture_matches = match contract.architecture {
        CpuArchitecture::X86_64 => ["x86_64", "amd64"]
            .iter()
            .any(|candidate| architecture.eq_ignore_ascii_case(candidate)),
        CpuArchitecture::X86 => ["x86", "i386", "i486", "i586", "i686"]
            .iter()
            .any(|candidate| architecture.eq_ignore_ascii_case(candidate)),
        CpuArchitecture::Aarch64 => ["aarch64", "arm64"]
            .iter()
            .any(|candidate| architecture.eq_ignore_ascii_case(candidate)),
        CpuArchitecture::Armv7 => ["armv7", "armv7l"]
            .iter()
            .any(|candidate| architecture.eq_ignore_ascii_case(candidate)),
        CpuArchitecture::Unknown => false,
    };

    if !os_matches || !architecture_matches {
        return Err(format!(
            "capability identity mismatch: contract={}/{} observed={os}/{architecture}; staging was not attempted",
            contract.operating_system.as_str(),
            contract.architecture.as_str()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        capability_probe_command, collector_plan, validate_capability_capture, workspace_for_token,
        CollectorPlan, RemoteShell,
    };
    use crate::runtime::mission::{
        CpuArchitecture, HostPlan, HostTarget, MissionSpec, OperatingSystem, PayloadQualification,
        PlatformHint, ResolvedPayload, TargetContract, TransportKind,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    fn plan(operating_system: OperatingSystem, transport: TransportKind) -> HostPlan {
        let contract = if operating_system == OperatingSystem::Windows {
            TargetContract::windows(
                CpuArchitecture::X86_64,
                transport == TransportKind::WindowsSmb,
            )
        } else {
            TargetContract::ssh(operating_system, CpuArchitecture::X86_64)
        };
        HostPlan::queued(
            HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 40)),
                platform: PlatformHint::Unknown,
                open_ports: vec![22, 445],
            },
            contract,
            vec![transport],
        )
        .with_payload(ResolvedPayload {
            operating_system,
            architecture: CpuArchitecture::X86_64,
            path: PathBuf::from(if operating_system == OperatingSystem::Windows {
                "release/chimera.exe"
            } else {
                "release/chimera"
            }),
            version: "test".into(),
            sha256: "a".repeat(64),
            qualification: PayloadQualification::LiveQualified,
            evidence: vec!["fixture".into()],
            size_bytes: 1,
        })
    }

    #[test]
    fn workspaces_are_unpredictable_and_not_mission_derived() {
        let first = workspace_for_token(
            &plan(OperatingSystem::Linux, TransportKind::SshSftp),
            "0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        )
        .expect("workspace");
        let second = workspace_for_token(
            &plan(OperatingSystem::Linux, TransportKind::SshSftp),
            "abcdef0123456789abcdef0123456789abcdef0123456789".into(),
        )
        .expect("workspace");

        assert_ne!(first.remote_temp_dir, second.remote_temp_dir);
        assert!(!first.remote_temp_dir.contains("mission"));
    }

    #[test]
    fn posix_workspace_rejects_links_ownership_and_unsafe_cleanup() {
        let workspace = workspace_for_token(
            &plan(OperatingSystem::FreeBsd, TransportKind::SshSftp),
            "0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        )
        .expect("workspace");
        let create = workspace.ensure_directories_command();
        let cleanup = workspace.cleanup_command();

        assert_eq!(workspace.shell, RemoteShell::Posix);
        assert!(create.contains("[ ! -L"));
        assert!(create.contains("owner_of"));
        assert!(create.contains("mode_of"));
        assert!(workspace.post_stage_commands()[0].contains("sha256sum"));
        assert!(workspace.post_stage_commands()[0].contains(&"a".repeat(64)));
        assert!(cleanup.contains(".pandora-owner"));
        assert!(!cleanup.contains("rm -rf"));
    }

    #[test]
    fn windows_workspace_rejects_reparse_points_and_uses_non_recursive_cleanup() {
        let workspace = workspace_for_token(
            &plan(OperatingSystem::Windows, TransportKind::SshSftp),
            "0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        )
        .expect("workspace");
        let create = workspace.ensure_directories_command();
        let cleanup = workspace.cleanup_command();

        assert_eq!(workspace.shell, RemoteShell::PowerShell);
        assert!(create.contains("ReparsePoint"));
        assert!(create.contains("Get-Acl"));
        assert!(create.contains("icacls.exe"));
        assert!(workspace.post_stage_commands()[0].contains("Get-FileHash"));
        assert!(!cleanup.contains("-Recurse"));
    }

    #[test]
    fn persisted_workspace_rejects_hostile_path_substitution() {
        let plan = plan(OperatingSystem::Linux, TransportKind::SshSftp);
        let mut workspace = workspace_for_token(
            &plan,
            "0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        )
        .expect("workspace");
        workspace.remote_temp_dir = "/tmp/operator-chosen-link".into();
        let error = workspace
            .validate_for_plan(&plan)
            .expect_err("tampered workspace must fail closed");
        assert!(error.contains("does not match"));
    }

    #[test]
    fn capability_validation_is_exact_before_staging() {
        let contract = TargetContract::ssh(OperatingSystem::PfSense, CpuArchitecture::X86_64);
        validate_capability_capture(
            "command: probe\nstdout:\npandora_os=FreeBSD\npandora_arch=amd64\n",
            &contract,
        )
        .expect("pfSense should match its FreeBSD runtime");
        let error =
            validate_capability_capture("pandora_os=Linux\npandora_arch=x86_64\n", &contract)
                .expect_err("incompatible payload must be stopped");
        assert!(error.contains("staging was not attempted"));
        assert!(!capability_probe_command(&contract).is_empty());
    }

    #[test]
    fn dry_run_plan_contains_no_remote_command_or_workspace() {
        let spec = MissionSpec {
            dry_run: true,
            ..MissionSpec::default()
        };
        assert_eq!(
            collector_plan(&spec, &plan(OperatingSystem::Linux, TransportKind::SshSftp))
                .expect("plan"),
            CollectorPlan::Preview
        );
    }
}
