use std::path::PathBuf;

use super::mission::{HostPlan, MissionSpec, PlatformHint, TransportKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteShell {
    Posix,
    Cmd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteWorkspace {
    pub shell: RemoteShell,
    pub collector_source_path: PathBuf,
    pub credentials_username: String,
    pub staged_local_name: String,
    pub remote_temp_dir: String,
    pub remote_binary_path: String,
    pub remote_output_root: String,
    pub inventory_endpoint: String,
    pub log_endpoint: String,
    pub collector_port: u16,
}

impl RemoteWorkspace {
    #[must_use]
    pub fn ensure_directories_command(&self) -> String {
        match self.shell {
            RemoteShell::Posix => format!(
                "mkdir -p '{}' '{}'",
                escape_posix_path(&self.remote_temp_dir),
                escape_posix_path(&self.remote_output_root),
            ),
            RemoteShell::Cmd => format!(
                r#"cmd.exe /C if not exist "{}" md "{}" && if not exist "{}" md "{}""#,
                self.remote_temp_dir,
                self.remote_temp_dir,
                self.remote_output_root,
                self.remote_output_root,
            ),
        }
    }

    #[must_use]
    pub fn post_stage_commands(&self) -> Vec<String> {
        match self.shell {
            RemoteShell::Posix => vec![format!("chmod +x {}", self.remote_binary_path)],
            RemoteShell::Cmd => Vec::new(),
        }
    }

    #[must_use]
    pub fn collector_command(&self) -> String {
        match self.shell {
            RemoteShell::Posix => {
                format!(
                    "{} --output-root {} collector",
                    self.remote_binary_path, self.remote_output_root
                )
            }
            RemoteShell::Cmd => format!(
                r#"cmd.exe /C "{} --output-root {} collector""#,
                self.remote_binary_path, self.remote_output_root,
            ),
        }
    }

    #[must_use]
    pub fn serve_command(&self) -> String {
        match self.shell {
            RemoteShell::Posix => format!(
                "{} --output-root {} serve --port {}",
                self.remote_binary_path, self.remote_output_root, self.collector_port,
            ),
            RemoteShell::Cmd => format!(
                r#"cmd.exe /C "{} --output-root {} serve --port {}""#,
                self.remote_binary_path, self.remote_output_root, self.collector_port,
            ),
        }
    }

    #[must_use]
    pub fn credentials_command(&self, magic: u32) -> String {
        match self.shell {
            RemoteShell::Posix => format!(
                "{} credentials --magic {} --username {}",
                self.remote_binary_path, magic, self.credentials_username
            ),
            RemoteShell::Cmd => format!(
                r#"cmd.exe /C "{} credentials --magic {} --username {}""#,
                self.remote_binary_path, magic, self.credentials_username,
            ),
        }
    }

    #[must_use]
    pub fn credentials_cleanup_command(&self, magic: u32) -> String {
        match self.shell {
            RemoteShell::Posix => format!(
                "sh -lc '\"{}\" credentials --magic {} --username {}; status=$?; rm -rf \"{}\"; exit $status'",
                self.remote_binary_path, magic, self.credentials_username, self.remote_temp_dir,
            ),
            RemoteShell::Cmd => format!(
                r#"cmd.exe /V:ON /C ""{}" credentials --magic {} --username {} & set PB_STATUS=!ERRORLEVEL! & if exist "{}" rmdir /S /Q "{}" & exit /B !PB_STATUS!""#,
                self.remote_binary_path, magic, self.credentials_username, self.remote_temp_dir, self.remote_temp_dir,
            ),
        }
    }

    #[must_use]
    pub fn preview_command(&self) -> String {
        match self.shell {
            RemoteShell::Posix => "sh -lc 'uname -a && printf \"\\n\" && id'".to_string(),
            RemoteShell::Cmd => r#"cmd.exe /C "ver & whoami""#.to_string(),
        }
    }

    #[must_use]
    pub fn cleanup_command(&self) -> String {
        match self.shell {
            RemoteShell::Posix => format!("rm -rf '{}'", escape_posix_path(&self.remote_temp_dir)),
            RemoteShell::Cmd => format!(
                r#"cmd.exe /C if exist "{}" rmdir /S /Q "{}""#,
                self.remote_temp_dir, self.remote_temp_dir
            ),
        }
    }
}

fn escape_posix_path(path: &str) -> String {
    path.replace('\'', r#"'\''"#)
}

fn remote_workspace_slug(mission_id: &str) -> String {
    let slug = mission_id
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '_',
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();

    if slug.is_empty() {
        "mission".to_string()
    } else {
        slug
    }
}

#[must_use]
pub fn remote_workspace(spec: &MissionSpec, plan: &HostPlan) -> RemoteWorkspace {
    let workspace_slug = remote_workspace_slug(&spec.mission_id);

    if uses_windows_shell(plan) {
        let remote_temp_dir = format!(r"C:\Windows\Temp\pandoras_box\{workspace_slug}");
        let remote_binary_path = format!(r"{remote_temp_dir}\chimera.exe");
        let remote_output_root = format!(r"{remote_temp_dir}\output");
        return RemoteWorkspace {
            shell: RemoteShell::Cmd,
            collector_source_path: spec.chimera_windows_path.clone(),
            credentials_username: spec.windows_username.clone(),
            staged_local_name: "chimera.exe".to_string(),
            remote_temp_dir,
            remote_binary_path,
            remote_output_root,
            inventory_endpoint: "inventory.json".to_string(),
            log_endpoint: "application.log".to_string(),
            collector_port: spec.collector_port,
        };
    }

    let remote_temp_dir = format!("/tmp/pandoras_box/{workspace_slug}");
    let remote_binary_path = format!("{remote_temp_dir}/chimera");
    let remote_output_root = format!("{remote_temp_dir}/output");

    RemoteWorkspace {
        shell: RemoteShell::Posix,
        collector_source_path: spec.chimera_unix_path.clone(),
        credentials_username: spec.unix_username.clone(),
        staged_local_name: "chimera".to_string(),
        remote_temp_dir,
        remote_binary_path,
        remote_output_root,
        inventory_endpoint: "inventory.json".to_string(),
        log_endpoint: "application.log".to_string(),
        collector_port: spec.collector_port,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectorPlan {
    Preview {
        workspace: RemoteWorkspace,
        command: String,
    },
    Chimera {
        workspace: RemoteWorkspace,
    },
}

#[must_use]
pub fn collector_plan(spec: &MissionSpec, plan: &HostPlan) -> CollectorPlan {
    let workspace = remote_workspace(spec, plan);

    if spec.dry_run {
        CollectorPlan::Preview {
            command: workspace.preview_command(),
            workspace,
        }
    } else {
        CollectorPlan::Chimera { workspace }
    }
}

fn uses_windows_shell(plan: &HostPlan) -> bool {
    matches!(
        plan.transport_chain.first().copied(),
        Some(TransportKind::WindowsSsh | TransportKind::WindowsSmb)
    ) || plan.target.platform == PlatformHint::Windows
}

#[cfg(test)]
mod tests {
    use super::{
        collector_plan, remote_workspace, remote_workspace_slug, CollectorPlan, RemoteShell,
        RemoteWorkspace,
    };
    use crate::runtime::mission::{HostPlan, HostTarget, MissionSpec, PlatformHint, TransportKind};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    fn plan(platform: PlatformHint, chain: Vec<TransportKind>) -> HostPlan {
        HostPlan::queued(
            HostTarget {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 40)),
                platform,
                open_ports: vec![22, 445],
            },
            chain,
        )
    }

    fn spec() -> MissionSpec {
        MissionSpec {
            mission_id: "mission-123".to_string(),
            chimera_unix_path: PathBuf::from("/tmp/chimera-local"),
            chimera_windows_path: PathBuf::from(r"C:\Temp\chimera-local.exe"),
            windows_username: "mitre".to_string(),
            collector_port: 44_372,
            ..MissionSpec::default()
        }
    }

    #[test]
    fn unix_remote_workspace_uses_posix_paths_and_launch_contract() {
        let workspace = remote_workspace(
            &spec(),
            &plan(PlatformHint::Unix, vec![TransportKind::UnixSsh]),
        );

        assert_eq!(
            workspace,
            RemoteWorkspace {
                shell: RemoteShell::Posix,
                collector_source_path: PathBuf::from("/tmp/chimera-local"),
                credentials_username: "root".to_string(),
                staged_local_name: "chimera".to_string(),
                remote_temp_dir: "/tmp/pandoras_box/mission-123".to_string(),
                remote_binary_path: "/tmp/pandoras_box/mission-123/chimera".to_string(),
                remote_output_root: "/tmp/pandoras_box/mission-123/output".to_string(),
                inventory_endpoint: "inventory.json".to_string(),
                log_endpoint: "application.log".to_string(),
                collector_port: 44_372,
            }
        );
        assert_eq!(
            workspace.collector_command(),
            "/tmp/pandoras_box/mission-123/chimera --output-root /tmp/pandoras_box/mission-123/output collector"
        );
        assert_eq!(
            workspace.serve_command(),
            "/tmp/pandoras_box/mission-123/chimera --output-root /tmp/pandoras_box/mission-123/output serve --port 44372"
        );
        assert_eq!(
            workspace.credentials_command(17),
            "/tmp/pandoras_box/mission-123/chimera credentials --magic 17 --username root"
        );
        assert_eq!(
            workspace.credentials_cleanup_command(17),
            r#"sh -lc '"/tmp/pandoras_box/mission-123/chimera" credentials --magic 17 --username root; status=$?; rm -rf "/tmp/pandoras_box/mission-123"; exit $status'"#
        );
        assert_eq!(
            workspace.ensure_directories_command(),
            "mkdir -p '/tmp/pandoras_box/mission-123' '/tmp/pandoras_box/mission-123/output'"
        );
        assert_eq!(
            workspace.post_stage_commands(),
            vec!["chmod +x /tmp/pandoras_box/mission-123/chimera"]
        );
        assert_eq!(
            workspace.cleanup_command(),
            "rm -rf '/tmp/pandoras_box/mission-123'"
        );
    }

    #[test]
    fn windows_remote_workspace_uses_cmd_paths_and_launch_contract() {
        let workspace = remote_workspace(
            &spec(),
            &plan(
                PlatformHint::Windows,
                vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb],
            ),
        );

        assert_eq!(
            workspace,
            RemoteWorkspace {
                shell: RemoteShell::Cmd,
                collector_source_path: PathBuf::from(r"C:\Temp\chimera-local.exe"),
                credentials_username: "mitre".to_string(),
                staged_local_name: "chimera.exe".to_string(),
                remote_temp_dir: r"C:\Windows\Temp\pandoras_box\mission-123".to_string(),
                remote_binary_path: r"C:\Windows\Temp\pandoras_box\mission-123\chimera.exe"
                    .to_string(),
                remote_output_root: r"C:\Windows\Temp\pandoras_box\mission-123\output".to_string(),
                inventory_endpoint: "inventory.json".to_string(),
                log_endpoint: "application.log".to_string(),
                collector_port: 44_372,
            }
        );
        assert_eq!(
            workspace.collector_command(),
            r#"cmd.exe /C "C:\Windows\Temp\pandoras_box\mission-123\chimera.exe --output-root C:\Windows\Temp\pandoras_box\mission-123\output collector""#
        );
        assert_eq!(
            workspace.serve_command(),
            r#"cmd.exe /C "C:\Windows\Temp\pandoras_box\mission-123\chimera.exe --output-root C:\Windows\Temp\pandoras_box\mission-123\output serve --port 44372""#
        );
        assert_eq!(
            workspace.credentials_command(17),
            r#"cmd.exe /C "C:\Windows\Temp\pandoras_box\mission-123\chimera.exe credentials --magic 17 --username mitre""#
        );
        assert_eq!(
            workspace.credentials_cleanup_command(17),
            r#"cmd.exe /V:ON /C ""C:\Windows\Temp\pandoras_box\mission-123\chimera.exe" credentials --magic 17 --username mitre & set PB_STATUS=!ERRORLEVEL! & if exist "C:\Windows\Temp\pandoras_box\mission-123" rmdir /S /Q "C:\Windows\Temp\pandoras_box\mission-123" & exit /B !PB_STATUS!""#
        );
        assert_eq!(
            workspace.ensure_directories_command(),
            r#"cmd.exe /C if not exist "C:\Windows\Temp\pandoras_box\mission-123" md "C:\Windows\Temp\pandoras_box\mission-123" && if not exist "C:\Windows\Temp\pandoras_box\mission-123\output" md "C:\Windows\Temp\pandoras_box\mission-123\output""#
        );
        assert!(workspace.post_stage_commands().is_empty());
        assert_eq!(
            workspace.cleanup_command(),
            r#"cmd.exe /C if exist "C:\Windows\Temp\pandoras_box\mission-123" rmdir /S /Q "C:\Windows\Temp\pandoras_box\mission-123""#
        );
    }

    #[test]
    fn remote_workspace_slug_sanitizes_mission_ids_for_remote_paths() {
        assert_eq!(
            remote_workspace_slug("prod scan/2026:west?"),
            "prod_scan_2026_west"
        );
        assert_eq!(remote_workspace_slug("___"), "mission");
    }

    #[test]
    fn dry_run_collector_plan_uses_preview_command_on_unix() {
        let mut spec = spec();
        spec.dry_run = true;

        let workspace = remote_workspace(
            &spec,
            &plan(PlatformHint::Unix, vec![TransportKind::UnixSsh]),
        );
        let plan = collector_plan(
            &spec,
            &plan(PlatformHint::Unix, vec![TransportKind::UnixSsh]),
        );

        assert_eq!(
            plan,
            CollectorPlan::Preview {
                workspace,
                command: "sh -lc 'uname -a && printf \"\\n\" && id'".to_string(),
            },
        );
    }

    #[test]
    fn apply_mode_collector_plan_uses_workspace_on_windows() {
        let workspace = remote_workspace(
            &spec(),
            &plan(
                PlatformHint::Windows,
                vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb],
            ),
        );

        assert_eq!(
            collector_plan(
                &spec(),
                &plan(
                    PlatformHint::Windows,
                    vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb],
                ),
            ),
            CollectorPlan::Chimera { workspace }
        );
    }
}
