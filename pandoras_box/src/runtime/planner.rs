use super::mission::{HostPlan, HostTarget, MissionSpec, OperatingSystem, TransportKind};

pub struct Planner;

impl Planner {
    /// Builds a plan only from the operator's explicit target contract. Passive
    /// discovery hints can inform reports, but never select an authenticated adapter.
    #[must_use]
    pub fn plan_host(spec: &MissionSpec, target: HostTarget) -> HostPlan {
        let contract = spec.target_contract(target.ip);
        let mut transport_chain = Vec::new();
        let profiles_configured = spec.credential_profiles.is_configured();
        let credential_policy = profiles_configured
            .then(|| spec.credential_policy(target.ip).ok())
            .flatten();
        let credential_policy_valid = !profiles_configured || credential_policy.is_some();

        if contract.validate().is_ok() && contract.is_explicit() {
            for transport in contract.transports.iter().copied() {
                let profile_allows = credential_policy_valid
                    && credential_policy
                        .as_ref()
                        .is_none_or(|policy| policy.allows_transport(transport));
                let available = profile_allows
                    && match transport {
                        TransportKind::SshSftp => target.has_port(
                            credential_policy
                                .as_ref()
                                .map_or(spec.ssh_port, |policy| policy.ssh_port),
                        ),
                        TransportKind::WindowsSmb => {
                            contract.operating_system == OperatingSystem::Windows
                                && spec.allow_smb_fallback
                                && super::transport::smb::ENCRYPTION_REQUIRED_REMOTE_EXEC_QUALIFIED
                                && target.has_port(
                                    credential_policy
                                        .as_ref()
                                        .map_or(445, |policy| policy.smb_port),
                                )
                        }
                    };
                if available && !transport_chain.contains(&transport) {
                    transport_chain.push(transport);
                }
            }
        }

        // An explicit Windows contract always prefers encrypted SSH/SFTP when it is
        // available, regardless of manifest ordering. SMB remains an opt-in fallback.
        if let Some(ssh_index) = transport_chain
            .iter()
            .position(|transport| *transport == TransportKind::SshSftp)
        {
            transport_chain.swap(0, ssh_index);
        }

        HostPlan::queued(target, contract, transport_chain)
    }
}

#[cfg(test)]
mod tests {
    use super::Planner;
    use crate::runtime::mission::{
        CpuArchitecture, HostTarget, MissionSpec, OperatingSystem, PlatformHint, TargetContract,
        TransportKind,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn host(platform: PlatformHint, ports: &[u16]) -> HostTarget {
        HostTarget {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            platform,
            open_ports: ports.to_vec(),
        }
    }

    #[test]
    fn planner_never_authenticates_from_an_autodetected_hint() {
        for hint in [PlatformHint::UnixLike, PlatformHint::Windows] {
            let plan = Planner::plan_host(&MissionSpec::default(), host(hint, &[22, 445]));
            assert!(plan.transport_chain.is_empty());
            assert!(!plan.contract.is_explicit());
        }
    }

    #[test]
    fn planner_uses_explicit_linux_ssh_contract() {
        let spec = MissionSpec {
            default_target_contract: TargetContract::ssh(
                OperatingSystem::Linux,
                CpuArchitecture::X86_64,
            ),
            ..MissionSpec::default()
        };
        let plan = Planner::plan_host(&spec, host(PlatformHint::Unknown, &[22, 445]));

        assert_eq!(plan.transport_chain, vec![TransportKind::SshSftp]);
        assert_eq!(plan.contract.operating_system, OperatingSystem::Linux);
    }

    #[test]
    fn planner_uses_the_selected_named_profile_port_without_downgrading_to_22() {
        let catalog = crate::runtime::CredentialProfileCatalog::from_json(
            r#"{
              "version":1,
              "default_profile":"custom-port",
              "profiles":[{
                "name":"custom-port",
                "operating_systems":["linux"],
                "username":"root",
                "authentication":{"type":"ssh_agent","public_key_sha256":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                "transports":["ssh_sftp"],
                "ssh_port":2222
              }]
            }"#,
            std::path::Path::new("."),
        )
        .expect("credential profiles");
        let spec = MissionSpec {
            default_target_contract: TargetContract::ssh(
                OperatingSystem::Linux,
                CpuArchitecture::X86_64,
            ),
            credential_profiles: catalog,
            ..MissionSpec::default()
        };

        let wrong_port = Planner::plan_host(&spec, host(PlatformHint::UnixLike, &[22]));
        let selected_port = Planner::plan_host(&spec, host(PlatformHint::UnixLike, &[2222]));

        assert!(wrong_port.transport_chain.is_empty());
        assert_eq!(selected_port.transport_chain, vec![TransportKind::SshSftp]);
    }

    #[test]
    fn planner_keeps_smb_requested_but_inactive_until_strict_exec_is_qualified() {
        let spec = MissionSpec {
            default_target_contract: TargetContract {
                operating_system: OperatingSystem::Windows,
                architecture: CpuArchitecture::X86_64,
                transports: vec![TransportKind::WindowsSmb, TransportKind::SshSftp],
            },
            allow_smb_fallback: true,
            ..MissionSpec::default()
        };
        let plan = Planner::plan_host(&spec, host(PlatformHint::Windows, &[22, 445]));

        assert_eq!(plan.transport_chain, vec![TransportKind::SshSftp]);
        assert!(plan
            .contract
            .transports
            .contains(&TransportKind::WindowsSmb));
    }

    #[test]
    fn planner_never_activates_unqualified_smb_even_with_explicit_opt_in() {
        let contract = TargetContract::windows(CpuArchitecture::X86_64, true);
        let denied = Planner::plan_host(
            &MissionSpec {
                default_target_contract: contract.clone(),
                allow_smb_fallback: false,
                ..MissionSpec::default()
            },
            host(PlatformHint::Windows, &[445]),
        );
        let allowed = Planner::plan_host(
            &MissionSpec {
                default_target_contract: contract,
                allow_smb_fallback: true,
                ..MissionSpec::default()
            },
            host(PlatformHint::Windows, &[445]),
        );

        assert!(denied.transport_chain.is_empty());
        assert!(allowed.transport_chain.is_empty());
        assert!(allowed
            .contract
            .transports
            .contains(&TransportKind::WindowsSmb));
    }

    #[test]
    fn planner_represents_bsd_and_pfsense_over_ssh() {
        for operating_system in [
            OperatingSystem::FreeBsd,
            OperatingSystem::OpenBsd,
            OperatingSystem::NetBsd,
            OperatingSystem::DragonFlyBsd,
            OperatingSystem::PfSense,
        ] {
            let spec = MissionSpec {
                default_target_contract: TargetContract::ssh(
                    operating_system,
                    CpuArchitecture::X86_64,
                ),
                ..MissionSpec::default()
            };
            let plan = Planner::plan_host(&spec, host(PlatformHint::UnixLike, &[22]));
            assert_eq!(plan.transport_chain, vec![TransportKind::SshSftp]);
            assert_eq!(plan.contract.operating_system, operating_system);
        }
    }
}
