use super::mission::{HostPlan, HostTarget, MissionSpec, PlatformHint, TransportKind};

pub struct Planner;

impl Planner {
    #[must_use]
    pub fn plan_host(spec: &MissionSpec, target: HostTarget) -> HostPlan {
        let transport_chain = match target.platform {
            PlatformHint::Unix => Self::unix_chain(spec, &target),
            PlatformHint::Windows => Self::windows_chain(spec, &target),
            PlatformHint::Unknown => Self::unknown_chain(spec, &target),
        };

        HostPlan::queued(target, transport_chain)
    }

    fn unix_chain(spec: &MissionSpec, target: &HostTarget) -> Vec<TransportKind> {
        if target.has_port(spec.ssh_port) {
            vec![TransportKind::UnixSsh]
        } else {
            Vec::new()
        }
    }

    fn windows_chain(spec: &MissionSpec, target: &HostTarget) -> Vec<TransportKind> {
        let has_ssh = target.has_port(spec.ssh_port);
        let has_smb = Self::has_smb(spec, target);

        match (has_ssh, has_smb) {
            (true, true) => vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb],
            (true, false) => vec![TransportKind::WindowsSsh],
            (false, true) => vec![TransportKind::WindowsSmb],
            (false, false) => Vec::new(),
        }
    }

    fn unknown_chain(spec: &MissionSpec, target: &HostTarget) -> Vec<TransportKind> {
        let has_ssh = target.has_port(spec.ssh_port);
        let has_smb = Self::has_smb(spec, target);

        if has_smb && has_ssh {
            return vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb];
        }

        if has_ssh {
            return vec![TransportKind::UnixSsh];
        }

        if has_smb {
            return vec![TransportKind::WindowsSmb];
        }

        Vec::new()
    }

    fn has_smb(spec: &MissionSpec, target: &HostTarget) -> bool {
        if target.has_port(139) || target.has_port(445) {
            return true;
        }

        spec.discovery_ports
            .iter()
            .copied()
            .filter(|port| *port != spec.ssh_port && !matches!(*port, 135 | 139 | 445))
            .any(|port| target.has_port(port))
    }
}

#[cfg(test)]
mod tests {
    use super::Planner;
    use crate::runtime::mission::{HostTarget, MissionSpec, PlatformHint, TransportKind};
    use std::net::{IpAddr, Ipv4Addr};

    fn host(platform: PlatformHint, ports: &[u16]) -> HostTarget {
        HostTarget {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            platform,
            open_ports: ports.to_vec(),
        }
    }

    #[test]
    fn planner_prefers_windows_ssh_before_smb() {
        let plan = Planner::plan_host(
            &MissionSpec::default(),
            host(PlatformHint::Windows, &[22, 445]),
        );

        assert_eq!(
            plan.transport_chain,
            vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb]
        );
    }

    #[test]
    fn planner_uses_unix_ssh_for_ssh_only_unknown_host() {
        let plan = Planner::plan_host(&MissionSpec::default(), host(PlatformHint::Unknown, &[22]));

        assert_eq!(plan.transport_chain, vec![TransportKind::UnixSsh]);
    }

    #[test]
    fn planner_keeps_smb_only_for_windows_without_ssh() {
        let plan = Planner::plan_host(&MissionSpec::default(), host(PlatformHint::Windows, &[445]));

        assert_eq!(plan.transport_chain, vec![TransportKind::WindowsSmb]);
    }

    #[test]
    fn planner_uses_configured_ssh_port_for_unknown_hosts() {
        let spec = MissionSpec {
            ssh_port: 2222,
            ..MissionSpec::default()
        };
        let plan = Planner::plan_host(&spec, host(PlatformHint::Unknown, &[2222]));

        assert_eq!(plan.transport_chain, vec![TransportKind::UnixSsh]);
    }

    #[test]
    fn planner_treats_forwarded_smb_port_as_windows_fallback() {
        let spec = MissionSpec {
            ssh_port: 4222,
            discovery_ports: vec![4222, 4445],
            ..MissionSpec::default()
        };
        let plan = Planner::plan_host(&spec, host(PlatformHint::Windows, &[4222, 4445]));

        assert_eq!(
            plan.transport_chain,
            vec![TransportKind::WindowsSsh, TransportKind::WindowsSmb]
        );
    }
}
