#[cfg(unix)]
use super::render_network_topology_png_explicit;
use super::{
    parse_remote_ip, record_from_report, render_asset_inventory_csv,
    render_asset_inventory_markdown, render_asset_inventory_pdf,
    render_network_topology_excalidraw, render_network_topology_markdown,
    render_network_topology_mermaid, AssetInventoryBundle, AssetInventoryHost, InventoryArtifact,
    NetworkTopology, TopologyEdge, TopologyHost,
};
use crate::runtime::{
    CpuArchitecture, HostExecutionReport, HostPlan, HostTarget, OperatingSystem, PlatformHint,
    TargetContract, TransportKind,
};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn asset_inventory_renderers_include_host_rows() {
    let bundle = AssetInventoryBundle {
        mission_id: "mission-123".to_string(),
        requested_targets: 1,
        reachable_targets: 1,
        unreachable_targets: 0,
        skipped_targets: 0,
        attempted_targets: 1,
        discovered_hosts: 1,
        completed_hosts: 1,
        failed_hosts: 0,
        partial_hosts: 0,
        hosts: vec![AssetInventoryHost {
            ip: "10.0.0.10".to_string(),
            final_state: "complete".to_string(),
            collection_state: "complete".to_string(),
            section_errors: Vec::new(),
            platform: "linux".to_string(),
            architecture: "x86_64".to_string(),
            payload_version: Some("fixture-v1".to_string()),
            payload_sha256: Some("a".repeat(64)),
            transport_chain: vec!["unix_ssh".to_string()],
            selected_transport: Some("unix_ssh".to_string()),
            failure_phase: None,
            failure_disposition: None,
            cleanup_outcome: "complete".to_string(),
            residue_present: false,
            partial_collection: false,
            hostname: Some("lab".to_string()),
            os: Some("Ubuntu".to_string()),
            open_ports: vec![22, 80],
            admin_users: vec!["root".to_string()],
            services: vec!["sshd".to_string()],
            shares: Vec::new(),
            container_count: 0,
            error: None,
        }],
    };

    let markdown = render_asset_inventory_markdown(&bundle);
    assert!(markdown.contains("| 10.0.0.10 | complete | complete | - | linux |"));
    assert!(markdown.contains("| complete | no | no | lab | Ubuntu | 22,80 | root | sshd |"));
    let csv = render_asset_inventory_csv(&bundle);
    assert!(csv.contains("10.0.0.10,complete,complete"));
    assert!(csv.contains(",linux,x86_64,fixture-v1,"));
    assert!(csv.contains(",unix_ssh,"));
    assert!(csv.contains("complete,false,false,lab,Ubuntu,\"22,80\",root,sshd"));
    let pdf = render_asset_inventory_pdf(&bundle);
    assert!(pdf.starts_with(b"%PDF-1.4"));
    let pdf_text = String::from_utf8_lossy(&pdf);
    assert!(pdf_text.contains("Pandora's Box Asset Inventory"));
    assert!(pdf_text.contains("lab  \\(10.0.0.10\\)"));
    assert!(pdf_text.contains("Requested"));
}

#[test]
fn network_topology_renderers_include_observed_edges() {
    let topology = NetworkTopology {
        hosts: vec![
            TopologyHost {
                ip: "10.0.0.51".to_string(),
                label: "web-01".to_string(),
                final_state: "complete".to_string(),
                platform: "unix".to_string(),
                os: Some("Ubuntu".to_string()),
                open_ports: vec![22],
                services: vec!["sshd".to_string()],
            },
            TopologyHost {
                ip: "10.0.0.52".to_string(),
                label: "db-01".to_string(),
                final_state: "complete".to_string(),
                platform: "unix".to_string(),
                os: Some("Ubuntu".to_string()),
                open_ports: vec![5432],
                services: vec!["postgresql".to_string()],
            },
        ],
        edges: vec![TopologyEdge {
            from_ip: "10.0.0.51".to_string(),
            to_ip: "10.0.0.52".to_string(),
        }],
    };

    assert!(render_network_topology_markdown("mission-123", &topology).contains("web-01 <-> db-01"));
    assert!(render_network_topology_mermaid(&topology)
        .contains("host_10_0_0_51 -. observed .- host_10_0_0_52"));
    let excalidraw = render_network_topology_excalidraw("mission-123", &topology);
    assert!(excalidraw.contains("\"type\": \"excalidraw\""));
    assert!(excalidraw.contains("Subnet 10.0.0.0/24"));
    assert!(excalidraw.contains("Diagram Key"));
    assert!(excalidraw.contains("host_box_10_0_0_51"));
    assert!(excalidraw.contains("edge_10_0_0_51_to_10_0_0_52"));
}

#[test]
fn network_topology_excalidraw_groups_failed_hosts_separately() {
    let topology = NetworkTopology {
        hosts: vec![
            TopologyHost {
                ip: "10.0.0.60".to_string(),
                label: "jump-01".to_string(),
                final_state: "complete".to_string(),
                platform: "unix".to_string(),
                os: Some("Ubuntu".to_string()),
                open_ports: vec![22],
                services: vec!["sshd".to_string()],
            },
            TopologyHost {
                ip: "10.0.1.61".to_string(),
                label: "db-02".to_string(),
                final_state: "complete".to_string(),
                platform: "unix".to_string(),
                os: Some("Ubuntu".to_string()),
                open_ports: vec![5432],
                services: vec!["postgresql".to_string()],
            },
            TopologyHost {
                ip: "10.0.9.99".to_string(),
                label: "lost-host".to_string(),
                final_state: "failed".to_string(),
                platform: "windows".to_string(),
                os: None,
                open_ports: vec![22, 445],
                services: Vec::new(),
            },
        ],
        edges: vec![TopologyEdge {
            from_ip: "10.0.0.60".to_string(),
            to_ip: "10.0.1.61".to_string(),
        }],
    };

    let excalidraw = render_network_topology_excalidraw("mission-456", &topology);
    assert!(excalidraw.contains("Subnet 10.0.0.0/24"));
    assert!(excalidraw.contains("Subnet 10.0.1.0/24"));
    assert!(excalidraw.contains("Unreachable / No Inventory"));
    assert!(excalidraw.contains("collection did not complete"));
}

#[test]
fn parse_remote_ip_accepts_socket_and_ip_forms() {
    assert_eq!(
        parse_remote_ip("10.0.0.52:5432"),
        Some("10.0.0.52".to_string())
    );
    assert_eq!(
        parse_remote_ip("[fe80::1]:443"),
        Some("fe80::1".to_string())
    );
    assert_eq!(parse_remote_ip(""), None);
    assert_eq!(parse_remote_ip("db.internal"), None);
}

#[test]
fn inventory_artifact_deserializer_allows_null_remote_addresses() {
    let artifact: InventoryArtifact = serde_json::from_str(
        r#"{
  "hostname": "DESKTOP-PTNJUS5",
  "os": "Windows 11 Pro",
  "ports": [],
  "connections": [
    {"remoteAddress": null, "protocol": "UDP"},
    {"remoteAddress": "10.0.2.2", "protocol": "TCP"}
  ],
  "services": [],
  "users": [],
  "shares": [],
  "containers": []
}"#,
    )
    .expect("inventory artifact should deserialize");

    assert_eq!(artifact.connections.len(), 2);
    assert_eq!(artifact.connections[0].remote_address, None);
    assert_eq!(
        artifact.connections[1].remote_address.as_deref(),
        Some("10.0.2.2")
    );
}

#[test]
fn aggregate_reports_surface_section_level_partial_inventory() {
    let inventory: InventoryArtifact = serde_json::from_str(
        r#"{
  "hostname":"partial-host",
  "os":"Linux",
  "ports":[],
  "connections":[],
  "services":[],
  "users":[],
  "shares":[],
  "containers":[],
  "sectionErrors":[{"section":"services","message":"systemctl timed out"}]
}"#,
    )
    .expect("partial inventory");
    let plan = HostPlan::queued(
        HostTarget {
            ip: "192.0.2.10".parse().expect("ip"),
            platform: PlatformHint::UnixLike,
            open_ports: vec![22],
        },
        TargetContract::ssh(OperatingSystem::Linux, CpuArchitecture::X86_64),
        vec![TransportKind::SshSftp],
    );
    let report = HostExecutionReport::success(plan, crate::runtime::HostState::Complete);
    let record = record_from_report(&report, Ok(inventory));
    assert_eq!(record.host.collection_state, "partial");
    assert_eq!(record.host.section_errors.len(), 1);
    assert!(record
        .host
        .error
        .as_deref()
        .expect("partial error")
        .contains("services: systemctl timed out"));

    let bundle = AssetInventoryBundle {
        mission_id: "partial".into(),
        requested_targets: 1,
        reachable_targets: 1,
        unreachable_targets: 0,
        skipped_targets: 0,
        attempted_targets: 1,
        discovered_hosts: 1,
        completed_hosts: 1,
        failed_hosts: 0,
        partial_hosts: 1,
        hosts: vec![record.host],
    };
    assert!(render_asset_inventory_markdown(&bundle).contains("systemctl timed out"));
    assert!(render_asset_inventory_csv(&bundle).contains("systemctl timed out"));
    assert!(
        String::from_utf8_lossy(&render_asset_inventory_pdf(&bundle))
            .contains("systemctl timed out")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn topology_png_renderer_is_explicit_digest_pinned_and_bounded() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let temp_root = std::env::temp_dir().join(format!("pandoras-box-renderer-test-{unique}"));
    fs::create_dir_all(&temp_root).expect("temp dir should exist");

    let script_path = temp_root.join("fake-renderer.sh");
    fs::write(&script_path, "#!/bin/sh\nprintf 'fake-png' > \"$2\"\n")
        .expect("stub renderer should exist");
    let mut permissions = fs::metadata(&script_path)
        .expect("stub metadata should exist")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script_path, permissions).expect("stub script should be executable");

    let renderer = crate::runtime::RendererSpec {
        executable: script_path.clone(),
        sha256: crate::runtime::payloads::sha256_file_bounded(&script_path, 4096)
            .await
            .expect("renderer digest"),
        timeout: std::time::Duration::from_secs(2),
        max_output_bytes: 32,
    };
    let store = crate::runtime::ArtifactStore::new(&temp_root, "mission").expect("artifact store");
    store
        .write_network_topology_excalidraw(r##"{"type":"excalidraw","version":2,"elements":[]}"##)
        .await
        .expect("topology source");

    render_network_topology_png_explicit(&store, &renderer)
        .await
        .expect("explicit renderer should run");
    assert_eq!(
        tokio::fs::read(store.network_topology_png_path())
            .await
            .expect("png"),
        b"fake-png"
    );
    let _ = fs::remove_dir_all(temp_root);
}
