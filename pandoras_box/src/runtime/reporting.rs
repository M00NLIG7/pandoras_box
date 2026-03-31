use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::artifact_store::ArtifactStore;
use super::scheduler::HostExecutionReport;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AssetInventoryBundle {
    pub mission_id: String,
    pub discovered_hosts: usize,
    pub completed_hosts: usize,
    pub failed_hosts: usize,
    pub hosts: Vec<AssetInventoryHost>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AssetInventoryHost {
    pub ip: String,
    pub final_state: String,
    pub platform: String,
    pub transport_chain: Vec<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub open_ports: Vec<u16>,
    pub admin_users: Vec<String>,
    pub services: Vec<String>,
    pub shares: Vec<String>,
    pub container_count: usize,
    pub error: Option<String>,
}

#[derive(Debug)]
struct InventoryReport {
    bundle: AssetInventoryBundle,
    topology: NetworkTopology,
}

#[derive(Debug, Clone)]
struct InventoryRecord {
    host: AssetInventoryHost,
    observed_peer_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkTopology {
    hosts: Vec<TopologyHost>,
    edges: Vec<TopologyEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TopologyHost {
    ip: String,
    label: String,
    platform: String,
    os: Option<String>,
    open_ports: Vec<u16>,
    services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TopologyEdge {
    from_ip: String,
    to_ip: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct InventoryArtifact {
    hostname: String,
    os: String,
    ports: Vec<InventoryPort>,
    connections: Vec<InventoryConnection>,
    services: Vec<InventoryService>,
    users: Vec<InventoryUser>,
    shares: Vec<InventoryShare>,
    containers: Vec<InventoryContainer>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct InventoryPort {
    port: u16,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct InventoryConnection {
    remote_address: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct InventoryService {
    name: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct InventoryUser {
    name: String,
    is_admin: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct InventoryShare {
    network_path: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct InventoryContainer {}

pub async fn write_asset_inventory_bundle(
    store: &ArtifactStore,
    reports: &[HostExecutionReport],
    discovered_hosts: usize,
) -> io::Result<()> {
    let report = build_inventory_report(store, reports, discovered_hosts).await;
    let json = serde_json::to_string_pretty(&report.bundle)
        .expect("asset inventory bundle should serialize to JSON");

    store.write_asset_inventory_json(&json).await?;
    store
        .write_asset_inventory_markdown(&render_asset_inventory_markdown(&report.bundle))
        .await?;
    store
        .write_asset_inventory_csv(&render_asset_inventory_csv(&report.bundle))
        .await?;
    store
        .write_asset_inventory_pdf(&render_asset_inventory_pdf(&report.bundle))
        .await?;
    store
        .write_network_topology_markdown(&render_network_topology_markdown(
            &report.bundle.mission_id,
            &report.topology,
        ))
        .await?;
    store
        .write_network_topology_mermaid(&render_network_topology_mermaid(&report.topology))
        .await?;
    store
        .write_network_topology_excalidraw(&render_network_topology_excalidraw(
            &report.bundle.mission_id,
            &report.topology,
        ))
        .await?;

    Ok(())
}

async fn build_inventory_report(
    store: &ArtifactStore,
    reports: &[HostExecutionReport],
    discovered_hosts: usize,
) -> InventoryReport {
    let mut ordered_reports = reports.to_vec();
    ordered_reports.sort_by_key(|report| report.plan.target.ip.to_string());

    let mut records = Vec::with_capacity(ordered_reports.len());
    for report in &ordered_reports {
        let inventory = read_inventory_artifact(store, report).await;
        records.push(record_from_report(report, inventory));
    }

    let bundle = AssetInventoryBundle {
        mission_id: store
            .mission_dir()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string(),
        discovered_hosts,
        completed_hosts: reports
            .iter()
            .filter(|report| report.final_state.as_str() == "complete")
            .count(),
        failed_hosts: reports
            .iter()
            .filter(|report| report.final_state.as_str() == "failed")
            .count(),
        hosts: records.iter().map(|record| record.host.clone()).collect(),
    };

    InventoryReport {
        topology: build_network_topology(&records),
        bundle,
    }
}

async fn read_inventory_artifact(
    store: &ArtifactStore,
    report: &HostExecutionReport,
) -> Result<InventoryArtifact, String> {
    let path = store
        .host_files_dir(report.plan.target.ip)
        .join("inventory.json");
    let raw = tokio::fs::read_to_string(&path)
        .await
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_str(&raw).map_err(|err| format!("failed to parse {}: {err}", path.display()))
}

fn record_from_report(
    report: &HostExecutionReport,
    inventory: Result<InventoryArtifact, String>,
) -> InventoryRecord {
    let fallback_ports = report.plan.target.open_ports.clone();
    let base_error = report.error.clone();

    match inventory {
        Ok(inventory) => InventoryRecord {
            observed_peer_ips: inventory
                .connections
                .into_iter()
                .filter_map(|connection| parse_remote_ip(&connection.remote_address))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            host: AssetInventoryHost {
                ip: report.plan.target.ip.to_string(),
                final_state: report.final_state.as_str().to_string(),
                platform: report.plan.target.platform.as_str().to_string(),
                transport_chain: report
                    .plan
                    .transport_chain
                    .iter()
                    .map(|kind| kind.as_str().to_string())
                    .collect(),
                hostname: non_empty(inventory.hostname),
                os: non_empty(inventory.os),
                open_ports: if inventory.ports.is_empty() {
                    fallback_ports
                } else {
                    inventory.ports.into_iter().map(|port| port.port).collect()
                },
                admin_users: inventory
                    .users
                    .into_iter()
                    .filter(|user| user.is_admin)
                    .filter_map(|user| non_empty(user.name))
                    .collect(),
                services: inventory
                    .services
                    .into_iter()
                    .filter_map(|service| non_empty(service.name))
                    .collect(),
                shares: inventory
                    .shares
                    .into_iter()
                    .filter_map(|share| non_empty(share.network_path))
                    .collect(),
                container_count: inventory.containers.len(),
                error: base_error,
            },
        },
        Err(inventory_error) => InventoryRecord {
            observed_peer_ips: Vec::new(),
            host: AssetInventoryHost {
                ip: report.plan.target.ip.to_string(),
                final_state: report.final_state.as_str().to_string(),
                platform: report.plan.target.platform.as_str().to_string(),
                transport_chain: report
                    .plan
                    .transport_chain
                    .iter()
                    .map(|kind| kind.as_str().to_string())
                    .collect(),
                hostname: None,
                os: None,
                open_ports: fallback_ports,
                admin_users: Vec::new(),
                services: Vec::new(),
                shares: Vec::new(),
                container_count: 0,
                error: Some(match base_error {
                    Some(error) if report.final_state.as_str() == "failed" => error,
                    Some(error) => format!("{error}; {inventory_error}"),
                    None => inventory_error,
                }),
            },
        },
    }
}

fn build_network_topology(records: &[InventoryRecord]) -> NetworkTopology {
    let host_index = records
        .iter()
        .map(|record| (record.host.ip.clone(), &record.host))
        .collect::<BTreeMap<_, _>>();

    let hosts = records
        .iter()
        .map(|record| TopologyHost {
            ip: record.host.ip.clone(),
            label: display_host_name(&record.host).to_string(),
            platform: record.host.platform.clone(),
            os: record.host.os.clone(),
            open_ports: record.host.open_ports.clone(),
            services: record.host.services.clone(),
        })
        .collect();

    let mut edge_set = BTreeSet::new();
    for record in records {
        for peer_ip in &record.observed_peer_ips {
            if peer_ip == &record.host.ip {
                continue;
            }
            if host_index.contains_key(peer_ip) {
                edge_set.insert(TopologyEdge {
                    from_ip: record.host.ip.clone(),
                    to_ip: peer_ip.clone(),
                });
            }
        }
    }

    NetworkTopology {
        hosts,
        edges: edge_set.into_iter().collect(),
    }
}

fn render_asset_inventory_markdown(bundle: &AssetInventoryBundle) -> String {
    let mut markdown = String::new();
    markdown.push_str("# Asset Inventory\n\n");
    markdown.push_str(&format!("Mission: `{}`\n\n", bundle.mission_id));
    markdown.push_str(&format!(
        "Discovered hosts: {}  \nCompleted hosts: {}  \nFailed hosts: {}\n\n",
        bundle.discovered_hosts, bundle.completed_hosts, bundle.failed_hosts
    ));
    markdown.push_str(
        "| IP | State | Platform | Hostname | OS | Ports | Admin Users | Services | Shares | Error |\n",
    );
    markdown.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");

    for host in &bundle.hosts {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            markdown_cell(&host.ip),
            markdown_cell(&host.final_state),
            markdown_cell(&host.platform),
            markdown_cell(optional_display(host.hostname.as_deref())),
            markdown_cell(optional_display(host.os.as_deref())),
            markdown_cell(&join_ports(&host.open_ports)),
            markdown_cell(&join_or_dash(&host.admin_users)),
            markdown_cell(&join_or_dash(&host.services)),
            markdown_cell(&join_or_dash(&host.shares)),
            markdown_cell(host.error.as_deref().unwrap_or("")),
        ));
    }

    markdown
}

fn render_asset_inventory_csv(bundle: &AssetInventoryBundle) -> String {
    let mut csv =
        String::from("ip,state,platform,hostname,os,ports,admin_users,services,shares,error\n");

    for host in &bundle.hosts {
        let ports = join_ports(&host.open_ports);
        let admin_users = join_or_dash(&host.admin_users);
        let services = join_or_dash(&host.services);
        let shares = join_or_dash(&host.shares);
        let row = [
            host.ip.as_str(),
            host.final_state.as_str(),
            host.platform.as_str(),
            optional_display(host.hostname.as_deref()),
            optional_display(host.os.as_deref()),
            ports.as_str(),
            admin_users.as_str(),
            services.as_str(),
            shares.as_str(),
            host.error.as_deref().unwrap_or(""),
        ];
        csv.push_str(
            &row.into_iter()
                .map(csv_escape)
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }

    csv
}

fn render_asset_inventory_pdf(bundle: &AssetInventoryBundle) -> Vec<u8> {
    render_minimal_pdf(&asset_inventory_pdf_lines(bundle))
}

fn asset_inventory_pdf_lines(bundle: &AssetInventoryBundle) -> Vec<String> {
    let mut lines = vec![
        "Pandora's Box Asset Inventory".to_string(),
        format!("Mission: {}", bundle.mission_id),
        format!(
            "Discovered: {}  Complete: {}  Failed: {}",
            bundle.discovered_hosts, bundle.completed_hosts, bundle.failed_hosts
        ),
        String::new(),
    ];

    for host in &bundle.hosts {
        lines.push(format!("Host {} ({})", display_host_name(host), host.ip));
        lines.push(format!(
            "State: {}  Platform: {}  OS: {}",
            host.final_state,
            host.platform,
            optional_display(host.os.as_deref())
        ));
        lines.push(format!("Ports: {}", join_ports(&host.open_ports)));
        lines.push(format!("Admin users: {}", join_or_dash(&host.admin_users)));
        lines.push(format!("Services: {}", join_or_dash(&host.services)));
        if !host.shares.is_empty() {
            lines.push(format!("Shares: {}", join_or_dash(&host.shares)));
        }
        if let Some(error) = &host.error {
            lines.push(format!("Error: {error}"));
        }
        lines.push(String::new());
    }

    lines
}

fn render_network_topology_markdown(mission_id: &str, topology: &NetworkTopology) -> String {
    let mut markdown = String::new();
    markdown.push_str("# Network Topology\n\n");
    markdown.push_str(&format!("Mission: `{mission_id}`\n\n"));

    markdown.push_str("## Hosts\n\n");
    for host in &topology.hosts {
        markdown.push_str(&format!(
            "- {} ({}) [{}] ports: {} services: {}\n",
            display_topology_name(host),
            host.ip,
            host.platform,
            join_ports(&host.open_ports),
            join_or_dash(&host.services),
        ));
    }

    markdown.push_str("\n## Observed Connections\n\n");
    if topology.edges.is_empty() {
        markdown.push_str("- No observed inter-host connections\n");
    } else {
        let host_lookup = topology_host_lookup(topology);
        for edge in &topology.edges {
            let from = host_lookup
                .get(edge.from_ip.as_str())
                .copied()
                .expect("topology edge source should exist");
            let to = host_lookup
                .get(edge.to_ip.as_str())
                .copied()
                .expect("topology edge target should exist");
            markdown.push_str(&format!(
                "- {} -> {} ({} -> {})\n",
                display_topology_name(from),
                display_topology_name(to),
                edge.from_ip,
                edge.to_ip,
            ));
        }
    }

    markdown
}

fn render_network_topology_mermaid(topology: &NetworkTopology) -> String {
    let mut mermaid = String::from("graph LR\n");

    for host in &topology.hosts {
        let label = [
            display_topology_name(host).to_string(),
            host.ip.clone(),
            host.platform.clone(),
            optional_display(host.os.as_deref()).to_string(),
        ]
        .join("\\n");
        mermaid.push_str(&format!(
            "  {}[\"{}\"]\n",
            mermaid_node_id(&host.ip),
            escape_mermaid_label(&label)
        ));
    }

    if topology.edges.is_empty() {
        mermaid.push_str("  topology_note[\"No observed inter-host connections\"]\n");
    } else {
        for edge in &topology.edges {
            mermaid.push_str(&format!(
                "  {} -. observed .-> {}\n",
                mermaid_node_id(&edge.from_ip),
                mermaid_node_id(&edge.to_ip)
            ));
        }
    }

    mermaid
}

fn render_network_topology_excalidraw(mission_id: &str, topology: &NetworkTopology) -> String {
    let mut elements = Vec::new();
    elements.push(excalidraw_text_element(
        "network_topology_title",
        48.0,
        30.0,
        620.0,
        38.0,
        "Network Topology".to_string(),
        30,
        "#10233C",
    ));
    elements.push(excalidraw_text_element(
        "network_topology_subtitle",
        48.0,
        78.0,
        980.0,
        38.0,
        format!(
            "Mission {}: observed host relationships inferred from collected inventory artifacts.",
            mission_id
        ),
        15,
        "#51606F",
    ));

    let mut host_boxes = BTreeMap::new();
    for (index, host) in topology.hosts.iter().enumerate() {
        let column = index % 3;
        let row = index / 3;
        let x = 48.0 + (column as f64 * 320.0);
        let y = 140.0 + (row as f64 * 190.0);
        let width = 260.0;
        let height = 126.0;
        let box_id = excalidraw_host_box_id(&host.ip);
        let text_id = excalidraw_host_text_id(&host.ip);
        let (stroke_color, fill_color, text_color) = excalidraw_host_palette(host);

        host_boxes.insert(
            host.ip.clone(),
            ExcalidrawBox {
                id: box_id.clone(),
                x,
                y,
                width,
                height,
            },
        );

        elements.push(excalidraw_rectangle_element(
            &box_id,
            x,
            y,
            width,
            height,
            stroke_color,
            fill_color,
        ));
        elements.push(excalidraw_text_element(
            &text_id,
            x + 16.0,
            y + 16.0,
            width - 32.0,
            height - 32.0,
            format!(
                "{}\n{}\n{}\nports: {}\nservices: {}",
                display_topology_name(host),
                host.ip,
                host.platform,
                join_ports(&host.open_ports),
                summarize_services(&host.services),
            ),
            14,
            text_color,
        ));
    }

    for edge in &topology.edges {
        let Some(from_box) = host_boxes.get(&edge.from_ip) else {
            continue;
        };
        let Some(to_box) = host_boxes.get(&edge.to_ip) else {
            continue;
        };
        elements.push(excalidraw_arrow_element(
            &format!(
                "edge_{}_to_{}",
                sanitize_identifier(&edge.from_ip),
                sanitize_identifier(&edge.to_ip)
            ),
            from_box,
            to_box,
        ));
    }

    if topology.edges.is_empty() {
        let note_y = 140.0 + ((topology.hosts.len().max(1) as f64 / 3.0).ceil() * 190.0);
        elements.push(excalidraw_text_element(
            "network_topology_note",
            48.0,
            note_y,
            420.0,
            19.0,
            "No observed inter-host connections in this mission.".to_string(),
            15,
            "#51606F",
        ));
    }

    serde_json::to_string_pretty(&json!({
        "type": "excalidraw",
        "version": 2,
        "source": "https://excalidraw.com",
        "elements": elements,
        "appState": {
            "viewBackgroundColor": "#FFFFFF"
        }
    }))
    .expect("excalidraw topology should serialize")
}

fn topology_host_lookup(topology: &NetworkTopology) -> BTreeMap<&str, &TopologyHost> {
    topology
        .hosts
        .iter()
        .map(|host| (host.ip.as_str(), host))
        .collect()
}

fn display_host_name(host: &AssetInventoryHost) -> &str {
    host.hostname.as_deref().unwrap_or(&host.ip)
}

fn display_topology_name(host: &TopologyHost) -> &str {
    if host.label.is_empty() {
        &host.ip
    } else {
        &host.label
    }
}

fn optional_display(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn join_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        "-".to_string()
    } else {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn join_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(",")
    }
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_remote_ip(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(addr) = trimmed.parse::<IpAddr>() {
        return Some(addr.to_string());
    }

    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Some(addr.ip().to_string());
    }

    if let Some((candidate, _)) = trimmed.rsplit_once(':') {
        let candidate = candidate.trim_matches(|ch| ch == '[' || ch == ']');
        if let Ok(addr) = candidate.parse::<IpAddr>() {
            return Some(addr.to_string());
        }
    }

    None
}

fn mermaid_node_id(ip: &str) -> String {
    let mut node_id = String::from("host_");
    for ch in ip.chars() {
        if ch.is_ascii_alphanumeric() {
            node_id.push(ch);
        } else {
            node_id.push('_');
        }
    }
    node_id
}

fn escape_mermaid_label(value: &str) -> String {
    value.replace('"', "'")
}

#[derive(Debug, Clone)]
struct ExcalidrawBox {
    id: String,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

fn excalidraw_host_palette(host: &TopologyHost) -> (&'static str, &'static str, &'static str) {
    if host.platform.eq_ignore_ascii_case("windows") {
        ("#2F5D50", "#E8F6F1", "#18352D")
    } else {
        ("#1F3A5F", "#EAF2FF", "#10233C")
    }
}

fn excalidraw_host_box_id(ip: &str) -> String {
    format!("host_box_{}", sanitize_identifier(ip))
}

fn excalidraw_host_text_id(ip: &str) -> String {
    format!("host_text_{}", sanitize_identifier(ip))
}

fn summarize_services(services: &[String]) -> String {
    match services.len() {
        0 => "-".to_string(),
        1..=3 => services.join(", "),
        _ => format!("{}, +{} more", services[..3].join(", "), services.len() - 3),
    }
}

fn sanitize_identifier(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn excalidraw_seed(id: &str) -> u32 {
    id.bytes().fold(2_166_136_261u32, |hash, byte| {
        hash.wrapping_mul(16_777_619) ^ u32::from(byte)
    })
}

fn excalidraw_text_element(
    id: &str,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    text: String,
    font_size: u32,
    stroke_color: &str,
) -> serde_json::Value {
    let seed = excalidraw_seed(id);
    json!({
        "id": id,
        "type": "text",
        "x": x,
        "y": y,
        "width": width,
        "height": height,
        "text": text.clone(),
        "originalText": text,
        "fontSize": font_size,
        "fontFamily": 3,
        "textAlign": "left",
        "verticalAlign": "top",
        "strokeColor": stroke_color,
        "backgroundColor": "transparent",
        "fillStyle": "solid",
        "strokeWidth": 1,
        "strokeStyle": "solid",
        "roughness": 0,
        "opacity": 100,
        "angle": 0,
        "seed": seed,
        "version": 1,
        "versionNonce": seed ^ 0x5A5A_5A5A,
        "isDeleted": false,
        "groupIds": [],
        "boundElements": null,
        "link": null,
        "locked": false,
        "lineHeight": 1.25
    })
}

fn excalidraw_rectangle_element(
    id: &str,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    stroke_color: &str,
    background_color: &str,
) -> serde_json::Value {
    let seed = excalidraw_seed(id);
    json!({
        "id": id,
        "type": "rectangle",
        "x": x,
        "y": y,
        "width": width,
        "height": height,
        "strokeColor": stroke_color,
        "backgroundColor": background_color,
        "fillStyle": "solid",
        "strokeWidth": 2,
        "strokeStyle": "solid",
        "roughness": 0,
        "opacity": 100,
        "angle": 0,
        "seed": seed,
        "version": 1,
        "versionNonce": seed ^ 0x1F2E_3D4C,
        "isDeleted": false,
        "groupIds": [],
        "boundElements": [],
        "link": null,
        "locked": false,
        "roundness": { "type": 3 }
    })
}

fn excalidraw_arrow_element(
    id: &str,
    from_box: &ExcalidrawBox,
    to_box: &ExcalidrawBox,
) -> serde_json::Value {
    let seed = excalidraw_seed(id);
    let from_x = from_box.x + (from_box.width / 2.0);
    let from_y = from_box.y + (from_box.height / 2.0);
    let to_x = to_box.x + (to_box.width / 2.0);
    let to_y = to_box.y + (to_box.height / 2.0);
    let dx = to_x - from_x;
    let dy = to_y - from_y;

    json!({
        "id": id,
        "type": "arrow",
        "x": from_x,
        "y": from_y,
        "width": dx,
        "height": dy,
        "strokeColor": "#425466",
        "backgroundColor": "transparent",
        "fillStyle": "solid",
        "strokeWidth": 2,
        "strokeStyle": "solid",
        "roughness": 0,
        "opacity": 100,
        "angle": 0,
        "seed": seed,
        "version": 1,
        "versionNonce": seed ^ 0x7C6D_5E4F,
        "isDeleted": false,
        "groupIds": [],
        "boundElements": [],
        "link": null,
        "locked": false,
        "points": [[0.0, 0.0], [dx, dy]],
        "startBinding": { "elementId": from_box.id, "focus": 0, "gap": 4 },
        "endBinding": { "elementId": to_box.id, "focus": 0, "gap": 4 },
        "startArrowhead": null,
        "endArrowhead": "arrow",
        "lastCommittedPoint": [dx, dy]
    })
}

fn render_minimal_pdf(lines: &[String]) -> Vec<u8> {
    let mut page_chunks = lines.chunks(42).collect::<Vec<_>>();
    if page_chunks.is_empty() {
        page_chunks.push(&[]);
    }

    let pages_id = 2usize;
    let font_id = 3usize;
    let mut objects = Vec::new();
    let mut page_ids = Vec::new();
    let mut next_object_id = 4usize;

    for chunk in page_chunks {
        let page_id = next_object_id;
        let content_id = next_object_id + 1;
        page_ids.push(page_id);
        next_object_id += 2;

        let content = pdf_page_stream(chunk);
        objects.push(object_bytes(
            page_id,
            format!(
                "<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
            ),
        ));
        objects.push(stream_object_bytes(content_id, content));
    }

    let kids = page_ids
        .iter()
        .map(|id| format!("{id} 0 R"))
        .collect::<Vec<_>>()
        .join(" ");

    let mut ordered_objects = vec![
        object_bytes(1, "<< /Type /Catalog /Pages 2 0 R >>".to_string()),
        object_bytes(
            pages_id,
            format!(
                "<< /Type /Pages /Kids [{}] /Count {} >>",
                kids,
                page_ids.len()
            ),
        ),
        object_bytes(
            font_id,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        ),
    ];
    ordered_objects.extend(objects);

    let mut pdf = b"%PDF-1.4\n%\xC2\xC3\xC4\xC5\n".to_vec();
    let mut offsets = vec![0usize];
    for object in ordered_objects {
        offsets.push(pdf.len());
        pdf.extend(object);
    }

    let xref_offset = pdf.len();
    pdf.extend(format!("xref\n0 {}\n", offsets.len()).as_bytes());
    pdf.extend(b"0000000000 65535 f \n");
    for offset in offsets.iter().skip(1) {
        pdf.extend(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            offsets.len(),
            xref_offset
        )
        .as_bytes(),
    );

    pdf
}

fn pdf_page_stream(lines: &[String]) -> Vec<u8> {
    let mut stream = String::from("BT\n/F1 10 Tf\n14 TL\n50 752 Td\n");

    if lines.is_empty() {
        stream.push_str("(Pandora's Box Asset Inventory) Tj\n");
    } else {
        for (index, line) in lines.iter().enumerate() {
            if index > 0 {
                stream.push_str("T*\n");
            }
            stream.push_str(&format!("({}) Tj\n", escape_pdf_text(line)));
        }
    }

    stream.push_str("ET\n");
    stream.into_bytes()
}

fn escape_pdf_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => ['\\', '\\'].into_iter().collect::<Vec<_>>(),
            '(' => ['\\', '('].into_iter().collect::<Vec<_>>(),
            ')' => ['\\', ')'].into_iter().collect::<Vec<_>>(),
            '\n' | '\r' | '\t' => vec![' '],
            ch if ch.is_ascii() => vec![ch],
            _ => vec!['?'],
        })
        .collect()
}

fn object_bytes(id: usize, body: String) -> Vec<u8> {
    format!("{id} 0 obj\n{body}\nendobj\n").into_bytes()
}

fn stream_object_bytes(id: usize, stream: Vec<u8>) -> Vec<u8> {
    let mut object = format!("{id} 0 obj\n<< /Length {} >>\nstream\n", stream.len()).into_bytes();
    object.extend(stream);
    object.extend(b"endstream\nendobj\n");
    object
}

#[cfg(test)]
mod tests {
    use super::{
        asset_inventory_pdf_lines, parse_remote_ip, render_asset_inventory_csv,
        render_asset_inventory_markdown, render_asset_inventory_pdf,
        render_network_topology_excalidraw, render_network_topology_markdown,
        render_network_topology_mermaid, AssetInventoryBundle, AssetInventoryHost, NetworkTopology,
        TopologyEdge, TopologyHost,
    };

    #[test]
    fn asset_inventory_renderers_include_host_rows() {
        let bundle = AssetInventoryBundle {
            mission_id: "mission-123".to_string(),
            discovered_hosts: 1,
            completed_hosts: 1,
            failed_hosts: 0,
            hosts: vec![AssetInventoryHost {
                ip: "10.0.0.10".to_string(),
                final_state: "complete".to_string(),
                platform: "unix".to_string(),
                transport_chain: vec!["unix_ssh".to_string()],
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

        assert!(render_asset_inventory_markdown(&bundle).contains(
            "| 10.0.0.10 | complete | unix | lab | Ubuntu | 22,80 | root | sshd | - |  |"
        ));
        assert!(render_asset_inventory_csv(&bundle)
            .contains("10.0.0.10,complete,unix,lab,Ubuntu,\"22,80\",root,sshd,-,"));
        assert!(render_asset_inventory_pdf(&bundle).starts_with(b"%PDF-1.4"));
        assert!(asset_inventory_pdf_lines(&bundle)
            .iter()
            .any(|line| line.contains("Host lab (10.0.0.10)")));
    }

    #[test]
    fn network_topology_renderers_include_observed_edges() {
        let topology = NetworkTopology {
            hosts: vec![
                TopologyHost {
                    ip: "10.0.0.51".to_string(),
                    label: "web-01".to_string(),
                    platform: "unix".to_string(),
                    os: Some("Ubuntu".to_string()),
                    open_ports: vec![22],
                    services: vec!["sshd".to_string()],
                },
                TopologyHost {
                    ip: "10.0.0.52".to_string(),
                    label: "db-01".to_string(),
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

        assert!(
            render_network_topology_markdown("mission-123", &topology).contains("web-01 -> db-01")
        );
        assert!(render_network_topology_mermaid(&topology)
            .contains("host_10_0_0_51 -. observed .-> host_10_0_0_52"));
        let excalidraw = render_network_topology_excalidraw("mission-123", &topology);
        assert!(excalidraw.contains("\"type\": \"excalidraw\""));
        assert!(excalidraw.contains("host_box_10_0_0_51"));
        assert!(excalidraw.contains("edge_10_0_0_51_to_10_0_0_52"));
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
}
