use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

const PDF_PAGE_WIDTH: f32 = 612.0;
const PDF_PAGE_HEIGHT: f32 = 792.0;
const PDF_MARGIN: f32 = 32.0;
const PDF_HEADER_TOP: f32 = 28.0;
const PDF_HEADER_HEIGHT: f32 = 86.0;
const PDF_SUMMARY_TOP: f32 = 128.0;
const PDF_SUMMARY_HEIGHT: f32 = 58.0;
const PDF_HOST_CARD_TOP: f32 = 210.0;
const PDF_HOST_CARD_HEIGHT: f32 = 126.0;
const PDF_HOST_CARD_GAP: f32 = 12.0;
const PDF_HOSTS_PER_PAGE: usize = 4;

#[derive(Debug, Clone)]
struct ExcalidrawRenderer {
    python: PathBuf,
    script: PathBuf,
}

#[derive(Debug, Clone, Copy)]
enum PdfFont {
    Regular,
    Bold,
}

#[derive(Debug, Clone)]
struct PdfTextLine {
    text: String,
    color: &'static str,
    font: PdfFont,
}

#[derive(Default)]
struct PdfPageBuilder {
    commands: String,
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
    remote_address: Option<String>,
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
    let topology_excalidraw =
        render_network_topology_excalidraw(&report.bundle.mission_id, &report.topology);
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
        .write_network_topology_excalidraw(&topology_excalidraw)
        .await?;
    if let Some(topology_png) = maybe_render_network_topology_png(&topology_excalidraw).await? {
        store.write_network_topology_png(&topology_png).await?;
    }

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
                .filter_map(|connection| connection.remote_address)
                .filter_map(|address| parse_remote_ip(&address))
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
    let total_pages = bundle.hosts.len().div_ceil(PDF_HOSTS_PER_PAGE).max(1);
    let page_streams = if bundle.hosts.is_empty() {
        vec![render_asset_inventory_pdf_page(bundle, &[], 1, total_pages)]
    } else {
        bundle
            .hosts
            .chunks(PDF_HOSTS_PER_PAGE)
            .enumerate()
            .map(|(index, hosts)| {
                render_asset_inventory_pdf_page(bundle, hosts, index + 1, total_pages)
            })
            .collect()
    };

    assemble_pdf(&page_streams)
}

fn render_asset_inventory_pdf_page(
    bundle: &AssetInventoryBundle,
    hosts: &[AssetInventoryHost],
    page_number: usize,
    total_pages: usize,
) -> Vec<u8> {
    let mut page = PdfPageBuilder::default();
    let content_width = PDF_PAGE_WIDTH - (PDF_MARGIN * 2.0);

    page.fill_rect(
        PDF_MARGIN,
        PDF_HEADER_TOP,
        content_width,
        PDF_HEADER_HEIGHT,
        "#EAF2FF",
    );
    page.fill_rect(
        PDF_MARGIN,
        PDF_HEADER_TOP,
        10.0,
        PDF_HEADER_HEIGHT,
        "#1F3A5F",
    );
    page.text(
        PDF_MARGIN + 24.0,
        PDF_HEADER_TOP + 16.0,
        PdfFont::Bold,
        22.0,
        "#10233C",
        "Pandora's Box Asset Inventory",
    );
    page.text(
        PDF_MARGIN + 24.0,
        PDF_HEADER_TOP + 45.0,
        PdfFont::Regular,
        11.0,
        "#51606F",
        &format!(
            "Mission {}  |  Page {} of {}  |  Collected host inventory, access paths, services, and shares.",
            bundle.mission_id, page_number, total_pages
        ),
    );

    render_pdf_summary_cards(&mut page, bundle);

    if hosts.is_empty() {
        page.fill_rect(
            PDF_MARGIN,
            PDF_HOST_CARD_TOP,
            content_width,
            132.0,
            "#F4F6F8",
        );
        page.stroke_rect(
            PDF_MARGIN,
            PDF_HOST_CARD_TOP,
            content_width,
            132.0,
            "#AAB7C4",
            1.0,
        );
        page.text(
            PDF_MARGIN + 24.0,
            PDF_HOST_CARD_TOP + 24.0,
            PdfFont::Bold,
            14.0,
            "#10233C",
            "No completed host inventory artifacts were available for this mission.",
        );
        page.text(
            PDF_MARGIN + 24.0,
            PDF_HOST_CARD_TOP + 52.0,
            PdfFont::Regular,
            10.0,
            "#51606F",
            "Pandora's Box still wrote JSON, Markdown, CSV, and topology side artifacts for follow-up review.",
        );
        return page.finish();
    }

    for (index, host) in hosts.iter().enumerate() {
        let top = PDF_HOST_CARD_TOP + (index as f32 * (PDF_HOST_CARD_HEIGHT + PDF_HOST_CARD_GAP));
        render_pdf_host_card(&mut page, host, top, content_width);
    }

    page.finish()
}

fn render_pdf_summary_cards(page: &mut PdfPageBuilder, bundle: &AssetInventoryBundle) {
    let card_gap = 12.0;
    let card_width = (PDF_PAGE_WIDTH - (PDF_MARGIN * 2.0) - (card_gap * 2.0)) / 3.0;
    let card_specs = [
        ("Discovered", bundle.discovered_hosts, "#F4F6F8", "#10233C"),
        ("Complete", bundle.completed_hosts, "#E8F6F1", "#18352D"),
        ("Failed", bundle.failed_hosts, "#FDEEE8", "#5E2B18"),
    ];

    for (index, (label, value, fill, text_color)) in card_specs.into_iter().enumerate() {
        let x = PDF_MARGIN + (index as f32 * (card_width + card_gap));
        page.fill_rect(x, PDF_SUMMARY_TOP, card_width, PDF_SUMMARY_HEIGHT, fill);
        page.stroke_rect(
            x,
            PDF_SUMMARY_TOP,
            card_width,
            PDF_SUMMARY_HEIGHT,
            "#AAB7C4",
            1.0,
        );
        page.text(
            x + 16.0,
            PDF_SUMMARY_TOP + 12.0,
            PdfFont::Regular,
            10.0,
            "#51606F",
            label,
        );
        page.text(
            x + 16.0,
            PDF_SUMMARY_TOP + 28.0,
            PdfFont::Bold,
            20.0,
            text_color,
            &value.to_string(),
        );
    }
}

fn render_pdf_host_card(
    page: &mut PdfPageBuilder,
    host: &AssetInventoryHost,
    top: f32,
    width: f32,
) {
    let (accent, fill, text_color) = pdf_host_palette(host);
    page.fill_rect(PDF_MARGIN, top, width, PDF_HOST_CARD_HEIGHT, fill);
    page.stroke_rect(PDF_MARGIN, top, width, PDF_HOST_CARD_HEIGHT, "#AAB7C4", 1.0);
    page.fill_rect(PDF_MARGIN, top, 8.0, PDF_HOST_CARD_HEIGHT, accent);

    page.text(
        PDF_MARGIN + 20.0,
        top + 14.0,
        PdfFont::Bold,
        14.0,
        text_color,
        &format!("{}  ({})", display_host_name(host), host.ip),
    );

    let state_chip_width = 90.0;
    let chip_x = PDF_MARGIN + width - state_chip_width - 18.0;
    page.fill_rect(chip_x, top + 14.0, state_chip_width, 22.0, accent);
    page.text(
        chip_x + 12.0,
        top + 18.0,
        PdfFont::Bold,
        9.0,
        "#F7FAFC",
        &host.final_state.to_ascii_uppercase(),
    );

    page.text(
        PDF_MARGIN + 20.0,
        top + 36.0,
        PdfFont::Regular,
        10.0,
        "#51606F",
        &format!(
            "{}  |  {}  |  {}",
            host.platform,
            optional_display(host.os.as_deref()),
            host.transport_chain.join(" -> ")
        ),
    );

    let mut line_top = top + 56.0;
    for line in host_card_lines(host) {
        page.text(
            PDF_MARGIN + 20.0,
            line_top,
            line.font,
            9.5,
            line.color,
            &line.text,
        );
        line_top += 13.0;
    }
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

async fn maybe_render_network_topology_png(excalidraw_source: &str) -> io::Result<Option<Vec<u8>>> {
    let Some(renderer) = resolve_excalidraw_renderer() else {
        return Ok(None);
    };
    let excalidraw_source = excalidraw_source.to_string();
    let render_result = tokio::task::spawn_blocking(move || {
        render_network_topology_png_with(&renderer, &excalidraw_source)
    })
    .await;

    match render_result {
        Ok(Ok(bytes)) => Ok(Some(bytes)),
        Ok(Err(_)) | Err(_) => Ok(None),
    }
}

fn resolve_excalidraw_renderer() -> Option<ExcalidrawRenderer> {
    let env_python = env::var_os("PANDORAS_BOX_EXCALIDRAW_PYTHON").map(PathBuf::from);
    let env_script = env::var_os("PANDORAS_BOX_EXCALIDRAW_RENDERER").map(PathBuf::from);
    if let (Some(python), Some(script)) = (env_python, env_script) {
        if python.is_file() && script.is_file() {
            return Some(ExcalidrawRenderer { python, script });
        }
    }

    let codex_home = env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".codex")))?;
    let references_dir = codex_home.join("skills/excalidraw-diagram/references");
    let python = references_dir.join(".venv/bin/python");
    let script = references_dir.join("render_excalidraw.py");
    if python.is_file() && script.is_file() {
        Some(ExcalidrawRenderer { python, script })
    } else {
        None
    }
}

fn render_network_topology_png_with(
    renderer: &ExcalidrawRenderer,
    excalidraw_source: &str,
) -> io::Result<Vec<u8>> {
    let workdir = temp_render_dir()?;
    let input = workdir.join("network_topology.excalidraw");
    let output = workdir.join("network_topology.png");
    std::fs::write(&input, excalidraw_source)?;

    let output_result = Command::new(&renderer.python)
        .arg(&renderer.script)
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .arg("--scale")
        .arg("2")
        .arg("--width")
        .arg("1920")
        .output();

    let render_bytes = match output_result {
        Ok(command_output) if command_output.status.success() => std::fs::read(&output),
        Ok(command_output) => Err(io::Error::other(format!(
            "excalidraw renderer failed: {}",
            String::from_utf8_lossy(&command_output.stderr).trim()
        ))),
        Err(err) => Err(io::Error::other(format!(
            "failed to invoke excalidraw renderer: {err}"
        ))),
    };

    let _ = std::fs::remove_dir_all(&workdir);
    render_bytes
}

fn temp_render_dir() -> io::Result<PathBuf> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| io::Error::other(format!("clock drift while preparing png render: {err}")))?
        .as_nanos();
    let path = env::temp_dir().join(format!("pandoras-box-topology-render-{unique}"));
    std::fs::create_dir_all(&path)?;
    Ok(path)
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

fn pdf_host_palette(host: &AssetInventoryHost) -> (&'static str, &'static str, &'static str) {
    if host.final_state.eq_ignore_ascii_case("failed") {
        ("#A64B2A", "#FDEEE8", "#5E2B18")
    } else if host.platform.eq_ignore_ascii_case("windows") {
        ("#2F5D50", "#E8F6F1", "#18352D")
    } else {
        ("#1F3A5F", "#EAF2FF", "#10233C")
    }
}

fn host_card_lines(host: &AssetInventoryHost) -> Vec<PdfTextLine> {
    let mut lines = Vec::new();
    let transports = if host.transport_chain.is_empty() {
        "-".to_string()
    } else {
        host.transport_chain.join(" -> ")
    };

    lines.extend(wrap_pdf_value_line(
        "Access",
        &format!("{transports}; ports {}", join_ports(&host.open_ports)),
        82,
        "#10233C",
    ));
    lines.extend(wrap_pdf_value_line(
        "Admins",
        &join_or_dash(&host.admin_users),
        82,
        "#10233C",
    ));
    lines.extend(wrap_pdf_value_line(
        "Services",
        &join_or_dash(&host.services),
        82,
        "#10233C",
    ));
    lines.extend(wrap_pdf_value_line(
        "Shares",
        &join_or_dash(&host.shares),
        82,
        "#10233C",
    ));

    if host.container_count > 0 {
        lines.push(PdfTextLine {
            text: format!("Containers: {}", host.container_count),
            color: "#10233C",
            font: PdfFont::Regular,
        });
    }

    if let Some(error) = &host.error {
        lines.extend(wrap_pdf_value_line("Error", error, 82, "#5E2B18"));
    }

    if lines.len() > 5 {
        lines.truncate(5);
        if let Some(last) = lines.last_mut() {
            if !last.text.ends_with("...") {
                last.text.push_str("...");
            }
        }
    }

    lines
}

fn wrap_pdf_value_line(
    label: &str,
    value: &str,
    width: usize,
    color: &'static str,
) -> Vec<PdfTextLine> {
    let mut wrapped = wrap_text_block(value, width.saturating_sub(label.len() + 2));
    if wrapped.is_empty() {
        wrapped.push("-".to_string());
    }

    wrapped
        .into_iter()
        .enumerate()
        .map(|(index, line)| PdfTextLine {
            text: if index == 0 {
                format!("{label}: {line}")
            } else {
                format!("  {line}")
            },
            color,
            font: PdfFont::Regular,
        })
        .collect()
}

fn wrap_text_block(value: &str, width: usize) -> Vec<String> {
    let normalized = value.replace('\n', " ");
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut lines = Vec::new();
    let mut current = String::new();
    for word in trimmed.split_whitespace() {
        let candidate_len = if current.is_empty() {
            word.len()
        } else {
            current.len() + 1 + word.len()
        };
        if candidate_len > width && !current.is_empty() {
            lines.push(current);
            current = word.to_string();
        } else if current.is_empty() {
            current.push_str(word);
        } else {
            current.push(' ');
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    lines
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

fn assemble_pdf(page_streams: &[Vec<u8>]) -> Vec<u8> {
    let pages_id = 2usize;
    let regular_font_id = 3usize;
    let bold_font_id = 4usize;
    let mut objects = Vec::new();
    let mut page_ids = Vec::new();
    let mut next_object_id = 5usize;

    for stream in page_streams {
        let page_id = next_object_id;
        let content_id = next_object_id + 1;
        page_ids.push(page_id);
        next_object_id += 2;

        objects.push(object_bytes(
            page_id,
            format!(
                "<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PDF_PAGE_WIDTH:.0} {PDF_PAGE_HEIGHT:.0}] /Resources << /Font << /F1 {regular_font_id} 0 R /F2 {bold_font_id} 0 R >> >> /Contents {content_id} 0 R >>"
            ),
        ));
        objects.push(stream_object_bytes(content_id, stream.clone()));
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
            regular_font_id,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
        ),
        object_bytes(
            bold_font_id,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>".to_string(),
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

impl PdfPageBuilder {
    fn fill_rect(&mut self, x: f32, top: f32, width: f32, height: f32, fill: &str) {
        let (r, g, b) = pdf_color(fill);
        let y = pdf_rect_y(top, height);
        let _ = writeln!(
            self.commands,
            "q {:.3} {:.3} {:.3} rg {:.2} {:.2} {:.2} {:.2} re f Q",
            r, g, b, x, y, width, height
        );
    }

    fn stroke_rect(
        &mut self,
        x: f32,
        top: f32,
        width: f32,
        height: f32,
        stroke: &str,
        line_width: f32,
    ) {
        let (r, g, b) = pdf_color(stroke);
        let y = pdf_rect_y(top, height);
        let _ = writeln!(
            self.commands,
            "q {:.3} {:.3} {:.3} RG {:.2} w {:.2} {:.2} {:.2} {:.2} re S Q",
            r, g, b, line_width, x, y, width, height
        );
    }

    fn text(&mut self, x: f32, top: f32, font: PdfFont, size: f32, color: &str, value: &str) {
        let (r, g, b) = pdf_color(color);
        let y = pdf_text_y(top, size);
        let font_name = match font {
            PdfFont::Regular => "F1",
            PdfFont::Bold => "F2",
        };
        let _ = writeln!(
            self.commands,
            "BT /{} {:.2} Tf {:.3} {:.3} {:.3} rg 1 0 0 1 {:.2} {:.2} Tm ({}) Tj ET",
            font_name,
            size,
            r,
            g,
            b,
            x,
            y,
            escape_pdf_text(value)
        );
    }

    fn finish(self) -> Vec<u8> {
        self.commands.into_bytes()
    }
}

fn pdf_rect_y(top: f32, height: f32) -> f32 {
    PDF_PAGE_HEIGHT - top - height
}

fn pdf_text_y(top: f32, size: f32) -> f32 {
    PDF_PAGE_HEIGHT - top - size
}

fn pdf_color(hex: &str) -> (f32, f32, f32) {
    let value = hex.strip_prefix('#').unwrap_or(hex);
    if value.len() != 6 {
        return (0.0, 0.0, 0.0);
    }
    let channel = |range: std::ops::Range<usize>| -> f32 {
        u8::from_str_radix(&value[range], 16)
            .map(|component| f32::from(component) / 255.0)
            .unwrap_or(0.0)
    };

    (channel(0..2), channel(2..4), channel(4..6))
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
        parse_remote_ip, render_asset_inventory_csv, render_asset_inventory_markdown,
        render_asset_inventory_pdf, render_network_topology_excalidraw,
        render_network_topology_markdown, render_network_topology_mermaid,
        render_network_topology_png_with, AssetInventoryBundle, AssetInventoryHost,
        ExcalidrawRenderer, InventoryArtifact, NetworkTopology, TopologyEdge, TopologyHost,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let pdf = render_asset_inventory_pdf(&bundle);
        assert!(pdf.starts_with(b"%PDF-1.4"));
        let pdf_text = String::from_utf8_lossy(&pdf);
        assert!(pdf_text.contains("Pandora's Box Asset Inventory"));
        assert!(pdf_text.contains("lab  \\(10.0.0.10\\)"));
        assert!(pdf_text.contains("Discovered"));
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
    fn topology_png_renderer_contract_accepts_external_renderer() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let temp_root = std::env::temp_dir().join(format!("pandoras-box-renderer-test-{unique}"));
        fs::create_dir_all(&temp_root).expect("temp dir should exist");

        let script_path = temp_root.join("fake-renderer.sh");
        fs::write(&script_path, "#!/bin/sh\nprintf 'fake-png' > \"$3\"\n")
            .expect("stub renderer should exist");
        let mut permissions = fs::metadata(&script_path)
            .expect("stub metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("stub script should be executable");

        let renderer = ExcalidrawRenderer {
            python: PathBuf::from("/bin/sh"),
            script: script_path.clone(),
        };

        let png = render_network_topology_png_with(
            &renderer,
            r##"{"type":"excalidraw","version":2,"source":"https://excalidraw.com","elements":[{"id":"box","type":"rectangle","x":0,"y":0,"width":120,"height":80,"strokeColor":"#1F3A5F","backgroundColor":"#EAF2FF","fillStyle":"solid","strokeWidth":2,"strokeStyle":"solid","roughness":0,"opacity":100,"angle":0,"seed":1,"version":1,"versionNonce":2,"isDeleted":false,"groupIds":[],"boundElements":[],"link":null,"locked":false}],"appState":{"viewBackgroundColor":"#FFFFFF"}}"##,
        )
        .expect("png renderer should return bytes");

        assert_eq!(png, b"fake-png");
        let _ = fs::remove_dir_all(temp_root);
    }
}
