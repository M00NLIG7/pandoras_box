use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::artifact_store::ArtifactStore;
use super::scheduler::HostExecutionReport;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AssetInventoryBundle {
    pub mission_id: String,
    pub requested_targets: usize,
    pub reachable_targets: usize,
    pub unreachable_targets: usize,
    pub skipped_targets: usize,
    pub attempted_targets: usize,
    /// Backward-compatible alias for `reachable_targets`.
    pub discovered_hosts: usize,
    pub completed_hosts: usize,
    pub failed_hosts: usize,
    pub partial_hosts: usize,
    pub hosts: Vec<AssetInventoryHost>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AssetInventorySectionError {
    pub section: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AssetInventoryHost {
    pub ip: String,
    pub final_state: String,
    pub collection_state: String,
    pub section_errors: Vec<AssetInventorySectionError>,
    pub platform: String,
    pub architecture: String,
    pub payload_version: Option<String>,
    pub payload_sha256: Option<String>,
    pub transport_chain: Vec<String>,
    pub selected_transport: Option<String>,
    pub failure_phase: Option<String>,
    pub failure_disposition: Option<String>,
    pub cleanup_outcome: String,
    pub residue_present: bool,
    pub partial_collection: bool,
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
    final_state: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopologySectionKind {
    Segment,
    Failed,
}

#[derive(Debug, Clone)]
struct TopologySection {
    id: String,
    title: String,
    subtitle: String,
    kind: TopologySectionKind,
    hosts: Vec<TopologyHost>,
}

#[derive(Debug, Clone)]
struct TopologySectionLayout {
    id: String,
    title: String,
    subtitle: String,
    kind: TopologySectionKind,
    frame: ExcalidrawBox,
    hosts: Vec<TopologyHostLayout>,
}

#[derive(Debug, Clone)]
struct TopologyHostLayout {
    host: TopologyHost,
    frame: ExcalidrawBox,
}

#[derive(Debug, Clone, Copy)]
struct ExcalidrawPoint {
    x: f64,
    y: f64,
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
const TOPOLOGY_LEFT_MARGIN: f64 = 48.0;
const TOPOLOGY_TOP: f64 = 168.0;
const TOPOLOGY_SECTION_GAP: f64 = 28.0;
const TOPOLOGY_SECTION_ROW_GAP: f64 = 36.0;
const TOPOLOGY_SECTION_WIDTH_SINGLE: f64 = 560.0;
const TOPOLOGY_SECTION_WIDTH_DOUBLE: f64 = 432.0;
const TOPOLOGY_SECTION_WIDTH_TRIPLE: f64 = 336.0;
const TOPOLOGY_MAX_SECTION_COLUMNS: usize = 3;
const TOPOLOGY_SECTION_HEADER_HEIGHT: f64 = 58.0;
const TOPOLOGY_SECTION_PADDING_X: f64 = 18.0;
const TOPOLOGY_SECTION_PADDING_BOTTOM: f64 = 18.0;
const TOPOLOGY_HOST_HEIGHT: f64 = 100.0;
const TOPOLOGY_HOST_GAP_X: f64 = 14.0;
const TOPOLOGY_HOST_GAP_Y: f64 = 14.0;
const TOPOLOGY_FAILED_SECTION_GAP: f64 = 24.0;
const TOPOLOGY_LEGEND_WIDTH: f64 = 268.0;

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
    section_errors: Vec<InventorySectionError>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct InventorySectionError {
    section: String,
    message: String,
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
    requested_targets: usize,
    reachable_targets: usize,
    unreachable_targets: usize,
    skipped_targets: usize,
    attempted_targets: usize,
) -> io::Result<()> {
    let report = build_inventory_report(
        store,
        reports,
        requested_targets,
        reachable_targets,
        unreachable_targets,
        skipped_targets,
        attempted_targets,
    )
    .await;
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
    Ok(())
}

async fn build_inventory_report(
    store: &ArtifactStore,
    reports: &[HostExecutionReport],
    requested_targets: usize,
    reachable_targets: usize,
    unreachable_targets: usize,
    skipped_targets: usize,
    attempted_targets: usize,
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
        requested_targets,
        reachable_targets,
        unreachable_targets,
        skipped_targets,
        attempted_targets,
        discovered_hosts: reachable_targets,
        completed_hosts: reports
            .iter()
            .filter(|report| report.final_state.as_str() == "complete")
            .count(),
        failed_hosts: reports
            .iter()
            .filter(|report| report.final_state.as_str() == "failed")
            .count(),
        partial_hosts: records
            .iter()
            .filter(|record| record.host.collection_state == "partial")
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
    let metadata = tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 16 * 1024 * 1024
    {
        return Err(format!(
            "inventory must be a regular non-link file no larger than 16777216 bytes: {}",
            path.display()
        ));
    }
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
        Ok(mut inventory) => {
            let section_errors = std::mem::take(&mut inventory.section_errors)
                .into_iter()
                .map(|error| AssetInventorySectionError {
                    section: error.section,
                    message: error.message,
                })
                .collect::<Vec<_>>();
            let collection_state = if section_errors.is_empty() {
                "complete"
            } else {
                "partial"
            };
            let partial_summary = (!section_errors.is_empty()).then(|| {
                format!(
                    "partial inventory: {}",
                    section_errors
                        .iter()
                        .map(|error| format!("{}: {}", error.section, error.message))
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            });
            let aggregate_error = match (base_error, partial_summary) {
                (Some(base), Some(partial)) => Some(format!("{base}; {partial}")),
                (Some(base), None) => Some(base),
                (None, Some(partial)) => Some(partial),
                (None, None) => None,
            };

            InventoryRecord {
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
                    collection_state: collection_state.to_string(),
                    section_errors,
                    platform: report.plan.contract.operating_system.as_str().to_string(),
                    architecture: report.plan.contract.architecture.as_str().to_string(),
                    payload_version: report
                        .plan
                        .payload
                        .as_ref()
                        .map(|payload| payload.version.clone()),
                    payload_sha256: report
                        .plan
                        .payload
                        .as_ref()
                        .map(|payload| payload.sha256.clone()),
                    transport_chain: report
                        .plan
                        .transport_chain
                        .iter()
                        .map(|kind| kind.as_str().to_string())
                        .collect(),
                    selected_transport: report
                        .selected_transport
                        .map(|kind| kind.as_str().to_string()),
                    failure_phase: report.failure_phase.map(|phase| phase.as_str().to_string()),
                    failure_disposition: report
                        .failure_disposition
                        .map(|disposition| disposition.as_str().to_string()),
                    cleanup_outcome: report.cleanup_outcome.as_str().to_string(),
                    residue_present: report.residue_present,
                    partial_collection: report.partial_collection,
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
                    error: aggregate_error,
                },
            }
        }
        Err(inventory_error) => InventoryRecord {
            observed_peer_ips: Vec::new(),
            host: AssetInventoryHost {
                ip: report.plan.target.ip.to_string(),
                final_state: report.final_state.as_str().to_string(),
                collection_state: "unavailable".to_string(),
                section_errors: Vec::new(),
                platform: report.plan.contract.operating_system.as_str().to_string(),
                architecture: report.plan.contract.architecture.as_str().to_string(),
                payload_version: report
                    .plan
                    .payload
                    .as_ref()
                    .map(|payload| payload.version.clone()),
                payload_sha256: report
                    .plan
                    .payload
                    .as_ref()
                    .map(|payload| payload.sha256.clone()),
                transport_chain: report
                    .plan
                    .transport_chain
                    .iter()
                    .map(|kind| kind.as_str().to_string())
                    .collect(),
                selected_transport: report
                    .selected_transport
                    .map(|kind| kind.as_str().to_string()),
                failure_phase: report.failure_phase.map(|phase| phase.as_str().to_string()),
                failure_disposition: report
                    .failure_disposition
                    .map(|disposition| disposition.as_str().to_string()),
                cleanup_outcome: report.cleanup_outcome.as_str().to_string(),
                residue_present: report.residue_present,
                partial_collection: report.partial_collection,
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
            final_state: record.host.final_state.clone(),
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
                let (from_ip, to_ip) = if record.host.ip <= *peer_ip {
                    (record.host.ip.clone(), peer_ip.clone())
                } else {
                    (peer_ip.clone(), record.host.ip.clone())
                };
                edge_set.insert(TopologyEdge { from_ip, to_ip });
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
        concat!(
            "Requested targets: {}  \n",
            "Reachable targets: {}  \n",
            "Unreachable targets: {}  \n",
            "Skipped targets: {}  \n",
            "Attempted targets: {}  \n",
            "Completed hosts: {}  \n",
            "Failed hosts: {}  \n",
            "Partial inventories: {}\n\n"
        ),
        bundle.requested_targets,
        bundle.reachable_targets,
        bundle.unreachable_targets,
        bundle.skipped_targets,
        bundle.attempted_targets,
        bundle.completed_hosts,
        bundle.failed_hosts,
        bundle.partial_hosts
    ));
    markdown.push_str(
        "| IP | State | Collection | Section failures | Platform | Architecture | Payload version | Payload SHA-256 | Selected transport | Failure disposition | Cleanup | Residue | Partial download | Hostname | OS | Ports | Admin Users | Services | Shares | Error |\n",
    );
    markdown.push_str(
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
    );

    for host in &bundle.hosts {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            markdown_cell(&host.ip),
            markdown_cell(&host.final_state),
            markdown_cell(&host.collection_state),
            markdown_cell(&section_errors_display(&host.section_errors)),
            markdown_cell(&host.platform),
            markdown_cell(&host.architecture),
            markdown_cell(optional_display(host.payload_version.as_deref())),
            markdown_cell(optional_display(host.payload_sha256.as_deref())),
            markdown_cell(optional_display(host.selected_transport.as_deref())),
            markdown_cell(optional_display(host.failure_disposition.as_deref())),
            markdown_cell(&host.cleanup_outcome),
            markdown_cell(if host.residue_present { "yes" } else { "no" }),
            markdown_cell(if host.partial_collection { "yes" } else { "no" }),
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
    let mut csv = String::from(
        "ip,state,collection_state,section_failures,platform,architecture,payload_version,payload_sha256,selected_transport,failure_phase,failure_disposition,cleanup_outcome,residue_present,partial_collection,hostname,os,ports,admin_users,services,shares,error\n",
    );

    for host in &bundle.hosts {
        let ports = join_ports(&host.open_ports);
        let admin_users = join_or_dash(&host.admin_users);
        let services = join_or_dash(&host.services);
        let shares = join_or_dash(&host.shares);
        let section_failures = section_errors_display(&host.section_errors);
        let row = [
            host.ip.as_str(),
            host.final_state.as_str(),
            host.collection_state.as_str(),
            section_failures.as_str(),
            host.platform.as_str(),
            host.architecture.as_str(),
            optional_display(host.payload_version.as_deref()),
            optional_display(host.payload_sha256.as_deref()),
            optional_display(host.selected_transport.as_deref()),
            optional_display(host.failure_phase.as_deref()),
            optional_display(host.failure_disposition.as_deref()),
            host.cleanup_outcome.as_str(),
            if host.residue_present {
                "true"
            } else {
                "false"
            },
            if host.partial_collection {
                "true"
            } else {
                "false"
            },
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
        ("Requested", bundle.requested_targets, "#F4F6F8", "#10233C"),
        ("Attempted", bundle.attempted_targets, "#E8F6F1", "#18352D"),
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
                "- {} <-> {} ({} <-> {})\n",
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
                "  {} -. observed .- {}\n",
                mermaid_node_id(&edge.from_ip),
                mermaid_node_id(&edge.to_ip)
            ));
        }
    }

    mermaid
}

fn render_network_topology_excalidraw(mission_id: &str, topology: &NetworkTopology) -> String {
    let mut elements = Vec::new();
    let section_layouts = layout_topology_sections(&build_topology_sections(topology));
    let topology_right = section_layouts
        .iter()
        .map(|section| section.frame.x + section.frame.width)
        .fold(
            TOPOLOGY_LEFT_MARGIN + TOPOLOGY_SECTION_WIDTH_DOUBLE,
            f64::max,
        );
    let legend_x = topology_right + 28.0;
    let subtitle_width = (legend_x - TOPOLOGY_LEFT_MARGIN - 24.0).max(700.0);
    elements.push(excalidraw_text_element(
        "network_topology_title",
        ExcalidrawBounds::new(48.0, 30.0, subtitle_width.min(700.0), 38.0),
        "Network Topology".to_string(),
        30,
        "#10233C",
    ));
    elements.push(excalidraw_text_element(
        "network_topology_subtitle",
        ExcalidrawBounds::new(48.0, 78.0, subtitle_width, 38.0),
        format!(
            "Mission {}: observed host relationships inferred from collected inventory artifacts.",
            mission_id
        ),
        15,
        "#51606F",
    ));
    elements.extend(render_topology_legend(legend_x));

    let mut host_boxes = BTreeMap::new();
    let mut host_sections = BTreeMap::new();
    let mut section_boxes = BTreeMap::new();
    for section in &section_layouts {
        section_boxes.insert(section.id.clone(), section.frame.clone());
        elements.extend(render_topology_section(section));
        for host in &section.hosts {
            host_boxes.insert(host.host.ip.clone(), host.frame.clone());
            host_sections.insert(host.host.ip.clone(), section.id.clone());
        }
    }

    let mut section_edge_counts = BTreeMap::<(String, String), usize>::new();
    for edge in &topology.edges {
        let from_section = host_sections.get(&edge.from_ip);
        let to_section = host_sections.get(&edge.to_ip);
        if let (Some(from_section), Some(to_section)) = (from_section, to_section) {
            if from_section != to_section {
                let key = if from_section <= to_section {
                    (from_section.clone(), to_section.clone())
                } else {
                    (to_section.clone(), from_section.clone())
                };
                *section_edge_counts.entry(key).or_insert(0) += 1;
                continue;
            }
        }

        let Some(from_box) = host_boxes.get(&edge.from_ip) else {
            continue;
        };
        let Some(to_box) = host_boxes.get(&edge.to_ip) else {
            continue;
        };
        elements.extend(excalidraw_connection_elements(
            &format!(
                "edge_{}_to_{}",
                sanitize_identifier(&edge.from_ip),
                sanitize_identifier(&edge.to_ip)
            ),
            from_box,
            to_box,
            None,
        ));
    }

    for ((from_section, to_section), _count) in section_edge_counts {
        let Some(from_box) = section_boxes.get(&from_section) else {
            continue;
        };
        let Some(to_box) = section_boxes.get(&to_section) else {
            continue;
        };
        elements.push(excalidraw_section_connection_element(
            &format!(
                "section_edge_{}_to_{}",
                sanitize_identifier(&from_section),
                sanitize_identifier(&to_section)
            ),
            from_box,
            to_box,
        ));
    }

    if topology.edges.is_empty() {
        let note_y = section_layouts
            .iter()
            .map(|section| section.frame.y + section.frame.height + 14.0)
            .fold(TOPOLOGY_TOP + 64.0, f64::max);
        elements.push(excalidraw_text_element(
            "network_topology_note",
            ExcalidrawBounds::new(48.0, note_y, 520.0, 38.0),
            "No observed inter-host connections were captured during this mission.\nThe layout still preserves network zones and unreachable targets.".to_string(),
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

fn build_topology_sections(topology: &NetworkTopology) -> Vec<TopologySection> {
    let mut section_hosts = BTreeMap::<String, Vec<TopologyHost>>::new();
    let mut section_titles = BTreeMap::<String, String>::new();
    let mut host_section = BTreeMap::<String, String>::new();
    let mut failed_hosts = Vec::new();

    for host in &topology.hosts {
        if host.final_state.eq_ignore_ascii_case("failed") {
            failed_hosts.push(host.clone());
            continue;
        }

        let (section_id, section_title) = topology_segment_key(&host.ip);
        host_section.insert(host.ip.clone(), section_id.clone());
        section_titles.insert(section_id.clone(), section_title);
        section_hosts
            .entry(section_id)
            .or_default()
            .push(host.clone());
    }

    let mut sections = Vec::new();
    for (section_id, mut hosts) in section_hosts {
        hosts.sort_by_key(|host| {
            (
                topology_role_rank(infer_topology_role(host)),
                display_topology_name(host).to_string(),
                host.ip.clone(),
            )
        });
        let internal_links = topology
            .edges
            .iter()
            .filter(|edge| {
                host_section.get(&edge.from_ip) == Some(&section_id)
                    && host_section.get(&edge.to_ip) == Some(&section_id)
            })
            .count();
        let cross_zone_links = topology
            .edges
            .iter()
            .filter(|edge| {
                let from_match = host_section.get(&edge.from_ip) == Some(&section_id);
                let to_match = host_section.get(&edge.to_ip) == Some(&section_id);
                from_match ^ to_match
            })
            .count();
        let title = section_titles
            .remove(&section_id)
            .unwrap_or_else(|| section_id.clone());
        sections.push(TopologySection {
            id: section_id,
            title,
            subtitle: topology_section_summary(hosts.len(), internal_links, cross_zone_links),
            kind: TopologySectionKind::Segment,
            hosts,
        });
    }

    sections.sort_by_key(|section| section.title.clone());

    if !failed_hosts.is_empty() {
        failed_hosts.sort_by_key(|host| (display_topology_name(host).to_string(), host.ip.clone()));
        sections.push(TopologySection {
            id: "failed_targets".to_string(),
            title: "Unreachable / No Inventory".to_string(),
            subtitle: format!(
                "{} {} failed before collection completed",
                failed_hosts.len(),
                pluralize_topology_word(failed_hosts.len(), "target", "targets")
            ),
            kind: TopologySectionKind::Failed,
            hosts: failed_hosts,
        });
    }

    sections
}

fn layout_topology_sections(sections: &[TopologySection]) -> Vec<TopologySectionLayout> {
    let mut layouts = Vec::new();
    let mut failed_section = None::<TopologySection>;
    let reachable_sections = sections
        .iter()
        .filter_map(|section| {
            if section.kind == TopologySectionKind::Failed {
                failed_section = Some(section.clone());
                None
            } else {
                Some(section.clone())
            }
        })
        .collect::<Vec<_>>();

    let columns = reachable_sections
        .len()
        .clamp(1, TOPOLOGY_MAX_SECTION_COLUMNS);
    let section_width = topology_section_width(columns);
    let grid_width =
        columns as f64 * section_width + columns.saturating_sub(1) as f64 * TOPOLOGY_SECTION_GAP;
    let mut row_y = TOPOLOGY_TOP;

    for row in reachable_sections.chunks(columns) {
        let row_width = row.len() as f64 * section_width
            + row.len().saturating_sub(1) as f64 * TOPOLOGY_SECTION_GAP;
        let start_x = TOPOLOGY_LEFT_MARGIN + ((grid_width - row_width) / 2.0);
        let mut row_layouts = Vec::new();
        let mut row_height = 0.0_f64;

        for (index, section) in row.iter().enumerate() {
            let x = start_x + index as f64 * (section_width + TOPOLOGY_SECTION_GAP);
            let layout = layout_topology_section(section, x, row_y, section_width);
            row_height = row_height.max(layout.frame.height);
            row_layouts.push(layout);
        }

        layouts.extend(row_layouts);
        row_y += row_height + TOPOLOGY_SECTION_ROW_GAP;
    }

    if let Some(section) = failed_section {
        let y = row_y.max(TOPOLOGY_TOP) + TOPOLOGY_FAILED_SECTION_GAP;
        layouts.push(layout_topology_section(
            &section,
            TOPOLOGY_LEFT_MARGIN,
            y,
            grid_width,
        ));
    }

    layouts
}

fn layout_topology_section(
    section: &TopologySection,
    x: f64,
    y: f64,
    width: f64,
) -> TopologySectionLayout {
    let cols = topology_section_columns(section, width);
    let inner_width = width - (TOPOLOGY_SECTION_PADDING_X * 2.0);
    let host_width = if cols == 1 {
        inner_width
    } else {
        (inner_width - ((cols - 1) as f64 * TOPOLOGY_HOST_GAP_X)) / cols as f64
    };
    let host_start_y = y + TOPOLOGY_SECTION_HEADER_HEIGHT + 10.0;
    let rows = section.hosts.len().div_ceil(cols);
    let section_height = TOPOLOGY_SECTION_HEADER_HEIGHT
        + 10.0
        + (rows as f64 * TOPOLOGY_HOST_HEIGHT)
        + ((rows.saturating_sub(1)) as f64 * TOPOLOGY_HOST_GAP_Y)
        + TOPOLOGY_SECTION_PADDING_BOTTOM;

    let hosts = section
        .hosts
        .iter()
        .enumerate()
        .map(|(index, host)| {
            let row = index / cols;
            let col = index % cols;
            let host_x =
                x + TOPOLOGY_SECTION_PADDING_X + (col as f64 * (host_width + TOPOLOGY_HOST_GAP_X));
            let host_y = host_start_y + (row as f64 * (TOPOLOGY_HOST_HEIGHT + TOPOLOGY_HOST_GAP_Y));

            TopologyHostLayout {
                host: host.clone(),
                frame: ExcalidrawBox {
                    id: excalidraw_host_box_id(&host.ip),
                    x: host_x,
                    y: host_y,
                    width: host_width,
                    height: TOPOLOGY_HOST_HEIGHT,
                },
            }
        })
        .collect();

    TopologySectionLayout {
        id: section.id.clone(),
        title: section.title.clone(),
        subtitle: section.subtitle.clone(),
        kind: section.kind,
        frame: ExcalidrawBox {
            id: format!("section_{}", sanitize_identifier(&section.id)),
            x,
            y,
            width,
            height: section_height,
        },
        hosts,
    }
}

fn render_topology_legend(x: f64) -> Vec<serde_json::Value> {
    let y = 28.0;
    let width = TOPOLOGY_LEGEND_WIDTH;
    let height = 146.0;
    let mut elements = vec![excalidraw_rectangle_element_with_style(
        "topology_legend",
        ExcalidrawBounds::new(x, y, width, height),
        "#AAB7C4",
        "#F4F6F8",
        "solid",
    )];

    elements.push(excalidraw_text_element(
        "topology_legend_title",
        ExcalidrawBounds::new(x + 18.0, y + 16.0, width - 36.0, 22.0),
        "Diagram Key".to_string(),
        17,
        "#10233C",
    ));

    let entries = [
        (
            "legend_unix",
            52.0,
            "#EAF2FF",
            "#1F3A5F",
            "Reachable Unix or generic host",
        ),
        (
            "legend_windows",
            78.0,
            "#E8F6F1",
            "#2F5D50",
            "Reachable Windows host",
        ),
        (
            "legend_failed",
            104.0,
            "#FDEEE8",
            "#A64B2A",
            "Failed or incomplete target",
        ),
    ];

    for (id, offset, fill, stroke, label) in entries {
        elements.push(excalidraw_rectangle_element(
            id,
            x + 18.0,
            y + offset,
            18.0,
            14.0,
            stroke,
            fill,
        ));
        elements.push(excalidraw_text_element(
            &format!("{id}_label"),
            ExcalidrawBounds::new(x + 46.0, y + offset - 2.0, width - 64.0, 18.0),
            label.to_string(),
            12,
            "#51606F",
        ));
    }

    elements.push(excalidraw_line_element(
        "legend_link",
        x + 18.0,
        y + 130.0,
        vec![(0.0, 0.0), (42.0, 0.0)],
        "#425466",
        "dashed",
    ));
    elements.push(excalidraw_text_element(
        "legend_link_label",
        ExcalidrawBounds::new(x + 72.0, y + 122.0, width - 90.0, 18.0),
        "Dashed links show observed peer traffic".to_string(),
        12,
        "#51606F",
    ));

    elements
}

fn render_topology_section(section: &TopologySectionLayout) -> Vec<serde_json::Value> {
    let (stroke, fill, chip_fill, chip_text) = topology_section_palette(section.kind);
    let mut elements = vec![excalidraw_rectangle_element_with_style(
        &section.frame.id,
        ExcalidrawBounds::new(
            section.frame.x,
            section.frame.y,
            section.frame.width,
            section.frame.height,
        ),
        stroke,
        fill,
        "dashed",
    )];

    let chip_width = estimate_text_width(&section.title, 15).min(section.frame.width - 36.0);
    elements.push(excalidraw_rectangle_element(
        &format!("{}_chip", section.id),
        section.frame.x + 18.0,
        section.frame.y + 14.0,
        chip_width,
        28.0,
        stroke,
        chip_fill,
    ));
    elements.push(excalidraw_text_element(
        &format!("{}_title", section.id),
        ExcalidrawBounds::new(
            section.frame.x + 30.0,
            section.frame.y + 20.0,
            chip_width - 20.0,
            18.0,
        ),
        section.title.clone(),
        15,
        chip_text,
    ));
    elements.push(excalidraw_text_element(
        &format!("{}_subtitle", section.id),
        ExcalidrawBounds::new(
            section.frame.x + 20.0,
            section.frame.y + 48.0,
            section.frame.width - 40.0,
            18.0,
        ),
        section.subtitle.clone(),
        12,
        "#51606F",
    ));

    for host in &section.hosts {
        elements.extend(render_topology_host_card(host));
    }

    elements
}

fn render_topology_host_card(layout: &TopologyHostLayout) -> Vec<serde_json::Value> {
    let (stroke, fill, text_color) = excalidraw_host_palette(&layout.host);
    let title = truncate_with_ellipsis(display_topology_name(&layout.host), 28);
    let body = topology_host_body(&layout.host).join("\n");
    let (badge_label, badge_fill, badge_stroke, badge_text) = topology_host_badge(&layout.host);
    let badge_width = estimate_text_width(&badge_label, 10).clamp(64.0, 122.0);

    vec![
        excalidraw_rectangle_element(
            &layout.frame.id,
            layout.frame.x,
            layout.frame.y,
            layout.frame.width,
            layout.frame.height,
            stroke,
            fill,
        ),
        excalidraw_rectangle_element(
            &format!("{}_badge_bg", layout.frame.id),
            layout.frame.x + layout.frame.width - badge_width - 14.0,
            layout.frame.y + 12.0,
            badge_width,
            18.0,
            badge_stroke,
            badge_fill,
        ),
        excalidraw_text_element(
            &format!("{}_title", layout.frame.id),
            ExcalidrawBounds::new(
                layout.frame.x + 14.0,
                layout.frame.y + 12.0,
                layout.frame.width - badge_width - 36.0,
                18.0,
            ),
            title,
            15,
            text_color,
        ),
        excalidraw_text_element(
            &format!("{}_badge_text", layout.frame.id),
            ExcalidrawBounds::new(
                layout.frame.x + layout.frame.width - badge_width - 4.0,
                layout.frame.y + 14.0,
                badge_width - 20.0,
                14.0,
            ),
            badge_label,
            10,
            badge_text,
        ),
        excalidraw_line_element(
            &format!("{}_divider", layout.frame.id),
            layout.frame.x + 14.0,
            layout.frame.y + 36.0,
            vec![(0.0, 0.0), (layout.frame.width - 28.0, 0.0)],
            stroke,
            "solid",
        ),
        excalidraw_text_element(
            &format!("{}_body", layout.frame.id),
            ExcalidrawBounds::new(
                layout.frame.x + 14.0,
                layout.frame.y + 46.0,
                layout.frame.width - 28.0,
                layout.frame.height - 56.0,
            ),
            body,
            12,
            text_color,
        ),
    ]
}

fn topology_section_columns(section: &TopologySection, width: f64) -> usize {
    match section.kind {
        TopologySectionKind::Failed => section.hosts.len().clamp(1, 3),
        TopologySectionKind::Segment => {
            if section.hosts.len() >= 6 && width >= TOPOLOGY_SECTION_WIDTH_SINGLE {
                2
            } else {
                1
            }
        }
    }
}

fn topology_section_width(columns: usize) -> f64 {
    match columns {
        1 => TOPOLOGY_SECTION_WIDTH_SINGLE,
        2 => TOPOLOGY_SECTION_WIDTH_DOUBLE,
        _ => TOPOLOGY_SECTION_WIDTH_TRIPLE,
    }
}

fn topology_segment_key(ip: &str) -> (String, String) {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(addr)) => {
            let octets = addr.octets();
            (
                format!("segment_{}_{}_{}_0_24", octets[0], octets[1], octets[2]),
                format!("Subnet {}.{}.{}.0/24", octets[0], octets[1], octets[2]),
            )
        }
        Ok(IpAddr::V6(addr)) => {
            let segments = addr.segments();
            (
                format!(
                    "segment_{:x}_{:x}_{:x}_{:x}_64",
                    segments[0], segments[1], segments[2], segments[3]
                ),
                format!(
                    "IPv6 {:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3]
                ),
            )
        }
        Err(_) => (
            format!("segment_{}", sanitize_identifier(ip)),
            format!("Zone {ip}"),
        ),
    }
}

fn topology_section_palette(
    kind: TopologySectionKind,
) -> (&'static str, &'static str, &'static str, &'static str) {
    match kind {
        TopologySectionKind::Segment => ("#AAB7C4", "#FFFFFF", "#EAF2FF", "#10233C"),
        TopologySectionKind::Failed => ("#A64B2A", "#FFF8F6", "#FDEEE8", "#5E2B18"),
    }
}

fn topology_section_summary(
    host_count: usize,
    internal_links: usize,
    cross_zone_links: usize,
) -> String {
    let mut parts = vec![format!(
        "{} {}",
        host_count,
        pluralize_topology_word(host_count, "host", "hosts"),
    )];

    if internal_links > 0 {
        parts.push(format!(
            "{} internal {}",
            internal_links,
            pluralize_topology_word(internal_links, "link", "links"),
        ));
    }
    if cross_zone_links > 0 {
        parts.push(format!(
            "{} cross-zone {}",
            cross_zone_links,
            pluralize_topology_word(cross_zone_links, "flow", "flows"),
        ));
    }
    if internal_links == 0 && cross_zone_links == 0 {
        parts.push("no observed peer traffic".to_string());
    }

    parts.join(" • ")
}

fn topology_host_body(host: &TopologyHost) -> Vec<String> {
    if host.final_state.eq_ignore_ascii_case("failed") {
        return vec![
            host.ip.clone(),
            "collection did not complete".to_string(),
            format!(
                "{} • ports {}",
                title_case_platform(&host.platform),
                summarize_ports(&host.open_ports)
            ),
        ];
    }

    vec![
        host.ip.clone(),
        format!(
            "{} • {}",
            infer_topology_role(host),
            short_topology_os(host.os.as_deref())
        ),
        format!(
            "ports {} • {}",
            summarize_ports(&host.open_ports),
            truncate_with_ellipsis(&summarize_services(&host.services), 28)
        ),
    ]
}

fn topology_host_badge(host: &TopologyHost) -> (String, &'static str, &'static str, &'static str) {
    if host.final_state.eq_ignore_ascii_case("failed") {
        return ("FAILED".to_string(), "#FDEEE8", "#A64B2A", "#5E2B18");
    }

    if host.platform.eq_ignore_ascii_case("windows") {
        return ("WINDOWS".to_string(), "#E8F6F1", "#2F5D50", "#18352D");
    }

    (
        title_case_platform(&host.platform).to_ascii_uppercase(),
        "#EAF2FF",
        "#1F3A5F",
        "#10233C",
    )
}

fn infer_topology_role(host: &TopologyHost) -> &'static str {
    let services = host
        .services
        .iter()
        .map(|service| service.to_ascii_lowercase())
        .collect::<Vec<_>>();

    if services.iter().any(|service| {
        service.contains("postgres")
            || service.contains("mysql")
            || service.contains("mssql")
            || service.contains("sql")
    }) {
        "database"
    } else if services.iter().any(|service| {
        service.contains("nginx")
            || service.contains("apache")
            || service.contains("httpd")
            || service.contains("iis")
    }) || host
        .open_ports
        .iter()
        .any(|port| matches!(port, 80 | 443 | 8080 | 8443))
    {
        "web/service"
    } else if host.platform.eq_ignore_ascii_case("windows") && host.open_ports.contains(&445) {
        "windows endpoint"
    } else if host.open_ports.contains(&22) {
        "ssh host"
    } else {
        "host"
    }
}

fn topology_role_rank(role: &str) -> usize {
    match role {
        "web/service" => 0,
        "windows endpoint" => 1,
        "ssh host" => 2,
        "database" => 3,
        _ => 4,
    }
}

fn short_topology_os(value: Option<&str>) -> String {
    truncate_with_ellipsis(optional_display(value), 28)
}

fn title_case_platform(platform: &str) -> String {
    if platform.is_empty() {
        return "Unknown".to_string();
    }
    let mut chars = platform.chars();
    let Some(first) = chars.next() else {
        return "Unknown".to_string();
    };
    format!("{}{}", first.to_ascii_uppercase(), chars.as_str())
}

fn pluralize_topology_word(
    count: usize,
    singular: &'static str,
    plural: &'static str,
) -> &'static str {
    if count == 1 {
        singular
    } else {
        plural
    }
}

fn estimate_text_width(value: &str, font_size: u32) -> f64 {
    (value.chars().count() as f64 * font_size as f64 * 0.56) + 24.0
}

fn truncate_with_ellipsis(value: &str, max_chars: usize) -> String {
    let total = value.chars().count();
    if total <= max_chars {
        return value.to_string();
    }

    let keep = max_chars.saturating_sub(3);
    let mut truncated = value.chars().take(keep).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn excalidraw_connection_elements(
    id: &str,
    from_box: &ExcalidrawBox,
    to_box: &ExcalidrawBox,
    label: Option<String>,
) -> Vec<serde_json::Value> {
    let seed = excalidraw_seed(id);
    let (start_side, end_side, route) = orthogonal_route_between_boxes(from_box, to_box);
    let start = route
        .first()
        .copied()
        .expect("route should always contain a start point");
    let end = route
        .last()
        .copied()
        .expect("route should always contain an end point");
    let rel_points = route
        .iter()
        .map(|point| vec![point.x - start.x, point.y - start.y])
        .collect::<Vec<_>>();
    let mut elements = vec![json!({
        "id": id,
        "type": "arrow",
        "x": start.x,
        "y": start.y,
        "width": end.x - start.x,
        "height": end.y - start.y,
        "strokeColor": "#425466",
        "backgroundColor": "transparent",
        "fillStyle": "solid",
        "strokeWidth": 2,
        "strokeStyle": "dashed",
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
        "points": rel_points,
        "startBinding": { "elementId": from_box.id, "focus": 0, "gap": 6 },
        "endBinding": { "elementId": to_box.id, "focus": 0, "gap": 6 },
        "startArrowhead": null,
        "endArrowhead": null,
        "lastCommittedPoint": [end.x - start.x, end.y - start.y],
        "customData": { "semantic": "observed_link", "startSide": start_side, "endSide": end_side }
    })];

    if let Some(label) = label {
        let label_position = connection_label_position(&route);
        elements.push(excalidraw_text_element(
            &format!("{id}_label"),
            ExcalidrawBounds::new(
                label_position.x - 84.0,
                label_position.y - 10.0,
                168.0,
                16.0,
            ),
            label,
            11,
            "#51606F",
        ));
    }

    elements
}

fn excalidraw_section_connection_element(
    id: &str,
    from_box: &ExcalidrawBox,
    to_box: &ExcalidrawBox,
) -> serde_json::Value {
    let seed = excalidraw_seed(id);
    let (start_side, end_side, route) = section_route_between_boxes(from_box, to_box);
    let start = route
        .first()
        .copied()
        .expect("route should always contain a start point");
    let end = route
        .last()
        .copied()
        .expect("route should always contain an end point");
    let rel_points = route
        .iter()
        .map(|point| vec![point.x - start.x, point.y - start.y])
        .collect::<Vec<_>>();

    json!({
        "id": id,
        "type": "arrow",
        "x": start.x,
        "y": start.y,
        "width": end.x - start.x,
        "height": end.y - start.y,
        "strokeColor": "#697586",
        "backgroundColor": "transparent",
        "fillStyle": "solid",
        "strokeWidth": 2,
        "strokeStyle": "dashed",
        "roughness": 0,
        "opacity": 100,
        "angle": 0,
        "seed": seed,
        "version": 1,
        "versionNonce": seed ^ 0x4D7B_94AC,
        "isDeleted": false,
        "groupIds": [],
        "boundElements": [],
        "link": null,
        "locked": false,
        "points": rel_points,
        "startBinding": { "elementId": from_box.id, "focus": 0, "gap": 4 },
        "endBinding": { "elementId": to_box.id, "focus": 0, "gap": 4 },
        "startArrowhead": null,
        "endArrowhead": null,
        "lastCommittedPoint": [end.x - start.x, end.y - start.y],
        "customData": { "semantic": "observed_section_link", "startSide": start_side, "endSide": end_side }
    })
}

fn orthogonal_route_between_boxes(
    from_box: &ExcalidrawBox,
    to_box: &ExcalidrawBox,
) -> (&'static str, &'static str, Vec<ExcalidrawPoint>) {
    let from_center = ExcalidrawPoint {
        x: from_box.x + (from_box.width / 2.0),
        y: from_box.y + (from_box.height / 2.0),
    };
    let to_center = ExcalidrawPoint {
        x: to_box.x + (to_box.width / 2.0),
        y: to_box.y + (to_box.height / 2.0),
    };
    let dx = to_center.x - from_center.x;
    let dy = to_center.y - from_center.y;

    let (start_side, end_side, route) = if dx.abs() >= dy.abs() {
        let start_side = if dx >= 0.0 { "right" } else { "left" };
        let end_side = if dx >= 0.0 { "left" } else { "right" };
        let start = box_edge_midpoint(from_box, start_side);
        let end = box_edge_midpoint(to_box, end_side);
        let lane_x = (start.x + end.x) / 2.0;
        (
            start_side,
            end_side,
            vec![
                start,
                ExcalidrawPoint {
                    x: lane_x,
                    y: start.y,
                },
                ExcalidrawPoint {
                    x: lane_x,
                    y: end.y,
                },
                end,
            ],
        )
    } else {
        let start_side = if dy >= 0.0 { "bottom" } else { "top" };
        let end_side = if dy >= 0.0 { "top" } else { "bottom" };
        let start = box_edge_midpoint(from_box, start_side);
        let end = box_edge_midpoint(to_box, end_side);
        let lane_y = (start.y + end.y) / 2.0;
        (
            start_side,
            end_side,
            vec![
                start,
                ExcalidrawPoint {
                    x: start.x,
                    y: lane_y,
                },
                ExcalidrawPoint {
                    x: end.x,
                    y: lane_y,
                },
                end,
            ],
        )
    };

    (start_side, end_side, compact_route_points(route))
}

fn section_route_between_boxes(
    from_box: &ExcalidrawBox,
    to_box: &ExcalidrawBox,
) -> (&'static str, &'static str, Vec<ExcalidrawPoint>) {
    let from_center = ExcalidrawPoint {
        x: from_box.x + (from_box.width / 2.0),
        y: from_box.y + (from_box.height / 2.0),
    };
    let to_center = ExcalidrawPoint {
        x: to_box.x + (to_box.width / 2.0),
        y: to_box.y + (to_box.height / 2.0),
    };
    let dx = to_center.x - from_center.x;
    let dy = to_center.y - from_center.y;

    let (start_side, end_side, route) = if dx.abs() >= dy.abs() {
        let start_side = if dx >= 0.0 { "right" } else { "left" };
        let end_side = if dx >= 0.0 { "left" } else { "right" };
        let start = section_edge_anchor(from_box, start_side);
        let end = section_edge_anchor(to_box, end_side);
        (start_side, end_side, vec![start, end])
    } else {
        let start_side = if dy >= 0.0 { "bottom" } else { "top" };
        let end_side = if dy >= 0.0 { "top" } else { "bottom" };
        let start = section_edge_anchor(from_box, start_side);
        let end = section_edge_anchor(to_box, end_side);
        (
            start_side,
            end_side,
            compact_route_points(vec![
                start,
                ExcalidrawPoint {
                    x: start.x,
                    y: (start.y + end.y) / 2.0,
                },
                ExcalidrawPoint {
                    x: end.x,
                    y: (start.y + end.y) / 2.0,
                },
                end,
            ]),
        )
    };

    (start_side, end_side, route)
}

fn compact_route_points(points: Vec<ExcalidrawPoint>) -> Vec<ExcalidrawPoint> {
    let mut compacted = Vec::new();

    for point in points {
        if compacted
            .last()
            .map(|last: &ExcalidrawPoint| {
                (last.x - point.x).abs() < f64::EPSILON && (last.y - point.y).abs() < f64::EPSILON
            })
            .unwrap_or(false)
        {
            continue;
        }

        if compacted.len() >= 2 {
            let previous = compacted[compacted.len() - 1];
            let before_previous = compacted[compacted.len() - 2];
            let vertical = (before_previous.x - previous.x).abs() < f64::EPSILON
                && (previous.x - point.x).abs() < f64::EPSILON;
            let horizontal = (before_previous.y - previous.y).abs() < f64::EPSILON
                && (previous.y - point.y).abs() < f64::EPSILON;
            if vertical || horizontal {
                compacted.pop();
            }
        }

        compacted.push(point);
    }

    compacted
}

fn connection_label_position(route: &[ExcalidrawPoint]) -> ExcalidrawPoint {
    match route.len() {
        0 => ExcalidrawPoint { x: 0.0, y: 0.0 },
        1 => route[0],
        2 => ExcalidrawPoint {
            x: (route[0].x + route[1].x) / 2.0,
            y: (route[0].y + route[1].y) / 2.0,
        },
        _ => {
            let middle = route.len() / 2;
            ExcalidrawPoint {
                x: (route[middle - 1].x + route[middle].x) / 2.0,
                y: (route[middle - 1].y + route[middle].y) / 2.0 - 12.0,
            }
        }
    }
}

fn box_edge_midpoint(box_frame: &ExcalidrawBox, side: &str) -> ExcalidrawPoint {
    match side {
        "left" => ExcalidrawPoint {
            x: box_frame.x,
            y: box_frame.y + (box_frame.height / 2.0),
        },
        "right" => ExcalidrawPoint {
            x: box_frame.x + box_frame.width,
            y: box_frame.y + (box_frame.height / 2.0),
        },
        "top" => ExcalidrawPoint {
            x: box_frame.x + (box_frame.width / 2.0),
            y: box_frame.y,
        },
        _ => ExcalidrawPoint {
            x: box_frame.x + (box_frame.width / 2.0),
            y: box_frame.y + box_frame.height,
        },
    }
}

fn section_edge_anchor(box_frame: &ExcalidrawBox, side: &str) -> ExcalidrawPoint {
    let header_y = box_frame.y + TOPOLOGY_SECTION_HEADER_HEIGHT + 4.0;
    match side {
        "left" => ExcalidrawPoint {
            x: box_frame.x,
            y: header_y,
        },
        "right" => ExcalidrawPoint {
            x: box_frame.x + box_frame.width,
            y: header_y,
        },
        "top" => ExcalidrawPoint {
            x: box_frame.x + (box_frame.width / 2.0),
            y: box_frame.y,
        },
        _ => ExcalidrawPoint {
            x: box_frame.x + (box_frame.width / 2.0),
            y: box_frame.y + box_frame.height,
        },
    }
}

pub async fn render_network_topology_png_explicit(
    store: &ArtifactStore,
    renderer: &super::mission::RendererSpec,
) -> Result<(), String> {
    let expected = super::payloads::normalize_sha256(&renderer.sha256)?;
    let metadata = tokio::fs::symlink_metadata(&renderer.executable)
        .await
        .map_err(|error| {
            format!(
                "explicit renderer {} is unavailable: {error}",
                renderer.executable.display()
            )
        })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > 128 * 1024 * 1024
    {
        return Err(format!(
            "explicit renderer must be a bounded regular non-link file: {}",
            renderer.executable.display()
        ));
    }

    let source = store.network_topology_excalidraw_path();
    let source_metadata = tokio::fs::symlink_metadata(&source)
        .await
        .map_err(|error| format!("topology source is unavailable: {error}"))?;
    if source_metadata.file_type().is_symlink()
        || !source_metadata.is_file()
        || source_metadata.len() > 16 * 1024 * 1024
    {
        return Err("topology source must be a bounded regular non-link file".into());
    }

    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| format!("renderer workspace randomness unavailable: {error}"))?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let workdir = store.mission_dir().join(format!(".renderer-{suffix}"));
    tokio::fs::create_dir(&workdir)
        .await
        .map_err(|error| format!("failed to create renderer workspace: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&workdir, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|error| format!("failed to restrict renderer workspace: {error}"))?;
    }
    let renderer_copy = workdir.join(if cfg!(windows) {
        "pinned-renderer.exe"
    } else {
        "pinned-renderer"
    });
    if let Err(error) = tokio::fs::copy(&renderer.executable, &renderer_copy).await {
        let _ = tokio::fs::remove_dir_all(&workdir).await;
        return Err(format!("failed to copy explicit renderer: {error}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) =
            tokio::fs::set_permissions(&renderer_copy, std::fs::Permissions::from_mode(0o700)).await
        {
            let _ = tokio::fs::remove_dir_all(&workdir).await;
            return Err(format!("failed to restrict renderer copy: {error}"));
        }
    }
    let actual = match super::payloads::sha256_file_bounded(&renderer_copy, 128 * 1024 * 1024).await
    {
        Ok(actual) => actual,
        Err(error) => {
            let _ = tokio::fs::remove_dir_all(&workdir).await;
            return Err(error);
        }
    };
    if actual != expected {
        let _ = tokio::fs::remove_dir_all(&workdir).await;
        return Err(format!(
            "explicit renderer digest mismatch: expected {expected}, got {actual}"
        ));
    }
    let output = workdir.join("network_topology.png");

    let render_result = async {
        let mut child = tokio::process::Command::new(&renderer_copy)
            .arg(&source)
            .arg(&output)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| format!("failed to launch explicit renderer: {error}"))?;
        let status = match tokio::time::timeout(renderer.timeout, child.wait()).await {
            Ok(result) => result.map_err(|error| format!("renderer wait failed: {error}"))?,
            Err(_) => {
                let _ = child.kill().await;
                return Err(format!("renderer exceeded {:?}", renderer.timeout));
            }
        };
        if !status.success() {
            return Err(format!("renderer exited with status {status}"));
        }
        let output_metadata = tokio::fs::symlink_metadata(&output)
            .await
            .map_err(|error| format!("renderer output is unavailable: {error}"))?;
        if output_metadata.file_type().is_symlink() || !output_metadata.is_file() {
            return Err("renderer output must be a regular non-link file".into());
        }
        if output_metadata.len() > renderer.max_output_bytes {
            return Err(format!(
                "renderer output was {} bytes, exceeding the {} byte bound",
                output_metadata.len(),
                renderer.max_output_bytes
            ));
        }
        let bytes = tokio::fs::read(&output)
            .await
            .map_err(|error| format!("failed to read renderer output: {error}"))?;
        store
            .write_network_topology_png(&bytes)
            .await
            .map_err(|error| format!("failed to persist renderer output: {error}"))
    }
    .await;

    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::fs::remove_dir_all(&workdir),
    )
    .await;
    render_result
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

fn section_errors_display(errors: &[AssetInventorySectionError]) -> String {
    if errors.is_empty() {
        return "-".to_string();
    }
    errors
        .iter()
        .map(|error| format!("{}: {}", error.section, error.message))
        .collect::<Vec<_>>()
        .join("; ")
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
    let neutralized = if value
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r'))
    {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if neutralized.contains([',', '"', '\n']) {
        format!("\"{}\"", neutralized.replace('"', "\"\""))
    } else {
        neutralized
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

#[derive(Debug, Clone, Copy)]
struct ExcalidrawBounds {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

impl ExcalidrawBounds {
    const fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
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
    if host.final_state.eq_ignore_ascii_case("failed") {
        ("#A64B2A", "#FDEEE8", "#5E2B18")
    } else if host.platform.eq_ignore_ascii_case("windows") {
        ("#2F5D50", "#E8F6F1", "#18352D")
    } else {
        ("#1F3A5F", "#EAF2FF", "#10233C")
    }
}

fn excalidraw_host_box_id(ip: &str) -> String {
    format!("host_box_{}", sanitize_identifier(ip))
}

fn summarize_services(services: &[String]) -> String {
    match services.len() {
        0 => "-".to_string(),
        1..=3 => services.join(", "),
        _ => format!("{}, +{} more", services[..3].join(", "), services.len() - 3),
    }
}

fn summarize_ports(ports: &[u16]) -> String {
    match ports.len() {
        0 => "-".to_string(),
        1..=4 => join_ports(ports),
        _ => format!(
            "{}, +{} more",
            ports[..4]
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            ports.len() - 4
        ),
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

    let payload_digest = host
        .payload_sha256
        .as_deref()
        .map(|digest| &digest[..digest.len().min(12)])
        .unwrap_or("-");
    lines.extend(wrap_pdf_value_line(
        "Access",
        &format!(
            "{}/{}; payload {}@{}; selected {}; chain {transports}; ports {}",
            host.platform,
            host.architecture,
            optional_display(host.payload_version.as_deref()),
            payload_digest,
            optional_display(host.selected_transport.as_deref()),
            join_ports(&host.open_ports)
        ),
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
    bounds: ExcalidrawBounds,
    text: String,
    font_size: u32,
    stroke_color: &str,
) -> serde_json::Value {
    let ExcalidrawBounds {
        x,
        y,
        width,
        height,
    } = bounds;
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
    excalidraw_rectangle_element_with_style(
        id,
        ExcalidrawBounds::new(x, y, width, height),
        stroke_color,
        background_color,
        "solid",
    )
}

fn excalidraw_rectangle_element_with_style(
    id: &str,
    bounds: ExcalidrawBounds,
    stroke_color: &str,
    background_color: &str,
    stroke_style: &str,
) -> serde_json::Value {
    let ExcalidrawBounds {
        x,
        y,
        width,
        height,
    } = bounds;
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
        "strokeStyle": stroke_style,
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

fn excalidraw_line_element(
    id: &str,
    x: f64,
    y: f64,
    points: Vec<(f64, f64)>,
    stroke_color: &str,
    stroke_style: &str,
) -> serde_json::Value {
    let seed = excalidraw_seed(id);
    let width = points
        .iter()
        .map(|(point_x, _)| *point_x)
        .fold(0.0, f64::max);
    let height = points
        .iter()
        .map(|(_, point_y)| *point_y)
        .fold(0.0, f64::max);

    json!({
        "id": id,
        "type": "line",
        "x": x,
        "y": y,
        "width": width,
        "height": height,
        "strokeColor": stroke_color,
        "backgroundColor": "transparent",
        "fillStyle": "solid",
        "strokeWidth": 1,
        "strokeStyle": stroke_style,
        "roughness": 0,
        "opacity": 100,
        "angle": 0,
        "seed": seed,
        "version": 1,
        "versionNonce": seed ^ 0x7C6D_5E4F,
        "isDeleted": false,
        "groupIds": [],
        "boundElements": null,
        "link": null,
        "locked": false,
        "points": points
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
    #[cfg(unix)]
    use super::render_network_topology_png_explicit;
    use super::{
        parse_remote_ip, record_from_report, render_asset_inventory_csv,
        render_asset_inventory_markdown, render_asset_inventory_pdf,
        render_network_topology_excalidraw, render_network_topology_markdown,
        render_network_topology_mermaid, AssetInventoryBundle, AssetInventoryHost,
        InventoryArtifact, NetworkTopology, TopologyEdge, TopologyHost,
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

        assert!(
            render_network_topology_markdown("mission-123", &topology).contains("web-01 <-> db-01")
        );
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
        let store =
            crate::runtime::ArtifactStore::new(&temp_root, "mission").expect("artifact store");
        store
            .write_network_topology_excalidraw(
                r##"{"type":"excalidraw","version":2,"elements":[]}"##,
            )
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
}
