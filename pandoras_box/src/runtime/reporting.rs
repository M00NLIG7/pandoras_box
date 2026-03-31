use std::io;

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct InventoryArtifact {
    hostname: String,
    ip: String,
    os: String,
    ports: Vec<InventoryPort>,
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
    let bundle = build_asset_inventory_bundle(store, reports, discovered_hosts).await;
    let json = serde_json::to_string_pretty(&bundle)
        .expect("asset inventory bundle should serialize to JSON");

    store.write_asset_inventory_json(&json).await?;
    store
        .write_asset_inventory_markdown(&render_asset_inventory_markdown(&bundle))
        .await?;
    store
        .write_asset_inventory_csv(&render_asset_inventory_csv(&bundle))
        .await?;

    Ok(())
}

async fn build_asset_inventory_bundle(
    store: &ArtifactStore,
    reports: &[HostExecutionReport],
    discovered_hosts: usize,
) -> AssetInventoryBundle {
    let mut hosts = Vec::with_capacity(reports.len());
    let mut ordered_reports = reports.to_vec();
    ordered_reports.sort_by_key(|report| report.plan.target.ip.to_string());

    for report in ordered_reports {
        let inventory = read_inventory_artifact(store, &report).await;
        hosts.push(host_from_report(report, inventory));
    }

    AssetInventoryBundle {
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
        hosts,
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

fn host_from_report(
    report: HostExecutionReport,
    inventory: Result<InventoryArtifact, String>,
) -> AssetInventoryHost {
    let fallback_ports = report.plan.target.open_ports.clone();
    let base_error = report.error.clone();

    match inventory {
        Ok(inventory) => AssetInventoryHost {
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
        Err(inventory_error) => AssetInventoryHost {
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
        let row = [
            host.ip.as_str(),
            host.final_state.as_str(),
            host.platform.as_str(),
            optional_display(host.hostname.as_deref()),
            optional_display(host.os.as_deref()),
            &join_ports(&host.open_ports),
            &join_or_dash(&host.admin_users),
            &join_or_dash(&host.services),
            &join_or_dash(&host.shares),
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

#[cfg(test)]
mod tests {
    use super::{
        render_asset_inventory_csv, render_asset_inventory_markdown, AssetInventoryBundle,
        AssetInventoryHost,
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
    }
}
