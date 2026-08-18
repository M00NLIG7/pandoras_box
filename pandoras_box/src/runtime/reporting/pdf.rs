use std::fmt::Write as _;

use super::{
    display_host_name, join_or_dash, join_ports, optional_display, AssetInventoryBundle,
    AssetInventoryHost,
};

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

pub(super) fn render_asset_inventory_pdf(bundle: &AssetInventoryBundle) -> Vec<u8> {
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
