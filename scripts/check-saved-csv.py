"""Check the saved-host CSV contract without building or running the operator."""

import csv
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "pandoras_box/src/runtime/reporting.rs"
FIXTURE = ROOT / "chimera/src/types/legacy_inventory.json"
# Compile only the production data types, projection, renderer and pure helpers.
# A moved boundary must fail setup rather than silently testing a copied renderer.
REGIONS = [
    ("#[derive(Debug, Clone, Serialize, PartialEq, Eq)]", "#[derive(Debug)]\nstruct InventoryReport"),
    ("#[derive(Debug, Clone)]\nstruct InventoryRecord", "#[derive(Debug, Clone, PartialEq, Eq)]"),
    ("#[derive(Debug, Default, Deserialize)]", "pub async fn write_asset_inventory_bundle"),
    ("fn record_from_report(", "fn build_network_topology("),
    ("fn render_asset_inventory_csv(", "fn render_network_topology_markdown("),
    ("fn optional_display(", "fn mermaid_node_id("),
]
CASES = [
    ("ordinary", "sample", "sample"),
    ("CR", "a\rb", "a\rb"),
    ("LF", "a\nb", "a\nb"),
    ("CRLF", "a\r\nb", "a\r\nb"),
    ("comma", "a,b", "a,b"),
    ("quote", 'a"b', 'a"b'),
    ("leading CR", "\rlead", "'\rlead"),
]


def check(crate):
    text = REPORT.read_text(encoding="utf-8")
    items = []
    for start, stop in REGIONS:
        first = text.index(start)
        items.append(text[first:text.index(stop, first)])
    src = crate / "src"
    src.mkdir()
    (src / "report_items.rs").write_text("\n".join(items), encoding="utf-8")
    shutil.copyfile(ROOT / "scripts/saved-csv/probe.rs", src / "main.rs")
    shutil.copyfile(ROOT / "scripts/saved-csv/Cargo.toml", crate / "Cargo.toml")
    shutil.copyfile(ROOT / "scripts/saved-csv/Cargo.lock", crate / "Cargo.lock")
    subprocess.run(["cargo", "build", "--locked", "--offline", "--quiet", "-j1", "--target-dir", "target"],
                   cwd=crate, check=True)
    probe = crate / "target/debug" / ("saved-csv-check.exe" if os.name == "nt" else "saved-csv-check")
    document = json.loads(FIXTURE.read_bytes())
    for label, raw, expected in CASES:
        document["services"][0]["name"] = raw
        output = subprocess.check_output([probe], input=json.dumps(document).encode())
        rows = list(csv.reader(io.StringIO(output.decode(), newline=""), strict=True))
        widths = [len(row) for row in rows]
        if widths != [21, 21]:
            raise ValueError(f"{label}: expected one header and one host of width 21, got {widths}")
        cell = rows[1][rows[0].index("services")]
        if cell != expected:
            raise ValueError(f"{label}: expected {expected!r}, got {cell!r}")
        print(f"{label}: one 21-column host; services={cell!r}")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="saved-csv-") as temp:
        check(Path(temp))
