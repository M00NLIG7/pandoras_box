"""Replay eight saved-inventory contracts in the isolated saved-CSV probe crate."""

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CSV = runpy.run_path(str(ROOT / "scripts/check-saved-csv.py"))
SUPPORT = ROOT / "scripts/saved-csv"
BASELINE = "4ecb6b63ae8fcdfdd30d7138a2f2e17f5c46353f"
BASELINE_TREE = "b2b85dc9f965fc6e5bb58df6fb011b56464e3a4b"
HOST = "chimera/src/types.rs"
HOST_REGION = ("/// Represents the operational status of a system service.",
               "/// Interface for user information operations.")
DIAGNOSTIC = {"section": "services", "message": "sample  message"}
UNAVAILABLE = {"typed_rejected": True, "saved_rejected": True, "collection": "unavailable"}
ONE_SERVICE_ROW = {"markdown_rows": 1, "markdown_service": "alpha beta"}

# Each non-legacy trial replaces or adds exactly one field in a fresh fixture.
CASES = (
    ("legacy", (), None, {
        "canonical_round_trip": True,
        "share_tags": ["NFS", "SMB"],
        "memory_and_disk_mib": [3073, 8193, 1025],
        "collection": "not recorded",
        "section_errors": [],
        "projected": {
            "hostname": "example-node", "os": "Example OS", "open_ports": [1234],
            "admin_users": ["sample-user"], "services": ["sample-service"],
            "shares": ["/example/shared", "//example/shared"], "container_count": 1,
        },
        "peers": ["192.0.2.42"],
    }),
    ("empty-section-errors", ("sectionErrors",), [], {
        "canonical_round_trip": True, "collection": "complete", "section_errors": [],
        "markdown_diagnostic": "-",
    }),
    ("populated-section-errors", ("sectionErrors",), [DIAGNOSTIC], {
        "canonical_round_trip": True, "collection": "partial", "section_errors": [DIAGNOSTIC],
        "markdown_diagnostic": "services: sample  message",
    }),
    ("null-section-errors", ("sectionErrors",), None, UNAVAILABLE),
    ("wrong-hostname-type", ("hostname",), 7, UNAVAILABLE),
    ("null-remote-address", ("connections", 0, "remoteAddress"), None, {
        "canonical_round_trip": True, "typed_remote_address": None, "peers": [],
    }),
    ("service-lf", ("services", 0, "name"), "alpha\nbeta", ONE_SERVICE_ROW),
    ("service-crlf", ("services", 0, "name"), "alpha\r\nbeta", ONE_SERVICE_ROW),
)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT,
                                   env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})


def source(path, baseline):
    if baseline:
        return git("cat-file", "blob", f"{BASELINE}:{path}")
    return (ROOT / path).read_bytes()


def region(data, start, stop):
    first = data.index(start.encode())
    return data[first:data.index(stop.encode(), first)]


def build(crate, baseline):
    src = crate / "src"
    src.mkdir()
    (src / "host_items.rs").write_bytes(region(source(HOST, baseline), *HOST_REGION))
    report = source(CSV["REPORT"].relative_to(ROOT).as_posix(), baseline)
    regions = [("fn render_asset_inventory_markdown(", stop)
               if start == "fn render_asset_inventory_csv(" else (start, stop)
               for start, stop in CSV["REGIONS"]]
    (src / "report_items.rs").write_bytes(b"\n".join(region(report, *span) for span in regions))
    shutil.copyfile(SUPPORT / "probe.rs", src / "csv_probe.rs")
    shutil.copyfile(SUPPORT / "replay.rs", src / "main.rs")
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copyfile(SUPPORT / name, crate / name)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "-j1",
                    "--target-dir", "target"], cwd=crate, check=True)
    return crate / "target/debug" / ("saved-csv-check.exe" if os.name == "nt" else "saved-csv-check")


def canonical_host(document):
    host = deepcopy(document)
    host.setdefault("sectionErrors", [])
    host["shares"][0]["shareType"] = "NFS"
    host["shares"][1]["shareType"] = "SMB"
    return host


def markdown_row(markdown):
    # A retained CR is a Markdown line break even when LF was replaced by a space.
    lines = markdown.split("\n")
    for index, header in enumerate(lines):
        if header.startswith("| IP |"):
            body = "\n".join(lines[index + 2:])
            rows = body.splitlines()
            raw_rows = body.split("\n")
            if raw_rows[-1] == "":
                raw_rows.pop()
            cells = {}
            if len(raw_rows) == 1:
                row = raw_rows[0]
                columns = [cell.strip(" ") for cell in header[1:-1].split("|")]
                values = [cell.strip(" ") for cell in row[1:-1].split("|")]
                if row.startswith("|") and row.endswith("|") and len(columns) == len(values):
                    cells = dict(zip(columns, values))
            return len(rows), cells
    return 0, {}


def observe(document, response, expected):
    typed = response["typed"].get("Ok", {})
    host = response["host"]
    rows, cells = markdown_row(response["markdown"])
    disk = next(iter(typed.get("disks", [])), {})
    connection = next(iter(typed.get("connections", [])), {})
    values = {
        "canonical_round_trip": bool(typed) and typed == canonical_host(document),
        "share_tags": [share.get("shareType") for share in typed.get("shares", [])],
        "memory_and_disk_mib": [typed.get("memory"), disk.get("totalSpace"), disk.get("availableSpace")],
        "typed_remote_address": connection.get("remoteAddress", "<missing>"),
        "typed_rejected": "Err" in response["typed"],
        "saved_rejected": response["saved_error"] is not None,
        "collection": host.get("collection_state"),
        "section_errors": host.get("section_errors"),
        "projected": {key: host.get(key) for key in expected.get("projected", {})},
        "peers": response["peers"],
        "markdown_rows": rows,
        "markdown_service": cells.get("Services"),
        "markdown_diagnostic": cells.get("Section failures"),
    }
    return {key: values[key] for key in expected}


def trial(probe, base, path, value, expected):
    document = deepcopy(base)
    if path:
        parent = document
        for step in path[:-1]:
            parent = parent[step]
        parent[path[-1]] = value
    response = json.loads(subprocess.check_output([probe], input=json.dumps(document).encode(), timeout=10))
    actual = observe(document, response, expected)
    details = {key: error for key, error in (
        ("typed_error", response["typed"].get("Err")), ("saved_error", response["saved_error"]),
    ) if error is not None}
    if actual.get("canonical_round_trip") is False and "Ok" in response["typed"]:
        details["typed_round_trip"] = response["typed"]["Ok"]
    return ("pass" if actual == expected else "fail"), actual, details


def check(baseline):
    with tempfile.TemporaryDirectory(prefix="saved-inventory-") as temp:
        ref, tree, probe = BASELINE if baseline else None, None, None
        try:
            ref = ref or git("rev-parse", "HEAD").decode().strip()
            tree = git("rev-parse", f"{ref}^{{tree}}").decode().strip()
            if baseline and tree != BASELINE_TREE:
                raise ValueError(f"expected baseline tree {BASELINE_TREE}, got {tree}")
            base = json.loads(source(CSV["FIXTURE"].relative_to(ROOT).as_posix(), baseline))
            probe = build(Path(temp), baseline)
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            problem = str(error)
        print(json.dumps({"source": "git blobs" if baseline else "working tree",
                          "commit": ref, "tree": tree}), flush=True)
        statuses = []
        for label, path, value, expected in CASES:
            if probe is None:
                status, actual, details = "blocked", {}, {"setup_error": problem}
            else:
                try:
                    status, actual, details = trial(probe, base, path, value, expected)
                except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.SubprocessError) as error:
                    status, actual, details = "blocked", {}, {"trial_error": str(error)}
            statuses.append(status)
            print(json.dumps({"id": label, "status": status, "expected": expected,
                              "actual": actual, **details}), flush=True)
    return 2 if "blocked" in statuses else int("fail" in statuses)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="store_true",
                        help=f"use fixed Git blobs at {BASELINE} instead of working-tree source")
    raise SystemExit(check(parser.parse_args().baseline))
