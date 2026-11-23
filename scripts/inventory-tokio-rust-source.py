#!/usr/bin/env python3
"""Reproduce the pinned Tokio Rust physical-line inventory."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

POLICY_PATH = Path("docs/reference/rust-source-size-policy.json")
HEADER = "physical_lines\tdisposition\texclusion_category\tpath\n"


class InventoryError(RuntimeError):
    """A reference checkout or policy invariant is invalid."""


def run_git(checkout: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(checkout), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise InventoryError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def physical_lines(path: Path) -> int:
    data = path.read_bytes()
    return data.count(b"\n") + int(bool(data) and not data.endswith(b"\n"))


def load_policy(repo_root: Path) -> dict:
    path = repo_root / POLICY_PATH
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise InventoryError(f"reference metadata is missing: {path}") from error
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(f"reference metadata is unreadable: {error}") from error
    if policy.get("schema_version") != 1:
        raise InventoryError("unsupported or missing source-size policy schema_version")
    return policy


def classify(path: str, exclusions: list[dict]) -> tuple[str, str]:
    matches = [rule for rule in exclusions if path.startswith(rule["path_prefix"])]
    if len(matches) > 1:
        raise InventoryError(f"overlapping reference exclusions classify {path}")
    if matches:
        return "excluded", matches[0]["category"]
    return "included", "-"


def build_inventory(
    checkout: Path, policy: dict
) -> tuple[bytes, list[tuple[int, str, str, str]]]:
    reference = policy["reference"]
    expected_commit = reference["commit"]
    expected_tag = reference["tag"]

    root = Path(
        run_git(checkout, "rev-parse", "--show-toplevel").decode().strip()
    ).resolve()
    if root != checkout.resolve():
        raise InventoryError(f"Tokio checkout must be its repository root: {checkout}")

    head = run_git(checkout, "rev-parse", "HEAD").decode().strip()
    if head != expected_commit:
        raise InventoryError(
            f"Tokio HEAD is {head}, expected pinned commit {expected_commit}"
        )
    tag_commit = (
        run_git(checkout, "rev-parse", f"refs/tags/{expected_tag}^{{commit}}")
        .decode()
        .strip()
    )
    if tag_commit != expected_commit:
        raise InventoryError(
            f"Tokio tag {expected_tag} resolves to {tag_commit}, expected {expected_commit}"
        )
    if run_git(checkout, "status", "--porcelain", "--untracked-files=no"):
        raise InventoryError(
            "Tokio checkout has tracked modifications; inventory refused"
        )

    exclusions = reference.get("exclusions")
    if not isinstance(exclusions, list):
        raise InventoryError("reference exclusions metadata is missing")
    for rule in exclusions:
        if set(rule) != {"path_prefix", "category", "reason"}:
            raise InventoryError(
                "each reference exclusion must contain path_prefix/category/reason"
            )
        if rule["category"] not in {
            "generated",
            "vendored",
            "build_output",
            "machine_produced_table",
            "fixture",
        }:
            raise InventoryError(f"unsupported exclusion category: {rule['category']}")
        if not rule["path_prefix"] or not rule["reason"]:
            raise InventoryError(
                "reference exclusions require a narrow prefix and reason"
            )

    raw_paths = run_git(checkout, "ls-files", "-z", "--", "*.rs")
    paths = [entry.decode("utf-8") for entry in raw_paths.split(b"\0") if entry]
    rows: list[tuple[int, str, str, str]] = []
    for relative in paths:
        if "\t" in relative or "\n" in relative:
            raise InventoryError(f"TSV-unsafe Rust path: {relative!r}")
        disposition, category = classify(relative, exclusions)
        rows.append(
            (physical_lines(checkout / relative), disposition, category, relative)
        )
    rows.sort(key=lambda row: (-row[0], row[3]))

    rendered = HEADER + "".join(
        f"{lines}\t{disposition}\t{category}\t{path}\n"
        for lines, disposition, category, path in rows
    )
    return rendered.encode("utf-8"), rows


def verify_summary(rows: list[tuple[int, str, str, str]], policy: dict) -> None:
    reference = policy["reference"]
    if len(rows) != reference["tracked_rust_files"]:
        raise InventoryError(
            f"inventory has {len(rows)} Rust files, expected {reference['tracked_rust_files']}"
        )
    if not rows:
        raise InventoryError("Tokio inventory is empty")
    absolute = rows[0]
    included = next((row for row in rows if row[1] == "included"), None)
    if included is None:
        raise InventoryError("Tokio inventory has no included hand-authored source")

    expected_absolute = reference["absolute_largest"]
    if (absolute[0], absolute[3]) != (
        expected_absolute["physical_lines"],
        expected_absolute["path"],
    ):
        raise InventoryError(f"absolute maximum changed: {absolute[3]} ({absolute[0]})")
    expected_included = reference["largest_included_hand_authored"]
    if (included[0], included[3]) != (
        expected_included["physical_lines"],
        expected_included["path"],
    ):
        raise InventoryError(f"included maximum changed: {included[3]} ({included[0]})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tokio-checkout", required=True, type=Path)
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--output", type=Path, help="write the deterministic TSV inventory"
    )
    output.add_argument(
        "--check", type=Path, help="compare against an existing TSV inventory"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    try:
        policy = load_policy(repo_root)
        rendered, rows = build_inventory(args.tokio_checkout, policy)
        verify_summary(rows, policy)
        if args.check:
            if not args.check.is_file():
                raise InventoryError(f"inventory to check is missing: {args.check}")
            if args.check.read_bytes() != rendered:
                raise InventoryError(
                    f"inventory differs from reproducible output: {args.check}"
                )
        elif args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(rendered)
        else:
            sys.stdout.buffer.write(rendered)

        absolute = rows[0]
        included = next(row for row in rows if row[1] == "included")
        excluded_count = sum(row[1] == "excluded" for row in rows)
        print(
            f"Tokio {policy['reference']['tag']} ({policy['reference']['commit']}): "
            f"{len(rows)} tracked .rs files, {excluded_count} excluded fixtures; "
            f"absolute={absolute[3]}:{absolute[0]}, included={included[3]}:{included[0]}",
            file=sys.stderr,
        )
        return 0
    except (InventoryError, KeyError, OSError, UnicodeDecodeError) as error:
        print(f"Tokio source inventory failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
