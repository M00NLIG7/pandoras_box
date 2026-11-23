#!/usr/bin/env python3
"""Enforce Pandora's source-pinned Tokio Rust physical-line limit."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

POLICY_RELATIVE = Path("docs/reference/rust-source-size-policy.json")
INVENTORY_HEADER = "physical_lines\tdisposition\texclusion_category\tpath"
ALLOWED_EXCLUSIONS = {
    "generated",
    "vendored",
    "build_output",
    "machine_produced_table",
    "fixture",
}


class PolicyError(RuntimeError):
    """The checked-in policy or source inventory is invalid."""


def git(repo_root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise PolicyError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def physical_lines(path: Path) -> int:
    data = path.read_bytes()
    return data.count(b"\n") + int(bool(data) and not data.endswith(b"\n"))


def required_mapping(parent: dict, key: str) -> dict:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise PolicyError(f"required metadata object is missing: {key}")
    return value


def load_policy(repo_root: Path) -> tuple[dict, Path]:
    path = repo_root / POLICY_RELATIVE
    if not path.is_file():
        raise PolicyError(
            f"required Tokio reference metadata is missing: {POLICY_RELATIVE}"
        )
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"Tokio reference metadata is unreadable: {error}") from error
    if policy.get("schema_version") != 1:
        raise PolicyError("source-size policy schema_version must be 1")
    return policy, path


def parse_reference_inventory(
    repo_root: Path, policy: dict
) -> list[tuple[int, str, str, str]]:
    reference = required_mapping(policy, "reference")
    inventory_name = reference.get("inventory_file")
    expected_digest = reference.get("inventory_sha256")
    if not isinstance(inventory_name, str) or not inventory_name:
        raise PolicyError("Tokio inventory_file metadata is missing")
    if not isinstance(expected_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_digest
    ):
        raise PolicyError("Tokio inventory_sha256 metadata is missing or invalid")
    inventory_path = repo_root / inventory_name
    if not inventory_path.is_file():
        raise PolicyError(
            f"required Tokio reference inventory is missing: {inventory_name}"
        )
    data = inventory_path.read_bytes()
    actual_digest = hashlib.sha256(data).hexdigest()
    if actual_digest != expected_digest:
        raise PolicyError(
            f"Tokio inventory digest mismatch: expected {expected_digest}, got {actual_digest}"
        )
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise PolicyError(f"Tokio inventory is not UTF-8: {error}") from error
    if not lines or lines[0] != INVENTORY_HEADER:
        raise PolicyError("Tokio inventory header is missing or unsupported")

    rows: list[tuple[int, str, str, str]] = []
    seen_paths: set[str] = set()
    for number, line in enumerate(lines[1:], start=2):
        fields = line.split("\t")
        if len(fields) != 4:
            raise PolicyError(f"Tokio inventory line {number} is not four-column TSV")
        raw_count, disposition, category, path = fields
        try:
            count = int(raw_count)
        except ValueError as error:
            raise PolicyError(
                f"Tokio inventory line {number} has an invalid count"
            ) from error
        if count < 0 or disposition not in {"included", "excluded"}:
            raise PolicyError(f"Tokio inventory line {number} has invalid fields")
        if disposition == "included" and category != "-":
            raise PolicyError(
                f"included Tokio inventory row {path} has an exclusion category"
            )
        if disposition == "excluded" and category not in ALLOWED_EXCLUSIONS:
            raise PolicyError(
                f"excluded Tokio inventory row {path} has an invalid category"
            )
        if not path or path in seen_paths:
            raise PolicyError(
                f"Tokio inventory has a missing or duplicate path: {path}"
            )
        seen_paths.add(path)
        rows.append((count, disposition, category, path))

    if rows != sorted(rows, key=lambda row: (-row[0], row[3])):
        raise PolicyError("Tokio inventory is not deterministically sorted")
    expected_count = reference.get("tracked_rust_files")
    if len(rows) != expected_count:
        raise PolicyError(
            f"Tokio inventory has {len(rows)} rows, expected {expected_count}"
        )
    return rows


def verify_reference(policy: dict, rows: list[tuple[int, str, str, str]]) -> int:
    reference = required_mapping(policy, "reference")
    measurement = required_mapping(policy, "measurement")
    if measurement.get("algorithm_id") != "lf_plus_unterminated_tail_v1":
        raise PolicyError("physical-line measurement algorithm metadata is missing")
    if reference.get("repository") != "https://github.com/tokio-rs/tokio":
        raise PolicyError("authoritative Tokio repository metadata is missing")
    if not re.fullmatch(r"tokio-[0-9]+\.[0-9]+\.[0-9]+", str(reference.get("tag", ""))):
        raise PolicyError("Tokio stable tag metadata is missing or invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", str(reference.get("commit", ""))):
        raise PolicyError("Tokio commit metadata is missing or invalid")
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}",
        str(reference.get("stable_release_checked_utc", "")),
    ):
        raise PolicyError("Tokio stable-release lookup date is missing or invalid")

    exclusions = reference.get("exclusions")
    if not isinstance(exclusions, list):
        raise PolicyError("Tokio reference exclusions metadata is missing")
    for rule in exclusions:
        if not isinstance(rule, dict) or set(rule) != {
            "path_prefix",
            "category",
            "reason",
        }:
            raise PolicyError("Tokio exclusions require path_prefix/category/reason")
        if rule["category"] not in ALLOWED_EXCLUSIONS:
            raise PolicyError(
                f"unsupported Tokio exclusion category: {rule['category']}"
            )
        if not rule["path_prefix"] or not rule["reason"]:
            raise PolicyError("Tokio exclusions require a narrow prefix and evidence")
    for count, disposition, category, path in rows:
        matches = [rule for rule in exclusions if path.startswith(rule["path_prefix"])]
        if len(matches) > 1:
            raise PolicyError(f"overlapping Tokio exclusions classify {path}")
        expected = (
            ("excluded", matches[0]["category"]) if matches else ("included", "-")
        )
        if (disposition, category) != expected:
            raise PolicyError(
                f"Tokio exclusion metadata does not classify {path} reproducibly"
            )

    absent = reference.get("reviewed_absent_categories")
    required_absent = {
        "generated",
        "vendored",
        "build_output",
        "machine_produced_table",
        "lockfile",
    }
    if (
        not isinstance(absent, dict)
        or set(absent) != required_absent
        or not all(absent.values())
    ):
        raise PolicyError("Tokio exclusion review evidence is incomplete")
    if not rows:
        raise PolicyError("Tokio reference inventory is empty")
    absolute = rows[0]
    included = next((row for row in rows if row[1] == "included"), None)
    if included is None:
        raise PolicyError("Tokio reference inventory has no included source")

    absolute_metadata = required_mapping(reference, "absolute_largest")
    included_metadata = required_mapping(reference, "largest_included_hand_authored")
    if (absolute[3], absolute[0]) != (
        absolute_metadata.get("path"),
        absolute_metadata.get("physical_lines"),
    ):
        raise PolicyError(
            "Tokio absolute maximum metadata does not match its inventory"
        )
    if (included[3], included[0]) != (
        included_metadata.get("path"),
        included_metadata.get("physical_lines"),
    ):
        raise PolicyError(
            "Tokio included maximum metadata does not match its inventory"
        )

    limit = policy.get("hard_limit_physical_lines")
    if not isinstance(limit, int) or limit <= 0:
        raise PolicyError("hard_limit_physical_lines metadata is missing or invalid")
    if limit != included[0]:
        raise PolicyError(
            f"hard limit {limit} does not equal pinned Tokio included maximum {included[0]}"
        )
    return limit


def pandora_inventory(
    repo_root: Path, policy: dict
) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    pandora = required_mapping(policy, "pandora")
    exclusions = pandora.get("excluded_rust_files")
    if not isinstance(exclusions, list):
        raise PolicyError("Pandora excluded_rust_files metadata is missing")
    exclusion_by_path: dict[str, dict] = {}
    for rule in exclusions:
        if not isinstance(rule, dict) or set(rule) != {
            "path",
            "category",
            "reason",
            "evidence",
        }:
            raise PolicyError(
                "Pandora exclusions require exact path/category/reason/evidence"
            )
        path = rule["path"]
        if (
            not isinstance(path, str)
            or not path.endswith(".rs")
            or path.startswith("/")
            or ".." in Path(path).parts
            or path in exclusion_by_path
        ):
            raise PolicyError(
                f"Pandora exclusion is not a unique exact Rust path: {path!r}"
            )
        if (
            rule["category"] not in ALLOWED_EXCLUSIONS
            or not rule["reason"]
            or not rule["evidence"]
        ):
            raise PolicyError(
                f"Pandora exclusion lacks category/reason/evidence: {path}"
            )
        exclusion_by_path[path] = rule

    raw_paths = git(
        repo_root,
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        "*.rs",
    )
    relative_paths = sorted(
        entry.decode("utf-8") for entry in raw_paths.split(b"\0") if entry
    )
    included: list[tuple[int, str]] = []
    excluded: list[tuple[int, str]] = []
    for relative in relative_paths:
        path = repo_root / relative
        if path.is_symlink() or not path.is_file():
            raise PolicyError(
                f"Rust source must be a regular non-link file: {relative}"
            )
        row = (physical_lines(path), relative)
        if relative in exclusion_by_path:
            excluded.append(row)
        else:
            included.append(row)

    missing = sorted(set(exclusion_by_path) - set(relative_paths))
    if missing:
        raise PolicyError(
            f"Pandora exclusion paths are missing from the inventory: {', '.join(missing)}"
        )
    included.sort(key=lambda row: (-row[0], row[1]))
    excluded.sort(key=lambda row: (-row[0], row[1]))
    return included, excluded


def main() -> int:
    try:
        script_root = Path(__file__).resolve().parent.parent
        repo_root = Path(
            git(script_root, "rev-parse", "--show-toplevel").decode().strip()
        ).resolve()
        if repo_root != script_root:
            raise PolicyError(
                f"source-size check must live at the repository root: {script_root}"
            )
        policy, _policy_path = load_policy(repo_root)
        reference_rows = parse_reference_inventory(repo_root, policy)
        limit = verify_reference(policy, reference_rows)
        included, excluded = pandora_inventory(repo_root, policy)
        violations = [row for row in included if row[0] > limit]

        reference = policy["reference"]
        absolute = reference["absolute_largest"]
        included_max = reference["largest_included_hand_authored"]
        print(
            f"Tokio reference: {reference['tag']} @ {reference['commit']} "
            f"({reference['tracked_rust_files']} tracked .rs files)"
        )
        print(
            f"Reference maxima: absolute {absolute['physical_lines']} {absolute['path']}; "
            f"included {included_max['physical_lines']} {included_max['path']}"
        )
        print(
            f"Pandora inventory: {len(included)} included hand-authored .rs files, "
            f"{len(excluded)} explicitly excluded; hard limit {limit} physical lines"
        )
        if included:
            print(f"Pandora maximum: {included[0][0]} {included[0][1]}")
        if violations:
            for count, path in violations:
                print(
                    f"source-size violation: {count} > {limit}: {path}", file=sys.stderr
                )
            return 1
        print("Rust source-size check passed")
        return 0
    except (PolicyError, KeyError, OSError, UnicodeDecodeError) as error:
        print(f"Rust source-size check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
