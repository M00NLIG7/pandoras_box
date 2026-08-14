# Pandora's Box

Pandora's Box is an authorized fleet-inventory orchestrator. It discovers requested targets, opens authenticated remote sessions, stages the Chimera collector, retrieves its terminal artifacts through the same authenticated session, cleans up, and writes durable mission reports.

> **Authorization required.** Use this software only on systems you own or are explicitly authorized to administer. Discovery, authentication, command execution, file transfer, and inventory collection can be disruptive and may expose sensitive operational data.

This tree is a first-release candidate, not evidence of support for every platform represented in the source. The release contract is deliberately narrow.

## First-release scope

| Component | Published target | Mandatory evidence | Status |
| --- | --- | --- | --- |
| Pandora operator | x86_64 Linux | Locked build and artifact smoke test | Release candidate |
| Chimera payload | `x86_64-unknown-linux-musl` | Exact artifact over SSH/SFTP against Ubuntu 24.04 and Alpine 3.21 | Release candidate |
| Windows SSH/SMB | None | Source compile-check only; no approved live gate | Not released or supported |
| BSD and other architectures | None | No mandatory live gate | Not released or supported |

A skipped, emulated-only, or unavailable gate is not support evidence. The workflow packages only the x86_64 Linux bundle after both Linux live gates pass.

The first release does **not** rotate passwords, harden hosts, download executables during compilation, ship Winexe, or expose an HTTP artifact server. Chimera writes terminal files locally; Pandora retrieves them with SFTP or, on the unreleased Windows path, through the already-authenticated SMB session.

## Components and trust boundaries

- **Pandora (`pandoras_box`)** owns mission validation, bounded target enumeration, discovery, transport selection, operation policy, checkpoints, accounting, and reports.
- **Chimera (`chimera`)** performs bounded, read-only inventory probes and records machine-readable section errors when data is incomplete.
- **RustRC (`rustrc`)** is the audited SSH/SFTP adapter. Its first-release surface excludes Winexe, WinRM, Telnet, embedded runtimes, listener-based transfer, and build-time downloads.
- **Smolder** supplies the SMB implementation from the immutable public revision `05cad6854d6044a1af659693ba202c3de5285d57` at <https://github.com/M00NLIG7/smolder.git>. `Cargo.lock` records the resolved source; no sibling checkout is used.

See [the threat model](docs/THREAT_MODEL.md) for assumptions and non-goals.

## Safe operator setup

Pandora requires a login secret from standard input or a protected file. It does not accept secrets in process arguments.

Before connecting, enroll and independently verify each SSH host key in the operator account's normal OpenSSH `known_hosts` file. Unknown and changed keys fail closed by default.

Run the packaged operator from the bundle root so its canonical `release/chimera` payload is available:

```sh
verified-secret-provider | ./bin/pandoras_box \
  --range 192.0.2.10/32 \
  --password-stdin \
  --mission_id inventory-001 \
  --artifact_root ./artifacts
```

A protected file or file descriptor is also supported:

```sh
chmod 600 /path/to/login-secret
./bin/pandoras_box \
  --range 192.0.2.0/28 \
  --password-file /path/to/login-secret \
  --mission_id inventory-002 \
  --artifact_root ./artifacts
```

`--dangerously-accept-unknown-host-keys` is a conspicuous first-contact escape hatch. It does not enroll a key and must not replace out-of-band fingerprint verification. A changed enrolled key remains rejected.

Use `--dry_run` to preview without permitting mutating session operations. Discovery and local report creation can still occur. The operation boundary, not only the planner, rejects remote mutations in dry-run mode.

## Target and exit semantics

- `/32` requests exactly one address; `/31` requests both addresses.
- Larger CIDRs are checked against `--max-targets` (default `65536`) before host materialization.
- `summary.json` separately records `requested_targets`, `reachable_targets`, `unreachable_targets`, `skipped_targets`, `attempted_targets`, `completed_hosts`, and `failed_hosts`.
- Strict mode is the default. Zero attempted targets or any handled host failure returns nonzero; an unhandled mission error always returns nonzero.
- `--best-effort` returns zero after handled target failures, including zero attempted targets. It does not convert an unhandled mission error into success.
- Eligible transport fallback is recorded in each host status. A fallback is not attempted after a non-idempotent side effect may have occurred.

## Mission artifacts

Mission identifiers are a single portable path component: 1–128 ASCII letters, digits, `.`, `_`, or `-`, beginning with a letter or digit and not ending in `.`. One process at a time may own an artifact root.

```text
artifacts/<mission-id>/
├── mission.json
├── summary.json
├── asset_inventory.{json,md,csv,pdf}
├── network_topology.{md,mmd,excalidraw,png}
└── hosts/<ip>/
    ├── plan.json
    ├── status.json
    ├── exec/
    ├── files/inventory.json
    └── logs/application.log
```

Durable JSON is serialized with Serde and replaced atomically. Host status retains the selected transport, attempt count, failure phase/disposition, and completed phases so cleanup or collection partial success remains visible. Chimera's `inventory.json` contains `sectionErrors` when an inventory section could not be collected.

Treat the artifact root as sensitive: inventories, usernames, topology, command output, and failure details can aid an attacker. Mission manifests exclude the login secret, and secret-bearing types redact `Debug` output, but operators remain responsible for storage and retention controls.

## Build, test, and provenance

Use the tested locked commands in [`docs/BUILDING.md`](docs/BUILDING.md). Release automation validates and packages first; publishing is a separate, explicit draft-release step that runs only after all gates pass. Binary bundles include checksums, Cargo metadata, and source/toolchain/Smolder provenance.

All repository documentation and generated documentation are local-only and are excluded from package uploads and release attachments.

The live scripts under [`scripts/`](scripts/README.md) are disposable test infrastructure, not operator tooling. Windows and mixed harnesses can modify a local lab fixture and are not release evidence in this branch.

Historical competition research is preserved under [`docs/archive/`](docs/archive/) with freshness warnings. It is not current product or build guidance.

## License

Source code in the first-release surface is available under the [MIT License](LICENSE). Removed historical Winexe/runc artifacts were not accepted as release inputs; see [`rustrc/PROVENANCE.md`](rustrc/PROVENANCE.md).
