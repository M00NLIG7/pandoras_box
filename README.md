# Pandora's Box

Pandora's Box is an authorized, cross-platform fleet-inventory orchestrator. One CLI discovers a requested range, applies explicit target and payload contracts, uses authenticated transports, runs the Chimera collector, and writes durable local reports.

> **Authorization required.** Discovery, authentication, command execution, staging, and collection can be disruptive. Use Pandora only on systems you own or are explicitly authorized to administer.

## Platform contract and qualification

Linux, Windows, FreeBSD/BSD, and pfSense are product support goals and first-class target contracts. A represented target is **not** automatically a live-supported target. Runtime execution requires all of the following before authentication:

1. an explicit OS, architecture, and transport contract;
2. an exact payload entry for that OS/architecture;
3. a nonempty version, expected SHA-256, and regular non-link payload file; and
4. `live_qualified` evidence in the payload manifest.

Missing, ambiguous, invalid, unknown, or contract-only payloads become isolated per-host outcomes. They do not authenticate and do not stop healthy hosts.

| Target/path | Implemented contract | Exact packaged/live evidence at this source revision |
| --- | --- | --- |
| Linux x86_64 over SSH/SFTP | Planning, capability probe, payload selection, secure workspace, collection, cleanup | The release workflow defines exact packaged-operator Ubuntu 24.04 and Alpine 3.21 gates. A bundle is qualified only when its generated payload manifest records those passing gates. No built artifact is present in this source tree. |
| Windows x86_64 over SSH/SFTP | First-class Windows shell, payload, and transport contract | Awaiting exact x86_64 Windows payload packaging and controlled live gate. Not currently claimed live-qualified. |
| Windows SMB fallback | Explicit fallback contract; SMB 3.1.1/signing and encryption-required ADMIN$ configuration | **Blocked before authentication** with pinned Smolder 0.4.0 because its public remote-exec builder cannot enforce `SecurityPolicy::pandora()` on every SCMR request. Awaiting a pinned strict adapter and controlled live gate. |
| FreeBSD, OpenBSD, NetBSD, and DragonFly BSD x86_64 over SSH/SFTP | Exact-family POSIX contracts and runtime capability checks; generic `bsd` is report-only to prevent ABI guessing | Awaiting exact native payloads and controlled live gates. |
| pfSense x86_64 over SSH/SFTP | First-class pfSense contract, verified as a FreeBSD runtime before staging | Awaiting an exact pfSense-compatible payload and controlled live gate. |
| Other architectures | `x86`, `aarch64`, and `armv7` are representable payload keys | No packaged artifacts or live claims yet. |

Passive TTL/port inference is retained only as a report hint. It never selects an authenticated adapter or payload.

## Fast one-bundle operation

A validated bundle contains one operator, the packaged collectors, and one generated payload manifest. Configure named credential profiles once, have the existing secret provider inject the referenced environment values/files/agent identities, then run one CLI from the bundle root:

```sh
./bin/pandoras_box \
  --range 192.0.2.0/28 \
  --profile linux-x86_64 \
  --credential-config ./pandora-credentials.json \
  --mission-id inventory-001 \
  --artifact-root ./artifacts
```

The default `release/payloads.json` is loaded automatically. The default target profile is `detect-only`; it performs bounded discovery and local reporting but never authenticates. This is the safe choice for unknown or mixed ranges and requires no credential prompt.

For mixed fleets, provide per-host contracts:

```json
{
  "targets": {
    "192.0.2.10": {
      "operating_system": "linux",
      "architecture": "x86_64",
      "transports": ["ssh_sftp"]
    },
    "192.0.2.20": {
      "operating_system": "windows",
      "architecture": "x86_64",
      "transports": ["ssh_sftp", "windows_smb"]
    },
    "192.0.2.30": {
      "operating_system": "pfsense",
      "architecture": "x86_64",
      "transports": ["ssh_sftp"]
    }
  }
}
```

Pass it with `--target-contracts contracts.json`. SMB is additionally disabled unless `--allow-encrypted-smb-fallback` is explicit, the selected named profile also permits `windows_smb`, and the current pinned adapter still fails closed as shown in the matrix.

## Named credential profiles

`--credential-config` loads a bounded versioned configuration with a fleet default, optional OS defaults, exact per-host overrides, and named policies. Profiles support:

- passwords from an external environment variable or protected file;
- pinned Ed25519/ECDSA private keys or one exact existing SSH-agent identity;
- username, Windows domain/workstation, SSH/SMB ports, transport allow-list, and host-key policy.

Selection is automatic: host override, then OS default, then fleet default. Missing, duplicate/ambiguous, unavailable, or policy-incompatible selections become terminal per-host `credentials` outcomes before target authentication. Pandora never prompts per host, tries another credential, or downgrades transport/identity policy. Secret values are absent from inventories, logs, reports, mission state, and resume signatures; only profile names and hashes of non-secret policy are persisted.

See [`docs/CREDENTIAL_PROFILES.md`](docs/CREDENTIAL_PROFILES.md) for the complete schema and external-provider contract. The legacy `--password-stdin`/`--password-file` path remains a fast one-global-secret compatibility mode and is internally represented as named defaults; it is mutually exclusive with `--credential-config`.

A payload manifest has this shape; paths are relative to the manifest directory unless absolute:

```json
{
  "payloads": [{
    "operating_system": "linux",
    "architecture": "x86_64",
    "path": "chimera",
    "version": "0.1.0",
    "sha256": "<64 lowercase hexadecimal characters>",
    "qualification": "live_qualified",
    "evidence": ["exact packaged operator gate identifier"]
  }]
}
```

Do not mark an entry `live_qualified` without exact artifact evidence. Use `contract_only` while implementation or validation remains incomplete; Pandora will report it without authentication.

## Safety behavior

- SSH/SFTP is preferred. Known-host verification is required by default. Credential-profile, authentication, and host-identity failures are terminal and block retry or fallback.
- Named profiles pin host-key policy per profile. The legacy `--dangerously-accept-unknown-host-keys` switch is an explicit first-contact exception; changed enrolled keys still fail closed.
- Secrets come only from an external environment variable, protected file, existing SSH agent/key, or legacy standard input—never an argument value or host contract.
- `--dry-run` never enters the authenticated transport stack. It performs no identity command, upload, service creation, SMB execution, or remote cleanup.
- Remote workspaces use a cryptographic 192-bit nonce, restrictive permissions/ACLs, an ownership token, OS-owned validation, and non-recursive cleanup. Links/reparse points, wrong owners, altered paths, and unsafe prior contents fail closed.
- Terminal stage, execute, and collect failures attempt bounded cleanup. Host status records `cleanup_outcome`, `residue_present`, and `partial_collection` without rewriting the initiating failure.
- Local directories and files default to 0700/0600 on Unix and a protected owner/Administrators/SYSTEM DACL on Windows. Artifact roots should also use encrypted storage where required.

## Bounds and tuning

Fast defaults are exposed rather than hard-coded. Relevant flags include:

- `--concurrency`, `--retries`, `--retry-backoff-ms`
- `--discovery-timeout-ms`, `--connect-timeout-ms`, `--inactivity-timeout-ms`
- `--command-timeout-ms`, `--transfer-timeout-ms`, `--cleanup-timeout-ms`
- `--host-timeout-ms`, `--mission-timeout-ms`
- `--max-command-output-bytes`, `--max-download-bytes`, `--max-payload-bytes`
- profile `ssh_port`/`smb_port`, legacy `--ssh-port`, and repeatable `--discovery-port`

Command output, payloads, downloads, connections, operations, hosts, cleanup, and missions are bounded. Ctrl-C stops new work, lets active bounded operations return, attempts workspace cleanup, and persists interruption outcomes.

## Mission reuse

Mission reuse is never implicit:

- an existing mission ID errors by default;
- `--resume --mission-id ID` verifies the exact target, non-secret selected credential policy, deadlines, and payload identity before using checkpoints;
- resumed random workspace descriptors are validated against the exact payload and target contract;
- `--fresh --mission-id ID` explicitly removes the prior private mission directory and starts over.

A repeated ID cannot silently present prior artifacts as a fresh collection.

## Reports and rendering

Core completion writes:

```text
artifacts/<mission-id>/
├── mission.json
├── summary.json
├── asset_inventory.{json,md,csv,pdf}
├── network_topology.{md,mmd,excalidraw}
└── hosts/<ip>/
    ├── plan.json
    ├── status.json
    ├── workspace.json
    ├── exec/
    ├── files/inventory.json
    └── logs/application.log
```

Aggregate reports expose Chimera `sectionErrors`, partial inventories, cleanup residue, and partial downloads. CSV fields are formula-neutralized.

PNG rendering is off by default. Pandora never searches or executes code under `HOME`, `CODEX_HOME`, or another ambient tool directory. Optional rendering requires both `--topology-renderer PATH` and `--topology-renderer-sha256 DIGEST`; the standalone renderer receives `input.excalidraw output.png`, has no stdin/stdout capture, runs after core mission completion, and is deadline/output bounded. Its independent result is written to `rendering_status.json`.

## Build and evidence

See [`docs/BUILDING.md`](docs/BUILDING.md) for locked local gates and exact-artifact qualification. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for trust boundaries and remaining evidence.

Repository documentation is local-only and is not included in release bundles or uploaded as generated documentation.

## License

Source is available under the [MIT License](LICENSE).
