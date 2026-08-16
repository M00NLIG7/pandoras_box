# First-release threat model

This document defines the security boundary of the `x86_64-unknown-linux-musl` first-release candidate. It is not a claim that GNU/glibc, unreleased Windows/SMB, or BSD paths passed live validation.

## Authorized-use boundary

Pandora performs active discovery, authentication, command execution, file staging, inventory collection, and cleanup. Operators must have explicit authorization for every requested address and account. The tool does not determine legal scope or prevent an authorized credential from being used against the wrong in-range host.

## Trusted components

- The operator host, local executable bundle, enrolled SSH host keys, login-secret provider, and artifact storage are trusted.
- The exact source revision, lockfile, Rust toolchain, Cross images, and checksummed Smolder crates.io release set are release inputs.
- The remote target and network are treated as potentially hostile.
- The Chimera process may run with elevated privileges, so its local output and cleanup paths are security-sensitive.

## Protected assets

- Login secrets and private SSH material
- Host identity and host-key enrollment
- Chimera executable integrity
- Inventory, topology, command output, and failure artifacts
- Mission checkpoint integrity and transport/failure attribution

## Security controls

### Authentication and host identity

Normal SSH mode requires a matching key in the operator's OpenSSH `known_hosts`. Unknown and changed keys fail closed. `--dangerously-accept-unknown-host-keys` is an explicit first-contact exception, does not persist enrollment, and still rejects a changed enrolled key.

Login secrets come from standard input or a protected file/file descriptor, never from a CLI value. Secret-bearing Rust types zeroize owned values where practical and redact `Debug`. Mission manifests do not serialize the secret.

### Artifact transfer

Chimera opens no HTTP or other artifact-listener socket. It writes `inventory.json` and `application.log` beneath its selected local output root. Pandora retrieves those terminal files through the established authenticated SFTP session. The unreleased Windows plan can use the established authenticated SMB session.

Traversal, unauthenticated fetch, replay, and destructive-read semantics are absent because there is no artifact request endpoint. Remote cleanup is a separate recorded operation; a cleanup failure does not erase already-collected success or become silent success.

### Mission safety and state

- CIDRs are bounded before materialization; `/32` and `/31` retain their addresses.
- Dry-run rejects mutating operations at the session-operation boundary.
- Transport fallback is eligible only when retry/failure disposition permits it and no non-idempotent side effect may be duplicated.
- The selected transport, attempt count, completed phases, failure phase, and failure disposition are durable host status.
- Mission identifiers are one validated path component.
- An artifact-root lock prevents concurrent active missions from corrupting shared state.
- JSON uses Serde and durable file replacement is atomic.
- Strict exit status treats zero attempted targets and handled host failures as failure unless the operator explicitly selects best-effort.

### Supply chain

The first-release RustRC surface is SSH/SFTP only. Winexe, opaque runtime artifacts, listener-based transfer, invalid-TLS behavior, and compile-time downloads are removed. Smolder uses the exact checksummed crates.io `0.4.0` release set, without a path or Git override. Release checks reject known advisories and unknown dependency sources without a broad waiver.

## Explicit non-goals and residual risk

- A compromised target can lie in inventory output, delay commands, consume resources within configured bounds, or disclose a credential valid on that host.
- Password authentication cannot provide per-host credential isolation when the operator supplies one credential for multiple targets. Pandora does not rotate or redesign those credentials.
- Dangerous first-contact mode is vulnerable to first-contact interception and must not be treated as enrollment.
- Inventory is best-effort by section. Missing commands, permissions, platform differences, or time/output limits appear in `sectionErrors`; a syntactically valid file is not proof of complete visibility.
- Dry-run is not passive: discovery and local artifact/report activity can occur.
- Local artifacts are not encrypted by Pandora. Filesystem access control, encryption at rest, retention, and secure deletion are operator responsibilities.
- Windows SSH/SMB, BSD, and architectures outside the stated support matrix remain unreleased until their exact artifacts pass mandatory live gates.

## Security regression anchors

Relevant tests cover host-key rejection/opt-in, secret redaction, bounded target enumeration, dry-run operation rejection, fallback idempotency, mission path validation, atomic/concurrent writes, truthful accounting, authenticated collector retrieval, and the absence of artifact-server traversal/read/delete/replay behavior. The release workflow additionally requires dependency audit/deny checks and exact Ubuntu/Alpine SSH interoperability.
