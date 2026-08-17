# Pandora cross-platform CCDC threat model

This document describes the implemented safety contract, not a claim that every represented platform has a qualified artifact.

## Boundary and adversary

Pandora performs active discovery, authentication, command execution, file transfer, inventory collection, and cleanup only for explicitly authorized targets. The operator host, selected bundle, payload manifest, secret provider, known-host enrollment, and artifact storage are trusted. The network, discovered services, target filesystem, remote output, and target timing are hostile.

Protected assets include credentials, SSH host identity, payload integrity, privileged target paths, collected inventory, mission provenance, and truthful cleanup/residue state.

## Platform and payload policy

Passive TTL and port observations are untrusted hints. They never select an authenticated transport or payload.

Before a host task starts, Pandora requires an explicit operating system, architecture, and transport contract. It preflights an exact OS/architecture payload by version and expected SHA-256, rejects links and size violations, and requires recorded live qualification. Unknown, missing, ambiguous, invalid, and contract-only targets are reported without authentication.

After authentication, a fixed platform-owned capability probe verifies the OS kernel and architecture before workspace creation or payload transfer. A mismatch is terminal and cannot fall through to an incompatible payload.

## Authentication and fallback

Named credential profiles separate non-secret host selection from external secret values. Exact host overrides take precedence over OS defaults and the fleet default. Duplicate/ambiguous bindings, missing profiles, unsupported target policy, absent secret files/environment values, key/fingerprint errors, and unavailable/ambiguous agent identities are typed terminal `credentials` outcomes for the affected host. Resolution is automatic and never invokes a prompt or secret-provider command.

Password values come from external environment variables, protected bounded files, or the legacy one-secret input. SSH key profiles require a pinned public-key fingerprint and reject unsafe files, encrypted prompt-requiring keys, fingerprint substitutions, and currently disabled RSA keys before target connection. Agent profiles select exactly one fingerprint from the existing OpenSSH agent before target connection. Secret values are redacted in memory and never persisted; see `docs/CREDENTIAL_PROFILES.md`.

SSH/SFTP is preferred. Normal mode requires a matching OpenSSH `known_hosts` key. Host-key policy is part of each named profile. The dangerous first-contact policy is explicit, does not enroll a key, and still rejects a changed enrolled key.

Credential-profile, authentication, and host-identity errors are typed at adapter boundaries. Exact RustRC wording such as `Authentication error: Failed to authenticate with password` is terminal. Missing credentials, authentication, account-lock, permission, and host-key failures cannot retry into another profile/credential attempt or fall back to SMB.

Windows SMB is opt-in. File-share construction requires SMB 3.1.1, signing, and encryption. The pinned Smolder 0.4.0 public remote-exec API cannot apply its strict Pandora policy to every separate SCMR session, so Pandora currently rejects SMB fallback before authentication. It must remain blocked until a pinned adapter can enforce encryption for every request and an exact controlled gate verifies it. A signed-but-unencrypted fallback is not acceptable.

## Dry-run invariant

Dry-run performs bounded discovery and local reporting only. It never enters the authenticated transport stack and therefore performs no identity command, upload, service creation, SMB command, workspace creation, download, or remote cleanup. The CLI exposes no arbitrary identity command.

## Workspace and cleanup

Each host receives a cryptographically random 192-bit workspace name and owner token. Platform-owned setup:

- creates the path with restrictive mode/ACL;
- verifies type, ownership, permissions, token, and known children;
- rejects POSIX links and Windows reparse points;
- validates resumed descriptors against the exact host/payload contract; and
- refuses altered or unsafe pre-existing paths before writes.

Cleanup repeats ownership/type/token checks, deletes only known files, and removes empty directories without recursive deletion. Terminal stage, execute, collection, host-deadline, mission-deadline, and operator-interruption paths attempt bounded cleanup. Status separately records the initiating error, cleanup outcome, possible residue, and partial collection.

Transport-internal cleanup is also bounded. A cleanup error never rewrites an earlier failure as success.

## Deadlines and resource limits

Discovery connect, authenticated connect, SSH inactivity, command, transfer, cleanup, host, and mission deadlines are separate and configurable. Output, downloads, and payload files have byte limits. SSH rejects excess channel output while receiving it and checks SFTP metadata plus a bounded stream. SMB metadata and transfer results are bounded. Chimera limits external command streams and container inspection count/concurrency.

Completed host tasks are drained during discovery to limit task retention. Ctrl-C stops new work, sets shared cancellation, waits only on bounded active operations, and drives host cleanup before final reconciliation.

## Mission and artifact integrity

- CIDRs and concurrency are bounded.
- Existing mission IDs fail by default.
- Resume is explicit and verifies target, transport, selected non-secret credential-profile policy, deadlines, and payload identity. External secret values/hashes are deliberately not artifacts.
- Fresh reuse is explicit and validates the local mission path before deletion.
- Random remote workspace descriptors are private durable state.
- Local artifact directories/files default to 0700/0600 on Unix and a protected owner/Administrators/SYSTEM DACL on Windows; paths reject links and wrong ownership.
- Durable state is atomically replaced under an artifact-root lock.
- Aggregate reports surface section-level collection errors, partial downloads, cleanup residue, and host failures.
- CSV values that could be interpreted as formulas are neutralized.

Artifacts are not encrypted by Pandora. Use filesystem encryption, retention controls, and restricted operator access.

## Optional rendering

Core JSON/Markdown/CSV/PDF/Excalidraw reports require no external renderer. Pandora does not search `HOME`, `CODEX_HOME`, or ambient plugin directories.

Optional PNG rendering requires an explicit executable and exact SHA-256. It receives no stdin, has discarded stdout/stderr, an execution deadline, a bounded regular output file, and a private temporary directory. It runs only after summary durability and active-mission cleanup; its independent status cannot turn core report completion into failure or success.

## Remaining evidence

The architecture represents Linux, Windows, FreeBSD/BSD, pfSense, and multiple CPU families. Only an exact packaged artifact whose generated manifest follows passing mandatory gates may be called live-qualified. Named-profile selection, redaction, isolation, and source/Windows cross-compilation have offline gates; exact SSH key/agent and Windows domain interoperability remain controlled live-evidence work. Windows SSH, Windows SMB, BSD, pfSense, and non-x86_64 artifacts remain evidence gaps at this revision; see `docs/BUILDING.md`.
