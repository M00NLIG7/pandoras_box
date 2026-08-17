# Building and validating Pandora's Box

Historical material under `docs/archive/` is non-authoritative. A compile check, emulation, skipped fixture, or hand-written manifest is not live support evidence.

## Pinned inputs

- Rust `1.94.1` (`rust-toolchain.toml`)
- Cross `0.2.5`
- cargo-audit `0.22.1`
- cargo-deny `0.20.2`
- digest-pinned Cross/live images in `Cross.toml`, workflow, and fixture scripts
- exact crates.io `smolder`, `smolder-smb-core`, and `smolder-proto` `0.4.0` releases and lockfile checksums

Do not replace release inputs with floating versions, Git/path overrides, or sibling checkouts.

## Local source gates

```sh
cargo fetch --locked
cargo metadata --locked --offline --format-version 1 >/dev/null
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets -- -D warnings
cargo test --locked --offline --workspace
cargo test --locked --offline -p rustrc --doc
cargo audit --no-fetch --stale -D warnings
cargo deny --locked --offline check advisories sources
bash -n scripts/*.sh
shellcheck scripts/*.sh
```

Refresh advisory data over verified TLS before a release and rerun `cargo audit -D warnings` plus `cargo deny --locked check advisories sources`.

## Canonical Linux artifact

```sh
cross build --locked --offline --release \
  -p pandoras_box --bin pandoras_box \
  --target x86_64-unknown-linux-musl
cross build --locked --offline --release \
  -p chimera --bin chimera \
  --target x86_64-unknown-linux-musl
```

Expected files:

```text
target/x86_64-unknown-linux-musl/release/pandoras_box
target/x86_64-unknown-linux-musl/release/chimera
```

Inspect static linkage and smoke-test those exact files. Do not substitute a debug or separately rebuilt binary.

## Exact packaged-operator gates

The release workflow passes both exact release files to each fixture:

```sh
PANDORAS_BOX_LIVE_OPERATOR_PATH="$PWD/target/x86_64-unknown-linux-musl/release/pandoras_box" \
PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH="$PWD/target/x86_64-unknown-linux-musl/release/chimera" \
  scripts/run-unix-ssh-interop.sh

PANDORAS_BOX_LIVE_OPERATOR_PATH="$PWD/target/x86_64-unknown-linux-musl/release/pandoras_box" \
PANDORAS_BOX_LIVE_ALPINE_CHIMERA_UNIX_PATH="$PWD/target/x86_64-unknown-linux-musl/release/chimera" \
  scripts/run-alpine-ssh-interop.sh
```

Each script still runs its source integration fixture, then runs a complete mission through the exact operator with an exact SHA-256 payload manifest. It independently checks summary creation and remote workspace absence. Only after both gates pass may packaging generate a Linux `live_qualified` entry.

The generated bundle contains:

```text
bin/pandoras_box
release/chimera
release/payloads.json
LICENSE
provenance.json
```

`release/payloads.json` contains the exact Chimera SHA-256, product version, target key, and both gate identifiers. Packaging verifies the manifest digest against the copied payload before creating the deterministic archive. Checksums and Cargo metadata remain adjacent validated release assets, not tar members.

## Cross-platform evidence ladder

| Target | Required gate before `live_qualified` | Current automation status |
| --- | --- | --- |
| Linux x86_64 musl | Exact packaged operator + payload on pinned Ubuntu and Alpine SSH/SFTP fixtures | Defined in release workflow; must pass for each artifact |
| Windows x86_64 SSH/SFTP | Exact x86_64 operator/payload compile, package, OpenSSH transfer/execution, capability identity, cleanup, hostile-path, timeout, and wrong-auth tests | x86_64 source compile-check and optional lab script only; no package/live claim |
| Windows SMB | All Windows artifact gates plus packet/server evidence that every ADMIN$/IPC$/SCMR request is encrypted | Runtime fails before authentication with Smolder 0.4.0; no live claim |
| FreeBSD/BSD x86_64 | Exact native payload build/package plus SSH/SFTP live fixture and hostile-path cleanup | Optional external fixture only; no artifact/live claim |
| pfSense x86_64 | Exact compatible payload plus controlled pfSense fixture, package provenance, and cleanup evidence | Not available; no artifact/live claim |
| x86, aarch64, armv7 | Exact OS/architecture artifact and corresponding live gate | Contract only |

The optional Windows/BSD/mixed scripts are controlled-lab infrastructure. They must not be run against real CCDC targets, and unavailable infrastructure must be recorded as unavailable rather than converted into support evidence.

## Windows source check

The release workflow uses `x86_64-pc-windows-gnu` for source linting because the represented Windows payload key is x86_64:

```sh
rustup target add x86_64-pc-windows-gnu --toolchain 1.94.1
cargo clippy --locked --offline --workspace --all-targets \
  --target x86_64-pc-windows-gnu -- -D warnings
```

This is compile-only evidence. It does not qualify Windows SSH or SMB.

## Documentation boundary

Repository documentation and generated documentation are local-only. Packaging and release steps must not upload or include `README.md`, `docs/`, rendered documentation, or documentation archives.
