# Building and validating Pandora's Box

These are the current repository-local build instructions. Historical commands under `docs/archive/` are intentionally non-authoritative.

## Pinned inputs

- Rust `1.94.1` from `rust-toolchain.toml`
- Cross `0.2.5`
- cargo-audit `0.22.1`
- cargo-deny `0.20.2`
- OCI build images by digest in `Cross.toml` and the live harness scripts
- Smolder revision `05cad6854d6044a1af659693ba202c3de5285d57` in `pandoras_box/Cargo.toml` and `Cargo.lock`

Do not replace exact versions or image/source revisions with floating tags in release validation.

## Tool setup

```sh
rustup toolchain install 1.94.1 \
  --profile minimal \
  --component clippy,rustfmt \
  --target x86_64-unknown-linux-musl,i686-pc-windows-gnu
cargo install cross --version 0.2.5 --locked
cargo install cargo-audit --version 0.22.1 --locked
cargo install cargo-deny --version 0.20.2 --locked
```

Docker or another Cross-compatible container engine is required for canonical cross-builds and live Linux fixtures.

## Clean-checkout dependency proof

Run this from a clean checkout with no sibling Smolder directory:

```sh
cargo fetch --locked
cargo metadata --locked --offline --format-version 1 >/dev/null
```

Cargo must resolve Smolder from the exact public Git revision. A local path override is not a release input.

## Mandatory source gates

```sh
cargo fmt --all -- --check
cargo clippy --locked --offline --workspace --all-targets -- -D warnings
cargo test --locked --offline --workspace
cargo test --locked --offline -p rustrc --doc
cargo check --locked --offline --workspace --all-targets \
  --target i686-pc-windows-gnu
```

The Windows command is a source compile-check only. It is not a live gate and does not make Windows a release target.

Refresh the advisory database over verified TLS, then run both dependency policies:

```sh
cargo audit -D warnings
cargo deny --locked check advisories sources
```

For an offline repeat using an already-fetched, sufficiently fresh advisory database:

```sh
cargo audit --no-fetch --stale -D warnings
```

`deny.toml` has no blanket advisory waiver. Any future exception requires specific reachability and remediation evidence.

## Canonical first-release binaries

```sh
cross build --locked --offline --release \
  -p pandoras_box --bin pandoras_box \
  --target x86_64-unknown-linux-musl
cross build --locked --offline --release \
  -p chimera --bin chimera \
  --target x86_64-unknown-linux-musl
```

Expected paths:

```text
target/x86_64-unknown-linux-musl/release/pandoras_box
target/x86_64-unknown-linux-musl/release/chimera
```

Inspect and smoke-test the exact files rather than a separately rebuilt copy:

```sh
file target/x86_64-unknown-linux-musl/release/pandoras_box \
     target/x86_64-unknown-linux-musl/release/chimera

for image in \
  ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea \
  alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
do
  docker run --rm --platform linux/amd64 \
    -v "$PWD:/workspace:ro" "$image" \
    /workspace/target/x86_64-unknown-linux-musl/release/pandoras_box --help
  docker run --rm --platform linux/amd64 \
    -v "$PWD:/workspace:ro" "$image" \
    /workspace/target/x86_64-unknown-linux-musl/release/chimera --help
done
```

## Mandatory exact-artifact interoperability

The same musl Chimera file selected above must pass both authenticated SSH/SFTP fixtures:

```sh
PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH="$PWD/target/x86_64-unknown-linux-musl/release/chimera" \
  scripts/run-unix-ssh-interop.sh

PANDORAS_BOX_LIVE_ALPINE_CHIMERA_UNIX_PATH="$PWD/target/x86_64-unknown-linux-musl/release/chimera" \
  scripts/run-alpine-ssh-interop.sh
```

The scripts create disposable local targets, generate ephemeral fixture credentials, enroll the fixture host key, run one exact ignored test, and remove their containers. See `scripts/README.md`. Do not run the Windows or mixed harness against anything except an explicitly authorized disposable lab.

## Packaging boundary

`.github/workflows/build.yml` validates before packaging and creates one `pandoras-box-<version>-x86_64-linux-musl.tar.gz` bundle with SHA-256 checksums, locked Cargo metadata, and machine-readable provenance. GNU/glibc binaries are not release inputs. Draft publication is a separate explicit input and must remain after every mandatory gate.

Repository documentation and generated documentation are local-only. Packaging and release steps must not upload or attach `README.md`, `docs/`, rendered documentation, or documentation archives.
