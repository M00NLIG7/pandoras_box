# Dependency audit record

## 2026-08-16 Smolder registry pin

After pinning the hardened Smolder release set to checksummed crates.io `0.4.0` packages, a freshly fetched 1,216-entry RustSec database and the source policy both passed without exceptions:

```sh
cargo audit -D warnings
cargo deny --locked check advisories sources
```

`cargo metadata --locked --offline` resolves `smolder`, `smolder-smb-core`, and `smolder-proto` only from the crates.io registry. There are no remaining advisory findings requiring a reachability exception, and `deny.toml` permits no Git source.

## 2026-08-14 remediation

The first-release dependency graph was refreshed after removing Chimera's legacy network/update modes and RustRC's non-SSH transports. Local verification against the available 1,216-entry RustSec database passed without an ignored advisory:

```sh
cargo audit --no-fetch --stale -D warnings
```

Release automation must run the same deny-warnings check against a freshly fetched advisory database. It must not add a blanket advisory waiver.

RustRC uses `russh` 0.62.6 with default features disabled and the `ring` backend. The vulnerable `rsa` crate is absent from the lockfile, and RustRC also rejects RSA private-key authentication at its own configuration boundary. The regression `rsa_private_keys_are_rejected_at_the_auth_boundary` guards that restriction. Ed25519 and ECDSA private keys, password authentication, and verification of enrolled server host keys remain supported.

Useful reachability checks:

```sh
cargo tree --locked -i rsa       # expected: no matching package
cargo tree --locked -i russh
cargo tree --locked -i rand@0.8.5 # expected: no matching package
```
