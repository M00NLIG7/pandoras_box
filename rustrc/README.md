# RustRC

RustRC is the SSH execution and SFTP transport adapter used by Pandora's Box. The first-release surface is intentionally limited to SSH; Winexe, WinRM, Telnet, embedded container runtimes, and remote-listener transfer helpers are not shipped.

## Security boundary

- Command execution and file transfer stay inside one authenticated SSH session.
- File upload and download use SFTP, including drive-aware Windows path candidates. Authentication and host-key failures remain typed terminal outcomes; Pandora never converts them into transport fallback.
- Connection and inactivity deadlines are separate from configurable command/transfer deadlines. Command output and downloads are byte-bounded while streaming.
- `SSHConfig::key`, `SSHConfig::agent_with_policy`, and `SSHConfig::password` require an enrolled `known_hosts` key by default.
- Pandora's named-profile adapter preflights private keys and exact SHA-256 fingerprints or selects one exact existing SSH-agent identity before opening a target connection. Missing/duplicate identities and agent signing errors fail terminally without trying another key.
- `HostKeyPolicy::DangerouslyAcceptUnknown` is an explicit first-contact escape hatch. It does not enroll or persist the key, and it still rejects a changed enrolled key.
- RustRC does not download tools or payloads during compilation.

## Example

Set `RUSTRC_SOCKET`, `RUSTRC_PASSWORD`, and optionally `RUSTRC_USERNAME`, enroll the server key in the operator's `known_hosts`, then run:

```sh
cargo run --locked -p rustrc --example ssh_client
```

The example reads the secret from the environment rather than a process argument. Pandora adds named runtime profiles for external environment/file secrets, pinned keys, and existing agents; see [`../docs/CREDENTIAL_PROFILES.md`](../docs/CREDENTIAL_PROFILES.md).

## Validation

```sh
cargo test --locked -p rustrc
cargo test --locked -p rustrc --doc
cargo clippy --locked -p rustrc --all-targets -- -D warnings
```

See [`PROVENANCE.md`](PROVENANCE.md) for the quarantined pre-release Winexe/runc findings and reintroduction requirements.

## License

RustRC source in this release is covered by the repository's MIT license.
