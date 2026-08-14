# RustRC

RustRC is the SSH execution and SFTP transport adapter used by Pandora's Box. The first-release surface is intentionally limited to SSH; Winexe, WinRM, Telnet, embedded container runtimes, and remote-listener transfer helpers are not shipped.

## Security boundary

- Command execution and file transfer stay inside one authenticated SSH session.
- File upload and download use SFTP. A failed Windows SFTP operation is returned to the caller so Pandora can apply its authenticated SMB fallback policy.
- `SSHConfig::key` and `SSHConfig::password` require an enrolled `known_hosts` key by default.
- `HostKeyPolicy::DangerouslyAcceptUnknown` is an explicit first-contact escape hatch. It does not enroll or persist the key, and it still rejects a changed enrolled key.
- RustRC does not download tools or payloads during compilation.

## Example

Set `RUSTRC_SOCKET`, `RUSTRC_PASSWORD`, and optionally `RUSTRC_USERNAME`, enroll the server key in the operator's `known_hosts`, then run:

```sh
cargo run --locked -p rustrc --example ssh_client
```

The example reads the secret from the environment rather than a process argument. Pandora provides stronger stdin/file-based secret input for operator use.

## Validation

```sh
cargo test --locked -p rustrc
cargo test --locked -p rustrc --doc
cargo clippy --locked -p rustrc --all-targets -- -D warnings
```

See [`PROVENANCE.md`](PROVENANCE.md) for the quarantined pre-release Winexe/runc findings and reintroduction requirements.

## License

RustRC source in this release is covered by the repository's MIT license.
