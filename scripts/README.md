# Live interop harnesses (test-only)

These scripts are integration-test infrastructure, not product commands or operator tooling. They create disposable Docker targets and write artifacts under `target/`. The Windows and mixed harnesses are local-lab-only: they can add VirtualBox NAT forwards, start or resume the configured Tiny11 fixture, and install/configure OpenSSH inside that fixture. Never point them at a production host.

## Linux release gates

```sh
scripts/run-unix-ssh-interop.sh
scripts/run-alpine-ssh-interop.sh
```

Each script generates an ephemeral test password unless its documented `PANDORAS_BOX_LIVE_*_PASSWORD` environment variable is already set. The password is passed to Docker BuildKit through a protected secret file, not a command argument. Both harnesses enroll the fixture's Ed25519 host key before running the one exact ignored test selected by the script.

Set `PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH` (or the Alpine-specific `PANDORAS_BOX_LIVE_ALPINE_CHIMERA_UNIX_PATH`) to test an already-built artifact. The path must be inside this checkout because the runner mounts the checkout read-only by path. If no path is supplied, the script builds a local debug fixture with locked Cargo inputs.

## Lab-only optional gates

- `run-windows-ssh-interop.sh`: requires a running Tiny11/OpenSSH fixture and an explicitly supplied credential.
- `run-windows-smb-interop.sh`: requires a running Tiny11 SMB fixture and an explicitly supplied credential.
- `run-bsd-ssh-interop.sh`: requires an externally provisioned BSD fixture.
- `run-mixed-live-concurrency-container.sh`: combines Unix, Alpine, a slow TCP fixture, and Tiny11. It is intentionally macOS/VirtualBox-specific and may start or resume the test VM.
- `ensure-tiny11-openssh.sh`: fixture bootstrap used by the Windows harness; it refuses Smolder helpers that cannot read a password from a protected file.

A skipped or unavailable lab gate is not release evidence. Record it as unavailable and do not claim that platform. The first release workflow publishes only the Linux target that must pass both Linux harnesses.

`tcp-port-proxy.rs` and `slow-ssh-target.rs` are narrow harness support programs compiled into `target/`. No unauthenticated Node proxy is included.
