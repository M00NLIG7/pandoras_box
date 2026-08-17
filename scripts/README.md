# Live interop harnesses (test-only)

These scripts are controlled integration infrastructure, not operator commands. They create disposable Docker targets and artifacts under `target/`. Windows, BSD, and mixed harnesses may depend on or modify an explicitly configured local lab fixture. Never point them at production or real CCDC targets.

## Linux exact-artifact gates

```sh
PANDORAS_BOX_LIVE_OPERATOR_PATH="$PWD/target/x86_64-unknown-linux-musl/release/pandoras_box" \
PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH="$PWD/target/x86_64-unknown-linux-musl/release/chimera" \
  scripts/run-unix-ssh-interop.sh

PANDORAS_BOX_LIVE_OPERATOR_PATH="$PWD/target/x86_64-unknown-linux-musl/release/pandoras_box" \
PANDORAS_BOX_LIVE_ALPINE_CHIMERA_UNIX_PATH="$PWD/target/x86_64-unknown-linux-musl/release/chimera" \
  scripts/run-alpine-ssh-interop.sh
```

Each script creates an ephemeral credential, enrolls the disposable target key, runs its ignored source fixture, and—when the operator path is supplied—runs a complete mission with the exact operator and payload. It generates a temporary exact-digest manifest, verifies a summary, and independently rejects remote `.pandora-*` residue.

Supplying only a Chimera path exercises the source integration test but is not an exact packaged-operator gate. The release workflow supplies both exact release files.

## Optional evidence-only harnesses

- `run-windows-ssh-interop.sh`: x86_64 Windows/OpenSSH controlled fixture. No packaged/live qualification is currently claimed.
- `run-windows-smb-interop.sh`: controlled SMB fixture. Pandora intentionally fails before SMB authentication until its pinned remote-exec adapter can enforce encryption on every request.
- `run-bsd-ssh-interop.sh`: externally provisioned BSD fixture; no native packaged payload is currently defined.
- `run-mixed-live-concurrency-container.sh`: mixed Unix/Alpine/Windows/slow fixture; lab-only and platform-specific.
- `ensure-tiny11-openssh.sh`: Windows fixture bootstrap.

A skipped, unavailable, source-only, or emulated gate is not support evidence. Record the missing exact artifact or fixture rather than marking a payload `live_qualified`.

`tcp-port-proxy.rs` and `slow-ssh-target.rs` are narrow test support programs compiled under `target/`. No unauthenticated product proxy/listener is included.
