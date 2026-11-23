# Contributing

## Check Chimera's inventory filename

From the project root, run this in a POSIX shell with Rust installed:

```sh
(
    set -eu
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/chimera-check.XXXXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    rustc --test chimera/src/inventory_path.rs -o "$tmp/check"
    "$tmp/check"
)
```

Expect two passing tests: the default directory gets `inventory.json`, and a
custom directory gets `<host>.json`. The checks use example paths and a supplied
host name without creating inventory files or looking up the machine's name.
Only the filename module is compiled; Cargo, the application build script,
password files and network access are not needed.
