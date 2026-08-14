> [!WARNING]
> **Historical build archive — do not use as current build instructions.**
> Recovered from dropped pre-release history on 2026-08-14. Its targets, dependency assumptions, scripts, and references to deleted modules are superseded and have not been revalidated. See [`../BUILDING.md`](../BUILDING.md) for tested, locked commands.

# Cross-Compilation Guide for Chimera

This guide explains how to build chimera for both Linux and Windows using `cross`.

## Archival scope

The original document also contained destructive tag/release commands, floating tool installation, obsolete download URLs, removed credential-rotation instructions, and references to deleted orchestration modules. Those executable sections are intentionally omitted from the current tree. The raw historical object remains protected by the local rescue ref `refs/rescue/pandora-dropped-conventions`; it is not a release input.

## How Cross Works

**cross** is a zero-setup cross-compilation tool that uses Docker containers with pre-configured toolchains.

### Supported Targets

Common targets for CCDC:
```bash
# Linux
x86_64-unknown-linux-gnu       # Standard Linux x86_64
x86_64-unknown-linux-musl      # Static Linux binary (no glibc dependency)
aarch64-unknown-linux-gnu      # ARM64 Linux (for Raspberry Pi, etc.)

# Windows
x86_64-pc-windows-gnu          # Windows x86_64 (MinGW)
x86_64-pc-windows-msvc         # Windows x86_64 (MSVC - requires license)

# BSD
x86_64-unknown-freebsd         # FreeBSD x86_64
```

### Build for Multiple Targets

```bash
# Build for all common targets
for target in \
    x86_64-unknown-linux-gnu \
    x86_64-pc-windows-gnu \
    x86_64-unknown-freebsd; do
  echo "Building for $target..."
  cross build --release --target $target --bin chimera
done
```

---

## Troubleshooting

### Issue: "cross: command not found"

**Solution**: Install cross
```bash
cargo install cross --git https://github.com/cross-rs/cross
```

### Issue: Docker not running

**Error**: `error: failed to execute docker`

**Solution**: Start Docker
```bash
# Linux
sudo systemctl start docker

# macOS
open -a Docker

# Windows
# Start Docker Desktop
```

### Issue: Permission denied on Docker socket

**Solution**: Add user to docker group
```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Issue: Windows build fails with "windows-sys" errors

**Solution**: This is expected if you have Windows-specific dependencies. Cross should handle this automatically, but if not:

```bash
# Try building with musl instead (static binary)
cross build --release --target x86_64-unknown-linux-musl --bin chimera
```

### Issue: Binary won't run on target system

**Check architecture**:
```bash
# On target Linux system
uname -m
# Should show: x86_64

# On target Windows system
wmic cpu get architecture
# Should show: 9 (x64)
```

---

## Testing the Binaries

### Linux Binary

```bash
# Check file type
file release/chimera-linux
# Should show: ELF 64-bit LSB executable, x86-64

# Test on Linux system
chmod +x release/chimera-linux
./release/chimera-linux --help
```

### Windows Binary

```bash
# Check file type
file release/chimera.exe
# Should show: PE32+ executable (console) x86-64, for MS Windows

# Test on Windows system
chimera.exe --help
```

### Removed credential test

The original credential-rotation test described removed first-release behavior and included a deterministic credential pattern. It is deliberately not reproduced here.
