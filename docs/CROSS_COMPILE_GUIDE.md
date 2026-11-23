# Cross-Compilation Guide for Chimera

This guide explains how to build chimera for both Linux and Windows using `cross`.

## Quick Start

**Delete release and rebuild everything:**
```bash
./scripts/build_and_release_chimera.sh
```

That's it! The script handles everything.

---

## Manual Steps (if you prefer)

### 1. Install cross

```bash
cargo install cross --git https://github.com/cross-rs/cross
```

### 2. Delete Existing Release

```bash
# Delete the release
gh release delete CCDC-2024-2025 --yes

# Delete the tag (local and remote)
git tag -d CCDC-2024-2025
git push origin :refs/tags/CCDC-2024-2025
```

### 3. Build for Linux

```bash
cd chimera
cross build --release --target x86_64-unknown-linux-gnu --bin chimera
```

**Output**: `target/x86_64-unknown-linux-gnu/release/chimera`

### 4. Build for Windows

```bash
cross build --release --target x86_64-pc-windows-gnu --bin chimera
```

**Output**: `target/x86_64-pc-windows-gnu/release/chimera.exe`

### 5. Verify Binaries

```bash
file target/x86_64-unknown-linux-gnu/release/chimera
file target/x86_64-pc-windows-gnu/release/chimera.exe

ls -lh target/x86_64-unknown-linux-gnu/release/chimera
ls -lh target/x86_64-pc-windows-gnu/release/chimera.exe
```

### 6. Create Release

```bash
# Copy binaries
mkdir -p release
cp target/x86_64-unknown-linux-gnu/release/chimera release/chimera-linux
cp target/x86_64-pc-windows-gnu/release/chimera.exe release/chimera.exe

# Create GitHub release
gh release create CCDC-2024-2025 \
  release/chimera-linux \
  release/chimera.exe \
  --title "Pandora's Box - Fixed Chimera" \
  --notes "29 bugs fixed. See release notes for details."
```

---

## Update Pandoras_Box to Use Your Release

After creating the release, update the URLs in `pandoras_box/src/orchestrator.rs`:

```rust
// Change from:
static CHIMERA_URL_UNIX: &str = "https://github.com/CSUSB-CISO/csusb-ccdc/releases/download/CCDC-2024-2025/chimera";
static CHIMERA_URL_WIN: &str = "https://github.com/CSUSB-CISO/csusb-ccdc/releases/download/CCDC-2024-2025/chimera.exe";

// To (replace M00NLIG7 with your GitHub username):
static CHIMERA_URL_UNIX: &str = "https://github.com/M00NLIG7/pandoras_box/releases/download/CCDC-2024-2025/chimera-linux";
static CHIMERA_URL_WIN: &str = "https://github.com/M00NLIG7/pandoras_box/releases/download/CCDC-2024-2025/chimera.exe";
```

Then rebuild pandoras_box:
```bash
cargo build --release --bin pandoras_box
```

---

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

## Changing the Password Before Building

### Option 1: Environment Variable

```bash
# Set password, then build
APP_PASSWORD="MySecureP@ss!" cross build --release --target x86_64-unknown-linux-gnu --bin chimera
APP_PASSWORD="MySecureP@ss!" cross build --release --target x86_64-pc-windows-gnu --bin chimera
```

### Option 2: Edit .password File

```bash
echo "MySecureP@ss!" > chimera/.password
cross build --release --target x86_64-unknown-linux-gnu --bin chimera
cross build --release --target x86_64-pc-windows-gnu --bin chimera
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

### Test Password Change

```bash
# Linux (in a VM/container)
./chimera-linux all -m 62

# Check if password changed
# Should be: Sudo!!UrM0m<last_octet * 62>

# Windows (in a VM)
chimera.exe all -m 62
```

---

## Alternative: Using GitHub Actions

For automated builds, create `.github/workflows/build-chimera.yml`:

```yaml
name: Build Chimera

on:
  push:
    tags:
      - 'CCDC-*'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      - name: Install cross
        run: cargo install cross --git https://github.com/cross-rs/cross

      - name: Build Linux
        run: cd chimera && cross build --release --target x86_64-unknown-linux-gnu --bin chimera

      - name: Build Windows
        run: cd chimera && cross build --release --target x86_64-pc-windows-gnu --bin chimera

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            target/x86_64-unknown-linux-gnu/release/chimera
            target/x86_64-pc-windows-gnu/release/chimera.exe
```

---

## Quick Reference

```bash
# Delete and rebuild everything
./scripts/build_and_release_chimera.sh

# Manual builds
cross build --release --target x86_64-unknown-linux-gnu --bin chimera
cross build --release --target x86_64-pc-windows-gnu --bin chimera

# Create release
gh release create CCDC-2024-2025 \
  target/x86_64-unknown-linux-gnu/release/chimera \
  target/x86_64-pc-windows-gnu/release/chimera.exe \
  --title "Fixed Chimera" \
  --notes "29 bugs fixed"

# Update orchestrator.rs URLs and rebuild
cargo build --release --bin pandoras_box
```
