#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VM_NAME="${PANDORAS_BOX_WINDOWS_VM:-Tiny11}"
SMB_RULE_NAME="${PANDORAS_BOX_WINDOWS_SMB_NAT_RULE:-smb-local}"
SSH_PROBE_PORT="${PANDORAS_BOX_LIVE_WINDOWS_SMB_SSH_PROBE_PORT:-2223}"
SMB_PORT="${PANDORAS_BOX_LIVE_WINDOWS_SMB_PORT:-1445}"
WINDOWS_HOST="${PANDORAS_BOX_LIVE_WINDOWS_SMB_HOST:-127.0.0.1}"
WINDOWS_USER="${PANDORAS_BOX_LIVE_WINDOWS_SMB_USERNAME:-${SMOLDER_WINDOWS_USERNAME:-}}"
WINDOWS_PASSWORD="${PANDORAS_BOX_LIVE_WINDOWS_SMB_PASSWORD:-${SMOLDER_WINDOWS_PASSWORD:-}}"
SMB_EXEC_MODE="${PANDORAS_BOX_LIVE_WINDOWS_SMB_EXEC_MODE:-smbexec}"
ARTIFACT_ROOT="${PANDORAS_BOX_LIVE_WINDOWS_SMB_ARTIFACT_ROOT:-$ROOT_DIR/target/live-windows-smb-artifacts}"
CHIMERA_PATH="${PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH:-}"
WINDOWS_BUILD_TARGET_DIR="${PANDORAS_BOX_WINDOWS_BUILD_TARGET_DIR:-$ROOT_DIR/target/chimera-windows}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s is required for the Windows SMB interop harness\n' "$1" >&2
    exit 1
  fi
}

have_windows_gnu_toolchain() {
  command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 &&
    rustup target list --installed | grep -Fxq 'x86_64-pc-windows-gnu'
}

require_non_empty() {
  if [[ -z "$2" ]]; then
    printf '%s must be set for the Windows SMB interop harness\n' "$1" >&2
    exit 1
  fi
}

absolute_path() {
  local value="$1"
  if [[ "$value" = /* ]]; then
    printf '%s\n' "$value"
  else
    printf '%s/%s\n' "$ROOT_DIR" "$value"
  fi
}

ensure_nat_forward() {
  local rule_name="$1"
  local host_ip="$2"
  local host_port="$3"
  local guest_port="$4"
  local vm_info

  vm_info="$(VBoxManage showvminfo "$VM_NAME" --machinereadable)"
  if printf '%s\n' "$vm_info" | grep -Eq "^Forwarding\\([0-9]+\\)=\"[^\"]+,tcp,${host_ip},${host_port},,${guest_port}\"$"; then
    return 0
  fi

  if printf '%s\n' "$vm_info" | grep -Fq "\"${rule_name},tcp,${host_ip},${host_port},,${guest_port}\""; then
    return 0
  fi

  if printf '%s\n' "$vm_info" | grep -Fq "\"${rule_name},tcp,"; then
    printf 'Rebinding Tiny11 NAT forward %s to %s:%s -> %s\n' "$rule_name" "$host_ip" "$host_port" "$guest_port"
    VBoxManage controlvm "$VM_NAME" natpf1 delete "$rule_name"
  else
    printf 'Adding Tiny11 NAT forward %s (%s:%s -> %s)\n' "$rule_name" "$host_ip" "$host_port" "$guest_port"
  fi
  VBoxManage controlvm "$VM_NAME" natpf1 "${rule_name},tcp,${host_ip},${host_port},,${guest_port}"
}

require_command VBoxManage
require_command nc
require_command cargo

require_non_empty PANDORAS_BOX_LIVE_WINDOWS_SMB_USERNAME "$WINDOWS_USER"
require_non_empty PANDORAS_BOX_LIVE_WINDOWS_SMB_PASSWORD "$WINDOWS_PASSWORD"

vm_state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable | sed -n 's/^VMState=\"\([^\"]*\)\"$/\1/p')"
if [[ "$vm_state" != "running" ]]; then
  printf 'Tiny11 fixture %s must be running, current state is %s\n' "$VM_NAME" "${vm_state:-unknown}" >&2
  exit 1
fi

ensure_nat_forward "$SMB_RULE_NAME" "$WINDOWS_HOST" "$SMB_PORT" 445

nc -vz "$WINDOWS_HOST" "$SMB_PORT"

if nc -z "$WINDOWS_HOST" "$SSH_PROBE_PORT" >/dev/null 2>&1; then
  printf 'The configured SMB-only SSH probe port %s:%s is already open; choose a closed port.\n' "$WINDOWS_HOST" "$SSH_PROBE_PORT" >&2
  exit 1
fi

if [[ -z "$CHIMERA_PATH" ]]; then
  if have_windows_gnu_toolchain; then
    windows_linker="$(command -v x86_64-w64-mingw32-gcc)"
    CARGO_TARGET_DIR="$WINDOWS_BUILD_TARGET_DIR" \
      CC_x86_64_pc_windows_gnu="$windows_linker" \
      CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$windows_linker" \
      cargo build -j 1 -p chimera --bin chimera --target x86_64-pc-windows-gnu
  else
    require_command cross
    CARGO_TARGET_DIR="$WINDOWS_BUILD_TARGET_DIR" \
      cross build -j 1 -p chimera --bin chimera --target x86_64-pc-windows-gnu
  fi
  CHIMERA_PATH="$WINDOWS_BUILD_TARGET_DIR/x86_64-pc-windows-gnu/debug/chimera.exe"
fi

CHIMERA_PATH="$(absolute_path "$CHIMERA_PATH")"

if [[ ! -f "$CHIMERA_PATH" ]]; then
  printf 'Windows Chimera binary not found at %s\n' "$CHIMERA_PATH" >&2
  exit 1
fi

mkdir -p "$ARTIFACT_ROOT"

export PANDORAS_BOX_LIVE_WINDOWS_SMB_HOST="$WINDOWS_HOST"
export PANDORAS_BOX_LIVE_WINDOWS_SMB_SSH_PROBE_PORT="$SSH_PROBE_PORT"
export PANDORAS_BOX_LIVE_WINDOWS_SMB_PORT="$SMB_PORT"
export PANDORAS_BOX_LIVE_WINDOWS_SMB_USERNAME="$WINDOWS_USER"
export PANDORAS_BOX_LIVE_WINDOWS_SMB_PASSWORD="$WINDOWS_PASSWORD"
export PANDORAS_BOX_LIVE_WINDOWS_SMB_EXEC_MODE="$SMB_EXEC_MODE"
export PANDORAS_BOX_LIVE_WINDOWS_SMB_ARTIFACT_ROOT="$ARTIFACT_ROOT"
export PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH="$CHIMERA_PATH"
cargo test -p pandoras_box \
  --test live_windows_smb \
  live_windows_smb_target_collects_inventory_and_cleans_up \
  -- --ignored --nocapture
