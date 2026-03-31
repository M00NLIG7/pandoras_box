#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VM_NAME="${PANDORAS_BOX_WINDOWS_VM:-Tiny11}"
SSH_RULE_NAME="${PANDORAS_BOX_WINDOWS_SSH_NAT_RULE:-ssh}"
SMB_RULE_NAME="${PANDORAS_BOX_WINDOWS_SMB_NAT_RULE:-smb445}"
COLLECTOR_RULE_NAME="${PANDORAS_BOX_WINDOWS_COLLECTOR_NAT_RULE:-pandora-collector}"
SSH_PORT="${PANDORAS_BOX_LIVE_WINDOWS_SSH_PORT:-2222}"
SMB_PORT="${PANDORAS_BOX_LIVE_WINDOWS_SMB_PORT:-445}"
COLLECTOR_PORT="${PANDORAS_BOX_LIVE_WINDOWS_COLLECTOR_PORT:-44372}"
WINDOWS_HOST="${PANDORAS_BOX_LIVE_WINDOWS_SSH_HOST:-127.0.0.1}"
WINDOWS_USER="${PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME:-${SMOLDER_WINDOWS_USERNAME:-}}"
WINDOWS_PASSWORD="${PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD:-${SMOLDER_WINDOWS_PASSWORD:-}}"
ARTIFACT_ROOT="${PANDORAS_BOX_LIVE_WINDOWS_SSH_ARTIFACT_ROOT:-$ROOT_DIR/target/live-windows-ssh-artifacts}"
CHIMERA_PATH="${PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH:-}"
WINDOWS_BUILD_TARGET_DIR="${PANDORAS_BOX_WINDOWS_BUILD_TARGET_DIR:-$ROOT_DIR/target/chimera-windows}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s is required for the Windows SSH interop harness\n' "$1" >&2
    exit 1
  fi
}

have_windows_gnu_toolchain() {
  command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 &&
    rustup target list --installed | grep -Fxq 'x86_64-pc-windows-gnu'
}

require_non_empty() {
  if [[ -z "$2" ]]; then
    printf '%s must be set for the Windows SSH interop harness\n' "$1" >&2
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
require_command ssh-keyscan

require_non_empty PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME "$WINDOWS_USER"
require_non_empty PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD "$WINDOWS_PASSWORD"

vm_state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable | sed -n 's/^VMState=\"\([^\"]*\)\"$/\1/p')"
if [[ "$vm_state" != "running" ]]; then
  printf 'Tiny11 fixture %s must be running, current state is %s\n' "$VM_NAME" "${vm_state:-unknown}" >&2
  exit 1
fi

ensure_nat_forward "$SSH_RULE_NAME" "$WINDOWS_HOST" "$SSH_PORT" 22
ensure_nat_forward "$SMB_RULE_NAME" "$WINDOWS_HOST" "$SMB_PORT" 445
ensure_nat_forward "$COLLECTOR_RULE_NAME" "$WINDOWS_HOST" "$COLLECTOR_PORT" "$COLLECTOR_PORT"

nc -vz "$WINDOWS_HOST" "$SSH_PORT"
nc -vz "$WINDOWS_HOST" "$SMB_PORT"
nc -vz "$WINDOWS_HOST" "$COLLECTOR_PORT" || true

if ! ssh-keyscan -p "$SSH_PORT" "$WINDOWS_HOST" >/dev/null 2>&1; then
  printf 'Tiny11 closed the SSH handshake on %s:%s\n' "$WINDOWS_HOST" "$SSH_PORT" >&2
  service_probe="$(
    VBoxManage guestcontrol "$VM_NAME" run \
      --exe "C:\\Windows\\System32\\cmd.exe" \
      --username "$WINDOWS_USER" \
      --password "$WINDOWS_PASSWORD" \
      -- cmd.exe /c sc query sshd 2>&1 || true
  )"
  if printf '%s\n' "$service_probe" | grep -Fq 'FAILED 1060'; then
    printf 'OpenSSH Server is not installed in the Tiny11 fixture (sc query sshd returned 1060).\n' >&2
    printf 'Bootstrapping OpenSSH through Smolder psexec.\n' >&2
    PANDORAS_BOX_WINDOWS_VM="$VM_NAME" \
    PANDORAS_BOX_LIVE_WINDOWS_SSH_HOST="$WINDOWS_HOST" \
    PANDORAS_BOX_LIVE_WINDOWS_SSH_PORT="$SSH_PORT" \
    PANDORAS_BOX_LIVE_WINDOWS_SMB_PORT="$SMB_PORT" \
    PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME="$WINDOWS_USER" \
    PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD="$WINDOWS_PASSWORD" \
    bash "$ROOT_DIR/scripts/ensure-tiny11-openssh.sh"
  else
    printf 'sshd service probe output:\n%s\n' "$service_probe" >&2
    exit 1
  fi

  if ! ssh-keyscan -p "$SSH_PORT" "$WINDOWS_HOST" >/dev/null 2>&1; then
    printf 'Tiny11 still does not answer SSH handshakes on %s:%s after bootstrap.\n' "$WINDOWS_HOST" "$SSH_PORT" >&2
    exit 1
  fi
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

export PANDORAS_BOX_LIVE_WINDOWS_SSH_HOST="$WINDOWS_HOST"
export PANDORAS_BOX_LIVE_WINDOWS_SSH_PORT="$SSH_PORT"
export PANDORAS_BOX_LIVE_WINDOWS_SMB_PORT="$SMB_PORT"
export PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME="$WINDOWS_USER"
export PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD="$WINDOWS_PASSWORD"
export PANDORAS_BOX_LIVE_WINDOWS_SSH_ARTIFACT_ROOT="$ARTIFACT_ROOT"
export PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH="$CHIMERA_PATH"

cargo test -p pandoras_box \
  --test live_windows_ssh \
  live_windows_ssh_target_collects_inventory_and_cleans_up \
  -- --ignored --nocapture
