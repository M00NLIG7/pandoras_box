#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VM_NAME="${PANDORAS_BOX_WINDOWS_VM:-Tiny11}"
SMB_RULE_NAME="${PANDORAS_BOX_WINDOWS_SMB_NAT_RULE:-smb-local}"
COLLECTOR_RULE_NAME="${PANDORAS_BOX_WINDOWS_COLLECTOR_NAT_RULE:-pandora-collector}"
SSH_PROBE_PORT="${PANDORAS_BOX_LIVE_WINDOWS_SMB_SSH_PROBE_PORT:-2223}"
SMB_PORT="${PANDORAS_BOX_LIVE_WINDOWS_SMB_PORT:-1445}"
COLLECTOR_PORT="${PANDORAS_BOX_LIVE_WINDOWS_COLLECTOR_PORT:-44372}"
WINDOWS_HOST="${PANDORAS_BOX_LIVE_WINDOWS_SMB_HOST:-127.0.0.1}"
WINDOWS_USER="${PANDORAS_BOX_LIVE_WINDOWS_SMB_USERNAME:-${SMOLDER_WINDOWS_USERNAME:-}}"
WINDOWS_PASSWORD="${PANDORAS_BOX_LIVE_WINDOWS_SMB_PASSWORD:-${SMOLDER_WINDOWS_PASSWORD:-}}"
SMB_EXEC_MODE="${PANDORAS_BOX_LIVE_WINDOWS_SMB_EXEC_MODE:-smbexec}"
ROTATION_MAGIC="${PANDORAS_BOX_LIVE_PASSWORD_ROTATION_MAGIC:-}"
ARTIFACT_ROOT="${PANDORAS_BOX_LIVE_WINDOWS_SMB_ARTIFACT_ROOT:-$ROOT_DIR/target/live-windows-smb-artifacts}"
CHIMERA_PATH="${PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH:-}"
WINDOWS_BUILD_TARGET_DIR="${PANDORAS_BOX_WINDOWS_BUILD_TARGET_DIR:-$ROOT_DIR/target/chimera-windows}"
SMOLDER_ROOT="${PANDORAS_BOX_SMOLDER_ROOT:-$ROOT_DIR/../smolder}"
SMOLDER_BINARY="${PANDORAS_BOX_SMOLDER_BINARY:-$SMOLDER_ROOT/target/debug/smolder}"
ROTATED_PASSWORD=""

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

guestcontrol_with_credentials() {
  local username="$1"
  local password="$2"
  local remote_command="$3"

  VBoxManage guestcontrol "$VM_NAME" run \
    --exe "C:\\Windows\\System32\\cmd.exe" \
    --username "$username" \
    --password "$password" \
    -- cmd.exe /c "$remote_command"
}

smolder_smbexec() {
  local username="$1"
  local password="$2"
  local remote_command="$3"

  if [[ -x "$SMOLDER_BINARY" ]]; then
    "$SMOLDER_BINARY" smbexec "smb://$WINDOWS_HOST:$SMB_PORT" \
      --username "$username" \
      --password "$password" \
      --command "$remote_command"
    return 0
  fi

  (
    cd "$SMOLDER_ROOT"
    cargo run -p smolder -- \
      smbexec "smb://$WINDOWS_HOST:$SMB_PORT" \
      --username "$username" \
      --password "$password" \
      --command "$remote_command"
  )
}

guest_ipv4() {
  local output
  local candidate

  output="$(
    guestcontrol_with_credentials \
      "$WINDOWS_USER" \
      "$WINDOWS_PASSWORD" \
      'wmic nicconfig where IPEnabled=true get IPAddress /value' 2>/dev/null | tr -d '\r'
  )"
  candidate="$(
    printf '%s\n' "$output" |
      grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' |
      grep -v '^127\.' |
      grep -v '^169\.254\.' |
      head -n 1
  )"
  if [[ -n "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  output="$(
    guestcontrol_with_credentials \
      "$WINDOWS_USER" \
      "$WINDOWS_PASSWORD" \
      'ipconfig' 2>/dev/null | tr -d '\r'
  )"
  printf '%s\n' "$output" |
    sed -n 's/.*IPv4 Address[. ]*: //p' |
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' |
    grep -v '^127\.' |
    grep -v '^169\.254\.' |
    head -n 1
}

compute_rotated_password() {
  local guest_ip
  local last_octet
  local base_password

  if [[ ! -f "$ROOT_DIR/.password" ]]; then
    printf '.password is required to verify and restore Windows password rotation\n' >&2
    exit 1
  fi

  guest_ip="$(guest_ipv4)"
  if [[ -z "$guest_ip" ]]; then
    printf 'Failed to determine the Tiny11 guest IPv4 address for password rotation\n' >&2
    exit 1
  fi

  last_octet="${guest_ip##*.}"
  base_password="$(tr -d '\r\n' < "$ROOT_DIR/.password")"
  printf '%s%s\n' "$base_password" "$(( last_octet * ROTATION_MAGIC ))"
}

restore_rotated_password() {
  local rotated_password="$1"

  set +e
  smolder_smbexec \
    "$WINDOWS_USER" \
    "$rotated_password" \
    "cmd.exe /c net user $WINDOWS_USER $WINDOWS_PASSWORD" >/dev/null 2>&1
  set -e
}

restore_rotation_state() {
  if [[ -n "$ROTATED_PASSWORD" ]]; then
    restore_rotated_password "$ROTATED_PASSWORD" || true
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

if [[ -n "$ROTATION_MAGIC" && ! "$ROTATION_MAGIC" =~ ^[0-9]+$ ]]; then
  printf 'PANDORAS_BOX_LIVE_PASSWORD_ROTATION_MAGIC must be a positive integer\n' >&2
  exit 1
fi

vm_state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable | sed -n 's/^VMState=\"\([^\"]*\)\"$/\1/p')"
if [[ "$vm_state" != "running" ]]; then
  printf 'Tiny11 fixture %s must be running, current state is %s\n' "$VM_NAME" "${vm_state:-unknown}" >&2
  exit 1
fi

if [[ -n "$ROTATION_MAGIC" ]]; then
  ROTATED_PASSWORD="$(compute_rotated_password)"
  trap restore_rotation_state EXIT
fi

ensure_nat_forward "$SMB_RULE_NAME" "$WINDOWS_HOST" "$SMB_PORT" 445
ensure_nat_forward "$COLLECTOR_RULE_NAME" "$WINDOWS_HOST" "$COLLECTOR_PORT" "$COLLECTOR_PORT"

nc -vz "$WINDOWS_HOST" "$SMB_PORT"
nc -vz "$WINDOWS_HOST" "$COLLECTOR_PORT" || true

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
if [[ -n "$ROTATION_MAGIC" ]]; then
  export PANDORAS_BOX_LIVE_PASSWORD_ROTATION_MAGIC="$ROTATION_MAGIC"
fi

cargo test -p pandoras_box \
  --test live_windows_smb \
  live_windows_smb_target_collects_inventory_and_cleans_up \
  -- --ignored --nocapture
