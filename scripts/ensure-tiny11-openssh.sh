#!/usr/bin/env bash
set -euo pipefail

VM_NAME="${PANDORAS_BOX_WINDOWS_VM:-Tiny11}"
SSH_HOST="${PANDORAS_BOX_LIVE_WINDOWS_SSH_HOST:-127.0.0.1}"
SSH_PORT="${PANDORAS_BOX_LIVE_WINDOWS_SSH_PORT:-2222}"
SMB_PORT="${PANDORAS_BOX_LIVE_WINDOWS_SMB_PORT:-445}"
WINDOWS_USER="${PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME:-${SMOLDER_WINDOWS_USERNAME:-}}"
WINDOWS_PASSWORD="${PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD:-${SMOLDER_WINDOWS_PASSWORD:-}}"
PSEXEC_BIN="${PANDORAS_BOX_SMOLDER_PSEXEC_BIN:-/Users/cmagana/Projects/smolder/target/debug/psexec}"
OPENSSH_MSI_URL="${PANDORAS_BOX_OPENSSH_MSI_URL:-https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.0.0.0p2-Preview/OpenSSH-Win64-v10.0.0.0.msi}"
OPENSSH_MSI_SHA256="${PANDORAS_BOX_OPENSSH_MSI_SHA256:-ddec9c53864280759cf9f74791cefd387100e3946aa849a1c138a4ed1b96b7d9}"
OPENSSH_MSI_PATH='C:\Windows\Temp\OpenSSH-Win64-v10.0.0.0.msi'
OPENSSH_LOG_PATH='C:\Windows\Temp\OpenSSH-install.log'

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s is required for the Tiny11 OpenSSH bootstrap\n' "$1" >&2
    exit 1
  fi
}

require_non_empty() {
  if [[ -z "$2" ]]; then
    printf '%s must be set for the Tiny11 OpenSSH bootstrap\n' "$1" >&2
    exit 1
  fi
}

run_remote() {
  local remote_command="$1"
  local timeout="${2:-60s}"

  "$PSEXEC_BIN" "smb://${SSH_HOST}:${SMB_PORT}" \
    --command "$remote_command" \
    --timeout "$timeout" \
    --username "$WINDOWS_USER" \
    --password "$WINDOWS_PASSWORD"
}

capture_remote() {
  local remote_command="$1"
  local timeout="${2:-60s}"

  set +e
  REMOTE_OUTPUT="$(run_remote "$remote_command" "$timeout" 2>&1 | tr -d '\r')"
  REMOTE_STATUS=$?
  set -e
}

wait_for_ssh() {
  local attempts="${1:-20}"
  local delay_seconds="${2:-2}"

  for _ in $(seq 1 "$attempts"); do
    if ssh-keyscan -p "$SSH_PORT" "$SSH_HOST" >/dev/null 2>&1; then
      printf 'Tiny11 OpenSSH handshake is now live on %s:%s\n' "$SSH_HOST" "$SSH_PORT"
      return 0
    fi
    sleep "$delay_seconds"
  done

  return 1
}

require_command ssh-keyscan
require_non_empty PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME "$WINDOWS_USER"
require_non_empty PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD "$WINDOWS_PASSWORD"

if [[ ! -x "$PSEXEC_BIN" ]]; then
  printf 'Smolder psexec binary not found at %s\n' "$PSEXEC_BIN" >&2
  exit 1
fi

if ssh-keyscan -p "$SSH_PORT" "$SSH_HOST" >/dev/null 2>&1; then
  printf 'Tiny11 already responds to SSH handshakes on %s:%s\n' "$SSH_HOST" "$SSH_PORT"
  exit 0
fi

capture_remote 'cmd.exe /c sc query sshd'
if [[ "$REMOTE_STATUS" -eq 0 ]]; then
  printf 'Tiny11 already has sshd installed; ensuring the service is running.\n'
  run_remote 'cmd.exe /c sc config sshd start= auto' >/dev/null || true
  run_remote 'cmd.exe /c sc start sshd' >/dev/null || true
  if wait_for_ssh; then
    exit 0
  fi
  printf 'sshd exists but the SSH handshake is still unavailable.\n' >&2
  printf '%s\n' "$REMOTE_OUTPUT" >&2
  exit 1
fi

if ! grep -Fq 'FAILED 1060' <<<"$REMOTE_OUTPUT"; then
  printf 'Unexpected sshd service probe failure:\n%s\n' "$REMOTE_OUTPUT" >&2
  exit 1
fi

printf 'Tiny11 is missing sshd; installing OpenSSH Server via Smolder psexec.\n'

run_remote "cmd.exe /c curl.exe -kL -o ${OPENSSH_MSI_PATH} ${OPENSSH_MSI_URL}" '300s'

capture_remote "cmd.exe /c certutil -hashfile ${OPENSSH_MSI_PATH} SHA256"
if [[ "$REMOTE_STATUS" -ne 0 ]]; then
  printf 'Failed to verify the downloaded OpenSSH MSI:\n%s\n' "$REMOTE_OUTPUT" >&2
  exit 1
fi
if ! grep -Fqi "$OPENSSH_MSI_SHA256" <<<"$REMOTE_OUTPUT"; then
  printf 'OpenSSH MSI hash mismatch. Expected %s but got:\n%s\n' "$OPENSSH_MSI_SHA256" "$REMOTE_OUTPUT" >&2
  exit 1
fi

run_remote "cmd.exe /c msiexec /i ${OPENSSH_MSI_PATH} /qn /l*v ${OPENSSH_LOG_PATH} ADDLOCAL=Server" '300s'

capture_remote 'cmd.exe /c sc query sshd'
if [[ "$REMOTE_STATUS" -ne 0 ]]; then
  printf 'OpenSSH MSI completed but sshd is still missing.\n' >&2
  printf 'sc query sshd output:\n%s\n' "$REMOTE_OUTPUT" >&2
  capture_remote "cmd.exe /c type ${OPENSSH_LOG_PATH}" '60s'
  if [[ -n "${REMOTE_OUTPUT:-}" ]]; then
    printf 'MSI log:\n%s\n' "$REMOTE_OUTPUT" >&2
  fi
  exit 1
fi

run_remote 'cmd.exe /c sc config sshd start= auto' >/dev/null || true
run_remote 'cmd.exe /c sc start sshd' >/dev/null || true

if wait_for_ssh; then
  exit 0
fi

printf 'Tiny11 OpenSSH install completed, but the SSH handshake is still unavailable.\n' >&2
capture_remote 'cmd.exe /c sc query sshd'
printf 'sc query sshd output:\n%s\n' "$REMOTE_OUTPUT" >&2
capture_remote "cmd.exe /c type ${OPENSSH_LOG_PATH}" '60s'
if [[ -n "${REMOTE_OUTPUT:-}" ]]; then
  printf 'MSI log:\n%s\n' "$REMOTE_OUTPUT" >&2
fi
exit 1
