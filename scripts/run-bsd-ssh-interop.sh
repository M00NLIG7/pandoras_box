#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BSD_HOST="${PANDORAS_BOX_LIVE_BSD_SSH_HOST:-}"
BSD_PORT="${PANDORAS_BOX_LIVE_BSD_SSH_PORT:-22}"
BSD_USER="${PANDORAS_BOX_LIVE_BSD_SSH_USERNAME:-root}"
BSD_PASSWORD="${PANDORAS_BOX_LIVE_BSD_SSH_PASSWORD:-}"
ARTIFACT_ROOT="${PANDORAS_BOX_LIVE_BSD_SSH_ARTIFACT_ROOT:-$ROOT_DIR/target/live-bsd-ssh-artifacts}"
CHIMERA_PATH="${PANDORAS_BOX_LIVE_CHIMERA_BSD_PATH:-}"
BSD_BUILD_TARGET_DIR="${PANDORAS_BOX_BSD_BUILD_TARGET_DIR:-$ROOT_DIR/target/chimera-freebsd}"
BSD_TARGET="${PANDORAS_BOX_LIVE_BSD_TARGET:-x86_64-unknown-freebsd}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s is required for the BSD SSH interop harness\n' "$1" >&2
    exit 1
  fi
}

require_non_empty() {
  if [[ -z "$2" ]]; then
    printf '%s must be set for the BSD SSH interop harness\n' "$1" >&2
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

require_command cargo
require_command nc
require_command ssh-keyscan
require_command ssh-keygen

require_non_empty PANDORAS_BOX_LIVE_BSD_SSH_HOST "$BSD_HOST"
require_non_empty PANDORAS_BOX_LIVE_BSD_SSH_PASSWORD "$BSD_PASSWORD"

if [[ -z "$CHIMERA_PATH" ]]; then
  require_command cross
  CARGO_TARGET_DIR="$BSD_BUILD_TARGET_DIR" \
    cross build -j 1 -p chimera --bin chimera --target "$BSD_TARGET" --release
  CHIMERA_PATH="$BSD_BUILD_TARGET_DIR/$BSD_TARGET/release/chimera"
fi

CHIMERA_PATH="$(absolute_path "$CHIMERA_PATH")"

if [[ ! -f "$CHIMERA_PATH" ]]; then
  printf 'BSD Chimera binary not found at %s\n' "$CHIMERA_PATH" >&2
  exit 1
fi

nc -vz "$BSD_HOST" "$BSD_PORT"

if ! ssh-keyscan -p "$BSD_PORT" "$BSD_HOST" >/dev/null 2>&1; then
  printf 'BSD SSH target closed the SSH handshake on %s:%s\n' "$BSD_HOST" "$BSD_PORT" >&2
  exit 1
fi

known_hosts_path="$HOME/.ssh/known_hosts"
known_host_query="$BSD_HOST"
if [[ "$BSD_PORT" != "22" ]]; then
  known_host_query="[$BSD_HOST]:$BSD_PORT"
fi
if [[ ! -f "$known_hosts_path" ]] || ! ssh-keygen -F "$known_host_query" -f "$known_hosts_path" >/dev/null; then
  printf 'BSD SSH host key is not enrolled in %s for %s; verify it out of band before running this gate\n' "$known_hosts_path" "$known_host_query" >&2
  exit 1
fi

mkdir -p "$ARTIFACT_ROOT"

export PANDORAS_BOX_LIVE_BSD_SSH_HOST="$BSD_HOST"
export PANDORAS_BOX_LIVE_BSD_SSH_PORT="$BSD_PORT"
export PANDORAS_BOX_LIVE_BSD_SSH_USERNAME="$BSD_USER"
export PANDORAS_BOX_LIVE_BSD_SSH_PASSWORD="$BSD_PASSWORD"
export PANDORAS_BOX_LIVE_BSD_SSH_ARTIFACT_ROOT="$ARTIFACT_ROOT"
export PANDORAS_BOX_LIVE_CHIMERA_BSD_PATH="$CHIMERA_PATH"

cargo test --locked -p pandoras_box \
  --test live_unix_ssh \
  live_bsd_ssh_target_collects_inventory_and_cleans_up \
  -- --ignored --nocapture
