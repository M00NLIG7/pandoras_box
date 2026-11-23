#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIX_IMAGE_NAME="pandoras-box-unix-ssh-interop:local"
UNIX_CONTAINER_NAME="pandoras-box-mixed-unix-target"
ALPINE_IMAGE_NAME="pandoras-box-alpine-ssh-interop:local"
ALPINE_CONTAINER_NAME="pandoras-box-mixed-alpine-target"
SLOW_CONTAINER_NAME="pandoras-box-mixed-slow-target"
UNIX_DOCKERFILE_DIR="$ROOT_DIR/pandoras_box/tests/fixtures/unix_ssh_target"
ALPINE_DOCKERFILE_DIR="$ROOT_DIR/pandoras_box/tests/fixtures/alpine_ssh_target"
LIVE_ARTIFACT_DIR="$ROOT_DIR/target/live-mixed-concurrency-artifacts/$(date +%s%N)"
NETWORK_NAME="pandoras-box-mixed-live-$(date +%s%N)"
MIXED_PASSWORD="${PANDORAS_BOX_LIVE_MIXED_PASSWORD:-}"
SSH_PORT="${PANDORAS_BOX_LIVE_MIXED_SSH_PORT:-4222}"
SMB_PORT="${PANDORAS_BOX_LIVE_MIXED_SMB_PORT:-4445}"
HOST_TIMEOUT_SECS="${PANDORAS_BOX_LIVE_MIXED_HOST_TIMEOUT_SECS:-120}"
CONNECT_TIMEOUT_SECS="${PANDORAS_BOX_LIVE_MIXED_CONNECT_TIMEOUT_SECS:-25}"
WINDOWS_LOCAL_SSH_PORT="${PANDORAS_BOX_LIVE_MIXED_WINDOWS_LOCAL_SSH_PORT:-3222}"
WINDOWS_LOCAL_SMB_PORT="${PANDORAS_BOX_LIVE_MIXED_WINDOWS_LOCAL_SMB_PORT:-3445}"
WINDOWS_BUILD_TARGET_DIR="${PANDORAS_BOX_WINDOWS_BUILD_TARGET_DIR:-$ROOT_DIR/target/chimera-windows}"
WINDOWS_CHIMERA_PATH="${PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH:-}"
LINUX_CHIMERA_PATH="${PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH:-$ROOT_DIR/target/x86_64-unknown-linux-musl/debug/chimera}"
LINUX_TEST_BINARY="${PANDORAS_BOX_LIVE_MIXED_TEST_BINARY:-}"
LINUX_TEST_TARGET_DIR="${PANDORAS_BOX_LIVE_MIXED_LINUX_TARGET_DIR:-$ROOT_DIR/target/live-mixed-linux}"
LINUX_TEST_RUSTFLAGS="${PANDORAS_BOX_LIVE_MIXED_LINUX_RUSTFLAGS:--C debuginfo=0 -C codegen-units=1}"
RUNNER_LINUX_TARGET="${PANDORAS_BOX_LIVE_MIXED_RUNNER_TARGET:-aarch64-unknown-linux-gnu}"
RUNNER_IMAGE="${PANDORAS_BOX_LIVE_MIXED_RUNNER_IMAGE:-ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea}"
RUNNER_BUILD_IMAGE="${PANDORAS_BOX_LIVE_MIXED_RUNNER_BUILD_IMAGE:-rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55}"
ALPINE_UTILITY_IMAGE="alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d"
VM_NAME="${PANDORAS_BOX_WINDOWS_VM:-Tiny11}"
LOCAL_SSH_RULE_NAME="${PANDORAS_BOX_WINDOWS_LOCAL_SSH_NAT_RULE:-mixed-ssh-local}"
LOCAL_SMB_RULE_NAME="${PANDORAS_BOX_WINDOWS_LOCAL_SMB_NAT_RULE:-mixed-smb-local}"
WINDOWS_SSH_USER="${PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME:-${SMOLDER_WINDOWS_USERNAME:-}}"
WINDOWS_SSH_PASSWORD="${PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD:-${SMOLDER_WINDOWS_PASSWORD:-}}"
WINDOWS_HOST="${PANDORAS_BOX_LIVE_MIXED_WINDOWS_HOST:-}"
SLOW_HOST="${PANDORAS_BOX_LIVE_MIXED_SLOW_HOST:-}"
PROXY_BINARY="$ROOT_DIR/target/live-harness/tcp-port-proxy"
PROXY_SOURCE="$ROOT_DIR/scripts/tcp-port-proxy.rs"
SLOW_TARGET_BINARY="$ROOT_DIR/target/live-harness/slow-ssh-target-linux-amd64"
SLOW_TARGET_SOURCE="$ROOT_DIR/scripts/slow-ssh-target.rs"
KNOWN_HOSTS_DIR="$ROOT_DIR/target/live-mixed-known-hosts-$$"
MIXED_PASSWORD_FILE="$ROOT_DIR/target/live-mixed-password-$$"
PROXY_PIDS=()

cleanup() {
  if ((${#PROXY_PIDS[@]} > 0)); then
    kill "${PROXY_PIDS[@]}" >/dev/null 2>&1 || true
  fi
  docker rm -f "$UNIX_CONTAINER_NAME" >/dev/null 2>&1 || true
  docker rm -f "$ALPINE_CONTAINER_NAME" >/dev/null 2>&1 || true
  docker rm -f "$SLOW_CONTAINER_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  rm -rf "$KNOWN_HOSTS_DIR"
  rm -f "$MIXED_PASSWORD_FILE"
}

show_logs_on_failure() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    docker logs "$UNIX_CONTAINER_NAME" 2>/dev/null || true
    docker logs "$ALPINE_CONTAINER_NAME" 2>/dev/null || true
    docker logs "$SLOW_CONTAINER_NAME" 2>/dev/null || true
  fi
  exit $exit_code
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s is required for the containerized mixed live concurrency harness\n' "$1" >&2
    exit 1
  fi
}

vm_state() {
  VBoxManage showvminfo "$VM_NAME" --machinereadable |
    sed -n 's/^VMState=\"\([^\"]*\)\"$/\1/p'
}

wait_for_vm_running() {
  local attempts="${1:-30}"
  local delay_seconds="${2:-2}"
  local state

  for _ in $(seq 1 "$attempts"); do
    state="$(vm_state)"
    if [[ "$state" == "running" ]]; then
      return 0
    fi
    sleep "$delay_seconds"
  done

  return 1
}

ensure_windows_vm_running() {
  local state

  state="$(vm_state)"
  case "$state" in
    running)
      return 0
      ;;
    saved|poweroff|aborted)
      printf 'Starting Tiny11 fixture %s from state %s\n' "$VM_NAME" "$state"
      VBoxManage startvm "$VM_NAME" --type headless >/dev/null
      ;;
    paused)
      printf 'Resuming Tiny11 fixture %s from paused state\n' "$VM_NAME"
      VBoxManage controlvm "$VM_NAME" resume >/dev/null
      ;;
    *)
      printf 'Tiny11 fixture %s is in unsupported state %s\n' "$VM_NAME" "${state:-unknown}" >&2
      exit 1
      ;;
  esac

  if ! wait_for_vm_running; then
    printf 'Tiny11 fixture %s failed to reach running state\n' "$VM_NAME" >&2
    exit 1
  fi
}

build_proxy_binary() {
  require_command rustc
  mkdir -p "$(dirname "$PROXY_BINARY")"
  if [[ ! -x "$PROXY_BINARY" || "$PROXY_SOURCE" -nt "$PROXY_BINARY" ]]; then
    rustc "$PROXY_SOURCE" -O -o "$PROXY_BINARY"
  fi
}

build_slow_target_binary() {
  mkdir -p "$(dirname "$SLOW_TARGET_BINARY")"
  if [[ -x "$SLOW_TARGET_BINARY" && "$SLOW_TARGET_SOURCE" -ot "$SLOW_TARGET_BINARY" ]]; then
    return 0
  fi

  docker run --rm \
    --platform linux/amd64 \
    -v "$ROOT_DIR:/work" \
    -w /work \
    "$RUNNER_BUILD_IMAGE" \
    rustc scripts/slow-ssh-target.rs -O -o target/live-harness/slow-ssh-target-linux-amd64
}

runner_platform() {
  case "$RUNNER_LINUX_TARGET" in
    aarch64-unknown-linux-gnu)
      printf 'linux/arm64\n'
      ;;
    x86_64-unknown-linux-gnu)
      printf 'linux/amd64\n'
      ;;
    *)
      printf 'Unsupported runner target %s\n' "$RUNNER_LINUX_TARGET" >&2
      exit 1
      ;;
  esac
}

ensure_windows_nat_forward() {
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
    VBoxManage controlvm "$VM_NAME" natpf1 delete "$rule_name"
  fi
  VBoxManage controlvm "$VM_NAME" natpf1 "${rule_name},tcp,${host_ip},${host_port},,${guest_port}"
}

resolve_host_gateway_ip() {
  docker run --rm "$ALPINE_UTILITY_IMAGE" sh -lc "ping -c 1 host.docker.internal | awk -F'[()]' 'NR==1 { print \$2 }'"
}

start_proxy() {
  local listen_host="$1"
  local listen_port="$2"
  local target_host="$3"
  local target_port="$4"
  local safe_host="${listen_host//:/_}"
  local log_path
  local proxy_pid

  safe_host="${safe_host//./_}"
  log_path="$LIVE_ARTIFACT_DIR/proxy-${safe_host}-${listen_port}.log"

  "$PROXY_BINARY" \
    "$listen_host" "$listen_port" "$target_host" "$target_port" >"$log_path" 2>&1 &
  proxy_pid=$!
  sleep 1
  if ! kill -0 "$proxy_pid" >/dev/null 2>&1; then
    printf 'Failed to start proxy %s:%s -> %s:%s\n' "$listen_host" "$listen_port" "$target_host" "$target_port" >&2
    cat "$log_path" >&2 || true
    exit 1
  fi

  PROXY_PIDS+=("$proxy_pid")
}

wait_for_network_port() {
  local host="$1"
  local port="$2"
  local label="$3"

  if docker run --rm \
    --platform linux/amd64 \
    --network "$NETWORK_NAME" \
    "$ALPINE_UTILITY_IMAGE" \
    sh -lc "for _ in \$(seq 1 30); do nc -z -w 1 '$host' '$port' && exit 0; sleep 1; done; exit 1" >/dev/null; then
    return 0
  fi

  printf 'Timed out waiting for %s at %s:%s on %s\n' "$label" "$host" "$port" "$NETWORK_NAME" >&2
  exit 1
}

have_windows_gnu_toolchain() {
  command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 &&
    rustup target list --installed | grep -Fxq 'x86_64-pc-windows-gnu'
}

absolute_path() {
  local value="$1"
  if [[ "$value" = /* ]]; then
    printf '%s\n' "$value"
  else
    printf '%s/%s\n' "$ROOT_DIR" "$value"
  fi
}

container_path() {
  local value
  value="$(absolute_path "$1")"
  case "$value" in
    "$ROOT_DIR"/*)
      printf '/work/%s\n' "${value#"$ROOT_DIR"/}"
      ;;
    *)
      printf 'Path %s must be inside %s for the containerized harness\n' "$value" "$ROOT_DIR" >&2
      exit 1
      ;;
  esac
}

resolve_linux_test_binary() {
  if [[ -n "$LINUX_TEST_BINARY" ]]; then
    absolute_path "$LINUX_TEST_BINARY"
    return 0
  fi

  find "$LINUX_TEST_TARGET_DIR/$RUNNER_LINUX_TARGET/debug/deps" \
    -maxdepth 1 -type f -name 'live_mixed_concurrency-*' -perm -111 | sort | tail -n 1
}

build_linux_test_binary() {
  mkdir -p "$LINUX_TEST_TARGET_DIR"

  case "$RUNNER_LINUX_TARGET" in
    aarch64-unknown-linux-gnu)
      docker run --rm \
        --platform "$(runner_platform)" \
        -v "$ROOT_DIR:/work" \
        -v "$HOME/.cargo/registry:/usr/local/cargo/registry" \
        -v "$HOME/.cargo/git:/usr/local/cargo/git" \
        -w /work \
        -e CARGO_TARGET_DIR="/work/target/live-mixed-linux" \
        -e CARGO_INCREMENTAL=0 \
        -e CARGO_PROFILE_TEST_DEBUG=0 \
        -e RUSTFLAGS="$LINUX_TEST_RUSTFLAGS" \
        "$RUNNER_BUILD_IMAGE" \
        cargo test --locked --offline -j 1 -p pandoras_box --test live_mixed_concurrency --target "$RUNNER_LINUX_TARGET" --no-run
      ;;
    *)
      CARGO_TARGET_DIR="$LINUX_TEST_TARGET_DIR" \
        CARGO_INCREMENTAL=0 \
        CARGO_PROFILE_TEST_DEBUG=0 \
        RUSTFLAGS="$LINUX_TEST_RUSTFLAGS" \
        cross test --locked -j 1 -p pandoras_box --test live_mixed_concurrency --target "$RUNNER_LINUX_TARGET" --no-run
      ;;
  esac
}

trap cleanup EXIT
trap show_logs_on_failure ERR

cd "$ROOT_DIR"

require_command docker
require_command cross
require_command cargo
require_command ssh-keyscan
require_command VBoxManage
require_command rustup
build_proxy_binary
build_slow_target_binary

mkdir -p "$ROOT_DIR/target"
umask 077
if [[ -n "$MIXED_PASSWORD" ]]; then
  printf '%s' "$MIXED_PASSWORD" > "$MIXED_PASSWORD_FILE"
else
  printf 'pbx-%s' "$(od -An -N18 -tx1 /dev/urandom | tr -d ' \n')" > "$MIXED_PASSWORD_FILE"
fi
MIXED_PASSWORD="$(<"$MIXED_PASSWORD_FILE")"
FIXTURE_CREDENTIAL_NONCE="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"

if [[ -z "$WINDOWS_SSH_USER" || -z "$WINDOWS_SSH_PASSWORD" ]]; then
  printf 'PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME/PASSWORD or SMOLDER_WINDOWS_USERNAME/PASSWORD must be set\n' >&2
  exit 1
fi

if [[ -z "$WINDOWS_HOST" ]]; then
  WINDOWS_HOST="$(resolve_host_gateway_ip | tr -d '\r')"
fi

if [[ -z "$WINDOWS_HOST" ]]; then
  printf 'Containerized mixed harness could not resolve the container-reachable host gateway IP.\n' >&2
  exit 1
fi

mkdir -p "$LIVE_ARTIFACT_DIR"

LINUX_CHIMERA_PATH="$(absolute_path "$LINUX_CHIMERA_PATH")"
cross build --locked -j 1 -p chimera --bin chimera --target x86_64-unknown-linux-musl

if [[ -z "$WINDOWS_CHIMERA_PATH" ]]; then
  if [[ -f "$ROOT_DIR/target/x86_64-pc-windows-gnu/release/chimera.exe" ]]; then
    WINDOWS_CHIMERA_PATH="$ROOT_DIR/target/x86_64-pc-windows-gnu/release/chimera.exe"
  elif [[ -f "$WINDOWS_BUILD_TARGET_DIR/x86_64-pc-windows-gnu/release/chimera.exe" ]]; then
    WINDOWS_CHIMERA_PATH="$WINDOWS_BUILD_TARGET_DIR/x86_64-pc-windows-gnu/release/chimera.exe"
  fi
fi

if have_windows_gnu_toolchain; then
  windows_linker="$(command -v x86_64-w64-mingw32-gcc)"
  CARGO_TARGET_DIR="$WINDOWS_BUILD_TARGET_DIR" \
    CC_x86_64_pc_windows_gnu="$windows_linker" \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$windows_linker" \
    cargo build --locked -j 1 -p chimera --bin chimera --target x86_64-pc-windows-gnu --release
else
  CARGO_TARGET_DIR="$WINDOWS_BUILD_TARGET_DIR" \
    cross build --locked -j 1 -p chimera --bin chimera --target x86_64-pc-windows-gnu --release
fi
WINDOWS_CHIMERA_PATH="${WINDOWS_CHIMERA_PATH:-$WINDOWS_BUILD_TARGET_DIR/x86_64-pc-windows-gnu/release/chimera.exe}"

WINDOWS_CHIMERA_PATH="$(absolute_path "$WINDOWS_CHIMERA_PATH")"
if [[ ! -f "$WINDOWS_CHIMERA_PATH" ]]; then
  printf 'Windows Chimera binary not found at %s\n' "$WINDOWS_CHIMERA_PATH" >&2
  exit 1
fi

build_linux_test_binary
LINUX_TEST_BINARY="$(resolve_linux_test_binary)"
if [[ -z "$LINUX_TEST_BINARY" || ! -x "$LINUX_TEST_BINARY" ]]; then
  printf 'Linux mixed concurrency test binary not found. Set PANDORAS_BOX_LIVE_MIXED_TEST_BINARY or build the x86_64-unknown-linux-gnu test.\n' >&2
  exit 1
fi

docker build \
  --platform linux/amd64 \
  --build-arg "FIXTURE_CREDENTIAL_NONCE=$FIXTURE_CREDENTIAL_NONCE" \
  --secret "id=root_password,src=$MIXED_PASSWORD_FILE" \
  -t "$UNIX_IMAGE_NAME" \
  "$UNIX_DOCKERFILE_DIR"
ALPINE_BUILD_SECRETS=(--secret "id=root_password,src=$MIXED_PASSWORD_FILE")
if [[ -n "${NODE_EXTRA_CA_CERTS:-}" && -f "$NODE_EXTRA_CA_CERTS" ]]; then
  ALPINE_BUILD_SECRETS+=(--secret "id=ca_certificate,src=$NODE_EXTRA_CA_CERTS")
fi
docker build \
  --platform linux/amd64 \
  --build-arg "FIXTURE_CREDENTIAL_NONCE=$FIXTURE_CREDENTIAL_NONCE" \
  "${ALPINE_BUILD_SECRETS[@]}" \
  -t "$ALPINE_IMAGE_NAME" \
  "$ALPINE_DOCKERFILE_DIR"

docker rm -f "$UNIX_CONTAINER_NAME" >/dev/null 2>&1 || true
docker rm -f "$ALPINE_CONTAINER_NAME" >/dev/null 2>&1 || true
docker rm -f "$SLOW_CONTAINER_NAME" >/dev/null 2>&1 || true
docker network create "$NETWORK_NAME" >/dev/null

docker run -d --rm \
  --name "$UNIX_CONTAINER_NAME" \
  --platform linux/amd64 \
  --network "$NETWORK_NAME" \
  "$UNIX_IMAGE_NAME" \
  /usr/sbin/sshd -D -e -p "$SSH_PORT" >/dev/null

docker run -d --rm \
  --name "$ALPINE_CONTAINER_NAME" \
  --platform linux/amd64 \
  --network "$NETWORK_NAME" \
  "$ALPINE_IMAGE_NAME" \
  /usr/sbin/sshd -D -e -p "$SSH_PORT" >/dev/null

docker run -d --rm \
  --name "$SLOW_CONTAINER_NAME" \
  --platform linux/amd64 \
  --network "$NETWORK_NAME" \
  -v "$ROOT_DIR:/work" \
  "$RUNNER_IMAGE" \
  /work/target/live-harness/slow-ssh-target-linux-amd64 0.0.0.0 "$SSH_PORT" >/dev/null

UNIX_HOST="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$UNIX_CONTAINER_NAME")"
ALPINE_HOST="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$ALPINE_CONTAINER_NAME")"
if [[ -z "$SLOW_HOST" ]]; then
  SLOW_HOST="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SLOW_CONTAINER_NAME")"
fi

if [[ -z "$UNIX_HOST" || -z "$ALPINE_HOST" || -z "$SLOW_HOST" ]]; then
  printf 'Failed to resolve Unix, Alpine, or slow container IPs on %s\n' "$NETWORK_NAME" >&2
  exit 1
fi

wait_for_network_port "$UNIX_HOST" "$SSH_PORT" "Unix SSH target"
wait_for_network_port "$ALPINE_HOST" "$SSH_PORT" "Alpine SSH target"
wait_for_network_port "$SLOW_HOST" "$SSH_PORT" "slow SSH target"

ensure_windows_vm_running
ensure_windows_nat_forward "$LOCAL_SSH_RULE_NAME" "127.0.0.1" "$WINDOWS_LOCAL_SSH_PORT" 22
ensure_windows_nat_forward "$LOCAL_SMB_RULE_NAME" "127.0.0.1" "$WINDOWS_LOCAL_SMB_PORT" 445

PANDORAS_BOX_LIVE_WINDOWS_SSH_HOST="127.0.0.1" \
PANDORAS_BOX_LIVE_WINDOWS_SSH_PORT="$WINDOWS_LOCAL_SSH_PORT" \
PANDORAS_BOX_LIVE_WINDOWS_SMB_HOST="127.0.0.1" \
PANDORAS_BOX_LIVE_WINDOWS_SMB_PORT="$WINDOWS_LOCAL_SMB_PORT" \
PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME="$WINDOWS_SSH_USER" \
PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD="$WINDOWS_SSH_PASSWORD" \
bash "$ROOT_DIR/scripts/ensure-tiny11-openssh.sh"

start_proxy "0.0.0.0" "$SSH_PORT" "127.0.0.1" "$WINDOWS_LOCAL_SSH_PORT"
start_proxy "0.0.0.0" "$SMB_PORT" "127.0.0.1" "$WINDOWS_LOCAL_SMB_PORT"

mkdir -p "$KNOWN_HOSTS_DIR"
docker exec "$UNIX_CONTAINER_NAME" cat /etc/ssh/ssh_host_ed25519_key.pub \
  | awk -v host="[$UNIX_HOST]:$SSH_PORT" '{print host " " $1 " " $2}' \
  > "$KNOWN_HOSTS_DIR/known_hosts"
docker exec "$ALPINE_CONTAINER_NAME" cat /etc/ssh/ssh_host_ed25519_key.pub \
  | awk -v host="[$ALPINE_HOST]:$SSH_PORT" '{print host " " $1 " " $2}' \
  >> "$KNOWN_HOSTS_DIR/known_hosts"
ssh-keyscan -p "$WINDOWS_LOCAL_SSH_PORT" 127.0.0.1 2>/dev/null \
  | awk -v host="[$WINDOWS_HOST]:$SSH_PORT" '{print host " " $2 " " $3}' \
  >> "$KNOWN_HOSTS_DIR/known_hosts"
chmod 700 "$KNOWN_HOSTS_DIR"
chmod 600 "$KNOWN_HOSTS_DIR/known_hosts"

export PANDORAS_BOX_LIVE_MIXED_PASSWORD="$MIXED_PASSWORD"
export PANDORAS_BOX_LIVE_MIXED_SSH_PORT="$SSH_PORT"
export PANDORAS_BOX_LIVE_MIXED_SMB_PORT="$SMB_PORT"
export PANDORAS_BOX_LIVE_MIXED_HOST_TIMEOUT_SECS="$HOST_TIMEOUT_SECS"
export PANDORAS_BOX_LIVE_MIXED_CONNECT_TIMEOUT_SECS="$CONNECT_TIMEOUT_SECS"
export PANDORAS_BOX_LIVE_MIXED_UNIX_HOST="$UNIX_HOST"
export PANDORAS_BOX_LIVE_MIXED_ALPINE_HOST="$ALPINE_HOST"
export PANDORAS_BOX_LIVE_MIXED_WINDOWS_HOST="$WINDOWS_HOST"
export PANDORAS_BOX_LIVE_MIXED_SLOW_HOST="$SLOW_HOST"
export PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME="$WINDOWS_SSH_USER"
export PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD="$WINDOWS_SSH_PASSWORD"
export PANDORAS_BOX_LIVE_MIXED_EXTERNAL_SLOW_TARGET=1
PANDORAS_BOX_LIVE_MIXED_ARTIFACT_ROOT="$(container_path "$LIVE_ARTIFACT_DIR")"
PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH="$(container_path "$LINUX_CHIMERA_PATH")"
PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH="$(container_path "$WINDOWS_CHIMERA_PATH")"
export PANDORAS_BOX_LIVE_MIXED_ARTIFACT_ROOT
export PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH
export PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH

docker run --rm \
  --platform "$(runner_platform)" \
  --network "$NETWORK_NAME" \
  -v "$ROOT_DIR:/work" \
  -v "$KNOWN_HOSTS_DIR:/root/.ssh:ro" \
  -w /work \
  -e PANDORAS_BOX_LIVE_MIXED_PASSWORD \
  -e PANDORAS_BOX_LIVE_MIXED_SSH_PORT \
  -e PANDORAS_BOX_LIVE_MIXED_SMB_PORT \
  -e PANDORAS_BOX_LIVE_MIXED_HOST_TIMEOUT_SECS \
  -e PANDORAS_BOX_LIVE_MIXED_CONNECT_TIMEOUT_SECS \
  -e PANDORAS_BOX_LIVE_MIXED_UNIX_HOST \
  -e PANDORAS_BOX_LIVE_MIXED_ALPINE_HOST \
  -e PANDORAS_BOX_LIVE_MIXED_WINDOWS_HOST \
  -e PANDORAS_BOX_LIVE_MIXED_SLOW_HOST \
  -e PANDORAS_BOX_LIVE_WINDOWS_SSH_USERNAME \
  -e PANDORAS_BOX_LIVE_WINDOWS_SSH_PASSWORD \
  -e PANDORAS_BOX_LIVE_MIXED_EXTERNAL_SLOW_TARGET \
  -e PANDORAS_BOX_LIVE_MIXED_ARTIFACT_ROOT \
  -e PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH \
  -e PANDORAS_BOX_LIVE_CHIMERA_WINDOWS_PATH \
  "$RUNNER_IMAGE" \
  "$(container_path "$LINUX_TEST_BINARY")" \
  live_mixed_concurrency_keeps_hosts_moving_until_end_reconciliation \
  --ignored --nocapture
