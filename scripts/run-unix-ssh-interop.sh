#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="pandoras-box-unix-ssh-interop:local"
CONTAINER_NAME="pandoras-box-unix-ssh-interop-target"
NETWORK_NAME="pandoras-box-unix-ssh-interop-network"
RUNNER_TARGET_VOLUME="pandoras-box-unix-ssh-interop-runner-target"
RUNNER_IMAGE="rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55"
DOCKERFILE_DIR="$ROOT_DIR/pandoras_box/tests/fixtures/unix_ssh_target"
HOST_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
LIVE_ARTIFACT_DIR="/workspace/target/live-unix-ssh-artifacts/$(date +%s%N)"
KNOWN_HOSTS_DIR="$ROOT_DIR/target/live-unix-known-hosts-$$"
PASSWORD_FILE="$ROOT_DIR/target/live-unix-password-$$"
CHIMERA_TARGET="${PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH:-}"

cleanup() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
    rm -rf "$KNOWN_HOSTS_DIR"
    rm -f "$PASSWORD_FILE"
}

show_logs_on_failure() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        docker logs "$CONTAINER_NAME" 2>/dev/null || true
    fi
    exit $exit_code
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf '%s is required for the Unix SSH interop harness\n' "$1" >&2
        exit 1
    fi
}

trap cleanup EXIT
trap show_logs_on_failure ERR

cd "$ROOT_DIR"
require_command docker
mkdir -p "$ROOT_DIR/target" "$HOST_CARGO_HOME/registry" "$HOST_CARGO_HOME/git"
umask 077
if [[ -n "${PANDORAS_BOX_LIVE_UNIX_SSH_PASSWORD:-}" ]]; then
    printf '%s' "$PANDORAS_BOX_LIVE_UNIX_SSH_PASSWORD" > "$PASSWORD_FILE"
else
    printf 'pbx-%s' "$(od -An -N18 -tx1 /dev/urandom | tr -d ' \n')" > "$PASSWORD_FILE"
fi
PANDORAS_BOX_LIVE_UNIX_SSH_PASSWORD="$(<"$PASSWORD_FILE")"
FIXTURE_CREDENTIAL_NONCE="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
export PANDORAS_BOX_LIVE_UNIX_SSH_PASSWORD

if [[ -z "$CHIMERA_TARGET" ]]; then
    require_command cross
    cross build --locked -j 1 -p chimera --bin chimera --target x86_64-unknown-linux-musl
    CHIMERA_TARGET="$ROOT_DIR/target/x86_64-unknown-linux-musl/debug/chimera"
elif [[ "$CHIMERA_TARGET" != /* ]]; then
    CHIMERA_TARGET="$ROOT_DIR/$CHIMERA_TARGET"
fi
if [[ ! -f "$CHIMERA_TARGET" ]]; then
    printf 'Linux Chimera binary not found at %s\n' "$CHIMERA_TARGET" >&2
    exit 1
fi
case "$CHIMERA_TARGET" in
    "$ROOT_DIR"/*) ;;
    *)
        printf 'Linux Chimera binary must be inside %s for the containerized harness\n' "$ROOT_DIR" >&2
        exit 1
        ;;
esac

docker build --platform linux/amd64 \
    --build-arg "FIXTURE_CREDENTIAL_NONCE=$FIXTURE_CREDENTIAL_NONCE" \
    --secret "id=root_password,src=$PASSWORD_FILE" \
    -t "$IMAGE_NAME" "$DOCKERFILE_DIR"
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
docker network create "$NETWORK_NAME" >/dev/null
docker run -d --rm \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --platform linux/amd64 \
    "$IMAGE_NAME" >/dev/null

TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME")"
mkdir -p "$KNOWN_HOSTS_DIR"
docker exec "$CONTAINER_NAME" cat /etc/ssh/ssh_host_ed25519_key.pub \
    | awk -v host="$TARGET_IP" '{print host " " $1 " " $2}' \
    > "$KNOWN_HOSTS_DIR/known_hosts"
chmod 700 "$KNOWN_HOSTS_DIR"
chmod 600 "$KNOWN_HOSTS_DIR/known_hosts"

PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH="/workspace/${CHIMERA_TARGET#"$ROOT_DIR/"}"
export PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH

docker run --rm \
    --network "$NETWORK_NAME" \
    -v "$ROOT_DIR:/workspace" \
    -v "$HOST_CARGO_HOME/registry:/usr/local/cargo/registry:ro" \
    -v "$HOST_CARGO_HOME/git:/usr/local/cargo/git:ro" \
    -v "$RUNNER_TARGET_VOLUME:/tmp/pandoras-box-target" \
    -v "$KNOWN_HOSTS_DIR:/tmp/pandoras-box-home/.ssh:ro" \
    -w /workspace \
    -e HOME=/tmp/pandoras-box-home \
    -e CARGO_BUILD_JOBS=1 \
    -e CARGO_INCREMENTAL=0 \
    -e CARGO_TARGET_DIR=/tmp/pandoras-box-target \
    -e PANDORAS_BOX_LIVE_ARTIFACT_ROOT="$LIVE_ARTIFACT_DIR" \
    -e RUSTUP_TOOLCHAIN=1.94.1 \
    -e RUSTFLAGS="-C debuginfo=0" \
    -e RUST_BACKTRACE=1 \
    -e PANDORAS_BOX_LIVE_CHIMERA_UNIX_PATH \
    -e PANDORAS_BOX_LIVE_UNIX_SSH_HOST="$TARGET_IP" \
    -e PANDORAS_BOX_LIVE_UNIX_SSH_PORT=22 \
    -e PANDORAS_BOX_LIVE_UNIX_SSH_PASSWORD \
    "$RUNNER_IMAGE" \
    bash -lc '/usr/local/cargo/bin/cargo test -j 1 --locked --offline -p pandoras_box --test live_unix_ssh live_unix_ssh_target_collects_inventory_and_cleans_up -- --ignored --nocapture'
