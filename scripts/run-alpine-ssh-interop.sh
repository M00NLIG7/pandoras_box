#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_NAME="pandoras-box-alpine-ssh-interop:local"
CONTAINER_NAME="pandoras-box-alpine-ssh-interop-target"
NETWORK_NAME="pandoras-box-alpine-ssh-interop-network"
RUNNER_TARGET_VOLUME="pandoras-box-alpine-ssh-interop-runner-target"
RUNNER_IMAGE="rust:1.94-bookworm"
DOCKERFILE_DIR="$ROOT_DIR/pandoras_box/tests/fixtures/alpine_ssh_target"
HOST_CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
LIVE_ARTIFACT_DIR="/workspace/target/live-alpine-ssh-artifacts/$(date +%s%N)"

cleanup() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
}

show_logs_on_failure() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        docker logs "$CONTAINER_NAME" 2>/dev/null || true
    fi
    exit $exit_code
}

trap cleanup EXIT
trap show_logs_on_failure ERR

cd "$ROOT_DIR"

cross build -j 1 -p chimera --bin chimera --target x86_64-unknown-linux-gnu
docker build --platform linux/amd64 -t "$IMAGE_NAME" "$DOCKERFILE_DIR"
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
docker network create "$NETWORK_NAME" >/dev/null
docker run -d --rm \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --platform linux/amd64 \
    "$IMAGE_NAME" >/dev/null

TARGET_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME")"

docker run --rm \
    --network "$NETWORK_NAME" \
    -v "$ROOT_DIR:/workspace" \
    -v "$HOST_CARGO_HOME/registry:/usr/local/cargo/registry:ro" \
    -v "$HOST_CARGO_HOME/git:/usr/local/cargo/git:ro" \
    -v "$RUNNER_TARGET_VOLUME:/tmp/pandoras-box-target" \
    -w /workspace \
    -e HOME=/tmp/pandoras-box-home \
    -e CARGO_BUILD_JOBS=1 \
    -e CARGO_INCREMENTAL=0 \
    -e CARGO_TARGET_DIR=/tmp/pandoras-box-target \
    -e PANDORAS_BOX_LIVE_ALPINE_SSH_ARTIFACT_ROOT="$LIVE_ARTIFACT_DIR" \
    -e RUSTFLAGS="-C debuginfo=0" \
    -e RUST_BACKTRACE=1 \
    -e PANDORAS_BOX_LIVE_ALPINE_CHIMERA_UNIX_PATH="/workspace/target/x86_64-unknown-linux-gnu/debug/chimera" \
    -e PANDORAS_BOX_LIVE_ALPINE_SSH_HOST="$TARGET_IP" \
    -e PANDORAS_BOX_LIVE_ALPINE_SSH_PORT="22" \
    -e PANDORAS_BOX_LIVE_ALPINE_SSH_PASSWORD="secret" \
    "$RUNNER_IMAGE" \
    bash -lc 'mkdir -p "$HOME/.ssh" && touch "$HOME/.ssh/known_hosts" && /usr/local/cargo/bin/cargo test -j 1 --locked --offline -p pandoras_box --test live_unix_ssh live_alpine_ssh_target_collects_inventory_and_cleans_up -- --ignored --nocapture'
