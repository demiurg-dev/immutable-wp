#!/usr/bin/env bash
# Builds the static (musl) iwp binary and prints its path on stdout (everything else: stderr).
# IWP_BIN_PATH, when set, is compiled in as the path the generated systemd units call.
set -euo pipefail
cd "$(dirname "$0")/.."
target=x86_64-unknown-linux-musl
if command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
  CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc cargo build --release --locked --target "$target" >&2
  bin=target/$target/release/iwp
elif command -v musl-gcc >/dev/null 2>&1; then
  CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --locked --target "$target" >&2
  bin=target/$target/release/iwp
else
  # Pinned by digest. Refresh: skopeo inspect --format '{{.Digest}}' docker://docker.io/library/rust:alpine
  img=docker.io/library/rust:alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f
  podman run --rm -v "$PWD":/src:z -v "${CARGO_HOME:-$HOME/.cargo}/registry":/usr/local/cargo/registry:z \
    -w /src -e CARGO_TARGET_DIR=/src/target/alpine ${IWP_BIN_PATH:+-e IWP_BIN_PATH="$IWP_BIN_PATH"} "$img" \
    sh -c 'apk add --no-cache musl-dev >/dev/null && cargo build --release --locked --target x86_64-unknown-linux-musl' >&2
  bin=target/alpine/$target/release/iwp
fi
out=$(file "$bin")
echo "$out" >&2
[[ "$out" == *static* ]] || { echo "not a static binary: $bin" >&2; exit 1; }
echo "$bin"
