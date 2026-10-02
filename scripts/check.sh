#!/usr/bin/env bash
# Single entry point for local checks and CI.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
if [[ "${IWP_PODMAN_TESTS:-}" == "1" ]]; then
  cargo test --test nginx_behaviour -- --nocapture
fi
if [[ "${IWP_NET_TESTS:-}" == "1" ]]; then
  cargo test --test wporg_live -- --nocapture
fi
if [[ "${IWP_PODMAN_TESTS:-}" == "1" ]]; then
  cargo test --test image_build -- --nocapture
  cargo test --test wpcli_container -- --nocapture
fi

echo "static binary: $(scripts/build-static.sh)"
