#!/usr/bin/env bash
# Builds dist/iwp-<version>-<release>.x86_64.rpm from the static binary. The units iwp
# generates call /usr/bin/iwp in this build. rpmbuild runs in a Rocky 9 container when it is
# not installed. Usage: scripts/rpm.sh [<release>]   (default release: 1)
set -euo pipefail
cd "$(dirname "$0")/.."
release=${1:-1}
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
bin=$(IWP_BIN_PATH=/usr/bin/iwp scripts/build-static.sh)
grep -qa '/usr/bin/iwp' "$bin" || { echo "$bin was not built with IWP_BIN_PATH=/usr/bin/iwp" >&2; exit 1; }

top=target/rpm
rm -rf "$top"
mkdir -p "$top/SOURCES" "$top/SPECS" dist
cp -p "$bin" packaging/iwp.toml README.md docs/operations.md LICENSE "$top/SOURCES/"
cp -p packaging/iwp.spec "$top/SPECS/"
build=(rpmbuild -bb --define "_topdir /build" --define "iwp_version $version"
  --define "iwp_release $release" /build/SPECS/iwp.spec)
if command -v rpmbuild >/dev/null 2>&1; then
  build[3]="_topdir $PWD/$top"; build[-1]="$PWD/$top/SPECS/iwp.spec"
  "${build[@]}" >&2
else
  podman run --rm -v "$PWD/$top":/build:z docker.io/rockylinux/rockylinux:9 \
    sh -c 'dnf install -y -q rpm-build >/dev/null && "$@"' sh "${build[@]}" >&2
fi
rpm=$top/RPMS/x86_64/iwp-$version-$release.x86_64.rpm
cp -p "$rpm" dist/
echo "dist/$(basename "$rpm")"
