#!/usr/bin/env bash
# PERF-01 measurements in disposable namespaces (no sudo, no host change). Release binaries:
# debug builds say nothing about performance. Prints JSON; see docs/performance.md.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
for tool in unshare nsenter ip nft wg python3; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
cargo build --locked --release -p lovpn-cli -p lovpn-server -p lovpn-client
t="${CARGO_TARGET_DIR:-target}/release"
host_netns=$(readlink /proc/self/ns/net)
timeout 600 unshare --user --map-root-user --net --pid --fork --mount-proc -- \
  python3 tests/performance/measure.py "$host_netns" "$t/lovpn-server" "$t/lovpn" "$t/lovpn-clientd" "${1:-1024}"
