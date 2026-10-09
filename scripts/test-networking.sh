#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
[[ $(uname -s) == Linux ]] || { echo 'Linux namespaces required.' >&2; exit 1; }
for tool in unshare nsenter ip nft wg python3 timeout; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
cargo build --locked -p lovpn-cli -p lovpn-server -p lovpn-client
host_netns=$(readlink /proc/self/ns/net)
# No sudo, host firewall changes, persistent namespaces, or external connections.
# Everything after this boundary runs in disposable user+network namespaces.
timeout 90 unshare --user --map-root-user --net -- \
  python3 tests/networking/firewall.py "$host_netns" "${CARGO_TARGET_DIR:-target}/debug/lovpn"
timeout 90 unshare --user --map-root-user --net -- \
  python3 tests/networking/server_firewall.py "$host_netns" \
  "${CARGO_TARGET_DIR:-target}/debug/lovpn-server" "${CARGO_TARGET_DIR:-target}/debug/lovpn"
# Server end-to-end gate: real WireGuard + broker, extra pid namespace so every helper
# process is reaped when the sandbox exits.
timeout 240 unshare --user --map-root-user --net --pid --fork --mount-proc -- \
  python3 tests/networking/server_e2e.py "$host_netns" \
  "${CARGO_TARGET_DIR:-target}/debug/lovpn-server" "${CARGO_TARGET_DIR:-target}/debug/lovpn"
# Client end-to-end gate: real lovpn-clientd/engine, broker recovery, and kill-switch
# lifecycle in a separate disposable namespace topology.
timeout 300 unshare --user --map-root-user --net --pid --fork --mount-proc -- \
  python3 tests/networking/client_e2e.py "$host_netns" \
  "${CARGO_TARGET_DIR:-target}/debug/lovpn-server" "${CARGO_TARGET_DIR:-target}/debug/lovpn" \
  "${CARGO_TARGET_DIR:-target}/debug/lovpn-clientd"
