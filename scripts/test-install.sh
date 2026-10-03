#!/usr/bin/env bash
# Smoke-test scripts/install-server.sh against a staging directory (no root, no
# systemd, no users created). Does NOT test a real installation or a running service.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

target="${CARGO_TARGET_DIR:-target}"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
fake="$stage/fake-bin"
mkdir -p "$fake"
for name in lovpn-server lovpn; do
  printf '#!/bin/sh\nexit 0\n' >"$fake/$name"
  chmod 755 "$fake/$name"
done
run=(./scripts/install-server.sh --destdir "$stage/root" --binary "$fake/lovpn-server" --client-binary "$fake/lovpn")

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

"${run[@]}" >/dev/null
[[ ! -e "$stage/root" ]] || fail "plan mode created files"
pass "plan mode changes nothing"

"${run[@]}" --yes >/dev/null
[[ -x "$stage/root/usr/local/bin/lovpn-server" ]] || fail "binary not installed"
[[ -f "$stage/root/etc/systemd/system/lovpn-server-broker.service" ]] || fail "unit not installed"
[[ $(stat -c %a "$stage/root/var/lib/lovpn-server") == 700 ]] || fail "state dir mode"
[[ $(stat -c %a "$stage/root/var/lib/lovpn-broker") == 700 ]] || fail "broker dir mode"
pass "staged install creates program, unit and 0700 directories"

echo keep >"$stage/root/var/lib/lovpn-server/server.key"
"${run[@]}" --uninstall --purge --yes >/dev/null
[[ ! -e "$stage/root/usr/local/bin/lovpn-server" ]] || fail "binary not removed"
[[ ! -e "$stage/root/etc/systemd/system/lovpn-server-broker.service" ]] || fail "unit not removed"
[[ ! -e "$stage/root/var/lib/lovpn-broker" ]] || fail "--purge did not remove the broker record"
[[ $(cat "$stage/root/var/lib/lovpn-server/server.key") == keep ]] || fail "uninstall deleted server state"
pass "uninstall removes program/unit, keeps the server key and state"

if command -v systemd-analyze >/dev/null; then
  unit="$stage/unit.service"
  sed "s|/usr/local/bin/lovpn-server|$fake/lovpn-server|" packaging/linux/lovpn-server-broker.service >"$unit"
  chmod 644 "$unit"
  output=$(systemd-analyze verify --man=no "$unit" 2>&1 || true)
  [[ -z "$output" ]] || fail "systemd-analyze verify: $output"
  pass "systemd-analyze verify accepts the broker unit (not a runtime test)"
fi
