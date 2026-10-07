#!/usr/bin/env bash
# Smoke-test both Linux installers against staging directories (no root, no systemd,
# no users created). Does NOT test a real installation or a running service.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

target="${CARGO_TARGET_DIR:-target}"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
fake="$stage/fake-bin"
mkdir -p "$fake"
for name in lovpn-server lovpn lovpn-clientd lovpn-ui; do
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
[[ -f "$stage/root/etc/systemd/system/lovpn-server-enroll.service" ]] || fail "enrollment unit not installed"
[[ $(stat -c %a "$stage/root/var/lib/lovpn-server") == 700 ]] || fail "state dir mode"
[[ $(stat -c %a "$stage/root/var/lib/lovpn-broker") == 700 ]] || fail "broker dir mode"
pass "staged install creates program, unit and 0700 directories"

echo keep >"$stage/root/var/lib/lovpn-server/server.key"
"${run[@]}" --uninstall --purge --yes >/dev/null
[[ ! -e "$stage/root/usr/local/bin/lovpn-server" ]] || fail "binary not removed"
[[ ! -e "$stage/root/etc/systemd/system/lovpn-server-broker.service" ]] || fail "unit not removed"
[[ ! -e "$stage/root/etc/systemd/system/lovpn-server-enroll.service" ]] || fail "enrollment unit not removed"
[[ ! -e "$stage/root/var/lib/lovpn-broker" ]] || fail "--purge did not remove the broker record"
[[ $(cat "$stage/root/var/lib/lovpn-server/server.key") == keep ]] || fail "uninstall deleted server state"
pass "uninstall removes program/unit, keeps the server key and state"

if command -v systemd-analyze >/dev/null; then
  server_unit="$stage/server-unit.service"
  client_unit="$stage/client-unit.service"
  sed "s|/usr/local/bin/lovpn-server|$fake/lovpn-server|" packaging/linux/lovpn-server-broker.service >"$server_unit"
  sed "s|/usr/local/bin/lovpn-clientd|$fake/lovpn-clientd|" packaging/linux/lovpn-clientd.service >"$client_unit"
  enroll_unit="$stage/enroll-unit.service"
  sed "s|/usr/local/bin/lovpn-server|$fake/lovpn-server|" packaging/linux/lovpn-server-enroll.service >"$enroll_unit"
  chmod 644 "$server_unit" "$client_unit" "$enroll_unit"
  output=$(systemd-analyze verify --man=no "$server_unit" "$client_unit" "$enroll_unit" 2>&1 || true)
  [[ -z "$output" ]] || fail "systemd-analyze verify: $output"
  pass "systemd-analyze verify accepts both broker units (not a runtime test)"
  if systemd-analyze security --help 2>&1 | grep -q -- '--offline'; then
    systemd-analyze security --offline=yes --no-pager "$server_unit" "$client_unit" "$enroll_unit" >/dev/null \
      || fail "systemd-analyze security --offline rejected a broker unit"
    pass "systemd-analyze security --offline accepts both broker units (static only)"
  else
    pass "systemd-analyze security --offline unavailable; skipped"
  fi
fi

client_root="$stage/client-root"
client_run=(./scripts/install-client.sh --destdir "$client_root" \
  --daemon-binary "$fake/lovpn-clientd" --client-binary "$fake/lovpn" --ui-binary "$fake/lovpn-ui" --owner-uid "$(id -u)")

"${client_run[@]}" >/dev/null
[[ ! -e "$client_root" ]] || fail "client plan mode created files"
pass "client plan mode changes nothing"

"${client_run[@]}" --yes >/dev/null
[[ -x "$client_root/usr/local/bin/lovpn-clientd" ]] || fail "client broker not installed"
[[ -x "$client_root/usr/local/bin/lovpn" ]] || fail "client CLI not installed"
[[ -x "$client_root/usr/local/bin/lovpn-ui" ]] || fail "client window not installed"
[[ -f "$client_root/usr/local/share/applications/lovpn.desktop" ]] || fail "desktop entry not installed"
[[ -f "$client_root/etc/systemd/system/lovpn-clientd.service" ]] || fail "client unit not installed"
[[ "$(cat "$client_root/etc/default/lovpn-client")" == "LOVPN_OWNER_UID=$(id -u)" ]] || fail "client owner configuration"
[[ $(stat -c %a "$client_root/var/lib/lovpn-client") == 700 ]] || fail "client state dir mode"
pass "client staged install creates broker, CLI, unit and 0700 state"

mkdir -p "$client_root/var/lib/lovpn-client/profiles"
printf 'keep-profile\n' >"$client_root/var/lib/lovpn-client/profiles/keep.toml"
"${client_run[@]}" --uninstall --yes >/dev/null
[[ ! -e "$client_root/usr/local/bin/lovpn-clientd" ]] || fail "client broker not removed"
[[ ! -e "$client_root/etc/systemd/system/lovpn-clientd.service" ]] || fail "client unit not removed"
[[ -f "$client_root/var/lib/lovpn-client/profiles/keep.toml" ]] || fail "client uninstall deleted a profile"
pass "client uninstall removes program/unit and keeps profiles and state"
