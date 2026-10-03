#!/usr/bin/env bash
# Install or remove the LoVPN server broker on a Linux host.
#
# Safe by default: with no --yes this only PRINTS what it would do. With --destdir it
# installs into a staging directory without creating users or touching systemd, which
# is how it is tested without root.
#
#   ./scripts/install-server.sh                      # print the plan
#   sudo ./scripts/install-server.sh --yes           # install
#   sudo ./scripts/install-server.sh --uninstall --yes
#   ./scripts/install-server.sh --destdir /tmp/stage --yes
#
# Uninstall removes the program, unit and (with --purge) the broker record. It NEVER
# deletes /var/lib/lovpn-server (your server key and peers) and never runs a firewall
# command: to remove LoVPN's interface and nft tables first run
#   lovpn-server teardown --yes
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary="${CARGO_TARGET_DIR:-$root/target}/release/lovpn-server"
cli_binary="${CARGO_TARGET_DIR:-$root/target}/release/lovpn"
yes=0 uninstall=0 purge=0 destdir=""

while (($#)); do
  case "$1" in
    --yes) yes=1 ;;
    --uninstall) uninstall=1 ;;
    --purge) purge=1 ;;
    --destdir) destdir="${2:?--destdir needs a directory}"; shift ;;
    --binary) binary="${2:?--binary needs a path}"; shift ;;
    --client-binary) cli_binary="${2:?--client-binary needs a path}"; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

bin_dir="$destdir/usr/local/bin"
unit_dir="$destdir/etc/systemd/system"
sysusers_dir="$destdir/usr/lib/sysusers.d"
tmpfiles_dir="$destdir/usr/lib/tmpfiles.d"
state_dir="$destdir/var/lib/lovpn-server"
broker_dir="$destdir/var/lib/lovpn-broker"

say() { printf '%s\n' "$*"; }
do_it() {
  if ((yes)); then "$@"; else say "  would run: $*"; fi
}
privileged=1
[[ -n "$destdir" ]] && privileged=0

if ((uninstall)); then
  say "Uninstall plan:"
  say "  - stop and disable lovpn-server-broker (if systemd manages it)"
  say "  - remove $bin_dir/lovpn-server, the unit, sysusers and tmpfiles files"
  ((purge)) && say "  - remove broker record $broker_dir (resets anti-rollback protection)"
  say "  - KEEP $state_dir (server key and peers) and the lovpn-server user"
  say "  - NOT removed here: WireGuard interface, nft tables, ip_forward. Run first:"
  say "      lovpn-server teardown --yes"
  if ((yes)); then
    if ((privileged)) && command -v systemctl >/dev/null; then
      systemctl disable --now lovpn-server-broker.service 2>/dev/null || true
    fi
    rm -f "$bin_dir/lovpn-server" "$unit_dir/lovpn-server-broker.service" \
      "$sysusers_dir/lovpn-server.conf" "$tmpfiles_dir/lovpn-server.conf"
    ((purge)) && rm -rf "$broker_dir"
    ((privileged)) && command -v systemctl >/dev/null && systemctl daemon-reload || true
    say "Uninstalled. Your state directory was left in place."
  else
    say "Dry run only. Repeat with --yes to proceed."
  fi
  exit 0
fi

[[ -x "$binary" ]] || { echo "Missing $binary. Build first: ./scripts/build-linux.sh" >&2; exit 1; }
if ((privileged && yes && EUID != 0)); then
  echo "Installing system-wide needs root (or use --destdir for a staging copy)." >&2
  exit 1
fi

say "Install plan:"
say "  - install $binary -> $bin_dir/lovpn-server (0755)"
[[ -x "$cli_binary" ]] && say "  - install $cli_binary -> $bin_dir/lovpn (0755)"
say "  - install systemd unit -> $unit_dir/lovpn-server-broker.service (0644)"
say "  - create user 'lovpn-server' via sysusers, state dir $state_dir (0700, that user),"
say "    broker dir $broker_dir (0700, root)"
say "  - NOT started automatically. No firewall, route or forwarding change is made now;"
say "    those happen only when you run 'lovpn-server apply' through the broker."

do_it install -d -m 0755 "$bin_dir" "$unit_dir" "$sysusers_dir" "$tmpfiles_dir"
do_it install -m 0755 "$binary" "$bin_dir/lovpn-server"
[[ -x "$cli_binary" ]] && do_it install -m 0755 "$cli_binary" "$bin_dir/lovpn"
do_it install -m 0644 "$root/packaging/linux/lovpn-server-broker.service" "$unit_dir/lovpn-server-broker.service"
do_it install -m 0644 "$root/packaging/linux/lovpn-server.sysusers" "$sysusers_dir/lovpn-server.conf"
do_it install -m 0644 "$root/packaging/linux/lovpn-server.tmpfiles" "$tmpfiles_dir/lovpn-server.conf"

if ((privileged)); then
  if command -v systemd-sysusers >/dev/null && command -v systemd-tmpfiles >/dev/null; then
    do_it systemd-sysusers lovpn-server.conf
    do_it systemd-tmpfiles --create lovpn-server.conf
    do_it systemctl daemon-reload
  else
    say "  systemd-sysusers/tmpfiles not found: create the user and directories manually (docs/server.md)."
  fi
else
  # Staging copy: no users to chown to; only the directory modes can be created.
  do_it install -d -m 0700 "$state_dir" "$broker_dir"
fi

if ((yes)); then
  say ""
  say "Installed. Next steps (as the lovpn-server user unless noted):"
  say "  1. sudo -u lovpn-server lovpn-server setup --dry-run --endpoint <ip>:51820 --pool 10.66.0.0/24 --wan-interface <uplink> --dns <resolver>"
  say "  2. the same command with --write-state instead of --dry-run"
  say "  3. as root: systemctl enable --now lovpn-server-broker"
  say "  4. sudo -u lovpn-server lovpn-server apply   (this is when networking changes)"
else
  say ""
  say "Dry run only. Repeat with --yes to proceed."
fi
