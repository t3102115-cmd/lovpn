#!/usr/bin/env bash
# Install or remove the Linux LoVPN client broker and CLI.
#
# Safe by default: without --yes this prints a plan and changes nothing. --destdir
# makes a root-free staged install possible and never invokes systemd. The broker's
# state directory is deliberately retained by uninstall; this script never deletes
# imported profiles or their private keys.
#
#   ./scripts/install-client.sh                         # print the plan
#   sudo ./scripts/install-client.sh --owner-user alice --yes
#   ./scripts/install-client.sh --destdir /tmp/stage --owner-uid 1000 --yes
#   sudo ./scripts/install-client.sh --uninstall --yes
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
daemon_binary="${CARGO_TARGET_DIR:-$root/target}/release/lovpn-clientd"
cli_binary="${CARGO_TARGET_DIR:-$root/target}/release/lovpn"
ui_binary="${CARGO_TARGET_DIR:-$root/target}/release/lovpn-ui"
tray_binary="${CARGO_TARGET_DIR:-$root/target}/release/lovpn-tray"
owner_uid=""
owner_user="${SUDO_USER:-${USER:-}}"
yes=0
uninstall=0
destdir=""

while (($#)); do
  case "$1" in
    --yes) yes=1 ;;
    --uninstall) uninstall=1 ;;
    --destdir) destdir="${2:?--destdir needs a directory}"; shift ;;
    --owner-uid) owner_uid="${2:?--owner-uid needs a numeric uid}"; shift ;;
    --owner-user) owner_user="${2:?--owner-user needs a user name}"; shift ;;
    --daemon-binary) daemon_binary="${2:?--daemon-binary needs a path}"; shift ;;
    --client-binary) cli_binary="${2:?--client-binary needs a path}"; shift ;;
    --ui-binary) ui_binary="${2:?--ui-binary needs a path}"; shift ;;
    --tray-binary) tray_binary="${2:?--tray-binary needs a path}"; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

bin_dir="$destdir/usr/local/bin"
unit_dir="$destdir/etc/systemd/system"
defaults_dir="$destdir/etc/default"
apps_dir="$destdir/usr/local/share/applications"
default_file="$defaults_dir/lovpn-client"
state_dir="$destdir/var/lib/lovpn-client"

say() { printf '%s\n' "$*"; }
do_it() {
  if ((yes)); then "$@"; else say "  would run: $*"; fi
}

privileged=1
[[ -n "$destdir" ]] && privileged=0
if ((privileged && yes && EUID != 0)); then
  echo "Installing system-wide needs root (or use --destdir for a staging copy)." >&2
  exit 1
fi

if ((uninstall)); then
  say "Uninstall plan:"
  say "  - stop and disable lovpn-clientd (if systemd manages it)"
  say "  - remove $bin_dir/lovpn-clientd, $bin_dir/lovpn, $bin_dir/lovpn-ui, $bin_dir/lovpn-tray, the desktop entry, the unit and $default_file"
  say "  - KEEP $state_dir and every imported profile, private key and session record"
  say "  - NOT removed here: tunnel, routes, nftables or resolver state; use 'lovpn reset' first"
  if ((yes)); then
    if ((privileged)) && command -v systemctl >/dev/null; then
      systemctl disable --now lovpn-clientd.service 2>/dev/null || true
    fi
    rm -f "$bin_dir/lovpn-clientd" "$bin_dir/lovpn" "$bin_dir/lovpn-ui" "$bin_dir/lovpn-tray" "$apps_dir/lovpn.desktop" \
      "$unit_dir/lovpn-clientd.service" "$default_file"
    ((privileged)) && command -v systemctl >/dev/null && systemctl daemon-reload || true
    say "Uninstalled. Client profiles and state were left in place."
  else
    say "Dry run only. Repeat with --yes to proceed."
  fi
  exit 0
fi

[[ -x "$daemon_binary" ]] || {
  echo "Missing $daemon_binary. Build first: ./scripts/build-linux.sh" >&2
  exit 1
}
if [[ -z "$owner_uid" ]]; then
  [[ -n "$owner_user" ]] || {
    echo "Give --owner-user or --owner-uid so the CLI owner is explicit." >&2
    exit 2
  }
  owner_uid=$(id -u "$owner_user" 2>/dev/null) || {
    echo "Could not resolve owner user '$owner_user'; use --owner-uid." >&2
    exit 2
  }
fi
[[ "$owner_uid" =~ ^[0-9]+$ ]] || {
  echo "--owner-uid must be numeric." >&2
  exit 2
}

say "Install plan:"
say "  - install $daemon_binary -> $bin_dir/lovpn-clientd (0755)"
[[ -x "$cli_binary" ]] && say "  - install $cli_binary -> $bin_dir/lovpn (0755)"
[[ -x "$ui_binary" ]] && say "  - install $ui_binary -> $bin_dir/lovpn-ui (0755) and a desktop entry in $apps_dir"
[[ -x "$tray_binary" ]] && say "  - install $tray_binary -> $bin_dir/lovpn-tray (0755); it is not started automatically"
say "  - install systemd unit -> $unit_dir/lovpn-clientd.service (0644)"
say "  - configure owner UID $owner_uid in $default_file (0644)"
say "  - create root-owned client state $state_dir (0700)"
say "  - NOT started automatically; no route, firewall, tunnel or DNS change is made"

do_it install -d -m 0755 "$bin_dir" "$unit_dir" "$defaults_dir"
do_it install -m 0755 "$daemon_binary" "$bin_dir/lovpn-clientd"
[[ -x "$cli_binary" ]] && do_it install -m 0755 "$cli_binary" "$bin_dir/lovpn"
if [[ -x "$ui_binary" ]]; then
  do_it install -m 0755 "$ui_binary" "$bin_dir/lovpn-ui"
  do_it install -d -m 0755 "$apps_dir"
  do_it install -m 0644 "$root/packaging/linux/lovpn.desktop" "$apps_dir/lovpn.desktop"
fi
[[ -x "$tray_binary" ]] && do_it install -m 0755 "$tray_binary" "$bin_dir/lovpn-tray"
do_it install -m 0644 "$root/packaging/linux/lovpn-clientd.service" "$unit_dir/lovpn-clientd.service"
do_it install -d -m 0700 "$state_dir"
if ((yes)); then
  printf 'LOVPN_OWNER_UID=%s\n' "$owner_uid" >"$default_file"
  chmod 0644 "$default_file"
else
  say "  would write: LOVPN_OWNER_UID=$owner_uid -> $default_file (0644)"
fi

if ((privileged)); then
  if command -v systemctl >/dev/null; then
    do_it systemctl daemon-reload
  else
    say "  systemctl not found: enable lovpn-clientd.service manually after installing systemd."
  fi
fi

if ((yes)); then
  say ""
  say "Installed. Next steps:"
  say "  1. import a profile with 'lovpn profile import' (the broker keeps its key under $state_dir)"
  say "  2. enable the broker: sudo systemctl enable --now lovpn-clientd"
  say "  3. inspect observed state with 'lovpn status'; use 'lovpn reset' before uninstall"
else
  say ""
  say "Dry run only. Repeat with --yes to proceed."
fi
