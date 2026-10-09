#!/usr/bin/env bash
# Real-host gate: LoVPN as real systemd services on two real Fedora VMs (KVM).
#
#   tests/linux-vm/run.sh [--fresh] [WORKDIR]
#
# Needs: qemu-system-x86_64 with /dev/kvm, qemu-img, xorriso or mkisofs, ssh, python3, curl.
# Downloads the Fedora Cloud Base image once (checksum verified) into WORKDIR. Touches
# nothing on the host except WORKDIR and two localhost TCP ports (SSH forwards 2201/2202,
# the guests' private LAN on 7700) plus 18080 for a host-side HTTP target. --fresh
# discards the VM disks and rebuilds them.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
fresh=0
if [[ ${1:-} == --fresh ]]; then fresh=1; shift; fi
work=$(realpath -m "${1:-${LOVPN_LAB_DIR:-target/linux-vm-lab}}")
mkdir -p "$work"
for tool in qemu-system-x86_64 qemu-img ssh scp ssh-keygen python3 curl; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
command -v xorriso >/dev/null || command -v mkisofs >/dev/null || { echo "Missing xorriso or mkisofs" >&2; exit 1; }
[[ -w /dev/kvm ]] || { echo "/dev/kvm is not writable: KVM is required" >&2; exit 1; }

release="${FEDORA_RELEASE:-44}"
image="Fedora-Cloud-Base-Generic-$release-1.7.x86_64.qcow2"
url="https://download.fedoraproject.org/pub/fedora/linux/releases/$release/Cloud/x86_64/images"
if [[ ! -f $work/base.qcow2 ]]; then
  curl -fL -o "$work/CHECKSUM" "$url/Fedora-Cloud-$release-1.7-x86_64-CHECKSUM"
  curl -fL -o "$work/base.qcow2.part" "$url/$image"
  expected=$(sed -n "s/^SHA256 ($image) = //p" "$work/CHECKSUM")
  [[ -n $expected ]] || { echo "No checksum for $image" >&2; exit 1; }
  [[ $(sha256sum "$work/base.qcow2.part" | cut -d' ' -f1) == "$expected" ]] || { echo "Image checksum mismatch" >&2; exit 1; }
  mv "$work/base.qcow2.part" "$work/base.qcow2"
fi

if ((fresh)); then
  for vm in srv cli; do
    [[ -f $work/$vm/qemu.pid ]] && kill "$(cat "$work/$vm/qemu.pid")" 2>/dev/null || true
  done
  sleep 2
  rm -rf "$work/srv" "$work/cli" "$work/state.json"
fi

cargo build --locked --release -p lovpn-server -p lovpn-cli -p lovpn-client
bin="${CARGO_TARGET_DIR:-target}/release"
python3 tests/linux-vm/bringup.py "$work" "$work/base.qcow2"
python3 tests/linux-vm/real_host.py "$work" "$bin"
