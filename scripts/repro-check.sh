#!/usr/bin/env bash
# Build the Linux release binaries twice, in two different directories, and compare hashes.
# Reproducible here means: same source, same locked dependencies, same toolchain, same
# machine type => identical bytes. It does not prove reproducibility across toolchains,
# distributions or CPUs. Prints the hashes so a release can publish them.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
root=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
bins=(lovpn-server lovpn lovpn-clientd lovpn-ui lovpn-tray)

build() {
  local out=$1
  CARGO_TARGET_DIR="$out" \
  RUSTFLAGS="--remap-path-prefix=$root=/src --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup" \
  SOURCE_DATE_EPOCH=1 \
    cargo build --locked --release -p lovpn-server -p lovpn-client -p lovpn-cli -p lovpn-ui -p lovpn-tray >/dev/null
}

build "$work/a"
build "$work/b"
status=0
for bin in "${bins[@]}"; do
  a=$(sha256sum "$work/a/release/$bin" | cut -d' ' -f1)
  b=$(sha256sum "$work/b/release/$bin" | cut -d' ' -f1)
  if [[ $a == "$b" ]]; then echo "SAME  $a  $bin"; else echo "DIFF  $bin: $a vs $b"; status=1; fi
done
exit $status
