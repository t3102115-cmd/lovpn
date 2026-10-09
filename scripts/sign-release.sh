#!/usr/bin/env bash
# Write SHA256SUMS for the given files and sign it with an SSH signing key.
# usage: sign-release.sh <private-key-file> <out-dir> <file>...
# The key is read by ssh-keygen only; this script never prints or copies it.
# Key custody (offline, hardware-backed, who holds it) is a human decision: see docs/release.md.
set -euo pipefail
key=${1:?private key file}; out=${2:?output dir}; shift 2
[ $# -gt 0 ] || { echo "no files to sign" >&2; exit 2; }
mkdir -p "$out"
: > "$out/SHA256SUMS"
for f in "$@"; do
  ( cd "$(dirname "$f")" && sha256sum -- "$(basename "$f")" ) >> "$out/SHA256SUMS"
done
rm -f "$out/SHA256SUMS.sig"
ssh-keygen -Y sign -f "$key" -n lovpn-release "$out/SHA256SUMS" >/dev/null
echo "wrote $out/SHA256SUMS and $out/SHA256SUMS.sig"
