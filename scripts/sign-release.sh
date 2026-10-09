#!/usr/bin/env bash
# Write a signed release manifest for the given files.
# usage: sign-release.sh <private-key-file> <out-dir> <version> <valid-days> <file>...
# MANIFEST holds `version:` and `expires:` header lines followed by sha256sum lines, and
# MANIFEST.sig is an `ssh-keygen -Y sign` signature over all of it. The key is read by
# ssh-keygen only; this script never prints or copies it. Key custody: docs/release.md.
set -euo pipefail
key=${1:?private key file}; out=${2:?output dir}; version=${3:?integer version, increasing}; days=${4:?valid days}
shift 4
[[ $version =~ ^[0-9]+$ ]] || { echo "version must be an integer" >&2; exit 2; }
[[ $days =~ ^[0-9]+$ ]] || { echo "valid-days must be an integer" >&2; exit 2; }
[ $# -gt 0 ] || { echo "no files to sign" >&2; exit 2; }
mkdir -p "$out"
{
  echo "version: $version"
  echo "expires: $(date -u -d "+$days days" +%Y-%m-%d)"
  for f in "$@"; do ( cd "$(dirname "$f")" && sha256sum -- "$(basename "$f")" ); done
} > "$out/MANIFEST"
rm -f "$out/MANIFEST.sig"
ssh-keygen -Y sign -f "$key" -n lovpn-release "$out/MANIFEST" >/dev/null
echo "wrote $out/MANIFEST and $out/MANIFEST.sig"
