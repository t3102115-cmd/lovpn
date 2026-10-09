#!/usr/bin/env bash
# Verify a signed release manifest, then every file in it.
# usage: verify-release.sh <allowed_signers> <dir> [min-version]
# Refuses: a bad signature, an expired manifest, a version below `min-version` (pass the highest
# version you have ever accepted; this script keeps no state), a listed file whose hash differs,
# and any file in the directory that the manifest does not list.
set -euo pipefail
signers=${1:?allowed_signers file}; dir=${2:?release dir}; min=${3:-0}
ssh-keygen -Y verify -f "$signers" -I lovpn-release -n lovpn-release \
  -s "$dir/MANIFEST.sig" < "$dir/MANIFEST" >/dev/null || { echo "bad signature" >&2; exit 1; }
version=$(sed -n '1s/^version: \([0-9][0-9]*\)$/\1/p' "$dir/MANIFEST")
expires=$(sed -n '2s/^expires: \([0-9-]\{10\}\)$/\1/p' "$dir/MANIFEST")
[[ -n $version && -n $expires ]] || { echo "malformed manifest header" >&2; exit 1; }
[[ $(date -u +%Y-%m-%d) < $expires ]] || { echo "manifest expired on $expires" >&2; exit 1; }
(( version >= min )) || { echo "rollback: manifest version $version < $min" >&2; exit 1; }
listed=$(tail -n +3 "$dir/MANIFEST" | sed 's/^[0-9a-f]\{64\}  //' | sort)
present=$(cd "$dir" && ls -1A | grep -vx -e MANIFEST -e MANIFEST.sig | sort)
[[ $listed == "$present" ]] || { echo "files differ from the manifest" >&2; diff <(echo "$listed") <(echo "$present") >&2 || true; exit 1; }
( cd "$dir" && tail -n +3 MANIFEST | sha256sum --check --strict )
echo "OK: version $version, expires $expires"
