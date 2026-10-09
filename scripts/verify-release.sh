#!/usr/bin/env bash
# Verify SHA256SUMS against a pinned allowed-signers file, then every listed file.
# usage: verify-release.sh <allowed_signers> <dir-with-SHA256SUMS-and-files>
set -euo pipefail
signers=${1:?allowed_signers file}; dir=${2:?release dir}
ssh-keygen -Y verify -f "$signers" -I lovpn-release -n lovpn-release \
  -s "$dir/SHA256SUMS.sig" < "$dir/SHA256SUMS" >/dev/null
( cd "$dir" && sha256sum --check --strict SHA256SUMS )
