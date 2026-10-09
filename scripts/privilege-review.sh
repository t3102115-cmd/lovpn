#!/usr/bin/env bash
# Mechanical privilege check of the shipped systemd units: fail if any unit's
# systemd-analyze exposure score exceeds the limit (default 4.0). Offline; needs no root.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
limit=${1:-4.0}; status=0
for unit in packaging/linux/*.service; do
  score=$(systemd-analyze security --offline=true "$unit" | sed -n 's/.*exposure level for [^:]*: \([0-9.]*\).*/\1/p')
  if awk -v s="$score" -v l="$limit" 'BEGIN{exit !(s>l)}'; then echo "FAIL $unit exposure $score > $limit"; status=1
  else echo "ok   $unit exposure $score"; fi
done
exit $status
