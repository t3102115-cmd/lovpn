#!/usr/bin/env bash
# Run a command inside the lab server's namespace (see lab-server.sh).
set -euo pipefail
: "${LAB_DIR:?set LAB_DIR}"
rm -f "$LAB_DIR/run.done" "$LAB_DIR/run.out"
printf '%s\n' "$*" >"$LAB_DIR/run.sh.tmp" && mv "$LAB_DIR/run.sh.tmp" "$LAB_DIR/run.sh"
for _ in $(seq 300); do [[ -e $LAB_DIR/run.done ]] && break; sleep 0.2; done
[[ -e $LAB_DIR/run.done ]] || { echo "lab-exec: timed out" >&2; exit 1; }
cat "$LAB_DIR/run.out"
