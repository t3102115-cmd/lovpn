#!/usr/bin/env bash
# Run the window's browser tests (optional: needs Playwright and axe-core, see tests/ui/README.md).
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

python="$(realpath -sm "${LOVPN_UI_PYTHON:-.venv/bin/python}")"
axe="$(realpath -sm "${LOVPN_AXE:-.axe/node_modules/axe-core/axe.min.js}")"
target="$(realpath -sm "${CARGO_TARGET_DIR:-target}")"
[[ -x "$python" ]] || { echo "missing $python: see tests/ui/README.md" >&2; exit 2; }
[[ -f "$axe" ]] || { echo "missing $axe: see tests/ui/README.md" >&2; exit 2; }

cargo build --locked -p lovpn-ui
cd tests/ui/browser
"$python" test_window.py "$target/debug/lovpn-ui"
"$python" axe_audit.py "$target/debug/lovpn-ui" "$axe"
