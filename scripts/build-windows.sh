#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) cargo build --locked --release --workspace ;;
  *)
    echo 'Native Windows build required. In the VM run:' >&2
    echo '  powershell -NoProfile -File scripts/build-windows.ps1' >&2
    echo 'Linux cargo check --target x86_64-pc-windows-msvc is only a compile check, not a native build.' >&2
    exit 1
    ;;
esac
