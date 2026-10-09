#!/usr/bin/env bash
# Coverage-guided fuzzing (libFuzzer via cargo-fuzz, nightly). usage: fuzz.sh [seconds-per-target]
# Needs: rustup toolchain nightly, cargo install cargo-fuzz. Corpus/artifacts stay in fuzz/ (ignored).
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../fuzz"
secs=${1:-60}
for target in config_text enroll_wire broker_request ip_json key_text; do
  echo "== $target"
  cargo +nightly fuzz run --fuzz-dir . "$target" -- -max_total_time="$secs" -max_len=4096
done
