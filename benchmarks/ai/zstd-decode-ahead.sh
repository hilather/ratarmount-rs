#!/usr/bin/env bash
# Usage: SIZE_MIB=256 THREADS=4 ./benchmarks/ai/zstd-decode-ahead.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
for tool in cargo python3 tar; do
  command -v "$tool" >/dev/null || { echo "skip: missing $tool" >&2; exit 0; }
done
if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} cargo build --release -p ratarmount >&2
  CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} cargo build --release -p ratarmount-session --example ai-zstd-read >&2
fi
exec python3 benchmarks/ai/decode-benchmark.py
