#!/usr/bin/env bash
# Regression: compare-python-vs-rust fixture builder emits tar.lz4, multi-frame
# tar.zst, and the BIG x10 blob without needing FUSE or Python ratarmount.
#
#   ./benchmarks/test-compare-fixtures.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PREPARE_ONLY=1
export BIG=1
export LARGE_MIB=2
export FRAME_MIB=1
export SKIP_PYTHON=1
export SKIP_BUILD=1
# Tiny blob keeps this off the FUSE path; 64 MiB medium fixtures are still built.

echo "==> PREPARE_ONLY fixture smoke (LARGE_MIB=$LARGE_MIB FRAME_MIB=$FRAME_MIB BIG=1)"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
if ! bash "$ROOT/benchmarks/compare-python-vs-rust.sh" >"$out" 2>&1; then
    echo "[FAIL] compare-python-vs-rust.sh PREPARE_ONLY exited non-zero"
    cat "$out"
    exit 1
fi

need=(
    "PREPARE_OK small-100.tar.lz4"
    "PREPARE_OK large-64m.tar.zst"
    "PREPARE_OK large-64m.tar.lz4"
    "PREPARE_OK small-1000.tar"
    "PREPARE_OK large-2m.tar"
    "PREPARE_OK large-2m.tar.zst"
    "PREPARE_OK large-2m.tar.lz4"
    "PREPARE_OK large-64m.tar.zst frames="
    "PREPARE_OK large-2m.tar.zst frames="
    "PREPARE_OK all expected fixtures"
)
fail=0
for n in "${need[@]}"; do
    if grep -F -q "$n" "$out"; then
        echo "  [ok] $n"
    else
        echo "  [FAIL] missing log line: $n"
        fail=1
    fi
done
if grep -q 'PREPARE_FAIL\|PREPARE_MISSING' "$out"; then
    echo "  [FAIL] prepare reported FAIL/MISSING"
    fail=1
fi
if [[ "$fail" -ne 0 ]]; then
    echo "---- log ----"
    cat "$out"
    exit 1
fi
echo "[ok] fixture builder"
exit 0
