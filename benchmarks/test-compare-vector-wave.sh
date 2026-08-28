#!/usr/bin/env bash
# Regression: vector-wave fixture builder emits many/hash/shuf/nested tars.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PREPARE_ONLY=1 VECTOR_MICRO=1 SKIP_BUILD=1
echo "==> PREPARE_ONLY vector-wave fixture smoke"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
if ! bash "$ROOT/benchmarks/compare-vector-wave.sh" >"$out" 2>&1; then
    echo "[FAIL] compare-vector-wave.sh PREPARE_ONLY exited non-zero"
    cat "$out"
    exit 1
fi
if ! grep -F -q "PREPARE_OK many.tar hash.tar shuf.tar nested.tar tiny.tar" "$out"; then
    echo "[FAIL] missing PREPARE_OK line"
    cat "$out"
    exit 1
fi
echo "[ok] vector-wave fixture builder"
exit 0
