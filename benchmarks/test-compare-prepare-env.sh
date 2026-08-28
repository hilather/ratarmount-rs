#!/usr/bin/env bash
# Regression: PREPARE_ONLY fixture path must not require Python ratarmount or a
# prebuilt binary (issue #9). SKIP_PYTHON=1 / SKIP_BUILD=1 / ALLOW_NO_PY=1
# alone must not skip env.sh gates on a full compare.
#
#   ./benchmarks/test-compare-prepare-env.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/benchmarks/compare-python-vs-rust.sh"

# Isolate from caller env (the bug is "no sibling Python, no RATARMOUNT_CMD").
unset RATARMOUNT_CMD RATARMOUNT_PY_ROOT RATARMOUNT_ALLOW_NO_PY || true

sibling_py=0
if [[ -d "$ROOT/../ratarmount/tests" || -d "$ROOT/../ratarmount-py/tests" ]]; then
    sibling_py=1
fi
has_bin=0
if [[ -x "$ROOT/target/release/ratarmount" || -x "$ROOT/target/debug/ratarmount" ]]; then
    has_bin=1
fi

fail=0
run_isolated() {
    # Usage: run_isolated <out-file> [ENV=val ...]
    local out=$1
    shift
    set +e
    env -u RATARMOUNT_CMD -u RATARMOUNT_PY_ROOT -u RATARMOUNT_ALLOW_NO_PY \
        "$@" bash "$SCRIPT" >"$out" 2>&1
    local rc=$?
    set -e
    return "$rc"
}

expect_fail_msg() {
    local name=$1
    local needle=$2
    shift 2
    local out
    out="$(mktemp)"
    local rc=0
    run_isolated "$out" "$@" || rc=$?
    if [[ "$rc" -eq 0 ]]; then
        echo "[FAIL] $name: expected env.sh error, got exit 0"
        cat "$out"
        fail=1
    elif grep -F -q "$needle" "$out"; then
        echo "[ok] $name (exit $rc, matched: $needle)"
    else
        echo "[FAIL] $name: exit $rc but missing '$needle'"
        cat "$out"
        fail=1
    fi
    rm -f "$out"
}

echo "==> env.sh gates for compare-python-vs-rust.sh (#9)"

if [[ "$sibling_py" -eq 0 ]]; then
    expect_fail_msg "flagless compare (no Python, no binary)" \
        "RATARMOUNT_PY_ROOT"
    expect_fail_msg "SKIP_PYTHON=1 alone is not rust-only / no-py" \
        "RATARMOUNT_PY_ROOT" \
        SKIP_PYTHON=1
else
    echo "skip: sibling Python tree present; PY_ROOT gate assertions not isolated"
fi

if [[ "$has_bin" -eq 0 ]]; then
    # Fake PY_ROOT so env.sh reaches the CMD gate (var set ⇒ skip sibling lookup).
    expect_fail_msg "SKIP_BUILD=1 alone must not dummy RATARMOUNT_CMD" \
        "RATARMOUNT_CMD" \
        RATARMOUNT_PY_ROOT=/nonexistent SKIP_BUILD=1
    expect_fail_msg "ALLOW_NO_PY=1 full run must still require a binary" \
        "RATARMOUNT_CMD" \
        RATARMOUNT_ALLOW_NO_PY=1
else
    echo "skip: ratarmount binary already built; CMD-gate assertions not isolated"
fi

if [[ "$fail" -ne 0 ]]; then
    echo "[FAIL] env-gate negatives"
    exit 1
fi

for need in python3 tar gzip; do
    if ! command -v "$need" >/dev/null 2>&1; then
        echo "skip: $need not found (cannot run PREPARE_ONLY MICRO smoke)"
        echo "[ok] env-gate negatives only"
        exit 0
    fi
done

echo "==> PREPARE_ONLY=1 MICRO=1 (SKIP_BUILD unset, no Python, no binary)"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
rc=0
run_isolated "$out" PREPARE_ONLY=1 MICRO=1 || rc=$?
if [[ "$rc" -ne 0 ]]; then
    echo "[FAIL] PREPARE_ONLY MICRO exited $rc"
    cat "$out"
    exit 1
fi
need=(
    "PREPARE_OK empty-1k.tar"
    "PREPARE_OK small-100.tar"
    "PREPARE_OK small-100.tar.gz"
    "PREPARE_OK all expected fixtures"
)
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
echo "[ok] PREPARE_ONLY env gates"
exit 0
