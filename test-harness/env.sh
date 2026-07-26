#!/usr/bin/env bash
# Shared env for dual-run against the Python ratarmount tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "${RATARMOUNT_PY_ROOT:-}" ]]; then
    if [[ -d "$ROOT/../ratarmount/tests" ]]; then
        RATARMOUNT_PY_ROOT="$(cd "$ROOT/../ratarmount" && pwd)"
    else
        echo "error: set RATARMOUNT_PY_ROOT to the Python ratarmount checkout" >&2
        exit 1
    fi
fi
export RATARMOUNT_PY_ROOT

if [[ -z "${RATARMOUNT_CMD:-}" ]]; then
    if [[ -x "$ROOT/target/release/ratarmount" ]]; then
        RATARMOUNT_CMD="$ROOT/target/release/ratarmount"
    elif [[ -x "$ROOT/target/debug/ratarmount" ]]; then
        RATARMOUNT_CMD="$ROOT/target/debug/ratarmount"
    else
        echo "error: build ratarmount first (cargo build --release) or set RATARMOUNT_CMD" >&2
        exit 1
    fi
fi
export RATARMOUNT_CMD

echo "RATARMOUNT_PY_ROOT=$RATARMOUNT_PY_ROOT"
echo "RATARMOUNT_CMD=$RATARMOUNT_CMD"
