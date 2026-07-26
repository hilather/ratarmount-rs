#!/usr/bin/env bash
# Phase-gated wrapper around the Python fixed-archive suite.
#
# Day-to-day CI should use the phase allowlists (run-all-phases.sh). This wrapper
# exists to drive Python's run-fixed-archive-tests.sh with RATARMOUNT_CMD set to
# the Rust binary — never enable full AppImage expansion unless TEST_EXTERNAL_COMMAND=1.
#
# Usage:
#   ./test-harness/run-fixed-archive-subset.sh           # dry-run (default)
#   RUN=1 ./test-harness/run-fixed-archive-subset.sh     # invoke Python suite
#   RUN=1 PARALLELIZATIONS=1 ./test-harness/run-fixed-archive-subset.sh
#
# Prefer ./test-harness/run-index-interop.sh for Py↔Rust index goldens.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

PY_RUN="$RATARMOUNT_PY_ROOT/tests/run-fixed-archive-tests.sh"
if [[ ! -f "$PY_RUN" ]]; then
    echo "error: Python fixed-archive runner not found at $PY_RUN" >&2
    exit 1
fi

# Python harness expects TEST_EXTERNAL_COMMAND=1 to use an external binary.
export TEST_EXTERNAL_COMMAND="${TEST_EXTERNAL_COMMAND:-1}"
export RATARMOUNT_CMD
# Keep matrix small unless overridden.
export PARALLELIZATIONS="${PARALLELIZATIONS:-1}"

echo "RATARMOUNT_CMD=$RATARMOUNT_CMD"
echo "TEST_EXTERNAL_COMMAND=$TEST_EXTERNAL_COMMAND"
echo "PARALLELIZATIONS=$PARALLELIZATIONS"
echo "Python runner: $PY_RUN"
echo
echo "Note: full fixed-archive can take a long time and may include formats we do not"
echo "claim yet. Prefer phase allowlists + run-index-interop.sh for routine CI."
echo

if [[ "${RUN:-0}" != "1" ]]; then
    echo "Dry-run only. Set RUN=1 to invoke the Python fixed-archive suite."
    echo "Example: RUN=1 PARALLELIZATIONS=1 $0"
    exit 0
fi

cd "$RATARMOUNT_PY_ROOT"
# shellcheck disable=SC1091
bash "$PY_RUN"
