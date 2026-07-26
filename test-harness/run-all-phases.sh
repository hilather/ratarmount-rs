#!/usr/bin/env bash
# Run all phase harnesses in order (Phase 11 productization).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

echo "=========================================="
echo " ratarmount-rs phase suite"
echo " RATARMOUNT_CMD=$RATARMOUNT_CMD"
echo " RATARMOUNT_PY_ROOT=$RATARMOUNT_PY_ROOT"
echo "=========================================="

failed=0
run() {
    local name=$1
    shift
    echo
    echo ">>> $name"
    if "$@"; then
        echo "<<< $name OK"
    else
        echo "<<< $name FAILED" >&2
        failed=1
    fi
}

run "cargo test --workspace" cargo test --workspace --quiet
run "phase2 tar"        "$SCRIPT_DIR/run-phase2-allowlist.sh"
run "phase3 gzip"       "$SCRIPT_DIR/run-phase3-gzip.sh"
run "phase4 bzip2"      "$SCRIPT_DIR/run-phase4-bzip2.sh"
run "phase5 xz+zstd"    "$SCRIPT_DIR/run-phase5-xz-zstd.sh"
run "stream codecs"     "$SCRIPT_DIR/run-phase-stream-codecs.sh"
run "phase6 zip"        "$SCRIPT_DIR/run-phase6-zip.sh"
run "phase7 nested"     "$SCRIPT_DIR/run-phase7-nested.sh"
run "phase8 overlay"    "$SCRIPT_DIR/run-phase8-overlay.sh"
run "phase8 complex"    "$SCRIPT_DIR/run-phase8-complex-usage.sh"
run "phase9 ar+cpio"    "$SCRIPT_DIR/run-phase9-ar-cpio.sh"
run "phase9 stencil"    "$SCRIPT_DIR/run-phase9-stencil-archives.sh"
run "phase9 libarchive" "$SCRIPT_DIR/run-phase9-libarchive.sh"
run "phase9 sevenzip"   "$SCRIPT_DIR/run-phase9-sevenzip.sh"
run "phase9 sqlar+sqfs" "$SCRIPT_DIR/run-phase9-sqlar-squashfs.sh"
run "phase9 ext4"       "$SCRIPT_DIR/run-phase9-ext4.sh"
run "phase9 fat"        "$SCRIPT_DIR/run-phase9-fat.sh"
run "phase9 asar"       "$SCRIPT_DIR/run-phase9-asar.sh"
run "phase9 misc"       "$SCRIPT_DIR/run-phase9-misc-formats.sh"
run "index interop"     "$SCRIPT_DIR/run-index-interop.sh"
run "phase10 http"      "$SCRIPT_DIR/run-phase10-http.sh"
run "phase10 remote"    "$SCRIPT_DIR/run-phase10-remote.sh"
run "phase11 bench"     "$SCRIPT_DIR/run-phase11-bench.sh"

echo
if [[ $failed -ne 0 ]]; then
    echo "SUITE FAILED"
    exit 1
fi
echo "SUITE OK"
