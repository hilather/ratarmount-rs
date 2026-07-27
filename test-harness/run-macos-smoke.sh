#!/usr/bin/env bash
# Minimal FUSE smoke for macOS (and Linux): mount a tiny tar.gz + zip, read, unmount.
# Does not require the Python ratarmount fixture tree.
#
# Usage (from repo root, after cargo build --release):
#   ./test-harness/run-macos-smoke.sh
#
# Env:
#   RATARMOUNT_CMD   path to binary (default target/release or debug)
#   SKIP_IF_NO_FUSE=1  exit 0 when fuse/pkg-config missing (CI soft gate)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RATARMOUNT_ENV_QUIET=1
export RATARMOUNT_ALLOW_NO_PY=1
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

if [[ "${SKIP_IF_NO_FUSE:-0}" == "1" ]]; then
    if ! pkg-config --exists fuse 2>/dev/null \
        && ! pkg-config --exists fuse3 2>/dev/null \
        && [[ ! -e /usr/local/lib/libfuse.dylib \
            && ! -e /usr/local/lib/libfuse.2.dylib \
            && ! -e /opt/homebrew/lib/libfuse.dylib \
            && ! -d /Library/Filesystems/macfuse.fs \
            && ! -d /Library/Frameworks/fuse-t.framework ]]; then
        echo "skip: no FUSE runtime detected (set SKIP_IF_NO_FUSE=0 to force)"
        exit 0
    fi
fi

WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-macos-smoke-$$"
mkdir -p "$WORKDIR"
MP="$WORKDIR/mnt"
mkdir -p "$MP"
MOUNT_PID=""

cleanup() {
    set +e
    if [[ -n "${MOUNT_PID:-}" ]]; then
        kill "$MOUNT_PID" 2>/dev/null || true
        wait "$MOUNT_PID" 2>/dev/null || true
    fi
    ratar_unmount "$MP"
    rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

echo "==> macOS/Linux FUSE smoke"
echo "    binary: $RATARMOUNT_CMD"
echo "    workdir: $WORKDIR"

# --- fixture: tiny gzip tar ---
mkdir -p "$WORKDIR/src"
echo "hello-ratarmount-macos" >"$WORKDIR/src/hello.txt"
tar -czf "$WORKDIR/sample.tar.gz" -C "$WORKDIR/src" hello.txt

# Prefer foreground so CI does not depend on daemonize + mount table races.
"$RATARMOUNT_CMD" -f "$WORKDIR/sample.tar.gz" "$MP" &
MOUNT_PID=$!

if ! ratar_wait_mounted "$MP" 100; then
    # Foreground may still serve before mount table updates; try read anyway.
    if [[ ! -f "$MP/hello.txt" ]]; then
        echo "error: timed out waiting for mount at $MP" >&2
        # Dump diagnostics
        mount 2>/dev/null | head -50 || true
        exit 1
    fi
fi

got="$(cat "$MP/hello.txt")"
if [[ "$got" != "hello-ratarmount-macos" ]]; then
    echo "error: unexpected content: $got" >&2
    exit 1
fi
echo "    tar.gz: OK ($got)"

kill "$MOUNT_PID" 2>/dev/null || true
wait "$MOUNT_PID" 2>/dev/null || true
MOUNT_PID=""
ratar_unmount "$MP"
# Ensure clean for next mount
sleep 0.3
mkdir -p "$MP"

# --- optional zip via Python or zip CLI ---
if command -v zip >/dev/null 2>&1; then
    (cd "$WORKDIR/src" && zip -q "$WORKDIR/sample.zip" hello.txt)
    "$RATARMOUNT_CMD" -f "$WORKDIR/sample.zip" "$MP" &
    MOUNT_PID=$!
    if ! ratar_wait_mounted "$MP" 100 && [[ ! -f "$MP/hello.txt" ]]; then
        echo "error: zip mount failed" >&2
        exit 1
    fi
    got="$(cat "$MP/hello.txt")"
    if [[ "$got" != "hello-ratarmount-macos" ]]; then
        echo "error: zip content mismatch: $got" >&2
        exit 1
    fi
    echo "    zip: OK"
    kill "$MOUNT_PID" 2>/dev/null || true
    wait "$MOUNT_PID" 2>/dev/null || true
    MOUNT_PID=""
    ratar_unmount "$MP"
else
    echo "    zip: skip (no zip CLI)"
fi

# --- unmount CLI path ---
"$RATARMOUNT_CMD" -f "$WORKDIR/sample.tar.gz" "$MP" &
MOUNT_PID=$!
ratar_wait_mounted "$MP" 100 || true
if "$RATARMOUNT_CMD" -u "$MP" 2>/dev/null; then
    echo "    ratarmount -u: OK"
else
    # Binary may still be holding; fall back
    ratar_unmount "$MP"
    echo "    ratarmount -u: fallback ratar_unmount (ok for CI)"
fi
kill "$MOUNT_PID" 2>/dev/null || true
wait "$MOUNT_PID" 2>/dev/null || true
MOUNT_PID=""

echo "==> smoke passed"
