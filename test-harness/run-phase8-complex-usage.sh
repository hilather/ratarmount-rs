#!/usr/bin/env bash
# Complex-usage subset: multi-source union + write overlay (no --commit-overlay yet).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-complex-$$"
mkdir -p "$WORKDIR"
MOUNT_PIDS=()

cleanup() {
    for pid in "${MOUNT_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for mp in "$WORKDIR"/mnt-*; do
        [[ -d "$mp" ]] && fusermount3 -u "$mp" 2>/dev/null || fusermount -u "$mp" 2>/dev/null || true
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

wait_mounted() {
    local mp=$1 i
    for i in $(seq 1 60); do
        mount 2>/dev/null | grep -F -q "$mp" && return 0
        sleep 0.05
    done
    return 1
}

echo "==> Complex-usage subset"
failed=0

# --- Union of two TARs: second shadows first ---
TAR1="$RATARMOUNT_PY_ROOT/tests/single-file.tar"
TAR2="$RATARMOUNT_PY_ROOT/tests/single-nested-file.tar"
if [[ -f "$TAR1" && -f "$TAR2" ]]; then
    mp="$WORKDIR/mnt-union"
    mkdir -p "$mp"
    echo "  [run] union single-file.tar + single-nested-file.tar"
    "$RATARMOUNT_CMD" -f "$TAR1" "$TAR2" "$mp" >"$WORKDIR/union.log" 2>&1 &
    MOUNT_PIDS+=($!)
    if ! wait_mounted "$mp"; then
        echo "  [FAIL] union mount"
        cat "$WORKDIR/union.log" || true
        failed=1
    else
        # Nested path from TAR2 must be visible
        if [[ -f "$mp/foo/fighter/ufo" ]]; then
            got=$(md5sum "$mp/foo/fighter/ufo" | awk '{print $1}')
            if [[ "$got" == "2709a3348eb2c52302a7606ecf5860bc" ]]; then
                echo "  [ok] union nested path md5 $got"
            else
                echo "  [FAIL] union md5 $got"
                failed=1
            fi
        else
            echo "  [FAIL] union missing foo/fighter/ufo"
            ls -laR "$mp" || true
            failed=1
        fi
        # bar from TAR1 may still exist depending on union order
        fusermount3 -u "$mp" 2>/dev/null || true
        wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
    fi
else
    echo "  [skip] union fixtures missing"
fi

# --- Write overlay :temp: ---
if [[ -f "$TAR1" ]]; then
    mp="$WORKDIR/mnt-overlay"
    mkdir -p "$mp"
    echo "  [run] write-overlay :temp: on single-file.tar"
    "$RATARMOUNT_CMD" -f -w :temp: "$TAR1" "$mp" >"$WORKDIR/ov.log" 2>&1 &
    MOUNT_PIDS+=($!)
    if ! wait_mounted "$mp"; then
        echo "  [FAIL] overlay mount"
        cat "$WORKDIR/ov.log" || true
        failed=1
    else
        # Create a new file in the overlay
        if echo "overlay-hello" >"$mp/new-from-overlay.txt" 2>/dev/null; then
            got=$(cat "$mp/new-from-overlay.txt")
            if [[ "$got" == "overlay-hello" ]]; then
                echo "  [ok] overlay write/read"
            else
                echo "  [FAIL] overlay readback $got"
                failed=1
            fi
        else
            echo "  [FAIL] overlay write denied"
            cat "$WORKDIR/ov.log" || true
            failed=1
        fi
        fusermount3 -u "$mp" 2>/dev/null || true
        wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
    fi
else
    echo "  [skip] overlay fixture missing"
fi

# --- Folder bind ---
folder="$WORKDIR/bind-src"
mkdir -p "$folder/sub"
echo "bind-data" >"$folder/sub/x.txt"
mp="$WORKDIR/mnt-bind"
mkdir -p "$mp"
echo "  [run] folder bind mount"
"$RATARMOUNT_CMD" -f "$folder" "$mp" >"$WORKDIR/bind.log" 2>&1 &
MOUNT_PIDS+=($!)
if ! wait_mounted "$mp"; then
    echo "  [FAIL] bind mount"
    cat "$WORKDIR/bind.log" || true
    failed=1
else
    if [[ "$(cat "$mp/sub/x.txt")" == "bind-data" ]]; then
        echo "  [ok] folder bind"
    else
        echo "  [FAIL] folder bind content"
        failed=1
    fi
    fusermount3 -u "$mp" 2>/dev/null || true
    wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
fi

# --- commit-overlay (uncompressed TAR + GNU tar) ---
if command -v tar >/dev/null && tar --version 2>/dev/null | grep -q 'GNU tar'; then
    echo "  [run] --commit-overlay append new file"
    tdir="$WORKDIR/commit"
    mkdir -p "$tdir/src" "$tdir/ov" "$tdir/mnt"
    echo "orig" >"$tdir/src/a.txt"
    tar -cf "$tdir/a.tar" -C "$tdir/src" a.txt
    "$RATARMOUNT_CMD" -f -w "$tdir/ov" "$tdir/a.tar" "$tdir/mnt" >"$tdir/m.log" 2>&1 &
    MOUNT_PIDS+=($!)
    if ! wait_mounted "$tdir/mnt"; then
        echo "  [FAIL] commit-overlay mount"
        cat "$tdir/m.log" || true
        failed=1
    else
        echo "committed-new" >"$tdir/mnt/new.txt"
        fusermount3 -u "$tdir/mnt" 2>/dev/null || true
        wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
        if "$RATARMOUNT_CMD" --commit-overlay --yes -w "$tdir/ov" "$tdir/a.tar" >"$tdir/c.log" 2>&1; then
            if tar -tf "$tdir/a.tar" | grep -q 'new.txt'; then
                echo "  [ok] commit-overlay"
            else
                echo "  [FAIL] new.txt missing after commit"
                tar -tvf "$tdir/a.tar" || true
                cat "$tdir/c.log" || true
                failed=1
            fi
        else
            echo "  [FAIL] commit-overlay command"
            cat "$tdir/c.log" || true
            failed=1
        fi
    fi
else
    echo "  [skip] commit-overlay (need GNU tar)"
fi

if [[ $failed -ne 0 ]]; then
    echo "Complex-usage FAILED"
    exit 1
fi
echo "Complex-usage OK"
