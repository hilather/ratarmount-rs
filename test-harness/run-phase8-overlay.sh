#!/usr/bin/env bash
# Phase 8: write overlay create/read/delete/replace + size-0 create-then-write
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-phase8-$$"
mkdir -p "$WORKDIR"
MP="$WORKDIR/mnt"
OV="$WORKDIR/overlay"
IDX="$WORKDIR/idx.sqlite"
mkdir -p "$MP" "$OV"

cleanup() {
    set +e
    ratar_unmount "$MP"
    [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true
    wait "${PID:-}" 2>/dev/null || true
    rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

ARCHIVE="$RATARMOUNT_PY_ROOT/tests/single-file.tar"
echo "==> Phase 8 write overlay"

"$RATARMOUNT_CMD" -f -c -w "$OV" --index-file "$IDX" "$ARCHIVE" "$MP" \
    >"$WORKDIR/mount.log" 2>&1 &
PID=$!

if ! ratar_wait_mounted "$MP" 50; then
    echo "[FAIL] mount"
    cat "$WORKDIR/mount.log"
    exit 1
fi

# Existing archive file still readable
got=$(md5sum "$MP/bar" | awk '{print $1}')
want=d3b07384d113edec49eaa6238ad5ff00
if [[ "$got" != "$want" ]]; then
    echo "[FAIL] archive bar md5 $got want $want"
    exit 1
fi
echo "[ok] read archive file bar"

# Create new file in overlay
echo "hello overlay" >"$MP/newfile.txt"
if [[ ! -f "$OV/newfile.txt" ]]; then
    echo "[FAIL] newfile not in overlay dir"
    ls -la "$OV"
    exit 1
fi
got=$(cat "$MP/newfile.txt")
if [[ "$got" != "hello overlay" ]]; then
    echo "[FAIL] readback newfile: $got"
    exit 1
fi
echo "[ok] create+read newfile via overlay"

# readdir must list the newly created name (dir cache invalidation)
if ! ls -1 "$MP" | grep -qx 'newfile.txt'; then
    echo "[FAIL] readdir missing newfile.txt"
    ls -la "$MP" || true
    exit 1
fi
echo "[ok] readdir sees create"

# Replace existing archive member content via overlay
echo "replaced-content" >"$MP/bar"
got=$(cat "$MP/bar")
if [[ "$got" != "replaced-content" ]]; then
    echo "[FAIL] replace archive bar: $got"
    exit 1
fi
if [[ ! -f "$OV/bar" ]]; then
    echo "[FAIL] replaced bar not in overlay dir"
    ls -la "$OV"
    exit 1
fi
echo "[ok] replace existing archive member"

# Empty-file create then write payload (size-0 FileInfo / Empty backend regression shape)
: >"$MP/empty_then_write.txt"
sz=$(stat -c%s "$MP/empty_then_write.txt" 2>/dev/null || echo x)
if [[ "$sz" != "0" ]]; then
    echo "[FAIL] empty create size=$sz want 0"
    exit 1
fi
echo "payload-after-empty" >"$MP/empty_then_write.txt"
got=$(cat "$MP/empty_then_write.txt")
if [[ "$got" != "payload-after-empty" ]]; then
    echo "[FAIL] empty-then-write cat: $got"
    exit 1
fi
# touch + write variant (create then cat non-empty)
touch "$MP/touch_then_write.txt"
printf 'nonempty\n' >"$MP/touch_then_write.txt"
got=$(cat "$MP/touch_then_write.txt")
if [[ "$got" != "nonempty" ]]; then
    echo "[FAIL] touch-then-write cat: $got"
    exit 1
fi
echo "[ok] empty create then cat non-empty (size-0 shape)"

# Delete archive file (mark deleted)
rm -f "$MP/bar"
if [[ -e "$MP/bar" ]]; then
    echo "[FAIL] bar still visible after delete"
    exit 1
fi
echo "[ok] delete hides archive file"

# Delete + recreate same name (archive member path)
echo "recreated-bar" >"$MP/bar"
got=$(cat "$MP/bar")
if [[ "$got" != "recreated-bar" ]]; then
    echo "[FAIL] delete+recreate bar: $got"
    exit 1
fi
if [[ ! -f "$OV/bar" ]]; then
    echo "[FAIL] recreated bar not in overlay dir"
    exit 1
fi
echo "[ok] delete+recreate same name (archive member)"

# Delete + recreate pure overlay name
echo "first" >"$MP/recreate_me.txt"
rm -f "$MP/recreate_me.txt"
if [[ -e "$MP/recreate_me.txt" ]]; then
    echo "[FAIL] recreate_me still visible after delete"
    exit 1
fi
echo "second" >"$MP/recreate_me.txt"
got=$(cat "$MP/recreate_me.txt")
if [[ "$got" != "second" ]]; then
    echo "[FAIL] overlay delete+recreate: $got"
    exit 1
fi
echo "[ok] delete+recreate same name (overlay-only)"

# mkdir
mkdir -p "$MP/subdir"
echo x >"$MP/subdir/x"
[[ -f "$OV/subdir/x" ]] || {
    echo "[FAIL] subdir write"
    exit 1
}
echo "[ok] mkdir + nested write"

echo "Phase 8 write overlay OK"
