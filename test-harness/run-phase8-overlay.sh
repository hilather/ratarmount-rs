#!/usr/bin/env bash
# Phase 8: write overlay create/read/delete
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
    ratar_unmount "$MP"
    [[ -n "${PID:-}" ]] && kill "$PID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

ARCHIVE="$RATARMOUNT_PY_ROOT/tests/single-file.tar"
echo "==> Phase 8 write overlay"

"$RATARMOUNT_CMD" -f -c -w "$OV" --index-file "$IDX" "$ARCHIVE" "$MP" \
    >"$WORKDIR/mount.log" 2>&1 &
PID=$!

for i in $(seq 1 50); do
    mount 2>/dev/null | grep -F -q "$MP" && break
    sleep 0.1
done

if ! mount 2>/dev/null | grep -F -q "$MP"; then
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
echo "hello overlay" > "$MP/newfile.txt"
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

# Delete archive file (mark deleted)
rm -f "$MP/bar"
if [[ -e "$MP/bar" ]]; then
    echo "[FAIL] bar still visible after delete"
    exit 1
fi
echo "[ok] delete hides archive file"

# mkdir
mkdir -p "$MP/subdir"
echo x > "$MP/subdir/x"
[[ -f "$OV/subdir/x" ]] || { echo "[FAIL] subdir write"; exit 1; }
echo "[ok] mkdir + nested write"

echo "Phase 8 write overlay OK"
