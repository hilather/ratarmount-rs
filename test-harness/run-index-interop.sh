#!/usr/bin/env bash
# Index interop goldens: Python builds SQLite index → Rust mounts with that index;
# optionally reverse (Rust index → Python open if available).
#
# Exit criteria (parity-todo P1): TAR + ZIP + 7z interop paths green.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-interop-$$"
mkdir -p "$WORKDIR"
MOUNT_PIDS=()

cleanup() {
    set +e
    for pid in "${MOUNT_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for mp in "$WORKDIR"/mnt-*; do
        if [[ -d "$mp" ]]; then
            ratar_unmount "$mp"
        fi
    done
    rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

wait_mounted() {
    local mp=$1 i
    for i in $(seq 1 80); do
        if mount 2>/dev/null | grep -F -q "$mp"; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

# Prefer venv Python from the Python tree.
PY=python3
if [[ -x "$RATARMOUNT_PY_ROOT/.venv/bin/python" ]]; then
    PY="$RATARMOUNT_PY_ROOT/.venv/bin/python"
elif [[ -x "$RATARMOUNT_PY_ROOT/venv/bin/python" ]]; then
    PY="$RATARMOUNT_PY_ROOT/venv/bin/python"
fi

echo "==> Index interop goldens"
echo "    RATARMOUNT_CMD=$RATARMOUNT_CMD"
echo "    RATARMOUNT_PY_ROOT=$RATARMOUNT_PY_ROOT"
echo "    PYTHON=$PY"

failed=0

# Cases: archive_rel | member | md5_or_dot | backend_label
# backend_label is informational (Python open_mount_source chooses automatically).
CASES=(
    "tests/single-file.tar|bar|d3b07384d113edec49eaa6238ad5ff00|tar"
    "tests/single-nested-file.tar|foo/fighter/ufo|2709a3348eb2c52302a7606ecf5860bc|tar"
    "tests/nested-with-symlink.zip|foo/fighter/ufo|2709a3348eb2c52302a7606ecf5860bc|zip"
    "tests/store-copy-two-files.7z|a.txt|.|7z"
)

build_index_python() {
    local archive=$1
    local index=$2
    # Build index with Python ratarmountcore (no FUSE).
    "$PY" - "$archive" "$index" <<'PY'
import os, sys
archive, index = sys.argv[1], sys.argv[2]
if os.path.exists(index):
    os.remove(index)
# Ensure core is importable from the Python checkout.
root = os.environ.get("RATARMOUNT_PY_ROOT", "")
sys.path[:0] = [
    os.path.join(root, "core"),
    os.path.join(root),
]
from ratarmountcore.mountsource.factory import open_mount_source

ms = open_mount_source(
    archive,
    writeIndex=True,
    indexFilePath=index,
    clearIndexCache=True,
    recursive=False,
)
# Force full index materialization
_ = ms.list("/")
try:
    if hasattr(ms, "__exit__"):
        ms.__exit__(None, None, None)
    elif hasattr(ms, "close"):
        ms.close()
except Exception:
    pass
assert os.path.isfile(index) and os.path.getsize(index) > 0, "python index missing"
print(f"python index ok: {index} ({os.path.getsize(index)} bytes)")
PY
}

run_case() {
    local archive_rel=$1 member=$2 expect=$3 label=$4
    local archive="$RATARMOUNT_PY_ROOT/$archive_rel"
    local name
    name="$(basename "$archive")"
    local idx="$WORKDIR/${name}.py.index.sqlite"
    local mp="$WORKDIR/mnt-$name"
    mkdir -p "$mp"

    echo "  [py→rs] $archive_rel ($label) -> $member"
    if [[ ! -f "$archive" ]]; then
        echo "  [skip] missing $archive"
        return
    fi

    set +e
    out=$(build_index_python "$archive" "$idx" 2>&1)
    rc=$?
    set -e
    echo "$out" | sed 's/^/    /'
    if [[ $rc -ne 0 ]]; then
        echo "  [FAIL] python index build rc=$rc"
        failed=1
        return
    fi

    # Rust: load existing index, do not recreate (-c off), mount foreground.
    set +e
    "$RATARMOUNT_CMD" -f --index-file "$idx" "$archive" "$mp" \
        >"$WORKDIR/mount-$name.log" 2>&1 &
    mpid=$!
    set -e
    MOUNT_PIDS+=("$mpid")

    if ! wait_mounted "$mp"; then
        echo "  [FAIL] rust mount with python index"
        cat "$WORKDIR/mount-$name.log" || true
        failed=1
        kill "$mpid" 2>/dev/null || true
        return
    fi

    # Confirm index was loaded (not rebuilt) when log is available.
    if grep -q 'Creating offset dictionary' "$WORKDIR/mount-$name.log" 2>/dev/null; then
        # Some backends may still log create if load fails; treat as soft warning.
        if ! grep -q 'Successfully loaded offset dictionary' "$WORKDIR/mount-$name.log" 2>/dev/null; then
            echo "  [FAIL] expected load of python index, saw rebuild only"
            cat "$WORKDIR/mount-$name.log" || true
            failed=1
            ratar_unmount "$mp"
            wait "$mpid" 2>/dev/null || true
            return
        fi
        echo "  [warn] saw create log; also loaded — check backend"
    fi

    target="$mp/$member"
    if [[ ! -e "$target" && ! -L "$target" ]]; then
        echo "  [FAIL] missing member $member"
        ls -laR "$mp" || true
        cat "$WORKDIR/mount-$name.log" || true
        failed=1
    elif [[ -f "$target" && "$expect" != "." ]]; then
        got=$(md5sum -- "$target" | awk '{print $1}')
        if [[ "$got" != "$expect" ]]; then
            echo "  [FAIL] md5 got $got want $expect"
            failed=1
        else
            echo "  [ok] md5 $got"
        fi
    else
        echo "  [ok] path exists $member"
    fi

    ratar_unmount "$mp"
    wait "$mpid" 2>/dev/null || true
}

# Reverse: Rust builds index, verify Python can open it (best-effort).
run_reverse_tar() {
    local archive_rel="tests/single-file.tar"
    local archive="$RATARMOUNT_PY_ROOT/$archive_rel"
    local idx="$WORKDIR/single-file.tar.rs.index.sqlite"
    echo "  [rs→py] $archive_rel"
    if [[ ! -f "$archive" ]]; then
        echo "  [skip] missing archive"
        return
    fi
    rm -f "$idx"
    if ! "$RATARMOUNT_CMD" --no-mount -c --index-file "$idx" "$archive" >/dev/null 2>&1; then
        echo "  [FAIL] rust index create"
        failed=1
        return
    fi
    set +e
    out=$(
        "$PY" - "$archive" "$idx" 2>&1 <<'PY'
import os, sys
archive, index = sys.argv[1], sys.argv[2]
root = os.environ.get("RATARMOUNT_PY_ROOT", "")
sys.path[:0] = [os.path.join(root, "core"), root]
from ratarmountcore.mountsource.factory import open_mount_source
ms = open_mount_source(archive, writeIndex=False, indexFilePath=index, clearIndexCache=False)
info = ms.lookup("/bar")
assert info is not None and info.size == 4, info
f = ms.open(info)
data = f.read()
assert data == b"foo\n", data  # tests/single-file.tar member "bar"
print(f"python opened rust index; /bar size={info.size} data={data!r}")
try:
    if hasattr(ms, "__exit__"):
        ms.__exit__(None, None, None)
    elif hasattr(ms, "close"):
        ms.close()
except Exception:
    pass
PY
    )
    rc=$?
    set -e
    echo "$out" | sed 's/^/    /'
    if [[ $rc -ne 0 ]]; then
        echo "  [FAIL] python could not open rust index"
        failed=1
    else
        echo "  [ok] rs→py tar index"
    fi
}

for case in "${CASES[@]}"; do
    IFS='|' read -r ar mem md lab <<<"$case"
    run_case "$ar" "$mem" "$md" "$lab"
done

run_reverse_tar

if [[ $failed -ne 0 ]]; then
    echo "Index interop FAILED"
    exit 1
fi
echo "Index interop OK"
