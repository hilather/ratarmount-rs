#!/usr/bin/env bash
# G7.3: IndexJob-written SQLite sidecars still open in Python ratarmount 0.7.x.
#
# Schema is always covered by:
#   cargo test -p ratarmount-session --lib index_job_sidecar_python_07_schema
# This script skips (exit 0) when Python ratarmountcore is absent.
#
# Usage (from repo root):
#   ./test-harness/run-indexjob-python-interop.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-indexjob-interop-$$"
mkdir -p "$WORKDIR"
cleanup() { rm -rf "$WORKDIR" || true; }
trap cleanup EXIT

# Locate a Python that can import ratarmountcore (venv, sibling tree, or system).
if [[ -z "${RATARMOUNT_PY_ROOT:-}" ]]; then
    if [[ -d "$ROOT/../ratarmount/tests" ]]; then
        RATARMOUNT_PY_ROOT="$(cd "$ROOT/../ratarmount" && pwd)"
    elif [[ -d "$ROOT/../ratarmount-py/tests" ]]; then
        RATARMOUNT_PY_ROOT="$(cd "$ROOT/../ratarmount-py" && pwd)"
    fi
fi
export RATARMOUNT_PY_ROOT="${RATARMOUNT_PY_ROOT:-}"

PY=""
for cand in \
    "${RATARMOUNT_PY_ROOT:+$RATARMOUNT_PY_ROOT/.venv/bin/python}" \
    "${RATARMOUNT_PY_ROOT:+$RATARMOUNT_PY_ROOT/venv/bin/python}" \
    python3 \
    python
do
    [[ -n "$cand" ]] || continue
    if ! command -v "$cand" >/dev/null 2>&1 && [[ ! -x "$cand" ]]; then
        continue
    fi
    if RATARMOUNT_PY_ROOT="$RATARMOUNT_PY_ROOT" "$cand" - <<'PY' >/dev/null 2>&1
import os, sys
root = os.environ.get("RATARMOUNT_PY_ROOT", "")
if root:
    sys.path[:0] = [os.path.join(root, "core"), root]
from ratarmountcore.mountsource.factory import open_mount_source
PY
    then
        PY="$cand"
        break
    fi
done

if [[ -z "$PY" ]]; then
    echo "skip: python ratarmount 0.7.x not available"
    exit 0
fi

echo "==> IndexJob → Python 0.7.x interop"
echo "    PYTHON=$PY"
echo "    RATARMOUNT_PY_ROOT=${RATARMOUNT_PY_ROOT:-}"

write_indexjob_sidecar() {
    local archive=$1
    local index=$2
    rm -f "$index"
    if command -v cargo >/dev/null 2>&1; then
        # IndexJob::run via the schema unit test (env write path).
        if ! (
            cd "$ROOT"
            RATARMOUNT_INDEXJOB_ARCHIVE="$archive" RATARMOUNT_INDEXJOB_INDEX="$index" \
                cargo test -p ratarmount-session --lib index_job_sidecar_python_07_schema \
                -- --nocapture
        ); then
            echo "  [FAIL] IndexJob sidecar write (cargo test)"
            return 1
        fi
        return 0
    fi
    # Fallback allowed by G7.3: CLI cold index writes the same 0.7.x schema.
    local cmd="${RATARMOUNT_CMD:-}"
    if [[ -z "$cmd" ]]; then
        if [[ -x "$ROOT/target/release/ratarmount" ]]; then
            cmd="$ROOT/target/release/ratarmount"
        elif [[ -x "$ROOT/target/debug/ratarmount" ]]; then
            cmd="$ROOT/target/debug/ratarmount"
        fi
    fi
    if [[ -n "$cmd" ]]; then
        echo "  [info] cargo missing; falling back to $cmd --no-mount -c"
        if ! "$cmd" --no-mount -c --index-file "$index" "$archive"; then
            echo "  [FAIL] rust index create"
            return 1
        fi
        return 0
    fi
    echo "skip: neither cargo nor ratarmount binary to write IndexJob sidecar"
    return 2
}

python_open_member() {
    local archive=$1
    local index=$2
    local member=$3
    RATARMOUNT_PY_ROOT="$RATARMOUNT_PY_ROOT" "$PY" - "$archive" "$index" "$member" <<'PY'
import os, sys
archive, index, member = sys.argv[1], sys.argv[2], sys.argv[3]
root = os.environ.get("RATARMOUNT_PY_ROOT", "")
sys.path[:0] = [os.path.join(root, "core"), root]
from ratarmountcore.mountsource.factory import open_mount_source

before = os.path.getmtime(index), os.path.getsize(index)
ms = open_mount_source(
    archive, writeIndex=False, indexFilePath=index, clearIndexCache=False
)
listing = ms.list("/")
assert listing, listing
path = member if member.startswith("/") else "/" + member
info = ms.lookup(path)
assert info is not None, (path, listing)
print(f"python opened IndexJob sidecar; {path} size={info.size} listing={list(listing)}")
try:
    if hasattr(ms, "__exit__"):
        ms.__exit__(None, None, None)
    elif hasattr(ms, "close"):
        ms.close()
except Exception:
    pass
after = os.path.getmtime(index), os.path.getsize(index)
assert after == before, (before, after)
PY
}

make_tar() {
    local dest=$1
    "$PY" - "$dest" <<'PY'
import io, sys, tarfile
dest = sys.argv[1]
data = b"foo\n"
info = tarfile.TarInfo("bar")
info.size = len(data)
with tarfile.open(dest, "w") as tf:
    tf.addfile(info, io.BytesIO(data))
PY
}

make_zip() {
    local dest=$1
    "$PY" - "$dest" <<'PY'
import sys, zipfile
dest = sys.argv[1]
with zipfile.ZipFile(dest, "w") as zf:
    zf.writestr("bar", b"foo\n")
PY
}

failed=0
skipped_write=0

run_case() {
    local label=$1 archive=$2 member=$3
    local idx="$WORKDIR/${label}.index.sqlite"
    echo "  [indexjob→py] $label -> $member"
    if [[ ! -f "$archive" ]]; then
        echo "  [skip] missing $archive"
        return
    fi
    set +e
    write_indexjob_sidecar "$archive" "$idx"
    local wrc=$?
    set -e
    if [[ $wrc -eq 2 ]]; then
        skipped_write=1
        return
    elif [[ $wrc -ne 0 ]]; then
        failed=1
        return
    fi
    if [[ ! -f "$idx" ]]; then
        echo "  [FAIL] sidecar missing after IndexJob write"
        failed=1
        return
    fi
    set +e
    local out
    out=$(python_open_member "$archive" "$idx" "$member" 2>&1)
    local rc=$?
    set -e
    echo "$out" | sed 's/^/    /'
    if [[ $rc -ne 0 ]]; then
        echo "  [FAIL] python could not open IndexJob sidecar ($label)"
        failed=1
    else
        echo "  [ok] indexjob→py $label"
    fi
}

# TAR always (self-made; no Python fixture tree required).
TAR="$WORKDIR/g73.tar"
make_tar "$TAR"
run_case "tar" "$TAR" "bar"
if [[ $skipped_write -eq 1 ]]; then
    echo "skip: neither cargo nor ratarmount binary to write IndexJob sidecar"
    exit 0
fi

# ZIP: Python zipfile (always) or fixture.
ZIP="$WORKDIR/g73.zip"
make_zip "$ZIP"
run_case "zip" "$ZIP" "bar"

# 7z: fixture if present, else 7z CLI, else skip this format only.
SEVEN=
if [[ -n "${RATARMOUNT_PY_ROOT:-}" && -f "$RATARMOUNT_PY_ROOT/tests/store-copy-two-files.7z" ]]; then
    SEVEN="$RATARMOUNT_PY_ROOT/tests/store-copy-two-files.7z"
    run_case "7z" "$SEVEN" "a.txt"
else
    SEVEN_BIN=""
    for c in 7z 7za 7zr; do
        if command -v "$c" >/dev/null 2>&1; then
            SEVEN_BIN="$c"
            break
        fi
    done
    if [[ -n "$SEVEN_BIN" ]]; then
        echo foo >"$WORKDIR/a.txt"
        SEVEN="$WORKDIR/g73.7z"
        if (cd "$WORKDIR" && "$SEVEN_BIN" a -mx=0 g73.7z a.txt >/dev/null); then
            run_case "7z" "$SEVEN" "a.txt"
        else
            echo "  [skip] $SEVEN_BIN failed to create store 7z"
        fi
    else
        echo "  [skip] no 7z fixture or 7z CLI"
    fi
fi

if [[ $failed -ne 0 ]]; then
    echo "IndexJob Python interop FAILED"
    exit 1
fi
echo "IndexJob Python interop OK"
