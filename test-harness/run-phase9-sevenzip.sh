#!/usr/bin/env bash
# Custom SevenZip MountSource smoke tests.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=env.sh
source "$ROOT/test-harness/env.sh"

BIN="${RATARMOUNT_CMD:-$ROOT/target/release/ratarmount}"
PY_ROOT="${RATARMOUNT_PY_ROOT:-$ROOT/../ratarmount}"
ALLOWLIST="${1:-$ROOT/test-harness/phase9-sevenzip.txt}"
WORKDIR=$(mktemp -d /tmp/ratarmount-rs-7z-XXXXXX)
trap 'fusermount3 -u "$WORKDIR/mnt" 2>/dev/null || true; rm -rf "$WORKDIR"' EXIT

mkdir -p "$WORKDIR/mnt"
echo "RATARMOUNT_CMD=$BIN"
echo "==> SevenZip allowlist: $ALLOWLIST"

while IFS='|' read -r archive member expect || [[ -n "${archive:-}" ]]; do
    [[ -z "${archive// }" || "$archive" =~ ^# ]] && continue
    archive="${archive//$'\r'/}"
    member="${member//$'\r'/}"
    expect="${expect//$'\r'/}"
    src="$PY_ROOT/$archive"
    if [[ ! -f "$src" ]]; then
        echo "  [skip] missing $src"
        continue
    fi
    echo "  [run] $archive  (path=$member)"
    idx="$WORKDIR/$(basename "$archive").index.sqlite"
    rm -f "$idx"
    fusermount3 -u "$WORKDIR/mnt" 2>/dev/null || true
    "$BIN" -f -c --index-file "$idx" "$src" "$WORKDIR/mnt" &
    pid=$!
    ok=0
    for _ in $(seq 1 100); do
        if [[ -e "$WORKDIR/mnt/$member" ]] || ls "$WORKDIR/mnt" &>/dev/null; then
            if [[ -e "$WORKDIR/mnt/$member" ]]; then
                ok=1
                break
            fi
        fi
        sleep 0.05
    done
    if [[ $ok -ne 1 ]]; then
        echo "  [fail] mount/member not ready: $member"
        kill "$pid" 2>/dev/null || true
        fusermount3 -u "$WORKDIR/mnt" 2>/dev/null || true
        exit 1
    fi
    size=$(stat -c%s "$WORKDIR/mnt/$member" 2>/dev/null || echo 0)
    if [[ -n "$expect" ]]; then
        got=$(head -c 64 "$WORKDIR/mnt/$member" 2>/dev/null || true)
        if [[ "$got" != *"$expect"* ]]; then
            echo "  [fail] expected substring '$expect' in head of $member, got: $got"
            kill "$pid" 2>/dev/null || true
            fusermount3 -u "$WORKDIR/mnt" 2>/dev/null || true
            exit 1
        fi
        echo "  [ok] content contains '$expect' (size=$size)"
    else
        if [[ "$size" -le 0 ]]; then
            echo "  [fail] empty member $member"
            kill "$pid" 2>/dev/null || true
            fusermount3 -u "$WORKDIR/mnt" 2>/dev/null || true
            exit 1
        fi
        echo "  [ok] size=$size"
    fi
    fusermount3 -u "$WORKDIR/mnt" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
done < "$ALLOWLIST"

echo "Phase 9 sevenzip OK"
