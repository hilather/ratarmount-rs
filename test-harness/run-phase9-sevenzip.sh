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
trap 'ratar_unmount "$WORKDIR/mnt"; rm -rf "$WORKDIR" || true' EXIT

mkdir -p "$WORKDIR/mnt"
echo "RATARMOUNT_CMD=$BIN"
echo "==> SevenZip allowlist: $ALLOWLIST"

# format: archive_relpath|member_path|expected_substring_or_empty[|password]
while IFS='|' read -r archive member expect password || [[ -n "${archive:-}" ]]; do
    [[ -z "${archive// }" || "$archive" =~ ^# ]] && continue
    archive="${archive//$'\r'/}"
    member="${member//$'\r'/}"
    expect="${expect//$'\r'/}"
    password="${password//$'\r'/}"
    src="$PY_ROOT/$archive"
    if [[ ! -f "$src" ]]; then
        echo "  [skip] missing $src"
        continue
    fi
    echo "  [run] $archive  (path=$member${password:+ password=***})"
    idx="$WORKDIR/$(basename "$archive").index.sqlite"
    rm -f "$idx"
    ratar_unmount "$WORKDIR/mnt"
    if [[ -n "${password:-}" ]]; then
        "$BIN" -f -c --index-file "$idx" --password "$password" "$src" "$WORKDIR/mnt" &
    else
        "$BIN" -f -c --index-file "$idx" "$src" "$WORKDIR/mnt" &
    fi
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
        ratar_unmount "$WORKDIR/mnt"
        exit 1
    fi
    size=$(stat -c%s "$WORKDIR/mnt/$member" 2>/dev/null || echo 0)
    if [[ -n "$expect" ]]; then
        got=$(head -c 64 "$WORKDIR/mnt/$member" 2>/dev/null || true)
        if [[ "$got" != *"$expect"* ]]; then
            echo "  [fail] expected substring '$expect' in head of $member, got: $got"
            kill "$pid" 2>/dev/null || true
            ratar_unmount "$WORKDIR/mnt"
            exit 1
        fi
        echo "  [ok] content contains '$expect' (size=$size)"
    else
        if [[ "$size" -le 0 ]]; then
            echo "  [fail] empty member $member"
            kill "$pid" 2>/dev/null || true
            ratar_unmount "$WORKDIR/mnt"
            exit 1
        fi
        echo "  [ok] size=$size"
    fi
    ratar_unmount "$WORKDIR/mnt"
    wait "$pid" 2>/dev/null || true
done < "$ALLOWLIST"

echo "Phase 9 sevenzip OK"
