#!/usr/bin/env bash
# Phase 3: gzip single-file and (later) tar.gz mount checks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

ALLOWLIST="${1:-$SCRIPT_DIR/phase3-gzip.txt}"
WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-phase3-$$"
mkdir -p "$WORKDIR"
MOUNT_PIDS=()

cleanup() {
    for pid in "${MOUNT_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for mp in "$WORKDIR"/mnt-*; do
        if [[ -d "$mp" ]]; then
            fusermount3 -u "$mp" 2>/dev/null || fusermount -u "$mp" 2>/dev/null || true
        fi
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

wait_mounted() {
    local mp=$1
    local i
    for i in $(seq 1 50); do
        if mount 2>/dev/null | grep -F -q "$mp"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

echo "==> Phase 3 gzip allowlist: $ALLOWLIST"
failed=0

while IFS=$'\t' read -r archive_rel path_in expected_md5 || [[ -n "${archive_rel:-}" ]]; do
    [[ -z "${archive_rel:-}" || "$archive_rel" =~ ^# ]] && continue
    archive="$RATARMOUNT_PY_ROOT/$archive_rel"
    [[ -f "$archive" ]] || { echo "  [skip] $archive"; continue; }
    name="$(basename "$archive")"
    mp="$WORKDIR/mnt-$name"
    mkdir -p "$mp"

    echo "  [run] $archive_rel -> $path_in"
    set +e
    "$RATARMOUNT_CMD" -f "$archive" "$mp" >"$WORKDIR/mount-$name.log" 2>&1 &
    mpid=$!
    set -e
    MOUNT_PIDS+=("$mpid")

    if ! wait_mounted "$mp"; then
        echo "  [FAIL] mount"
        cat "$WORKDIR/mount-$name.log" || true
        failed=1
        continue
    fi

    target="$mp/$path_in"
    if [[ ! -f "$target" ]]; then
        echo "  [FAIL] missing $path_in"
        ls -laR "$mp" || true
        failed=1
    else
        got=$(md5sum -- "$target" | awk '{print $1}')
        if [[ -n "${expected_md5:-}" && "$got" != "$expected_md5" ]]; then
            echo "  [FAIL] md5 got $got want $expected_md5"
            failed=1
        else
            echo "  [ok] md5 $got"
        fi
    fi
    fusermount3 -u "$mp" 2>/dev/null || true
    wait "$mpid" 2>/dev/null || true
done < "$ALLOWLIST"

if [[ $failed -ne 0 ]]; then
    echo "Phase 3 gzip FAILED"
    exit 1
fi
echo "Phase 3 gzip OK"
