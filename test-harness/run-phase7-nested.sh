#!/usr/bin/env bash
# Phase 7: recursive automount (requires -r)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

ALLOWLIST="${1:-$SCRIPT_DIR/phase7-nested.txt}"
WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-phase7-$$"
mkdir -p "$WORKDIR"
MOUNT_PIDS=()

cleanup() {
    for pid in "${MOUNT_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    for mp in "$WORKDIR"/mnt-*; do
        [[ -d "$mp" ]] && ratar_unmount "$mp"
    done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

wait_mounted() {
    local mp=$1 i
    for i in $(seq 1 50); do
        mount 2>/dev/null | grep -F -q "$mp" && return 0
        sleep 0.1
    done
    return 1
}

echo "==> Phase 7 nested: $ALLOWLIST"
failed=0
declare -A MOUNTED_ARCHIVES=()

while IFS=$'\t' read -r archive_rel path_in expected_md5 || [[ -n "${archive_rel:-}" ]]; do
    [[ -z "${archive_rel:-}" || "$archive_rel" =~ ^# ]] && continue
    archive="$RATARMOUNT_PY_ROOT/$archive_rel"
    [[ -f "$archive" ]] || { echo "  [skip] $archive"; continue; }

    name="$(basename "$archive")"
    mp="$WORKDIR/mnt-$name"
    idx="$WORKDIR/$name.index.sqlite"

    if [[ -z "${MOUNTED_ARCHIVES[$name]:-}" ]]; then
        mkdir -p "$mp"
        echo "  [mount -r] $archive_rel"
        set +e
        "$RATARMOUNT_CMD" -f -c -r --ignore-zeros --detect-gnu-incremental \
            --index-file "$idx" "$archive" "$mp" \
            >"$WORKDIR/mount-$name.log" 2>&1 &
        mpid=$!
        set -e
        MOUNT_PIDS+=("$mpid")
        MOUNTED_ARCHIVES[$name]=1
        if ! wait_mounted "$mp"; then
            echo "  [FAIL] mount"
            cat "$WORKDIR/mount-$name.log" || true
            failed=1
            continue
        fi
    fi

    target="$mp/$path_in"
    echo "  [check] $archive_rel :: $path_in"
    if [[ ! -f "$target" ]]; then
        echo "  [FAIL] missing $path_in"
        find "$mp" 2>/dev/null | head -40 || true
        failed=1
        continue
    fi
    got=$(md5sum -- "$target" | awk '{print $1}')
    if [[ "$got" != "$expected_md5" ]]; then
        echo "  [FAIL] md5 got $got want $expected_md5"
        failed=1
    else
        echo "  [ok] md5 $got"
    fi
done < "$ALLOWLIST"

if [[ $failed -ne 0 ]]; then
    echo "Phase 7 nested FAILED"
    exit 1
fi
echo "Phase 7 nested OK"
