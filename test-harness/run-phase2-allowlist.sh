#!/usr/bin/env bash
# Phase-gated smoke: index create/load + FUSE mount + content check.
# Does NOT set full Python TEST_EXTERNAL_COMMAND expansion of pytestedTests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

ALLOWLIST="${1:-$SCRIPT_DIR/phase2-tar.txt}"
WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-phase2-$$"
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
        if mountpoint -q "$mp" 2>/dev/null || mount 2>/dev/null | grep -F -q "$mp"; then
            return 0
        fi
        # FUSE often makes ls work even before mountpoint is reliable
        if [[ -n "$(ls -A "$mp" 2>/dev/null || true)" ]] || [[ -e "$mp/." ]]; then
            # empty tar has no children; check that mount isn't just empty dir via findfs
            if mount 2>/dev/null | grep -F -q "$mp"; then
                return 0
            fi
        fi
        sleep 0.1
    done
    return 1
}

echo "==> Phase 2 allowlist: $ALLOWLIST"

failed=0
while IFS=$'\t' read -r archive_rel path_in expected_md5 || [[ -n "${archive_rel:-}" ]]; do
    [[ -z "${archive_rel:-}" || "$archive_rel" =~ ^# ]] && continue
    archive="$RATARMOUNT_PY_ROOT/$archive_rel"
    if [[ ! -f "$archive" ]]; then
        echo "  [skip] missing $archive"
        continue
    fi
    name="$(basename "$archive")"
    mp="$WORKDIR/mnt-$name"
    idx="$WORKDIR/$name.index.sqlite"
    mkdir -p "$mp"

    echo "  [run] $archive_rel  (path=$path_in md5=${expected_md5:-none})"
    set +e
    out="$("$RATARMOUNT_CMD" -f -c --no-mount \
        --ignore-zeros --detect-gnu-incremental --recursive \
        -P 1 --index-file "$idx" \
        "$archive" 2>&1)"
    rc=$?
    set -e
    echo "$out"

    if [[ $rc -ne 0 ]]; then
        echo "  [FAIL] index create rc=$rc"
        failed=1
        continue
    fi
    if ! grep -q 'Creating offset dictionary' <<<"$out"; then
        echo "  [FAIL] missing log: Creating offset dictionary"
        failed=1
        continue
    fi
    set +e
    out2="$("$RATARMOUNT_CMD" -f --no-mount --index-file "$idx" "$archive" 2>&1)"
    rc2=$?
    set -e
    echo "$out2"
    if [[ $rc2 -ne 0 ]]; then
        echo "  [FAIL] index load rc=$rc2"
        failed=1
        continue
    fi
    if ! grep -q 'Successfully loaded offset dictionary' <<<"$out2"; then
        echo "  [FAIL] missing log: Successfully loaded offset dictionary"
        failed=1
        continue
    fi

    # FUSE mount + content (skip path_in == .)
    if [[ "$path_in" != "." ]]; then
        set +e
        "$RATARMOUNT_CMD" -f --index-file "$idx" "$archive" "$mp" \
            >"$WORKDIR/mount-$name.log" 2>&1 &
        mpid=$!
        set -e
        MOUNT_PIDS+=("$mpid")
        if ! wait_mounted "$mp"; then
            echo "  [FAIL] mount did not come up"
            cat "$WORKDIR/mount-$name.log" || true
            kill "$mpid" 2>/dev/null || true
            failed=1
            continue
        fi
        target="$mp/$path_in"
        if [[ ! -e "$target" ]]; then
            echo "  [FAIL] missing mounted path: $path_in"
            ls -laR "$mp" || true
            fusermount3 -u "$mp" 2>/dev/null || true
            kill "$mpid" 2>/dev/null || true
            failed=1
            continue
        fi
        if [[ -f "$target" ]]; then
            got=$(md5sum -- "$target" | awk '{print $1}')
            if [[ -n "${expected_md5:-}" && "$got" != "$expected_md5" ]]; then
                echo "  [FAIL] md5 mismatch for $path_in: got $got want $expected_md5"
                failed=1
            else
                echo "  [ok] md5 $got"
            fi
        else
            echo "  [ok] path exists (dir) $path_in"
        fi
        fusermount3 -u "$mp" 2>/dev/null || fusermount -u "$mp" 2>/dev/null || true
        wait "$mpid" 2>/dev/null || true
    fi

    echo "  [ok] $archive_rel"
done < "$ALLOWLIST"

if [[ $failed -ne 0 ]]; then
    echo "Phase 2 allowlist FAILED"
    exit 1
fi
echo "Phase 2 allowlist OK"
