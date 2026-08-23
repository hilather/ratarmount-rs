#!/usr/bin/env bash
# Custom SevenZip MountSource smoke tests.
#
# Python fixture rows come from phase9-sevenzip.txt. Rows with a
# `generated:` archive prefix build a SMALL_FOLDER_FULL_CACHE+ (4 MiB)
# AES+LZMA2 or BCJ+LZMA2 solid under a temp dir when a 7z CLI is present
# and `cat`/cmp a late member. Skip without 7z (the crate unit tests are
# the product gate).
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

# 3 MiB + 2 MiB unpack = 5 MiB > SMALL_FOLDER_FULL_CACHE (4 MiB). Same sizes
# as ratarmount-formats-sevenzip AES/BCJ progressive cargo tests.
A_LEN=$((3 * 1024 * 1024))
B_LEN=$((2 * 1024 * 1024))

find_sevenz() {
    local c
    for c in 7zz 7z 7za; do
        if command -v "$c" >/dev/null 2>&1; then
            printf '%s' "$c"
            return 0
        fi
    done
    return 1
}

# Build a solid 7z into dest/. Sets src to archive.7z and orig to the late
# member payload (b.bin). Returns 1 after a [skip] line on failure.
generate_solid_7z() {
    local kind=$1
    local sevenz=$2
    local dest=$3
    mkdir -p "$dest"
    local a="$dest/a.bin"
    local b="$dest/b.bin"
    local archive="$dest/archive.7z"
    # Repeating non-zero bytes so a wrong decode cannot pass as all-zero.
    head -c "$A_LEN" /dev/zero | tr '\0' 'A' >"$a"
    head -c "$B_LEN" /dev/zero | tr '\0' 'B' >"$b"
    local asize bsize
    asize=$(stat -c%s "$a" 2>/dev/null || echo 0)
    bsize=$(stat -c%s "$b" 2>/dev/null || echo 0)
    if [[ "$asize" -ne "$A_LEN" || "$bsize" -ne "$B_LEN" ]]; then
        echo "  [skip] generated:$kind: failed to write ${A_LEN}+${B_LEN} payloads"
        return 1
    fi
    rm -f "$archive"
    local -a args
    case "$kind" in
        aes-lzma2-solid-4mib)
            args=(a -t7z -m0=LZMA2 -mx=1 -ms=on -psecret -mhe=off -y)
            ;;
        bcj-lzma2-solid-4mib)
            args=(a -t7z -m0=BCJ -m1=LZMA2 -mx=1 -ms=on -y)
            ;;
        *)
            echo "  [skip] generated:$kind: unknown kind"
            return 1
            ;;
    esac
    local st=0
    (cd "$dest" && "$sevenz" "${args[@]}" archive.7z a.bin b.bin) >"$dest/7z.out" 2>"$dest/7z.err" || st=$?
    if [[ "$st" -gt 1 || ! -s "$archive" ]]; then
        echo "  [skip] generated:$kind: 7z create failed (exit $st): $(tr '\n' ' ' <"$dest/7z.err")"
        return 1
    fi
    src=$archive
    orig=$b
    return 0
}

# format: archive_relpath|member_path|expected_substring_or_empty[|password]
# generated:<kind> is built at runtime (see generate_solid_7z).
while IFS='|' read -r archive member expect password || [[ -n "${archive:-}" ]]; do
    [[ -z "${archive// }" || "$archive" =~ ^# ]] && continue
    archive="${archive//$'\r'/}"
    member="${member//$'\r'/}"
    expect="${expect//$'\r'/}"
    password="${password//$'\r'/}"
    src=""
    orig=""
    if [[ "$archive" == generated:* ]]; then
        kind="${archive#generated:}"
        if ! sevenz=$(find_sevenz); then
            echo "  [skip] $archive: 7z CLI (7zz/7z/7za) not found"
            continue
        fi
        if ! generate_solid_7z "$kind" "$sevenz" "$WORKDIR/gen/$kind"; then
            continue
        fi
    else
        src="$PY_ROOT/$archive"
        if [[ ! -f "$src" ]]; then
            echo "  [skip] missing $src"
            continue
        fi
    fi
    echo "  [run] $archive  (path=$member${password:+ password=***})"
    # Colons in generated:kind would make a surprising index filename.
    idx="$WORKDIR/${archive//[:\/]/_}.index.sqlite"
    rm -f "$idx"
    ratar_unmount "$WORKDIR/mnt"
    if [[ -n "${password:-}" ]]; then
        "$BIN" -f -c --index-file "$idx" --password "$password" "$src" "$WORKDIR/mnt" &
    else
        "$BIN" -f -c --index-file "$idx" "$src" "$WORKDIR/mnt" &
    fi
    pid=$!
    ok=0
    for _ in $(seq 1 200); do
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
    if [[ -n "$orig" ]]; then
        # Full read of the late member (cat/cmp), not only a 64-byte head.
        if ! cmp -s "$WORKDIR/mnt/$member" "$orig"; then
            echo "  [fail] cmp late member $member (size=$size)"
            kill "$pid" 2>/dev/null || true
            ratar_unmount "$WORKDIR/mnt"
            exit 1
        fi
        echo "  [ok] cmp late member $member (size=$size)"
    elif [[ -n "$expect" ]]; then
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
