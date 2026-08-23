#!/usr/bin/env bash
# Complex-usage subset: multi-source union, write overlay, commit-overlay (tar/gz/zip), B-4,
# versioned FUSE (.versions on updated-file.tar).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-complex-$$"
mkdir -p "$WORKDIR"
MOUNT_PIDS=()

cleanup() {
    set +e
    for pid in "${MOUNT_PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${MOUNT_PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
    for mp in "$WORKDIR"/mnt-*; do
        [[ -d "$mp" ]] && ratar_unmount "$mp"
    done
    # also nested workdirs used by commit helpers
    for mp in "$WORKDIR"/*/mnt; do
        [[ -d "$mp" ]] && ratar_unmount "$mp"
    done
    rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

wait_mounted() {
    local mp=$1
    if command -v ratar_wait_mounted >/dev/null 2>&1; then
        ratar_wait_mounted "$mp" 60
        return $?
    fi
    local i
    for i in $(seq 1 60); do
        mount 2>/dev/null | grep -F -q "$mp" && return 0
        sleep 0.05
    done
    return 1
}

echo "==> Complex-usage subset"
failed=0

# --- Union of two TARs: second shadows first ---
TAR1="$RATARMOUNT_PY_ROOT/tests/single-file.tar"
TAR2="$RATARMOUNT_PY_ROOT/tests/single-nested-file.tar"
if [[ -f "$TAR1" && -f "$TAR2" ]]; then
    mp="$WORKDIR/mnt-union"
    mkdir -p "$mp"
    echo "  [run] union single-file.tar + single-nested-file.tar"
    "$RATARMOUNT_CMD" -f "$TAR1" "$TAR2" "$mp" >"$WORKDIR/union.log" 2>&1 &
    MOUNT_PIDS+=($!)
    if ! wait_mounted "$mp"; then
        echo "  [FAIL] union mount"
        cat "$WORKDIR/union.log" || true
        failed=1
    else
        # Nested path from TAR2 must be visible
        if [[ -f "$mp/foo/fighter/ufo" ]]; then
            got=$(md5sum "$mp/foo/fighter/ufo" | awk '{print $1}')
            if [[ "$got" == "2709a3348eb2c52302a7606ecf5860bc" ]]; then
                echo "  [ok] union nested path md5 $got"
            else
                echo "  [FAIL] union md5 $got"
                failed=1
            fi
        else
            echo "  [FAIL] union missing foo/fighter/ufo"
            ls -laR "$mp" || true
            failed=1
        fi
        ratar_unmount "$mp"
        wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
    fi
else
    echo "  [skip] union fixtures missing"
fi

# --- Union rightmost wins content (folder binds) ---
f1="$WORKDIR/union-left"
f2="$WORKDIR/union-right"
mkdir -p "$f1" "$f2"
echo "from-left" >"$f1/shared.txt"
echo "from-right" >"$f2/shared.txt"
echo "only-left" >"$f1/left-only.txt"
echo "only-right" >"$f2/right-only.txt"
mp="$WORKDIR/mnt-union-rw"
mkdir -p "$mp"
echo "  [run] union rightmost wins (folder binds)"
"$RATARMOUNT_CMD" -f "$f1" "$f2" "$mp" >"$WORKDIR/union-rw.log" 2>&1 &
MOUNT_PIDS+=($!)
if ! wait_mounted "$mp"; then
    echo "  [FAIL] union rightmost mount"
    cat "$WORKDIR/union-rw.log" || true
    failed=1
else
    got=$(cat "$mp/shared.txt" 2>/dev/null || true)
    if [[ "$got" == "from-right" ]]; then
        echo "  [ok] union rightmost content"
    else
        echo "  [FAIL] union rightmost got '$got' want from-right"
        failed=1
    fi
    if [[ -f "$mp/left-only.txt" && -f "$mp/right-only.txt" ]]; then
        echo "  [ok] union merges both sides"
    else
        echo "  [FAIL] union missing left-only or right-only"
        ls -la "$mp" || true
        failed=1
    fi
    ratar_unmount "$mp"
    wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
fi

# --- B-4: directory wins over symlink in union (both mount orders) ---
b1="$WORKDIR/b4/branch1"
b2="$WORKDIR/b4/branch2"
mkdir -p "$b1/subdir1/subdir2" "$b2/subdir0/subdir2" "$b2/subdir1/subdir2"
echo file1 >"$b1/subdir1/subdir2/file1"
ln -sfn ./subdir1 "$b1/subdir0"
echo file2 >"$b2/subdir0/subdir2/file2"
echo file3 >"$b2/subdir1/subdir2/file3"

check_b4() {
    local mp=$1 label=$2
    # subdir0 must be a real directory, not a symlink (directory wins)
    if [[ ! -d "$mp/subdir0" ]] || [[ -L "$mp/subdir0" ]]; then
        echo "  [FAIL] $label: subdir0 not directory (symlink wins?)"
        ls -la "$mp" || true
        return 1
    fi
    local names
    names=$(ls -1 "$mp/subdir0/subdir2" 2>/dev/null || true)
    if ! echo "$names" | grep -qx 'file2'; then
        echo "  [FAIL] $label: missing file2 in subdir0/subdir2 ($names)"
        return 1
    fi
    if ! echo "$names" | grep -qx 'file1'; then
        echo "  [FAIL] $label: missing file1 in subdir0/subdir2 ($names)"
        return 1
    fi
    if [[ "$(cat "$mp/subdir0/subdir2/file1" 2>/dev/null || true)" != "file1" ]]; then
        echo "  [FAIL] $label: file1 content"
        return 1
    fi
    if [[ "$(cat "$mp/subdir0/subdir2/file2" 2>/dev/null || true)" != "file2" ]]; then
        echo "  [FAIL] $label: file2 content"
        return 1
    fi
    return 0
}

mp="$WORKDIR/mnt-b4a"
mkdir -p "$mp"
echo "  [run] B-4 union (symlink branch then real-dir)"
"$RATARMOUNT_CMD" -f "$b1" "$b2" "$mp" >"$WORKDIR/b4a.log" 2>&1 &
MOUNT_PIDS+=($!)
if ! wait_mounted "$mp"; then
    echo "  [FAIL] B-4a mount"
    cat "$WORKDIR/b4a.log" || true
    failed=1
else
    if check_b4 "$mp" "B-4a"; then
        echo "  [ok] B-4 directory wins (order: symlink, dir)"
    else
        failed=1
    fi
    ratar_unmount "$mp"
    wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
fi

mp="$WORKDIR/mnt-b4b"
mkdir -p "$mp"
echo "  [run] B-4 union (real-dir then symlink branch)"
"$RATARMOUNT_CMD" -f "$b2" "$b1" "$mp" >"$WORKDIR/b4b.log" 2>&1 &
MOUNT_PIDS+=($!)
if ! wait_mounted "$mp"; then
    echo "  [FAIL] B-4b mount"
    cat "$WORKDIR/b4b.log" || true
    failed=1
else
    if check_b4 "$mp" "B-4b"; then
        echo "  [ok] B-4 directory wins (order: dir, symlink)"
    else
        failed=1
    fi
    ratar_unmount "$mp"
    wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
fi

# --- Write overlay :temp: ---
if [[ -f "$TAR1" ]]; then
    mp="$WORKDIR/mnt-overlay"
    mkdir -p "$mp"
    echo "  [run] write-overlay :temp: on single-file.tar"
    "$RATARMOUNT_CMD" -f -w :temp: "$TAR1" "$mp" >"$WORKDIR/ov.log" 2>&1 &
    MOUNT_PIDS+=($!)
    if ! wait_mounted "$mp"; then
        echo "  [FAIL] overlay mount"
        cat "$WORKDIR/ov.log" || true
        failed=1
    else
        # Create a new file in the overlay
        if echo "overlay-hello" >"$mp/new-from-overlay.txt" 2>/dev/null; then
            got=$(cat "$mp/new-from-overlay.txt")
            if [[ "$got" == "overlay-hello" ]]; then
                echo "  [ok] overlay write/read"
            else
                echo "  [FAIL] overlay readback $got"
                failed=1
            fi
        else
            echo "  [FAIL] overlay write denied"
            cat "$WORKDIR/ov.log" || true
            failed=1
        fi
        ratar_unmount "$mp"
        wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
    fi
else
    echo "  [skip] overlay fixture missing"
fi

# --- Folder bind ---
folder="$WORKDIR/bind-src"
mkdir -p "$folder/sub"
echo "bind-data" >"$folder/sub/x.txt"
mp="$WORKDIR/mnt-bind"
mkdir -p "$mp"
echo "  [run] folder bind mount"
"$RATARMOUNT_CMD" -f "$folder" "$mp" >"$WORKDIR/bind.log" 2>&1 &
MOUNT_PIDS+=($!)
if ! wait_mounted "$mp"; then
    echo "  [FAIL] bind mount"
    cat "$WORKDIR/bind.log" || true
    failed=1
else
    if [[ "$(cat "$mp/sub/x.txt")" == "bind-data" ]]; then
        echo "  [ok] folder bind"
    else
        echo "  [FAIL] folder bind content"
        failed=1
    fi
    ratar_unmount "$mp"
    wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
fi

# --- commit-overlay (uncompressed TAR + GNU tar) ---
if command -v tar >/dev/null && tar --version 2>/dev/null | grep -q 'GNU tar'; then
    echo "  [run] --commit-overlay append new file (uncompressed tar)"
    tdir="$WORKDIR/commit"
    mkdir -p "$tdir/src" "$tdir/ov" "$tdir/mnt"
    echo "orig" >"$tdir/src/a.txt"
    tar -cf "$tdir/a.tar" -C "$tdir/src" a.txt
    "$RATARMOUNT_CMD" -f -w "$tdir/ov" "$tdir/a.tar" "$tdir/mnt" >"$tdir/m.log" 2>&1 &
    MOUNT_PIDS+=($!)
    if ! wait_mounted "$tdir/mnt"; then
        echo "  [FAIL] commit-overlay mount"
        cat "$tdir/m.log" || true
        failed=1
    else
        echo "committed-new" >"$tdir/mnt/new.txt"
        ratar_unmount "$tdir/mnt"
        wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
        if "$RATARMOUNT_CMD" --commit-overlay --yes -w "$tdir/ov" "$tdir/a.tar" >"$tdir/c.log" 2>&1; then
            if tar -tf "$tdir/a.tar" | grep -q 'new.txt'; then
                echo "  [ok] commit-overlay tar"
            else
                echo "  [FAIL] new.txt missing after commit"
                tar -tvf "$tdir/a.tar" || true
                cat "$tdir/c.log" || true
                failed=1
            fi
        else
            echo "  [FAIL] commit-overlay command"
            cat "$tdir/c.log" || true
            failed=1
        fi
    fi
else
    echo "  [skip] commit-overlay tar (need GNU tar)"
fi

# --- commit-overlay gzip (.tar.gz) ---
if command -v gzip >/dev/null && command -v tar >/dev/null && tar --version 2>/dev/null | grep -q 'GNU tar'; then
    echo "  [run] --commit-overlay gzip (.tar.gz)"
    tdir="$WORKDIR/commit-gz"
    mkdir -p "$tdir/src" "$tdir/ov" "$tdir/mnt"
    echo "orig-gz" >"$tdir/src/a.txt"
    tar -czf "$tdir/a.tar.gz" -C "$tdir/src" a.txt
    "$RATARMOUNT_CMD" -f -w "$tdir/ov" "$tdir/a.tar.gz" "$tdir/mnt" >"$tdir/m.log" 2>&1 &
    MOUNT_PIDS+=($!)
    if ! wait_mounted "$tdir/mnt"; then
        echo "  [FAIL] commit-overlay gzip mount"
        cat "$tdir/m.log" || true
        failed=1
    else
        echo "committed-gz" >"$tdir/mnt/new.txt"
        ratar_unmount "$tdir/mnt"
        wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
        if "$RATARMOUNT_CMD" --commit-overlay --yes -w "$tdir/ov" "$tdir/a.tar.gz" >"$tdir/c.log" 2>&1; then
            if ! gzip -t "$tdir/a.tar.gz" 2>/dev/null; then
                echo "  [FAIL] archive not gzip after commit"
                file "$tdir/a.tar.gz" || true
                cat "$tdir/c.log" || true
                failed=1
            elif ! tar -tzf "$tdir/a.tar.gz" | grep -q 'new.txt'; then
                echo "  [FAIL] new.txt missing after gzip commit"
                tar -tzvf "$tdir/a.tar.gz" || true
                cat "$tdir/c.log" || true
                failed=1
            else
                body=$(tar -xzOf "$tdir/a.tar.gz" new.txt)
                if [[ "$body" == "committed-gz" ]]; then
                    echo "  [ok] commit-overlay gzip"
                else
                    echo "  [FAIL] gzip commit content '$body'"
                    failed=1
                fi
            fi
        else
            echo "  [FAIL] commit-overlay gzip command"
            cat "$tdir/c.log" || true
            failed=1
        fi
    fi
else
    echo "  [skip] commit-overlay gzip (need gzip + GNU tar)"
fi

# --- commit-overlay zip (full rebuild) ---
if command -v zip >/dev/null && command -v unzip >/dev/null; then
    echo "  [run] --commit-overlay zip (add + replace)"
    tdir="$WORKDIR/commit-zip"
    mkdir -p "$tdir/src" "$tdir/ov" "$tdir/mnt"
    echo "orig-zip" >"$tdir/src/a.txt"
    (cd "$tdir/src" && zip -q "$tdir/a.zip" a.txt)
    "$RATARMOUNT_CMD" -f -w "$tdir/ov" "$tdir/a.zip" "$tdir/mnt" >"$tdir/m.log" 2>&1 &
    MOUNT_PIDS+=($!)
    if ! wait_mounted "$tdir/mnt"; then
        echo "  [FAIL] commit-overlay zip mount"
        cat "$tdir/m.log" || true
        failed=1
    else
        echo "committed-zip" >"$tdir/mnt/new.txt"
        echo "replaced-zip" >"$tdir/mnt/a.txt"
        ratar_unmount "$tdir/mnt"
        wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
        if "$RATARMOUNT_CMD" --commit-overlay --yes -w "$tdir/ov" "$tdir/a.zip" >"$tdir/c.log" 2>&1; then
            if ! unzip -p "$tdir/a.zip" new.txt 2>/dev/null | grep -qx 'committed-zip'; then
                echo "  [FAIL] zip commit missing/wrong new.txt"
                unzip -l "$tdir/a.zip" || true
                cat "$tdir/c.log" || true
                failed=1
            elif ! unzip -p "$tdir/a.zip" a.txt 2>/dev/null | grep -qx 'replaced-zip'; then
                echo "  [FAIL] zip commit did not replace a.txt"
                unzip -p "$tdir/a.zip" a.txt || true
                cat "$tdir/c.log" || true
                failed=1
            else
                echo "  [ok] commit-overlay zip"
            fi
        else
            echo "  [FAIL] commit-overlay zip command"
            cat "$tdir/c.log" || true
            failed=1
        fi
    fi
else
    echo "  [skip] commit-overlay zip (need zip + unzip)"
fi

# --- Versioned files FUSE: updated-file.tar latest vs .versions/1,2,3 ---
# md5s match phase2-tar.txt (b3de7534… latest/v3, 2709a334… v1, 9a12be5e… v2).
UPDATED="${RATARMOUNT_PY_ROOT:+$RATARMOUNT_PY_ROOT/tests/updated-file.tar}"
if [[ ! -e /dev/fuse ]]; then
    echo "  [skip] versioned FUSE: /dev/fuse missing"
elif [[ -z "${UPDATED}" || ! -f "$UPDATED" ]]; then
    echo "  [skip] versioned FUSE: tests/updated-file.tar missing (set RATARMOUNT_PY_ROOT)"
else
    mp="$WORKDIR/mnt-versions"
    mkdir -p "$mp"
    echo "  [run] versioned FUSE updated-file.tar"
    # Isolate the index under WORKDIR so -c does not write next to the Python fixture.
    "$RATARMOUNT_CMD" -f -c --ignore-zeros --file-versions \
        --index-file "$WORKDIR/updated-file.index.sqlite" \
        "$UPDATED" "$mp" \
        >"$WORKDIR/versions.log" 2>&1 &
    MOUNT_PIDS+=($!)
    if ! wait_mounted "$mp"; then
        echo "  [FAIL] versioned FUSE mount"
        cat "$WORKDIR/versions.log" || true
        failed=1
    else
        latest="$mp/foo/fighter/ufo"
        v1="$mp/foo/fighter/ufo.versions/1"
        v2="$mp/foo/fighter/ufo.versions/2"
        v3="$mp/foo/fighter/ufo.versions/3"
        check_ver_md5() {
            local path=$1 want=$2 label=$3
            if [[ ! -f "$path" ]]; then
                echo "  [FAIL] versioned FUSE missing $label"
                return 1
            fi
            local got
            got=$(md5sum -- "$path" | awk '{print $1}')
            if [[ "$got" != "$want" ]]; then
                echo "  [FAIL] versioned FUSE $label md5 $got want $want"
                return 1
            fi
            return 0
        }
        ver_ok=1
        check_ver_md5 "$latest" "b3de7534cbc8b8a7270c996235d0c2da" "latest" || ver_ok=0
        check_ver_md5 "$v1" "2709a3348eb2c52302a7606ecf5860bc" "v1" || ver_ok=0
        check_ver_md5 "$v2" "9a12be5ebb21d497bd1024d159f2cc5f" "v2" || ver_ok=0
        check_ver_md5 "$v3" "b3de7534cbc8b8a7270c996235d0c2da" "v3" || ver_ok=0
        if [[ $ver_ok -eq 1 ]]; then
            if ! cmp -s "$latest" "$v3"; then
                echo "  [FAIL] versioned FUSE cmp latest vs v3 (should be identical)"
                ver_ok=0
            fi
            if cmp -s "$latest" "$v1"; then
                echo "  [FAIL] versioned FUSE cmp latest vs v1 (should differ)"
                ver_ok=0
            fi
            if cmp -s "$latest" "$v2"; then
                echo "  [FAIL] versioned FUSE cmp latest vs v2 (should differ)"
                ver_ok=0
            fi
        fi
        if [[ $ver_ok -eq 1 ]]; then
            echo "  [ok] versioned FUSE latest==v3, differs v1/v2"
        else
            ls -laR "$mp/foo/fighter" 2>/dev/null || true
            cat "$WORKDIR/versions.log" || true
            failed=1
        fi
        ratar_unmount "$mp"
        wait "${MOUNT_PIDS[-1]}" 2>/dev/null || true
    fi
fi

if [[ $failed -ne 0 ]]; then
    echo "Complex-usage FAILED"
    exit 1
fi
echo "Complex-usage OK"
