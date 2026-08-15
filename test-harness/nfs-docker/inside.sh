#!/usr/bin/env bash
# In-container: generate a fixture tar, start the *shipped* ratarmount NFS
# export, kernel-mount it, and cmp member bytes against the files that
# were packed (never a separately hard-coded expected payload).
set -euo pipefail

VERS="${1:-}"
MODE="${2:-ro}"
case "$VERS" in
    3 | 4) ;;
    *)
        echo "usage: inside.sh 3|4 [ro|write]" >&2
        exit 2
        ;;
esac
case "$MODE" in
    ro | write) ;;
    *)
        echo "usage: inside.sh 3|4 [ro|write]" >&2
        exit 2
        ;;
esac

BIN="${RATARMOUNT_BIN:-/usr/local/bin/ratarmount}"
PORT="${NFS_IT_PORT:-20490}"
WORKDIR="${NFS_IT_WORKDIR:-/tmp/nfs-it}"
MNT="${NFS_IT_MNT:-/mnt/nfs}"
MEMBER_PAYLOAD="payload.bin"
MEMBER_SIDECAR="sidecar.txt"

if [[ ! -x "$BIN" ]]; then
    echo "FAIL: ratarmount binary missing or not executable: $BIN" >&2
    exit 1
fi

echo "==> binary: $BIN"
"$BIN" --print-features || true
if [[ "$VERS" == 4 ]]; then
    if ! "$BIN" --print-features | grep -qx '  nfsv4: compiled'; then
        echo "FAIL: --nfs-vers 4 needs a binary built with --features nfsv4" >&2
        exit 1
    fi
fi

# Kernel NFS client: skip only when the module/filesystem cannot be used.
if ! grep -Eqw 'nfs|nfs4' /proc/filesystems; then
    modprobe nfs 2>/dev/null || true
    modprobe nfsv3 2>/dev/null || true
    modprobe nfsv4 2>/dev/null || true
fi
if ! grep -Eqw 'nfs|nfs4' /proc/filesystems; then
    echo "skip: kernel NFS client not available (no nfs/nfs4 in /proc/filesystems)"
    exit 0
fi
echo "==> /proc/filesystems:"
grep -E 'nfs' /proc/filesystems || true

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/tree" "$MNT"

# Skip only when this container cannot privileged-mount. After this probe,
# mount.nfs failures (including Permission denied) are FAIL — they are not
# a substitute for missing CAP_SYS_ADMIN.
if [[ "$(id -u)" -ne 0 ]]; then
    echo "skip: not running as root (need docker --privileged for mount -t nfs)"
    exit 0
fi
if ! timeout 5 mount -t tmpfs -o size=1m nfs-it-cap "$MNT" >"$WORKDIR/cap.out" 2>&1; then
    echo "skip: cannot mount tmpfs (no CAP_SYS_ADMIN / privileged Docker)"
    cat "$WORKDIR/cap.out" || true
    exit 0
fi
umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true

# Best-effort portmap for clients that still poke 111 even with port=.
if command -v rpcbind >/dev/null 2>&1; then
    rpcbind -w 2>/dev/null || rpcbind 2>/dev/null || true
fi
# Unique fixture bytes written first, then packed. Assertions cmp these files.
{
    printf 'ratarmount-nfs-docker\n'
    date -u +%Y-%m-%dT%H:%M:%SZ
    cat /proc/sys/kernel/random/uuid
    printf 'bin:'
    dd if=/dev/urandom bs=64 count=1 status=none
} >"$WORKDIR/tree/$MEMBER_PAYLOAD"
{
    printf 'sidecar\n'
    cat /proc/sys/kernel/random/uuid
} >"$WORKDIR/tree/$MEMBER_SIDECAR"
# Keep copies outside the tree so later mutation cannot change expected bytes.
cp -a "$WORKDIR/tree/$MEMBER_PAYLOAD" "$WORKDIR/expected-payload.bin"
cp -a "$WORKDIR/tree/$MEMBER_SIDECAR" "$WORKDIR/expected-sidecar.txt"
tar -C "$WORKDIR/tree" -cf "$WORKDIR/fixture.tar" "$MEMBER_PAYLOAD" "$MEMBER_SIDECAR"
echo "==> fixture.tar members:"
tar -tf "$WORKDIR/fixture.tar"
echo "==> payload bytes: $(wc -c <"$WORKDIR/expected-payload.bin")"

SERVER_LOG="$WORKDIR/server.log"
IDX="$WORKDIR/index.sqlite"
SERVER_ARGS=(
    --nfs
    --nfs-bind "127.0.0.1:${PORT}"
    --index-file "$IDX"
)
if [[ "$MODE" == write ]]; then
    mkdir -p "$WORKDIR/ov"
    SERVER_ARGS+=(-w "$WORKDIR/ov")
fi
if [[ "$VERS" == 4 ]]; then
    SERVER_ARGS+=(--nfs-vers 4)
fi
SERVER_ARGS+=("$WORKDIR/fixture.tar")

echo "==> starting: $BIN ${SERVER_ARGS[*]}"
"$BIN" "${SERVER_ARGS[@]}" >"$SERVER_LOG" 2>&1 &
PID=$!

cleanup() {
    set +e
    if mountpoint -q "$MNT" 2>/dev/null || grep -F -q " on ${MNT} " /proc/mounts 2>/dev/null; then
        umount -l "$MNT" 2>/dev/null || umount "$MNT" 2>/dev/null || true
    fi
    if [[ -n "${PID:-}" ]]; then
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

ACCESS="ro"
if [[ "$MODE" == write ]]; then
    ACCESS="rw overlay"
fi
READY_NEEDLE="NFSv3 (${ACCESS})"
if [[ "$VERS" == 4 ]]; then
    READY_NEEDLE="NFSv4.1 (${ACCESS})"
fi

ready=0
for _ in $(seq 1 100); do
    if grep -F -q "$READY_NEEDLE" "$SERVER_LOG" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "FAIL: ratarmount exited before ready"
        cat "$SERVER_LOG"
        exit 1
    fi
    sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
    echo "FAIL: timeout waiting for ready line ($READY_NEEDLE)"
    cat "$SERVER_LOG"
    exit 1
fi
echo "==> server ready:"
grep -F "$READY_NEEDLE" "$SERVER_LOG" || true

# Confirm TCP accept before mount so "connection refused" is a server bug.
tcp_ok=0
for _ in $(seq 1 50); do
    if timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/${PORT}" 2>/dev/null; then
        tcp_ok=1
        break
    fi
    sleep 0.1
done
if [[ "$tcp_ok" -ne 1 ]]; then
    echo "FAIL: nothing listening on 127.0.0.1:${PORT}"
    cat "$SERVER_LOG"
    exit 1
fi

if [[ "$VERS" == 4 ]]; then
    MOUNT_OPTS="vers=4.1,tcp,port=${PORT},sec=sys"
else
    MOUNT_OPTS="vers=3,tcp,nolock,port=${PORT},mountport=${PORT}"
fi

echo "==> mount -t nfs -o ${MOUNT_OPTS} 127.0.0.1:/ ${MNT}"
set +e
timeout 30 mount -t nfs -o "$MOUNT_OPTS" 127.0.0.1:/ "$MNT" >"$WORKDIR/mount.out" 2>&1
mount_rc=$?
set -e
if [[ "$mount_rc" -ne 0 ]]; then
    echo "==> mount failed (exit ${mount_rc}):"
    cat "$WORKDIR/mount.out"
    echo "==> server log:"
    cat "$SERVER_LOG"
    # Capability was already proven via tmpfs. "Permission denied" from
    # mount.nfs after that is export/AUTH/idmap — fail, do not skip.
    if grep -Eiq 'must be superuser' "$WORKDIR/mount.out"; then
        echo "skip: mount -t nfs requires superuser (capability probe was insufficient)"
        exit 0
    fi
    echo "FAIL: kernel mount -t nfs vers=${VERS} (server was listening)"
    exit 1
fi

if ! mountpoint -q "$MNT" 2>/dev/null; then
    if ! grep -F -q " on ${MNT} " /proc/mounts; then
        echo "FAIL: mount returned 0 but ${MNT} is not a mountpoint"
        cat "$WORKDIR/mount.out"
        cat /proc/mounts || true
        exit 1
    fi
fi
echo "==> mount table:"
grep -E ' nfs|nfs4 ' /proc/mounts || true

echo "==> ls -la ${MNT}"
timeout 30 ls -la "$MNT"
LIST="$(timeout 30 ls -1 "$MNT")"
echo "==> ls -1:"
printf '%s\n' "$LIST"
if ! printf '%s\n' "$LIST" | grep -qx "$MEMBER_PAYLOAD"; then
    echo "FAIL: readdir missing ${MEMBER_PAYLOAD}"
    exit 1
fi
if ! printf '%s\n' "$LIST" | grep -qx "$MEMBER_SIDECAR"; then
    echo "FAIL: readdir missing ${MEMBER_SIDECAR}"
    exit 1
fi

GOT_PAYLOAD="$WORKDIR/got-payload.bin"
GOT_SIDECAR="$WORKDIR/got-sidecar.txt"
timeout 30 cat "$MNT/$MEMBER_PAYLOAD" >"$GOT_PAYLOAD"
timeout 30 cat "$MNT/$MEMBER_SIDECAR" >"$GOT_SIDECAR"

if [[ ! -s "$GOT_PAYLOAD" ]]; then
    echo "FAIL: cat ${MEMBER_PAYLOAD} was empty (empty/nobody/wrong bytes is a fail)"
    ls -la "$MNT/$MEMBER_PAYLOAD" || true
    exit 1
fi
if ! cmp -s "$GOT_PAYLOAD" "$WORKDIR/expected-payload.bin"; then
    echo "FAIL: ${MEMBER_PAYLOAD} bytes != fixture file packed into the archive"
    echo "-- expected (wc=$(wc -c <"$WORKDIR/expected-payload.bin")) --"
    od -An -tx1 -N 80 "$WORKDIR/expected-payload.bin" || true
    echo "-- got (wc=$(wc -c <"$GOT_PAYLOAD")) --"
    od -An -tx1 -N 80 "$GOT_PAYLOAD" || true
    exit 1
fi
if ! cmp -s "$GOT_SIDECAR" "$WORKDIR/expected-sidecar.txt"; then
    echo "FAIL: ${MEMBER_SIDECAR} bytes != fixture file packed into the archive"
    echo "-- expected --"
    cat "$WORKDIR/expected-sidecar.txt" || true
    echo "-- got --"
    cat "$GOT_SIDECAR" || true
    exit 1
fi

if [[ "$MODE" == write ]]; then
    WRITE_NAME="overlay-created.bin"
    {
        printf 'nfs-docker-overlay-write\n'
        date -u +%Y-%m-%dT%H:%M:%SZ
        cat /proc/sys/kernel/random/uuid
    } >"$WORKDIR/expected-write.bin"
    echo "==> write ${MNT}/${WRITE_NAME} through kernel mount"
    # Single write(2) via shell redirect. Linux NFSv4 CLOSE/COMMIT can return EIO
    # on cp/dd close even when bytes landed (printf/redirect is enough to cmp).
    set +e
    timeout 30 bash -c "cat '$WORKDIR/expected-write.bin' > '$MNT/$WRITE_NAME'"
    wr_rc=$?
    set -e
    if [[ "$wr_rc" -ne 0 ]]; then
        echo "note: write/close rc=${wr_rc} (will still cmp mount bytes)"
    fi
    timeout 30 cat "$MNT/$WRITE_NAME" >"$WORKDIR/got-write.bin"
    if [[ ! -s "$WORKDIR/got-write.bin" ]]; then
        echo "FAIL: overlay write then cat was empty"
        ls -la "$MNT" || true
        exit 1
    fi
    if ! cmp -s "$WORKDIR/got-write.bin" "$WORKDIR/expected-write.bin"; then
        echo "FAIL: written member bytes != bytes just written through the mount"
        od -An -tx1 -N 80 "$WORKDIR/expected-write.bin" || true
        od -An -tx1 -N 80 "$WORKDIR/got-write.bin" || true
        exit 1
    fi
    echo "PASS: NFSv${VERS} kernel overlay write/cmp matches written file"
else
    echo "PASS: NFSv${VERS} kernel mount list+cat matches fixture files"
fi
