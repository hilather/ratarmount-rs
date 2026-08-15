#!/usr/bin/env bash
# Host launcher: build shipped ratarmount (--features nfsv4), run a privileged
# Ubuntu container with nfs-common, and kernel-mount NFSv3 and/or NFSv4.1.
#
# Usage: ./test-harness/nfs-docker/run.sh [3|4|all]
#
# Not part of default unprivileged CI. Skip (exit 0) when docker or a
# privileged NFS mount cannot run. A mount that succeeds with empty or
# wrong member bytes is a fail (exit 1).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERS="${1:-all}"
IMAGE="${NFS_IT_IMAGE:-ratarmount-nfs-it:local}"
PROFILE="${NFS_IT_PROFILE:-debug}"

case "$VERS" in
    3 | 4 | all) ;;
    *)
        echo "usage: $0 [3|4|all]" >&2
        exit 2
        ;;
esac

skip() {
    echo "skip: $*"
    exit 0
}

if ! command -v docker >/dev/null 2>&1; then
    skip "docker not on PATH"
fi
if ! docker info >/dev/null 2>&1; then
    skip "docker daemon not usable (permission / not running)"
fi

if [[ -n "${RATARMOUNT_BIN:-}" ]]; then
    BIN="$RATARMOUNT_BIN"
else
    case "$PROFILE" in
        release) CARGO_FLAGS=(--release) ;;
        debug) CARGO_FLAGS=() ;;
        *)
            echo "FAIL: NFS_IT_PROFILE must be debug or release (got $PROFILE)" >&2
            exit 2
            ;;
    esac
    echo "==> cargo build -p ratarmount --features nfsv4 ${CARGO_FLAGS[*]}"
    (cd "$ROOT" && cargo build -p ratarmount --features nfsv4 "${CARGO_FLAGS[@]}")
    BIN="$ROOT/target/${PROFILE}/ratarmount"
fi

if [[ ! -x "$BIN" ]]; then
    echo "FAIL: binary not executable: $BIN" >&2
    exit 1
fi
if [[ "$VERS" == 4 || "$VERS" == all ]]; then
    if ! "$BIN" --print-features | grep -qx '  nfsv4: compiled'; then
        echo "FAIL: $BIN was not built with --features nfsv4" >&2
        "$BIN" --print-features || true
        exit 1
    fi
fi

echo "==> docker build -t $IMAGE"
docker build -t "$IMAGE" "$SCRIPT_DIR"

# Distinguish "cannot run privileged containers" (skip) from inside.sh FAIL.
if ! docker run --rm --privileged --entrypoint /bin/true "$IMAGE" >/tmp/nfs-it-priv.$$.out 2>&1; then
    echo "skip: docker --privileged not available"
    cat /tmp/nfs-it-priv.$$.out || true
    rm -f /tmp/nfs-it-priv.$$.out
    exit 0
fi
rm -f /tmp/nfs-it-priv.$$.out

run_one() {
    local v="$1"
    echo "==> docker run --privileged NFSv${v}"
    # Real binary + real mount -t nfs live in inside.sh (same container loopback).
    docker run --rm --privileged \
        --name "ratarmount-nfs-it-${v}-$$" \
        -e "RATARMOUNT_BIN=/usr/local/bin/ratarmount" \
        -v "$BIN:/usr/local/bin/ratarmount:ro" \
        -v "$SCRIPT_DIR/inside.sh:/usr/local/bin/nfs-it-inside.sh:ro" \
        "$IMAGE" "$v"
}

if [[ "$VERS" == all ]]; then
    run_one 3
    run_one 4
else
    run_one "$VERS"
fi
