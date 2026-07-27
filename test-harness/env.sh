#!/usr/bin/env bash
# Shared env for dual-run against the Python ratarmount tree.
# Also provides portable unmount / mount-ready helpers (Linux + macOS).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export RATARMOUNT_RS_ROOT="$ROOT"

# ---------------------------------------------------------------------------
# Platform helpers (safe to source without Python fixtures)
# ---------------------------------------------------------------------------

# Unmount a FUSE (or FUSE-T / macFUSE) mountpoint. Never fails the caller.
ratar_unmount() {
    local mp="${1:-}"
    [[ -n "$mp" ]] || return 0
    case "$(uname -s)" in
        Darwin)
            umount "$mp" 2>/dev/null \
                || diskutil unmount "$mp" 2>/dev/null \
                || diskutil unmount force "$mp" 2>/dev/null \
                || true
            ;;
        *)
            # Prefer lazy unmount so EXIT traps can remove workdirs while FUSE settles.
            fusermount3 -uz "$mp" 2>/dev/null \
                || fusermount3 -u "$mp" 2>/dev/null \
                || fusermount -uz "$mp" 2>/dev/null \
                || fusermount -u "$mp" 2>/dev/null \
                || umount -l "$mp" 2>/dev/null \
                || umount "$mp" 2>/dev/null \
                || true
            ;;
    esac
}

# True if the path looks like an active mount (util-linux mountpoint, mount table, or readdir).
ratar_is_mounted() {
    local mp="${1:-}"
    [[ -n "$mp" && -d "$mp" ]] || return 1
    if command -v mountpoint >/dev/null 2>&1; then
        if mountpoint -q "$mp" 2>/dev/null; then
            return 0
        fi
    fi
    if mount 2>/dev/null | grep -F -q " on ${mp} " \
        || mount 2>/dev/null | grep -F -q " on ${mp}(" \
        || mount 2>/dev/null | grep -F -q " on ${mp}"$'\t'; then
        return 0
    fi
    # Last resort: absolute path substring (Darwin often uses /private/tmp/...)
    if mount 2>/dev/null | grep -F -q "$mp"; then
        return 0
    fi
    return 1
}

# Wait until mount is visible (default ~5s).
ratar_wait_mounted() {
    local mp=$1
    local attempts=${2:-50}
    local i
    for i in $(seq 1 "$attempts"); do
        if ratar_is_mounted "$mp"; then
            return 0
        fi
        # Empty archives: readdir may succeed once FUSE is up even if mount table lags.
        if ls -A "$mp" >/dev/null 2>&1; then
            if ratar_is_mounted "$mp"; then
                return 0
            fi
        fi
        sleep 0.1
    done
    return 1
}

# Python fixture root (required unless RATARMOUNT_ALLOW_NO_PY=1, e.g. macOS smoke).
if [[ -z "${RATARMOUNT_PY_ROOT:-}" ]]; then
    if [[ -d "$ROOT/../ratarmount/tests" ]]; then
        RATARMOUNT_PY_ROOT="$(cd "$ROOT/../ratarmount" && pwd)"
    elif [[ -d "$ROOT/../ratarmount-py/tests" ]]; then
        RATARMOUNT_PY_ROOT="$(cd "$ROOT/../ratarmount-py" && pwd)"
    elif [[ "${RATARMOUNT_ALLOW_NO_PY:-0}" != "1" ]]; then
        echo "error: set RATARMOUNT_PY_ROOT to the Python ratarmount checkout" >&2
        exit 1
    fi
fi
if [[ -n "${RATARMOUNT_PY_ROOT:-}" ]]; then
    export RATARMOUNT_PY_ROOT
fi

if [[ -z "${RATARMOUNT_CMD:-}" ]]; then
    if [[ -x "$ROOT/target/release/ratarmount" ]]; then
        RATARMOUNT_CMD="$ROOT/target/release/ratarmount"
    elif [[ -x "$ROOT/target/debug/ratarmount" ]]; then
        RATARMOUNT_CMD="$ROOT/target/debug/ratarmount"
    else
        echo "error: build ratarmount first (cargo build --release) or set RATARMOUNT_CMD" >&2
        exit 1
    fi
fi
export RATARMOUNT_CMD

if [[ "${RATARMOUNT_ENV_QUIET:-0}" != "1" ]]; then
    [[ -n "${RATARMOUNT_PY_ROOT:-}" ]] && echo "RATARMOUNT_PY_ROOT=$RATARMOUNT_PY_ROOT"
    echo "RATARMOUNT_CMD=$RATARMOUNT_CMD"
fi
