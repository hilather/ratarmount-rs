#!/usr/bin/env bash
# Build a ratarmount AppImage (optional tooling).
#
# Prerequisites on the build host:
#   - cargo + fuse3 + libarchive development packages
#   - linuxdeploy + appimagetool on PATH (or downloaded next to this script)
#   - For optional format helpers inside the image: e2fsprogs (debugfs), squashfs-tools
#
# Usage (from repo root or packaging/):
#   ./packaging/build-appimage.sh
#   OUT_DIR=dist ./packaging/build-appimage.sh
#
# This is a best-effort scaffold. For production, build inside an old-glibc
# container (e.g. manylinux) so the binary runs on a wide range of distros.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

OUT_DIR="${OUT_DIR:-$ROOT/dist}"
ARCH="$(uname -m)"
APPDIR="$OUT_DIR/AppDir"
BIN_NAME=ratarmount

command_exists() { command -v "$1" >/dev/null 2>&1; }

echo "==> Building release binary"
export PATH="${HOME}/.cargo/bin:${PATH}"
cargo build --release -p ratarmount

mkdir -p "$OUT_DIR"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"

install -m 755 "target/release/$BIN_NAME" "$APPDIR/usr/bin/$BIN_NAME"
install -m 644 packaging/ratarmount.desktop "$APPDIR/usr/share/applications/ratarmount.desktop"
# linuxdeploy expects a desktop file and icon at AppDir root as well.
cp packaging/ratarmount.desktop "$APPDIR/ratarmount.desktop"

# Prefer an icon from the sibling Python tree if present; else a 1x1 placeholder is skipped.
ICON_SRC=""
for cand in \
    "$ROOT/packaging/ratarmount.png" \
    "$ROOT/../ratarmount/ratarmount.svg" \
    "$ROOT/../ratarmount/AppImage/ratarmount-metadata/ratarmount.svg"
do
    if [[ -f "$cand" ]]; then
        ICON_SRC="$cand"
        break
    fi
done
if [[ -n "$ICON_SRC" ]]; then
    case "$ICON_SRC" in
        *.svg)
            mkdir -p "$APPDIR/usr/share/icons/hicolor/scalable/apps"
            install -m 644 "$ICON_SRC" "$APPDIR/usr/share/icons/hicolor/scalable/apps/ratarmount.svg"
            cp "$ICON_SRC" "$APPDIR/ratarmount.svg"
            ;;
        *)
            install -m 644 "$ICON_SRC" "$APPDIR/usr/share/icons/hicolor/256x256/apps/ratarmount.png"
            cp "$ICON_SRC" "$APPDIR/ratarmount.png"
            ;;
    esac
else
    echo "warning: no icon found; linuxdeploy may require --icon-file"
fi

# AppRun: prefer bundled binary; host fuse3 still required typically.
cat >"$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
export PATH="${HERE}/usr/bin:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/lib:${HERE}/usr/lib64:${LD_LIBRARY_PATH:-}"
# Optional helpers if bundled (EXT4 / SquashFS MVP paths)
export PATH="${HERE}/usr/sbin:${PATH}"
exec "${HERE}/usr/bin/ratarmount" "$@"
EOF
chmod 755 "$APPDIR/AppRun"

# Optionally bundle common helper binaries used by format MVPs.
bundle_helper() {
    local name=$1
    local src
    src="$(command -v "$name" 2>/dev/null || true)"
    if [[ -z "$src" && -x "/usr/sbin/$name" ]]; then
        src="/usr/sbin/$name"
    fi
    if [[ -n "$src" && -x "$src" ]]; then
        mkdir -p "$APPDIR/usr/sbin"
        # Copy only if not a shell script dependency maze; skip if multi-arch issues later.
        if file "$src" 2>/dev/null | grep -qi 'ELF'; then
            install -m 755 "$src" "$APPDIR/usr/sbin/$name"
            echo "  bundled helper: $name from $src"
        fi
    fi
}
if [[ "${BUNDLE_HELPERS:-1}" == "1" ]]; then
    echo "==> Bundling optional format helpers (set BUNDLE_HELPERS=0 to skip)"
    bundle_helper debugfs
    bundle_helper unsquashfs
fi

if command_exists linuxdeploy; then
    echo "==> Running linuxdeploy"
    LINUXDEPLOY_ARGS=(
        --appdir="$APPDIR"
        --executable="$APPDIR/usr/bin/$BIN_NAME"
        --desktop-file="$APPDIR/ratarmount.desktop"
        --output appimage
    )
    if [[ -f "$APPDIR/ratarmount.png" ]]; then
        LINUXDEPLOY_ARGS+=(--icon-file="$APPDIR/ratarmount.png")
    elif [[ -f "$APPDIR/ratarmount.svg" ]]; then
        LINUXDEPLOY_ARGS+=(--icon-file="$APPDIR/ratarmount.svg")
    fi
    # Pull in dynamically linked libs (libarchive, libfuse3, …)
    (
        cd "$OUT_DIR"
        linuxdeploy "${LINUXDEPLOY_ARGS[@]}"
    )
    echo "AppImage artifacts under $OUT_DIR"
elif command_exists appimagetool; then
    echo "==> linuxdeploy not found; packing AppDir with appimagetool only"
    echo "    (shared libraries may be missing — install linuxdeploy for a complete image)"
    (
        cd "$OUT_DIR"
        appimagetool "$APPDIR" "ratarmount-${ARCH}.AppImage"
    )
else
    echo
    echo "AppDir prepared at: $APPDIR"
    echo "Install linuxdeploy + appimagetool to produce a .AppImage, e.g.:"
    echo "  curl -L -o linuxdeploy https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-${ARCH}.AppImage"
    echo "  chmod +x linuxdeploy && ./linuxdeploy --appdir=$APPDIR --executable=$APPDIR/usr/bin/$BIN_NAME \\"
    echo "    --desktop-file=$APPDIR/ratarmount.desktop --icon-file=... --output appimage"
    echo
    echo "Runtime deps on target systems if not bundled:"
    echo "  fuse3, libarchive, optionally e2fsprogs (debugfs) and squashfs-tools"
    exit 0
fi

echo "Done."
