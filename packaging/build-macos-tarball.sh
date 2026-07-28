#!/usr/bin/env bash
# Build a macOS release tarball (arm64 / x86_64).
#
# Usage (from repo root, on a Mac with FUSE + libarchive + Rust):
#   ./packaging/build-macos-tarball.sh
#   VERSION=0.1.3 OUT_DIR=dist ./packaging/build-macos-tarball.sh
#
# Env:
#   VERSION          default: workspace Cargo.toml version
#   OUT_DIR          default: dist
#   SKIP_BUILD=1     reuse existing target/release/ratarmount
#   PKG_CONFIG_PATH  should include Homebrew libarchive when keg-only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: build-macos-tarball.sh is intended to run on macOS (got $(uname -s))" >&2
    exit 1
fi

export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

# Homebrew libarchive is often keg-only.
if command -v brew >/dev/null 2>&1; then
    la_prefix="$(brew --prefix libarchive 2>/dev/null || true)"
    if [[ -n "$la_prefix" && -d "$la_prefix/lib/pkgconfig" ]]; then
        export PKG_CONFIG_PATH="${la_prefix}/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    fi
    # macFUSE / FUSE-T pkg-config paths
    for p in \
        /usr/local/lib/pkgconfig \
        /opt/homebrew/lib/pkgconfig \
        /Library/Filesystems/macfuse.fs/Contents/Resources/pkgconfig \
        "$(brew --prefix 2>/dev/null)/lib/pkgconfig"; do
        if [[ -n "$p" && -d "$p" ]]; then
            export PKG_CONFIG_PATH="${p}${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
        fi
    done
fi

OUT_DIR="${OUT_DIR:-$ROOT/dist}"
NAME="${PACKAGE_NAME:-ratarmount}"
VERSION="${VERSION:-}"
if [[ -z "$VERSION" ]]; then
    VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
fi
VERSION="${VERSION#v}"

ARCH_UNAME="$(uname -m)"
case "$ARCH_UNAME" in
    x86_64|amd64) ARCH_LABEL=x86_64 ;;
    arm64|aarch64) ARCH_LABEL=arm64 ;;
    *) ARCH_LABEL="$ARCH_UNAME" ;;
esac

mkdir -p "$OUT_DIR"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    echo "==> cargo build --release -p ratarmount"
    cargo build --release -p ratarmount
fi
test -x target/release/ratarmount

STAGE_NAME="${NAME}-${VERSION}-macos-${ARCH_LABEL}"
STAGE="$OUT_DIR/.macos-stage-$$"
mkdir -p "$STAGE/$STAGE_NAME"
cp -a target/release/ratarmount "$STAGE/$STAGE_NAME/"
cp -a LICENSE "$STAGE/$STAGE_NAME/" 2>/dev/null || true
if [[ -f README.md ]]; then
    cp -a README.md "$STAGE/$STAGE_NAME/"
fi
cat >"$STAGE/$STAGE_NAME/MACOS.txt" <<EOF
${NAME} ${VERSION} (macOS ${ARCH_LABEL})

Install binary:
  install -m 755 ratarmount ~/.local/bin/
  # or: /usr/local/bin

FUSE is required (macOS has no built-in FUSE). Pick ONE:

  # Recommended — macFUSE 5.x
  brew install --cask macfuse
  # After install, approve system extension if prompted (System Settings → Privacy & Security).
  # On macOS 26 Tahoe, prefer FSKit if the kernel extension is blocked:
  #   ratarmount -f -o backend=fskit archive.tar.gz mnt/

  # Alternative — FUSE-T (no kernel extension)
  brew install macos-fuse-t/homebrew-cask/fuse-t
  # On Tahoe 26+, run fuse-t.app once to enable FSKit if needed, then:
  #   ratarmount -f -o backend=fskit archive.tar.gz mnt/

Also useful:
  brew install libarchive pkgconf

Unmount:
  ratarmount -u mnt
  # or: umount mnt   /   diskutil unmount mnt

Full guide: https://github.com/hilather/ratarmount-rs/blob/main/docs/macos.md
(or docs/macos.md in the source tree)
EOF

TARBALL="$OUT_DIR/${STAGE_NAME}.tar.gz"
tar -C "$STAGE" -czf "$TARBALL" "$STAGE_NAME"
rm -rf "$STAGE"
echo "Wrote $TARBALL"

# Portable checksum (macOS has shasum; Linux has sha256sum)
(
    cd "$OUT_DIR"
    base="$(basename "$TARBALL")"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$base" | tee "${base}.sha256"
    else
        shasum -a 256 "$base" | tee "${base}.sha256"
    fi
)

file target/release/ratarmount | tee "$OUT_DIR/file-info-macos-${ARCH_LABEL}.txt" || true
ls -la "$OUT_DIR"/${NAME}-${VERSION}-macos-${ARCH_LABEL}*
echo "==> macOS tarball done"
