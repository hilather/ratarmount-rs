#!/usr/bin/env bash
# Build release binary and .deb / .rpm with nfpm (if available).
#
# Usage (from repo root, after system deps + rustc):
#   ./packaging/build-native-packages.sh
#   OUT_DIR=dist VERSION=0.1.0 ./packaging/build-native-packages.sh
#
# Env:
#   PACKAGE_FAMILY=deb|rpm|auto   (default auto: detect from /etc/os-release)
#   SKIP_BUILD=1                  skip cargo build
#   OUT_DIR=dist
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.cargo/bin:${PATH}"

OUT_DIR="${OUT_DIR:-$ROOT/dist}"
NAME="${PACKAGE_NAME:-ratarmount}"
MAINTAINER="${MAINTAINER:-ratarmount-rs maintainers <noreply@localhost>}"
VERSION="${VERSION:-}"
if [[ -z "$VERSION" ]]; then
    VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
fi
# nfpm wants semver without leading v
VERSION="${VERSION#v}"

ARCH_UNAME="$(uname -m)"
case "$ARCH_UNAME" in
    x86_64|amd64) ARCH_DEB=amd64; ARCH_RPM=x86_64; ARCH_NFPM=amd64 ;;
    aarch64|arm64) ARCH_DEB=arm64; ARCH_RPM=aarch64; ARCH_NFPM=arm64 ;;
    *) ARCH_DEB="$ARCH_UNAME"; ARCH_RPM="$ARCH_UNAME"; ARCH_NFPM="$ARCH_UNAME" ;;
esac

detect_family() {
    if [[ -n "${PACKAGE_FAMILY:-}" && "$PACKAGE_FAMILY" != auto ]]; then
        echo "$PACKAGE_FAMILY"
        return
    fi
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        case "${ID_LIKE:-$ID}" in
            *debian*|*ubuntu*) echo deb ;;
            *rhel*|*fedora*|*centos*|*rocky*|*alma*) echo rpm ;;
            *)
                case "${ID:-}" in
                    ubuntu|debian) echo deb ;;
                    rocky|almalinux|rhel|fedora|centos) echo rpm ;;
                    *) echo both ;;
                esac
                ;;
        esac
    else
        echo both
    fi
}

FAMILY="$(detect_family)"
mkdir -p "$OUT_DIR"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    echo "==> cargo build --release -p ratarmount"
    cargo build --release -p ratarmount
fi
test -x target/release/ratarmount

# Always ship a portable tarball of the binary (works on any glibc-compatible peer).
TARBALL="$OUT_DIR/${NAME}-${VERSION}-linux-${ARCH_UNAME}.tar.gz"
tar -C target/release -czf "$TARBALL" ratarmount
echo "Wrote $TARBALL"
# Optional checksum
( cd "$OUT_DIR" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

install_nfpm() {
    if command -v nfpm >/dev/null 2>&1; then
        return 0
    fi
    echo "==> installing nfpm"
    local ver="${NFPM_VERSION:-v2.41.3}"
    local url="https://github.com/goreleaser/nfpm/releases/download/${ver}/nfpm_${ver#v}_Linux_x86_64.tar.gz"
    if [[ "$ARCH_UNAME" == "aarch64" ]]; then
        url="https://github.com/goreleaser/nfpm/releases/download/${ver}/nfpm_${ver#v}_Linux_arm64.tar.gz"
    fi
    curl -fsSL "$url" | tar -xz -C /tmp nfpm
    install -m 755 /tmp/nfpm "$HOME/.local/bin/nfpm" 2>/dev/null \
        || sudo install -m 755 /tmp/nfpm /usr/local/bin/nfpm
    export PATH="${HOME}/.local/bin:${PATH}"
}

write_nfpm_config() {
    local family=$1
    local conf="$OUT_DIR/nfpm-${family}.yaml"
    local arch depends
    if [[ "$family" == deb ]]; then
        arch="$ARCH_NFPM"
        depends=$'  - fuse3\n  - libarchive13'
    else
        arch="$ARCH_RPM"
        depends=$'  - fuse3\n  - libarchive'
    fi
    # Escape for sed replacement of multi-line depends
    sed \
        -e "s/@NAME@/${NAME}/g" \
        -e "s/@VERSION@/${VERSION}/g" \
        -e "s/@ARCH@/${arch}/g" \
        -e "s|@MAINTAINER@|${MAINTAINER}|g" \
        "$SCRIPT_DIR/nfpm.yaml.tmpl" \
        | awk -v dep="$depends" '
            /@DEPENDS@/ { print dep; next }
            { print }
          ' > "$conf"
    echo "$conf"
}

pack_with_nfpm() {
    local family=$1
    install_nfpm
    local conf
    conf="$(write_nfpm_config "$family")"
    echo "==> nfpm pkg --packager $family"
    (
        cd "$ROOT"
        nfpm pkg --packager "$family" --config "$conf" --target "$OUT_DIR"
    )
}

case "$FAMILY" in
    deb) pack_with_nfpm deb ;;
    rpm) pack_with_nfpm rpm ;;
    both)
        pack_with_nfpm deb || echo "warning: deb packaging failed"
        pack_with_nfpm rpm || echo "warning: rpm packaging failed"
        ;;
    *)
        echo "Unknown PACKAGE_FAMILY=$FAMILY; tarball only"
        ;;
esac

echo "==> artifacts in $OUT_DIR"
ls -la "$OUT_DIR"
