#!/usr/bin/env bash
# Build release binary and .deb / .rpm with nfpm (if available).
#
# Usage (from repo root, after system deps + rustc):
#   ./packaging/build-native-packages.sh
#   OUT_DIR=dist VERSION=0.1.0 ./packaging/build-native-packages.sh
#
# Env:
#   PACKAGE_FAMILY=deb|rpm|auto|none   (default auto; none = tarball only)
#   SKIP_BUILD=1                       skip cargo build
#   OUT_DIR=dist
#   DISTRO_LABEL=ubuntu-22.04          tag tarball/package filenames for multi-job CI
#   TARBALL_ONLY=1                     only emit the binary tarball (+ checksums)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.cargo/bin:${HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin:${PATH}"

OUT_DIR="${OUT_DIR:-$ROOT/dist}"
NAME="${PACKAGE_NAME:-ratarmount}"
MAINTAINER="${MAINTAINER:-ratarmount-rs maintainers <noreply@localhost>}"
VERSION="${VERSION:-}"
if [[ -z "$VERSION" ]]; then
    VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
fi
# nfpm wants semver without leading v
VERSION="${VERSION#v}"

# Human-readable distro tag for artifact names (avoid collisions across CI matrix jobs).
if [[ -z "${DISTRO_LABEL:-}" ]]; then
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        DISTRO_LABEL="${ID:-linux}${VERSION_ID:-}"
    else
        DISTRO_LABEL=linux
    fi
fi
# sanitize for filenames (strip newline from echo so tr does not append a trailing '-')
DISTRO_LABEL="$(printf '%s' "$DISTRO_LABEL" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '-' | sed 's/-\+/-/g; s/^-//; s/-$//')"

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
    # NFSv4.1 via embednfs (rustc ≥ 1.88). Linux package jobs install rustup
    # stable, so this is on. Stronger than gzip-rapidgzip (still off). If a
    # Rocky/portable builder is ever pinned below 1.88, drop --features nfsv4
    # and document in docs/packaging.md. Workflow YAML alone does not compile v4.
    echo "==> cargo build --release -p ratarmount --features nfsv4,sftp-russh"
    cargo build --release -p ratarmount --features nfsv4,sftp-russh
fi
test -x target/release/ratarmount

# Always ship a tarball of the binary (glibc-linked; run on peers with equal-or-newer glibc).
TARBALL_BASE="${NAME}-${VERSION}-${DISTRO_LABEL}-${ARCH_UNAME}"
TARBALL="$OUT_DIR/${TARBALL_BASE}.tar.gz"
# Include a small README in the tarball
STAGE="$OUT_DIR/.tarball-stage-$$"
mkdir -p "$STAGE"
cp -a target/release/ratarmount "$STAGE/"
cat >"$STAGE/README.txt" <<EOF
${NAME} ${VERSION}
Built on: ${DISTRO_LABEL} (${ARCH_UNAME})
Install:  install -m 755 ratarmount /usr/local/bin/
Runtime:  fuse3, libarchive (and optional e2fsprogs, squashfs-tools)
NFS:      --nfs is NFSv3; --nfs-vers 4 is NFSv4.1 (compiled in this package).
          Linux kernel client verified on loopback (privileged Docker
          test-harness/nfs-docker; not default CI). See docs/nfs-export.md.
EOF
tar -C "$STAGE" -czf "$TARBALL" ratarmount README.txt
rm -rf "$STAGE"
echo "Wrote $TARBALL"
(
    cd "$OUT_DIR"
    sha256sum "$(basename "$TARBALL")" | tee "$(basename "$TARBALL").sha256"
)

if [[ "${TARBALL_ONLY:-0}" == "1" || "${PACKAGE_FAMILY:-}" == "none" ]]; then
    echo "==> TARBALL_ONLY/PACKAGE_FAMILY=none — skipping .deb/.rpm"
    ls -la "$OUT_DIR"
    exit 0
fi

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
    mkdir -p "${HOME}/.local/bin"
    if install -m 755 /tmp/nfpm "${HOME}/.local/bin/nfpm" 2>/dev/null; then
        :
    elif command -v sudo >/dev/null 2>&1 && sudo install -m 755 /tmp/nfpm /usr/local/bin/nfpm; then
        :
    else
        install -m 755 /tmp/nfpm /usr/local/bin/nfpm
    fi
    export PATH="${HOME}/.local/bin:/usr/local/bin:${PATH}"
    command -v nfpm >/dev/null
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
