#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKGBUILD_FILE="${SCRIPT_DIR}/PKGBUILD"
VERSION="${1:-$(sed -n 's/^pkgver=//p' "$PKGBUILD_FILE" | head -n1)}"
BASE_URL="https://github.com/hilather/ratarmount-rs/releases/download/v${VERSION}"
SUMS_FILE="$(mktemp)"
trap 'rm -f "$SUMS_FILE"' EXIT
curl --fail --location --silent --show-error "${BASE_URL}/SHA256SUMS" -o "$SUMS_FILE"

for arch in x86_64 aarch64; do
  asset="ratarmount-${VERSION}-portable-glibc2.31-${arch}.tar.gz"
  sum="$(awk -v name="$asset" '$2 == name { print $1 }' "$SUMS_FILE")"
  [[ "$sum" =~ ^[[:xdigit:]]{64}$ ]] || {
    echo "SHA256SUMS does not contain a valid checksum for ${asset}" >&2
    exit 1
  }
  sed -i "s/^pkgver=.*/pkgver=${VERSION}/" "$PKGBUILD_FILE"
  sed -i "s/^sha256sums_${arch}=.*/sha256sums_${arch}=('${sum}')/" "$PKGBUILD_FILE"
done

echo "Updated portable tarball checksums for ${VERSION} in ${PKGBUILD_FILE}"
