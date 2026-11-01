#!/usr/bin/env bash
# Build libarchive and the compression libraries it links (xz, lz4, zstd) from
# pinned, checksummed sources for the macOS wheel (python.yml), at the wheel's
# MACOSX_DEPLOYMENT_TARGET. Homebrew's libarchive/xz/lz4 bottles on the
# macos-15 runner require macOS 15, which delocate-wheel rejects at the
# wheel's 14.0 target. zstd is built too: Homebrew libarchive links it and its
# bottle has the same floor, so dropping it would remove the zstd filter.
#
#   packaging/build-macos-deps.sh build <prefix>   # cache miss
#   packaging/build-macos-deps.sh check <prefix>   # every run, cache hit too
set -euo pipefail

mode="${1:?usage: $0 build|check <prefix>}"
P="${2:?usage: $0 build|check <prefix>}"
: "${MACOSX_DEPLOYMENT_TARGET:?MACOSX_DEPLOYMENT_TARGET must be set}"

fail() { echo "::error::build-macos-deps: $*" >&2; exit 1; }

fetch() { # file url sha256 -> extracted into $W/<name>
  local file=$1 url=$2 sum=$3 dir="$W/${1%%.tar*}"
  curl -fsSL --retry 3 -o "$W/$file" "$url"
  echo "$sum  $W/$file" | shasum -a 256 -c -
  mkdir -p "$dir"
  tar -xf "$W/$file" -C "$dir" --strip-components 1
}

build() {
  W="$(mktemp -d)"
  mkdir -p "$P"
  local j
  j="$(sysctl -n hw.ncpu)"

  fetch xz-5.8.4.tar.gz \
    https://github.com/tukaani-project/xz/releases/download/v5.8.4/xz-5.8.4.tar.gz \
    0014c7886930454fe8bd4228665b51af55eeae560ea135c9c4cd33f55b2591d9
  (cd "$W/xz-5.8.4" &&
    ./configure --prefix="$P" --disable-static --disable-doc --disable-nls \
      --disable-xz --disable-xzdec --disable-lzmadec --disable-lzmainfo \
      --disable-lzma-links --disable-scripts &&
    make -j"$j" && make install)

  # PREFIX on both make calls: the Darwin install_name derives from it.
  fetch lz4-1.10.0.tar.gz \
    https://github.com/lz4/lz4/archive/refs/tags/v1.10.0.tar.gz \
    537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b
  make -C "$W/lz4-1.10.0/lib" -j"$j" PREFIX="$P"
  make -C "$W/lz4-1.10.0/lib" install PREFIX="$P"

  fetch zstd-1.5.7.tar.gz \
    https://github.com/facebook/zstd/archive/refs/tags/v1.5.7.tar.gz \
    37d7284556b20954e56e1ca85b80226768902e2edabd3b649e9e72c0c9012ee3
  make -C "$W/zstd-1.5.7/lib" -j"$j" lib-release PREFIX="$P"
  make -C "$W/zstd-1.5.7/lib" install PREFIX="$P"

  # PKG_CONFIG_LIBDIR hides Homebrew's .pc files (libxml-2.0, openssl, libb2)
  # so configure links only the libraries above or macOS's own /usr/lib ones.
  fetch libarchive-3.8.11.tar.xz \
    https://www.libarchive.org/downloads/libarchive-3.8.11.tar.xz \
    a3dc0872b1b39da34dc18ef1b944f0f11ffd37425d70ae04be679279f1cf43d2
  (cd "$W/libarchive-3.8.11" &&
    PKG_CONFIG_LIBDIR="$P/lib/pkgconfig" PKG_CONFIG_PATH="" \
      CPPFLAGS="-I$P/include" LDFLAGS="-L$P/lib" \
      ./configure --prefix="$P" --disable-static \
        --disable-bsdtar --disable-bsdcpio --disable-bsdcat --disable-bsdunzip \
        --without-openssl --without-nettle --without-mbedtls --without-libb2 \
        --without-xml2 --with-expat &&
    make -j"$j" && make install &&
    cp config.h "$P/libarchive-config.h")
  rm -rf "$W"
}

check() {
  local lib="$P/lib/libarchive.13.dylib" cfg="$P/libarchive-config.h" d f minos
  [[ -f "$lib" ]] || fail "missing $lib"
  [[ -f "$P/lib/pkgconfig/libarchive.pc" ]] || fail "missing libarchive.pc"
  local deps
  deps="$(otool -L "$lib" | tail -n +2 | awk '{print $1}')"
  for want in liblzma liblz4 libzstd; do
    grep -q "^$P/lib/$want\." <<<"$deps" || fail "libarchive does not link $P/lib/$want"
  done
  for f in "$P"/lib/*.dylib; do
    [[ -L "$f" ]] && continue
    for d in $(otool -L "$f" | tail -n +2 | awk '{print $1}'); do
      case "$d" in
        "$P"/lib/* | /usr/lib/* | /System/*) ;;
        *) fail "$f links $d (only $P/lib, /usr/lib, /System allowed)" ;;
      esac
    done
    # Read all of otool's output (no early awk exit): an early exit can SIGPIPE
    # otool and fail a valid dylib under pipefail (test-build-macos-deps-check.sh).
    minos="$(otool -l "$f" | awk '/LC_BUILD_VERSION/{b=1} b && $1=="minos" && m==""{m=$2} END{print m}')"
    [[ -n "$minos" ]] || fail "$f has no LC_BUILD_VERSION minos"
    python3 -I -c 'import sys; v=lambda s: tuple(map(int, s.split("."))); sys.exit(v(sys.argv[1]) > v(sys.argv[2]))' \
      "$minos" "$MACOSX_DEPLOYMENT_TARGET" || fail "$f minos $minos > $MACOSX_DEPLOYMENT_TARGET"
  done
  for h in HAVE_LZMA_H HAVE_LZ4_H HAVE_ZSTD_H HAVE_EXPAT_H; do
    grep -q "^#define $h 1" "$cfg" || fail "libarchive built without $h"
  done
  if grep -q '^#define HAVE_LIBXML_XMLREADER_H 1' "$cfg"; then
    fail "libarchive picked libxml2; expected the expat backend"
  fi
  echo "ok: $lib links lzma, lz4, zstd from $P; every dylib minos <= $MACOSX_DEPLOYMENT_TARGET"
}

case "$mode" in
  build) build; check ;;
  check) check ;;
  *) fail "unknown mode $mode" ;;
esac
