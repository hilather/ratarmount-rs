#!/usr/bin/env bash
# Audit direct ELF dependencies in the portable binary (or release tarball).
# Indirect dependencies of system libarchive/libfuse are resolved by those
# distro packages and are outside this binary's direct NEEDED entries.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <ratarmount-binary|portable-release.tar.gz>" >&2
  exit 2
fi

INPUT="$1"
if [[ ! -f "$INPUT" ]]; then
  echo "error: input file does not exist: $INPUT" >&2
  exit 2
fi

TMPDIR_AUDIT=""
cleanup() {
  if [[ -n "$TMPDIR_AUDIT" ]]; then
    rm -rf "$TMPDIR_AUDIT"
  fi
}
trap cleanup EXIT

if tar -tzf "$INPUT" >/dev/null 2>&1; then
  TMPDIR_AUDIT="$(mktemp -d)"
  if ! tar -xOzf "$INPUT" ratarmount > "$TMPDIR_AUDIT/ratarmount"; then
    echo "error: tarball does not contain a root-level ratarmount binary" >&2
    exit 1
  fi
  BINARY="$TMPDIR_AUDIT/ratarmount"
else
  BINARY="$INPUT"
fi

if ! command -v readelf >/dev/null 2>&1 && ! command -v objdump >/dev/null 2>&1; then
  echo 'error: readelf or objdump is required' >&2
  exit 2
fi

if command -v readelf >/dev/null 2>&1; then
  NEEDED="$(readelf -d "$BINARY" 2>/dev/null \
    | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p')"
else
  NEEDED="$(objdump -p "$BINARY" 2>/dev/null \
    | awk '$1 == "NEEDED" { print $2 }')"
fi

if [[ -z "$NEEDED" ]]; then
  echo "error: no ELF NEEDED entries found in $INPUT" >&2
  exit 1
fi

echo "Direct NEEDED libraries for $INPUT:"
printf '  %s\n' $NEEDED

failed=0
while IFS= read -r library; do
  case "$library" in
    # glibc 2.31-compatible runtime family, plus the compiler runtime.
    libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|libutil.so.1|libresolv.so.2|libanl.so.1|libgcc_s.so.1|ld-linux*.so.*) ;;
    # Declared host runtime packages: FUSE and libarchive. Compression libraries
    # may remain dynamic; these SONAMEs are stable across supported Linux distros.
    libfuse3.so.3|libarchive.so.13|libz.so.1|libbz2.so.1.0|liblzma.so.5|libzstd.so.1) ;;
    *)
      echo "FAIL: unapproved direct dependency: $library" >&2
      failed=1
      ;;
  esac
done <<< "$NEEDED"

if (( failed )); then
  echo 'Portable binary must not directly depend on libssl or libcrypto; vendor OpenSSL in the portable build.' >&2
  exit 1
fi

echo 'OK: all direct dependencies are on the portable allowlist (no libssl/libcrypto)'
