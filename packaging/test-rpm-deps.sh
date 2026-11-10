#!/usr/bin/env bash
# Audit every ELF's direct dependencies against the rpm's declared Requires.
# OpenSSL must be vendored; libfuse3 is loaded at runtime, never via NEEDED.
# libarchive's distro package supplies its own compression dependencies.
set -euo pipefail

usage() {
  echo "usage: $0 <package.rpm>" >&2
  echo "       $0 --payload <dir> --requires <file>" >&2
  echo "       $0 --payload-cpio <file.cpio> --requires <file>" >&2
  exit 2
}

MODE=rpm
if [[ $# -eq 1 && "$1" != --* ]]; then
  INPUT="$1"
elif [[ $# -eq 4 && ( "$1" == --payload || "$1" == --payload-cpio ) && "$3" == --requires ]]; then
  MODE="$1"
  INPUT="$2"
  REQUIRES="$4"
  if [[ ! -f "$REQUIRES" ]]; then
    echo "error: Requires file does not exist: $REQUIRES" >&2
    exit 2
  fi
else
  usage
fi

if [[ "$MODE" == --payload ]]; then
  if [[ ! -d "$INPUT" ]]; then
    echo "error: payload directory does not exist: $INPUT" >&2
    exit 2
  fi
elif [[ ! -f "$INPUT" ]]; then
  echo "error: input file does not exist: $INPUT" >&2
  exit 2
fi

if ! command -v readelf >/dev/null 2>&1 && ! command -v objdump >/dev/null 2>&1; then
  echo 'error: readelf or objdump is required' >&2
  exit 2
fi
if [[ "$MODE" != --payload ]] && ! command -v cpio >/dev/null 2>&1; then
  echo 'error: cpio is required' >&2
  exit 2
fi
if [[ "$MODE" == rpm ]]; then
  for tool in rpm rpm2cpio; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "error: $tool is required" >&2
      exit 2
    fi
  done
fi

TMPDIR_AUDIT="$(mktemp -d)"
cleanup() {
  rm -rf "$TMPDIR_AUDIT"
}
trap cleanup EXIT

# Both rpm2cpio and the cpio fixture seam use this extraction path. Strip any
# leading slash so even an absolute member name stays under the temp payload.
extract_cpio() {
  (cd "$TMPDIR_AUDIT/payload" && cpio -idm --quiet --no-absolute-filenames)
}

case "$MODE" in
  rpm)
    mkdir -p "$TMPDIR_AUDIT/payload" "$TMPDIR_AUDIT/rpmdb"
    REQUIRES="$TMPDIR_AUDIT/requires"
    if ! rpm --dbpath "$TMPDIR_AUDIT/rpmdb" -qp --requires "$INPUT" > "$REQUIRES"; then
      echo "error: cannot read rpm Requires: $INPUT" >&2
      exit 2
    fi
    if ! rpm2cpio "$INPUT" | extract_cpio; then
      echo "error: cannot extract rpm payload: $INPUT" >&2
      exit 2
    fi
    PAYLOAD="$TMPDIR_AUDIT/payload"
    ;;
  --payload-cpio)
    mkdir -p "$TMPDIR_AUDIT/payload"
    if ! extract_cpio < "$INPUT"; then
      echo "error: cannot extract cpio payload: $INPUT" >&2
      exit 2
    fi
    PAYLOAD="$TMPDIR_AUDIT/payload"
    ;;
  --payload) PAYLOAD="$(cd "$INPUT" && pwd)" ;;
esac

echo "Requires for $INPUT:"
CAPABILITIES=()
REQUIRES_ERRORS=()
while IFS= read -r line || [[ -n "$line" ]]; do
  printf '  %s\n' "$line"
  # Check the entire line before dropping version expressions or ignoring
  # rpmlib/path entries. Rich dependencies must not hide an OpenSSL dependency.
  case "${line,,}" in
    *libssl*|*libcrypto*|*openssl*)
      REQUIRES_ERRORS+=("OpenSSL-related Requires is forbidden: $line")
      continue
      ;;
  esac
  read -r capability _ <<< "$line"
  case "$capability" in
    \(*) REQUIRES_ERRORS+=("unsupported rich dependency; declare plain capabilities: $line") ;;
    ""|rpmlib\(*|/*) ;;
    *) CAPABILITIES+=("$capability") ;;
  esac
done < "$REQUIRES"

has_requires() {
  local wanted="$1" capability
  for capability in "${CAPABILITIES[@]}"; do
    if [[ "$capability" == "$wanted" ]]; then
      return 0
    fi
  done
  return 1
}

if ! has_requires fuse3; then
  REQUIRES_ERRORS+=("undeclared runtime dependency: fuse3")
fi

failed=0
elf_count=0
if ! find "$PAYLOAD" -type f -print0 > "$TMPDIR_AUDIT/files"; then
  echo "error: cannot list payload: $PAYLOAD" >&2
  exit 2
fi
while IFS= read -r -d '' binary; do
  magic="$(od -An -tx1 -N4 "$binary" | tr -d ' \n')"
  if [[ "$magic" != 7f454c46 ]]; then
    continue
  fi
  elf_count=$((elf_count + 1))
  relative="${binary#"${PAYLOAD%/}"/}"
  if command -v readelf >/dev/null 2>&1; then
    if ! NEEDED="$(readelf -d "$binary" 2>/dev/null \
      | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p')"; then
      echo "error: cannot inspect ELF: $relative" >&2
      exit 2
    fi
  else
    if ! NEEDED="$(objdump -p "$binary" 2>/dev/null \
      | awk '$1 == "NEEDED" { print $2 }')"; then
      echo "error: cannot inspect ELF: $relative" >&2
      exit 2
    fi
  fi

  echo "Direct NEEDED libraries for $relative:"
  if [[ -n "$NEEDED" ]]; then
    while IFS= read -r library; do printf '  %s\n' "$library"; done <<< "$NEEDED"
  fi
  for error in "${REQUIRES_ERRORS[@]}"; do
    echo "FAIL: $relative: $error" >&2
    failed=1
  done
  while IFS= read -r library; do
    case "$library" in
      "") ;;
      # Base-system glibc family, plus the compiler runtime (libgcc).
      libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|libutil.so.1|libresolv.so.2|libanl.so.1|libgcc_s.so.1|ld-linux*.so.*) ;;
      libarchive.so.13)
        if ! has_requires libarchive && ! has_requires 'libarchive.so.13()(64bit)'; then
          echo "FAIL: $relative: undeclared direct dependency: $library (Requires libarchive)" >&2
          failed=1
        fi
        ;;
      libz.so.1|libbz2.so.1.0|liblzma.so.5|libzstd.so.1)
        case "$library" in
          libz.so.1) package=zlib ;;
          libbz2.so.1.0) package=bzip2-libs ;;
          liblzma.so.5) package=xz-libs ;;
          libzstd.so.1) package=libzstd ;;
        esac
        if ! has_requires libarchive && ! has_requires 'libarchive.so.13()(64bit)' \
          && ! has_requires "$package" && ! has_requires "$library()(64bit)"; then
          echo "FAIL: $relative: undeclared direct dependency: $library (Requires libarchive or $package)" >&2
          failed=1
        fi
        ;;
      libssl*|libcrypto*)
        echo "FAIL: $relative: $library: the rpm must vendor OpenSSL (do not set OPENSSL_NO_VENDOR in the rpm job)" >&2
        failed=1
        ;;
      libfuse*)
        echo "FAIL: $relative: rpm must not link libfuse at load time: $library (libfuse3 is loaded at runtime)" >&2
        failed=1
        ;;
      *)
        echo "FAIL: $relative: unapproved/undeclared direct dependency: $library" >&2
        failed=1
        ;;
    esac
  done <<< "$NEEDED"
done < "$TMPDIR_AUDIT/files"

if (( elf_count == 0 )); then
  echo "FAIL: .: no ELF file found in payload: $INPUT" >&2
  failed=1
fi
if (( failed )); then
  exit 1
fi

echo 'OK: all rpm ELF direct dependencies are approved and declared (no libssl/libcrypto)'
