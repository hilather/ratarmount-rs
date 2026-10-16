#!/usr/bin/env bash
# Fixture self-test for test-portable-deps.sh. No release binary and no network.
set -euo pipefail

CHECKER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test-portable-deps.sh"

if ! command -v python3 >/dev/null 2>&1; then
  echo python3 >&2
  exit 2
fi
if ! command -v readelf >/dev/null 2>&1; then
  echo readelf >&2
  exit 2
fi

WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

ALLOWLIST=(
  libc.so.6
  libm.so.6
  libpthread.so.0
  libdl.so.2
  librt.so.1
  libutil.so.1
  libresolv.so.2
  libanl.so.1
  libgcc_s.so.1
  ld-linux-x86-64.so.2
  libfuse3.so.3
  libarchive.so.13
  libz.so.1
  libbz2.so.1.0
  liblzma.so.5
  libzstd.so.1
)

write_elf() {
  local dest="$1"
  shift
  python3 - "$dest" "$@" << 'PY'
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
sonames = sys.argv[2:]

def write_elf(path, sonames):
    strs = b"\x00"
    offs = []
    for name in sonames:
        offs.append(len(strs))
        strs += name.encode() + b"\x00"
    dyn_off = 176
    dyn_size = (len(sonames) + 3) * 16
    str_off = dyn_off + dyn_size
    def phdr(p_type, flags, off, filesz, align):
        return struct.pack("<IIQQQQQQ", p_type, flags, off, off, off, filesz, filesz, align)
    ph_load = phdr(1, 5, 0, str_off + len(strs), 0x1000)
    ph_dyn = phdr(2, 4, dyn_off, dyn_size, 8)
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9,
        3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0,
    )
    dyn = b"".join(struct.pack("<QQ", 1, off) for off in offs)
    dyn += struct.pack("<QQ", 5, str_off)
    dyn += struct.pack("<QQ", 10, len(strs))
    dyn += struct.pack("<QQ", 0, 0)
    path.write_bytes(ehdr + ph_load + ph_dyn + dyn + strs)

write_elf(path, sonames)
PY
}

OUT=""
ERR=""
RC=0

run() {
  local outf="${WORK}/stdout" errf="${WORK}/stderr"
  : >"$outf"
  : >"$errf"
  set +e
  bash "$CHECKER" "$@" >"$outf" 2>"$errf"
  RC=$?
  set -e
  OUT="$(<"$outf")"
  ERR="$(<"$errf")"
}

miss() {
  echo "case ${1}: exit ${RC}" >&2
  echo "--- stdout ---" >&2
  printf '%s\n' "$OUT" >&2
  echo "--- stderr ---" >&2
  printf '%s\n' "$ERR" >&2
  exit 1
}

expect_exit() {
  if [[ "$RC" -ne "$2" ]]; then
    miss "$1"
  fi
}

expect_out_has() {
  if [[ "$OUT" != *"$2"* ]]; then
    miss "$1"
  fi
}

expect_err_has() {
  if [[ "$ERR" != *"$2"* ]]; then
    miss "$1"
  fi
}

expect_out_lacks() {
  if [[ "$OUT" == *"$2"* ]]; then
    miss "$1"
  fi
}

expect_err_lacks() {
  if [[ "$ERR" == *"$2"* ]]; then
    miss "$1"
  fi
}

# 1. no arguments
run
expect_exit 1 2
expect_err_has 1 "usage:"

# 2. missing path
run "${WORK}/does-not-exist"
expect_exit 2 2
expect_err_has 2 "does not exist"

# 3. allowlist ELF
write_elf "${WORK}/allow.elf" "${ALLOWLIST[@]}"
run "${WORK}/allow.elf"
expect_exit 3 0
expect_out_has 3 "OK: all direct dependencies are on the portable allowlist"
expect_out_lacks 3 "FAIL:"
expect_err_lacks 3 "FAIL:"

# 4. gzip tarball of the allowlist ELF, member name ratarmount
mkdir -p "${WORK}/c4"
write_elf "${WORK}/c4/ratarmount" "${ALLOWLIST[@]}"
tar -C "${WORK}/c4" -czf "${WORK}/c4.tar.gz" ratarmount
run "${WORK}/c4.tar.gz"
expect_exit 4 0
expect_out_has 4 "OK: all direct dependencies are on the portable allowlist"
expect_out_lacks 4 "FAIL:"
expect_err_lacks 4 "FAIL:"

# 5. allowlist plus libssl.so.1.1
write_elf "${WORK}/ssl11.elf" "${ALLOWLIST[@]}" libssl.so.1.1
run "${WORK}/ssl11.elf"
expect_exit 5 1
expect_err_has 5 "FAIL: unapproved direct dependency: libssl.so.1.1"
expect_err_has 5 "vendor OpenSSL"

# 6. allowlist plus libcrypto.so.1.1
write_elf "${WORK}/crypto11.elf" "${ALLOWLIST[@]}" libcrypto.so.1.1
run "${WORK}/crypto11.elf"
expect_exit 6 1
expect_err_has 6 "FAIL: unapproved direct dependency: libcrypto.so.1.1"
expect_err_has 6 "vendor OpenSSL"

# 7. allowlist plus libssl.so.3
write_elf "${WORK}/ssl3.elf" "${ALLOWLIST[@]}" libssl.so.3
run "${WORK}/ssl3.elf"
expect_exit 7 1
expect_err_has 7 "FAIL: unapproved direct dependency: libssl.so.3"

# 8. allowlist plus libfoo.so.1
write_elf "${WORK}/libfoo.elf" "${ALLOWLIST[@]}" libfoo.so.1
run "${WORK}/libfoo.elf"
expect_exit 8 1
expect_err_has 8 "FAIL: unapproved direct dependency: libfoo.so.1"

# 9. gzip tarball of the libssl.so.1.1 ELF, member name ratarmount
mkdir -p "${WORK}/c9"
write_elf "${WORK}/c9/ratarmount" "${ALLOWLIST[@]}" libssl.so.1.1
tar -C "${WORK}/c9" -czf "${WORK}/c9.tar.gz" ratarmount
run "${WORK}/c9.tar.gz"
expect_exit 9 1
expect_err_has 9 "libssl.so.1.1"
expect_err_has 9 "vendor OpenSSL"

# 10. gzip tarball whose only member is README.txt
mkdir -p "${WORK}/c10"
printf 'not the binary\n' > "${WORK}/c10/README.txt"
tar -C "${WORK}/c10" -czf "${WORK}/c10.tar.gz" README.txt
run "${WORK}/c10.tar.gz"
expect_exit 10 1
expect_err_has 10 "root-level ratarmount"

# 11. regular non-ELF file
printf 'hello\n' > "${WORK}/hello.txt"
run "${WORK}/hello.txt"
expect_exit 11 1
expect_out_lacks 11 "OK:"

echo "OK: portable dependency allowlist self-test"
