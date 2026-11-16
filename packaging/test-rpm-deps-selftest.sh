#!/usr/bin/env bash
# Regression: #291 rpm installs without declaring its host OpenSSL 1.1 link.
# Fixture self-test for test-rpm-deps.sh. No release binary, rpm tools or network.
set -euo pipefail

CHECKER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/test-rpm-deps.sh"

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
    path.parent.mkdir(parents=True, exist_ok=True)
    data = ehdr + ph_load + ph_dyn + dyn + strs
    # Binutils 2.30 over-reads this sectionless ELF's dynamic string table.
    # Pad the file; PT_LOAD still covers the complete string table above.
    data += b"\x00" * (-len(data) % 4096)
    path.write_bytes(data)

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

printf 'fuse3\nlibarchive\n' > "$WORK/good.requires"
printf 'fuse3\n' > "$WORK/fuse-only.requires"

# Usage errors must fail with exit 2, without needing rpm tools.
run
expect_exit no-args 2
expect_err_has no-args 'usage:'
run "$WORK/missing.rpm"
expect_exit missing-rpm 2
expect_err_has missing-rpm 'does not exist'
run first.rpm second.rpm
expect_exit several-rpms 2
expect_err_has several-rpms 'usage:'
run --unknown
expect_exit unknown-option 2
expect_err_has unknown-option 'usage:'
run --payload "$WORK/missing" --requires "$WORK/good.requires"
expect_exit missing-payload 2
expect_err_has missing-payload 'payload directory does not exist'
run --payload-cpio "$WORK/missing.cpio" --requires "$WORK/good.requires"
expect_exit missing-cpio 2
expect_err_has missing-cpio 'input file does not exist'
run --payload "$WORK" --requires "$WORK/missing.requires"
expect_exit missing-requires 2
expect_err_has missing-requires 'Requires file does not exist'
run --payload "$WORK"
expect_exit incomplete-options 2
expect_err_has incomplete-options 'usage:'
run --payload "$WORK" --wrong "$WORK/good.requires"
expect_exit wrong-options 2
expect_err_has wrong-options 'usage:'

# Regression: a failed mktemp is an infrastructure error, not a violation.
TMPDIR="$WORK/missing-tmpdir" run --payload "$WORK" --requires "$WORK/good.requires"
expect_exit missing-tmpdir 2
expect_err_has missing-tmpdir 'error: cannot create temporary directory'

# Regression: unreadable inputs must report tool/read errors with exit 2.
if (( EUID == 0 )); then
  echo 'skip: unreadable payload/Requires regressions require non-root (root can read mode-000 files)'
else
  write_elf "$WORK/unreadable/usr/bin/ratarmount" libc.so.6
  chmod 000 "$WORK/unreadable/usr/bin/ratarmount"
  run --payload "$WORK/unreadable" --requires "$WORK/good.requires"
  expect_exit unreadable-payload 2
  expect_err_has unreadable-payload 'error: cannot read payload file magic:'
  printf 'fuse3\nlibarchive\n' > "$WORK/unreadable.requires"
  chmod 000 "$WORK/unreadable.requires"
  run --payload "$WORK" --requires "$WORK/unreadable.requires"
  expect_exit unreadable-requires 2
  expect_err_has unreadable-requires 'error: cannot read Requires file:'
fi

# All approved libraries, plus a non-ELF mount helper, are accepted.
write_elf "$WORK/good/usr/bin/ratarmount" "${ALLOWLIST[@]}"
printf '#!/bin/sh\nexec ratarmount "$@"\n' > "$WORK/good/usr/bin/mount.fuse.ratarmount"
run --payload "$WORK/good" --requires "$WORK/good.requires"
expect_exit good 0
expect_out_has good 'Direct NEEDED libraries for usr/bin/ratarmount:'
expect_out_has good 'Requires for '
expect_out_has good 'OK: all rpm ELF direct dependencies are approved and declared'
expect_out_lacks good 'mount.fuse.ratarmount'
expect_out_lacks good 'FAIL:'
expect_err_lacks good 'FAIL:'

# Regression: exit 0 and resolved names must not hide inspection diagnostics.
readelf() {
  command readelf "$@"
  echo 'warning: fixture inspection diagnostic' >&2
}
export -f readelf
run --payload "$WORK/good" --requires "$WORK/good.requires"
unset -f readelf
expect_exit inspection-stderr 2
expect_err_has inspection-stderr 'error: cannot resolve NEEDED names: usr/bin/ratarmount'
expect_err_has inspection-stderr 'warning: fixture inspection diagnostic'
expect_out_lacks inspection-stderr 'OK:'

# Regression: the v0.2.1 shape links undeclared OpenSSL 1.1.
write_elf "$WORK/old/usr/bin/ratarmount" "${ALLOWLIST[@]}" libssl.so.1.1 libcrypto.so.1.1
run --payload "$WORK/old" --requires "$WORK/good.requires"
expect_exit openssl11 1
expect_err_has openssl11 'usr/bin/ratarmount: libssl.so.1.1'
expect_err_has openssl11 'usr/bin/ratarmount: libcrypto.so.1.1'
expect_err_has openssl11 'the rpm must vendor OpenSSL (do not set OPENSSL_NO_VENDOR in the rpm job)'

# Regression: translated inspection output must not hide OpenSSL dependencies.
# Without the French locale installed, the locale request is a no-op; these
# dependency assertions must still pass.
LANGUAGE=fr LC_ALL=fr_FR.UTF-8 LANG=fr_FR.UTF-8 LC_MESSAGES=fr_FR.UTF-8 \
  run --payload "$WORK/old" --requires "$WORK/good.requires"
expect_exit openssl11-french 1
expect_err_has openssl11-french 'FAIL: usr/bin/ratarmount: libssl.so.1.1: the rpm must vendor OpenSSL'

# Regression: unresolved NEEDED names must never become an empty approved list.
# Binutils 2.30 can print a raw hex value; newer versions may instead print
# "<corrupt: 0x...>". A rendered corrupt name is a policy failure (1), while
# an unresolved name or any inspection stderr is an inspection error (2).
for corruption in needed-offset string-table; do
  binary="$WORK/corrupt-$corruption/usr/bin/ratarmount"
  write_elf "$binary" libssl.so.1.1
  python3 - "$binary" "$corruption" << 'PY'
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())
dyn_off = 176
if sys.argv[2] == "needed-offset":
    struct.pack_into("<Q", data, dyn_off + 8, 0xffff)  # NEEDED beyond DT_STRSZ.
else:
    struct.pack_into("<Q", data, dyn_off + 16 + 8, 0x10000)  # DT_STRTAB past EOF.
path.write_bytes(data)
PY
  run --payload "$WORK/corrupt-$corruption" --requires "$WORK/good.requires"
  case "$RC" in
    1) expect_err_has "corrupt-$corruption" 'unapproved/undeclared direct dependency' ;;
    2) expect_err_has "corrupt-$corruption" 'error: cannot resolve NEEDED names: usr/bin/ratarmount' ;;
    *) miss "corrupt-$corruption" ;;
  esac
  expect_out_lacks "corrupt-$corruption" 'OK:'
done

# OpenSSL 3 and either libfuse3 SONAME are also forbidden.
for soname in libssl.so.3 libcrypto.so.3 libfuse3.so.3 libfuse3.so.4 libfoo.so.1; do
  write_elf "$WORK/extra/usr/bin/ratarmount" "${ALLOWLIST[@]}" "$soname"
  run --payload "$WORK/extra" --requires "$WORK/good.requires"
  expect_exit "$soname" 1
  expect_err_has "$soname" "usr/bin/ratarmount:"
  expect_err_has "$soname" "$soname"
  case "$soname" in
    libssl*|libcrypto*) expect_err_has "$soname" 'the rpm must vendor OpenSSL' ;;
    libfuse*) expect_err_has "$soname" 'libfuse3 is loaded at runtime' ;;
    *) expect_err_has "$soname" 'unapproved/undeclared direct dependency' ;;
  esac
done

run --payload "$WORK/good" --requires "$WORK/fuse-only.requires"
expect_exit missing-libarchive 1
expect_err_has missing-libarchive 'undeclared direct dependency: libarchive.so.13'

# Compression can be covered by libarchive, a package, or its SONAME capability.
for pair in libz.so.1:zlib libbz2.so.1.0:bzip2-libs liblzma.so.5:xz-libs libzstd.so.1:libzstd; do
  soname="${pair%%:*}"
  package="${pair#*:}"
  write_elf "$WORK/compression/usr/bin/ratarmount" libc.so.6 "$soname"
  run --payload "$WORK/compression" --requires "$WORK/fuse-only.requires"
  expect_exit "$soname-undeclared" 1
  expect_err_has "$soname-undeclared" "undeclared direct dependency: $soname"
  printf 'fuse3\n%s\n' "$package" > "$WORK/compression.requires"
  run --payload "$WORK/compression" --requires "$WORK/compression.requires"
  expect_exit "$soname-package" 0
  printf 'fuse3\n%s()(64bit)\n' "$soname" > "$WORK/compression.requires"
  run --payload "$WORK/compression" --requires "$WORK/compression.requires"
  expect_exit "$soname-capability" 0
done

printf 'fuse3\nlibarchive >= 3\n' > "$WORK/versioned.requires"
run --payload "$WORK/good" --requires "$WORK/versioned.requires"
expect_exit versioned 0
printf 'fuse3\nlibarchive.so.13()(64bit)\n' > "$WORK/capability.requires"
run --payload "$WORK/good" --requires "$WORK/capability.requires"
expect_exit archive-capability 0

printf 'libarchive\n' > "$WORK/no-fuse.requires"
run --payload "$WORK/good" --requires "$WORK/no-fuse.requires"
expect_exit missing-fuse 1
expect_err_has missing-fuse 'usr/bin/ratarmount: undeclared runtime dependency: fuse3'

# Whole-line, case-insensitive OpenSSL refusal precedes all normalization.
for requirement in openssl-libs 'LIBSSL.so.3()(64bit)' libcrypto.so.1.1 \
  'foo >= OpenSSL' '/usr/lib/libssl.so.3' 'rpmlib(openssl)' '(libarchive and openssl-libs)'; do
  printf 'fuse3\nlibarchive\n%s\n' "$requirement" > "$WORK/openssl.requires"
  run --payload "$WORK/good" --requires "$WORK/openssl.requires"
  expect_exit "$requirement" 1
  expect_err_has "$requirement" "usr/bin/ratarmount: OpenSSL-related Requires is forbidden: $requirement"
done

printf 'fuse3\n(libarchive or foo)\n' > "$WORK/rich.requires"
run --payload "$WORK/good" --requires "$WORK/rich.requires"
expect_exit rich-dependency 1
expect_err_has rich-dependency 'unsupported rich dependency; declare plain capabilities'
expect_err_has rich-dependency 'undeclared direct dependency: libarchive.so.13'

printf 'fuse3\nlibarchive\nrpmlib(PayloadIsZstd) <= 5.4.18-1\n/bin/sh\n\n' > "$WORK/ignored.requires"
run --payload "$WORK/good" --requires "$WORK/ignored.requires"
expect_exit ignored-requires 0

mkdir -p "$WORK/script/usr/bin"
printf '#!/bin/sh\nexit 0\n' > "$WORK/script/usr/bin/ratarmount"
run --payload "$WORK/script" --requires "$WORK/good.requires"
expect_exit no-elf 1
expect_err_has no-elf 'no ELF file found in payload'
expect_out_lacks no-elf 'OK:'

# Regression: auditing only the primary binary misses another ELF's host link.
write_elf "$WORK/two/usr/bin/ratarmount" "${ALLOWLIST[@]}"
write_elf "$WORK/two/usr/libexec/second" "${ALLOWLIST[@]}" libssl.so.3
run --payload "$WORK/two" --requires "$WORK/good.requires"
expect_exit second-elf 1
expect_out_has second-elf 'Direct NEEDED libraries for usr/bin/ratarmount:'
expect_out_has second-elf 'Direct NEEDED libraries for usr/libexec/second:'
expect_err_has second-elf 'usr/libexec/second: libssl.so.3'

# Regression: cpio must strip absolute member names even when run as root.
# Write newc directly so the archive really contains the absolute name; do not
# rely on cpio's writer, which may normalize it before the extraction test.
if command -v cpio >/dev/null 2>&1; then
  python3 - "$WORK" << 'PY'
import stat
import sys
from pathlib import Path

work = Path(sys.argv[1])

def member(name, data, mode):
    name = name.encode() + b"\x00"
    fields = (1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0)
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    record = header + name
    record += b"\x00" * (-len(record) % 4)
    return record + data + b"\x00" * (-len(data) % 4)

name = str(work / "escape/usr/bin/ratarmount")
data = (work / "good/usr/bin/ratarmount").read_bytes()
archive = member(name, data, stat.S_IFREG | 0o755)
archive += member("TRAILER!!!", b"", 0)
(work / "absolute.cpio").write_bytes(archive)
PY
  run --payload-cpio "$WORK/absolute.cpio" --requires "$WORK/good.requires"
  expect_exit absolute-cpio 0
  expect_out_has absolute-cpio "Direct NEEDED libraries for ${WORK#/}/escape/usr/bin/ratarmount:"
  expect_out_has absolute-cpio 'libarchive.so.13'
  expect_out_has absolute-cpio 'OK: all rpm ELF direct dependencies are approved and declared'
  if [[ -e "$WORK/escape" ]]; then
    miss absolute-cpio-escaped
  fi
  echo 'OK: absolute cpio member stayed inside the temporary payload and was audited'
else
  echo 'skip: absolute cpio member regression requires cpio'
fi

echo 'OK: rpm dependency guard self-test'
