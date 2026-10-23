#!/usr/bin/env bash
# Regression (R11-CI, #199): the aarch64 wheels (Linux and macOS) exported
# blake3's NEON FFI shim `blake3_compress_in_place_portable` (blake3-1.8.2
# src/ffi_neon.rs, `#[no_mangle] pub extern "C"`, built under cfg(blake3_neon)),
# and the wheel export audit refused them. `ratarmount-python`'s
# `extension-module` feature (the wheel and `maturin develop`/`build` feature)
# now builds blake3 with `no_neon` on aarch64.
#
# This checks the dependency graph only: that `no_neon` is unified into blake3
# for aarch64 builds with `extension-module` and for nothing else (default and
# `embedding` builds of ratarmount-python, the `ratarmount` CLI, x86_64). It
# does not inspect what the library exports. The end-to-end regression is the
# wheels job's `python3 -I packaging/audit_native_exports.py dist/*.whl` on
# aarch64 Linux and macOS, plus the installed-wheel pytest
# `test_regression_native_exports_are_private`.
#
# Observed `cargo tree -e features -i blake3` line for the positive rows:
#   ├── blake3 feature "no_neon"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MATCH='blake3 feature "no_neon"'
AARCH64_TARGETS=(aarch64-unknown-linux-gnu aarch64-apple-darwin)
X86_TARGET=x86_64-unknown-linux-gnu

# Every target queried below must be fetched first (the aarch64 graphs hold
# crates an x86_64 job never fetched, and the x86_64 row needs `multiversion`).
cargo fetch --target "${AARCH64_TARGETS[0]}" --target "${AARCH64_TARGETS[1]}" --target "$X86_TARGET"

fail=0
tree() {
  # Prints the feature tree; a cargo failure fails the script (no silent pass).
  local target=$1
  shift
  cargo tree --offline -e features -i blake3 --target "$target" "$@"
}
expect() {
  local want=$1 target=$2
  shift 2
  local out
  out=$(tree "$target" "$@")
  if grep -qF "$MATCH" <<<"$out"; then
    got=yes
  else
    got=no
  fi
  if [ "$got" = "$want" ]; then
    echo "ok   no_neon=$want: $target $*"
  else
    echo "FAIL no_neon=$got (want $want): $target $*" >&2
    fail=1
  fi
}

for target in "${AARCH64_TARGETS[@]}"; do
  expect yes "$target" -p ratarmount-python --features extension-module
  expect no "$target" -p ratarmount-python
  expect no "$target" -p ratarmount-python --features embedding
  expect no "$target" -p ratarmount
done
expect no "$X86_TARGET" -p ratarmount-python --features extension-module

if [ "$fail" -ne 0 ]; then
  echo "test-wheel-blake3-no-neon: FAILED" >&2
  exit 1
fi
echo "test-wheel-blake3-no-neon: ok"
