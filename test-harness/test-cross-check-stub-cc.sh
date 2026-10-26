#!/usr/bin/env bash
# Regression (R10-FIX8, r10 skeptic #3): Unix-only code (an `open_admitted_file`
# call with `libc::O_NONBLOCK`) in ratarmount-compositing broke the Windows
# build, and Linux CI never type-checks other targets.
#
# `cargo check` for Windows and macOS on a Linux host, with a stub C compiler:
# build scripts only need their C objects to exist (nothing is linked), so an
# empty object file stands in for each. Type-checks the Rust code only.
# A target that is not installed (`rustup target add ...`) is skipped.
# Warnings are errors, as in CI (override with CROSS_CHECK_RUSTFLAGS).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR"' EXIT
cat >"$STUB_DIR/cc" <<'STUB'
#!/bin/sh
# Writes an empty file at the output path (`-o PATH`, `-oPATH`, MSVC `-FoPATH`).
out=""
prev=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"
  case "$a" in -Fo*) out="${a#-Fo}" ;; -o?*) out="${a#-o}" ;; esac
  prev="$a"
done
[ -n "$out" ] && : >"$out"
exit 0
STUB
chmod +x "$STUB_DIR/cc"

TARGET_DIR="${CROSS_CHECK_TARGET_DIR:-$ROOT/target/cross-check-stub-cc}"
installed="$(rustup target list --installed 2>/dev/null || true)"
failed=0

check() {
  local target="$1"
  shift
  if ! grep -qx "$target" <<<"$installed"; then
    echo "skip: rust target $target is not installed"
    return
  fi
  local var="${target//-/_}"
  echo "== cargo check --target $target $*"
  # CI's workflow-level RUSTFLAGS=-Dwarnings (the windows-lib job too): a
  # dead_code warning on another target fails CI (R11-S2-FIX1).
  if ! env "CC_$var=$STUB_DIR/cc" "AR_$var=ar" CARGO_TARGET_DIR="$TARGET_DIR" \
    RUSTFLAGS="${CROSS_CHECK_RUSTFLAGS--Dwarnings}" \
    cargo check --manifest-path "$ROOT/Cargo.toml" --target "$target" "$@"; then
    echo "FAIL: cargo check --target $target $*" >&2
    failed=1
  fi
}

# The windows-lib CI gate, as CI runs it (warnings are errors), plus
# compositing type-checked without -Dwarnings (CI checks it only through
# ratarmount-session, and skips that step without libarchive; it still has
# Windows-only unused-code warnings).
check x86_64-pc-windows-gnu -p ratarmount-core -p ratarmount-index --all-targets
check x86_64-pc-windows-gnu -p ratarmount-formats-zip -p ratarmount-formats-tar --all-targets
CROSS_CHECK_RUSTFLAGS="" check x86_64-pc-windows-gnu -p ratarmount-compositing
check aarch64-apple-darwin -p ratarmount-core -p ratarmount-index -p ratarmount-compositing \
  -p ratarmount-formats-tar --all-targets
# An unverified Unix ABI (outside the checked-open predicate): tests that use
# the acquisition seams must be gated out, not fail to compile (R11-S3).
# Without -Dwarnings: ratarmount-formats-zip uses `libc::time_t`, deprecated
# on musl (CI builds no musl target).
CROSS_CHECK_RUSTFLAGS="" check x86_64-unknown-linux-musl -p ratarmount-core -p ratarmount-index -p ratarmount-compositing \
  --all-targets
# A 32-bit target (R11-S6-FIX3): portable tests must not use addresses or
# shifts that overflow a 32-bit `usize` (`1 << 40` as a load bias). That
# deny-by-default `arithmetic_overflow` lint runs during code generation,
# which `cargo check` skips, so the lib test harness is compiled
# (`cargo rustc --profile test`) and "linked" with `true`.
codegen_tests() {
  local target="$1"
  shift
  if ! grep -qx "$target" <<<"$installed"; then
    echo "skip: rust target $target is not installed"
    return
  fi
  local var="${target//-/_}"
  echo "== cargo rustc --target $target --profile test $* (codegen, no link)"
  if ! env "CC_$var=$STUB_DIR/cc" "AR_$var=ar" CARGO_TARGET_DIR="$TARGET_DIR" \
    cargo rustc --manifest-path "$ROOT/Cargo.toml" --target "$target" --profile test "$@" \
    -- -C linker=true; then
    echo "FAIL: cargo rustc --target $target --profile test $*" >&2
    failed=1
  fi
}
codegen_tests i686-unknown-linux-gnu -p ratarmount-index --lib

exit "$failed"
