#!/usr/bin/env bash
# Regression: test-only env seams (RATARMOUNT_TEST_HASH_LOG, _HASH_DELAY_MS,
# _HASH_HOLD, _HASH_GATE, _STAT_PANIC) must not exist in a release binary.
# Usage: packaging/test-no-test-hooks-in-release.sh [path/to/ratarmount]
#        packaging/test-no-test-hooks-in-release.sh --self-test
set -euo pipefail

count_hooks() {
  # `strings` finds the literal env names; fall back to grep -a without it.
  if command -v strings >/dev/null 2>&1; then
    strings "$1" | grep -c 'RATARMOUNT_TEST_' || true
  else
    grep -a -o 'RATARMOUNT_TEST_[A-Z_]*' "$1" | wc -l
  fi
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  printf 'clean\0binary\0' >"$tmp/clean"
  printf 'x\0RATARMOUNT_TEST_HASH_LOG\0y\0' >"$tmp/dirty"
  [ "$(count_hooks "$tmp/clean")" = 0 ] || { echo "self-test: clean binary flagged" >&2; exit 1; }
  [ "$(count_hooks "$tmp/dirty")" != 0 ] || { echo "self-test: dirty binary missed" >&2; exit 1; }
  echo "self-test ok"
  exit 0
fi

bin="${1:-target/release/ratarmount}"
[ -f "$bin" ] || { echo "no binary at $bin (build with: cargo build --release -p ratarmount)" >&2; exit 2; }
n="$(count_hooks "$bin")"
if [ "$n" != 0 ]; then
  echo "FAIL: $n RATARMOUNT_TEST_ strings in $bin" >&2
  strings "$bin" | grep 'RATARMOUNT_TEST_' | sort -u >&2
  exit 1
fi
echo "ok: no RATARMOUNT_TEST_ strings in $bin"
