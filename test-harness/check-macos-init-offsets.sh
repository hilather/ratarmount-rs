#!/usr/bin/env bash
# Init-section layout check for the macOS checked-open step (ci.yml): at the
# wheel's MACOSX_DEPLOYMENT_TARGET Apple's linker rewrites `__mod_init_func`
# into `__init_offsets`. Fail unless the linked test binary really has that
# layout, so the constructor tests in the same step ran against it.
#
#   ./test-harness/check-macos-init-offsets.sh <linked Mach-O binary>
set -euo pipefail

bin="${1:?usage: $0 <binary>}"
sects="$(otool -l "$bin" | awk '$1 == "sectname" {print $2}')"
if ! grep -qx '__init_offsets' <<<"$sects"; then
  echo "FAIL: $bin has no __init_offsets section" >&2
  exit 1
fi
if grep -qx '__mod_init_func' <<<"$sects"; then
  echo "FAIL: $bin still has a __mod_init_func section" >&2
  exit 1
fi
echo "ok: $bin uses __init_offsets (no __mod_init_func)"
