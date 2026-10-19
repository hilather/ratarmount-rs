#!/usr/bin/env bash
# Regression (R6-G8): make-overlay-v0.1.35.sh ran `rm -rf "$OUT"`, which deleted
# the committed README.md beside the generated fixture. Regenerating replaces
# the overlay and base.tar (including stale files inside the old overlay) and
# keeps the README. No FUSE and no released binary needed (`--publish-only`).
#
#   ./test-harness/test-make-overlay-v0.1.35.sh [path/to/make-overlay-v0.1.35.sh]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${1:-$HERE/make-overlay-v0.1.35.sh}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/work/overlay" "$TMP/out/overlay"
echo new-overlay > "$TMP/work/overlay/created.txt"
echo new-base > "$TMP/work/base.tar"
echo "documentation" > "$TMP/out/README.md"
echo stale > "$TMP/out/overlay/stale.txt"
echo old-base > "$TMP/out/base.tar"

bash "$SCRIPT" --publish-only "$TMP/work" "$TMP/out"

fail() { echo "FAIL: $1" >&2; exit 1; }
[ "$(cat "$TMP/out/README.md" 2>/dev/null)" = documentation ] || fail "README.md was deleted or changed"
[ "$(cat "$TMP/out/overlay/created.txt")" = new-overlay ] || fail "overlay was not replaced"
[ ! -e "$TMP/out/overlay/stale.txt" ] || fail "a stale file survived inside the overlay"
[ "$(cat "$TMP/out/base.tar")" = new-base ] || fail "base.tar was not replaced"
echo "ok: README kept, overlay and base.tar replaced"
