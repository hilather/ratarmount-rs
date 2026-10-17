#!/usr/bin/env bash
# Regression: the Rust gzip A/B benchmark can run without optional Python deps.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cat >"$TMP/ratarmount" <<'STUB'
#!/usr/bin/env sh
exit 0
STUB
chmod +x "$TMP/ratarmount"

RATARMOUNT_ALLOW_NO_PY=1 \
RATARMOUNT_CMD=/bin/true \
RUST_BIN="$TMP/ratarmount" \
RUST_FEATURES=gzip-rapidgzip \
SKIP_BUILD=1 \
SKIP_PYTHON=1 \
SKIP_FUSE=1 \
CORPUS_MIB=2 \
RUNS=1 \
OUT_DIR="$TMP/results" \
  "$ROOT/benchmarks/compare-gzip-backends.sh" >"$TMP/run.log" 2>&1

grep -q '^rust-g3;' "$TMP/results/results.csv"
grep -q '^rust-rapidgzip;' "$TMP/results/results.csv"
if grep -q '^python;' "$TMP/results/results.csv"; then
  echo "FAIL: Python rows present with SKIP_PYTHON=1" >&2
  exit 1
fi

echo "OK: gzip backend A/B runs without Python or FUSE"
