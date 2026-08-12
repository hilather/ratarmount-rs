#!/usr/bin/env bash
# Compare nested archive open cost **with** vs **without** durable nested indexes
# (outer SQLite side table `nestedindexes`).
#
# Modes (same outer archive + same outer warm index where applicable):
#   cold_first        First -c -r open: builds outer index + nestedindexes (store)
#   warm_with_nested  Remount -r with nestedindexes present (import hit)
#   warm_without_nested
#                     Remount -r after DELETE FROM nestedindexes (outer warm, nested cold rebuild)
#   cold_no_durable   -c -r with --index-file :memory: (no durable nested store/load)
#
# Usage:
#   ./benchmarks/compare-nested-durable.sh
#   N_FILES=5000 RUNS=3 ./benchmarks/compare-nested-durable.sh
#
# Requires: release ratarmount, tar, zip, sqlite3, python3. Optional: 7z/7za for 7z leg.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${RATARMOUNT_CMD:-$ROOT/target/release/ratarmount}"
OUT_DIR="${OUT_DIR:-$ROOT/benchmarks/nested-durable-results}"
WORKDIR="${WORKDIR:-$(mktemp -d /tmp/ratarmount-nested-durable-XXXXXX)}"
N_FILES="${N_FILES:-2000}"
RUNS="${RUNS:-3}"
INCLUDE_7Z="${INCLUDE_7Z:-1}"
KEEP_WORK="${KEEP_WORK:-0}"

mkdir -p "$OUT_DIR" "$WORKDIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
CSV="$OUT_DIR/results-$STAMP.csv"
MD="$OUT_DIR/results-$STAMP.md"

cleanup() {
  if [[ "$KEEP_WORK" != "1" ]]; then
    rm -rf "$WORKDIR" || true
  else
    echo "KEEP_WORK=1: left $WORKDIR" >&2
  fi
}
trap cleanup EXIT

echoerr() { echo "$@" >&2; }

if [[ ! -x "$BIN" ]]; then
  echoerr "Building release ratarmount..."
  (cd "$ROOT" && cargo build -p ratarmount --release)
fi
if [[ ! -x "$BIN" ]]; then
  echoerr "ERROR: binary not found: $BIN"
  exit 1
fi

# Median of floating seconds from stdin (one per line)
median_f() {
  python3 -c '
import sys
xs=[float(x) for x in sys.stdin.read().split() if x.strip()]
if not xs:
    print("nan"); raise SystemExit(1)
xs.sort()
n=len(xs)
print(f"{xs[n//2] if n%2 else 0.5*(xs[n//2-1]+xs[n//2]):.4f}")
'
}

# Wall-time one command; prints seconds to stdout
time_cmd() {
  local start end
  start=$(date +%s.%N)
  "$@" >/dev/null
  end=$(date +%s.%N)
  python3 -c "print(f'{float(\"$end\")-float(\"$start\"):.6f}')"
}

count_nestedindexes() {
  local idx=$1
  if [[ ! -f "$idx" ]]; then
    echo 0
    return
  fi
  sqlite3 "$idx" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='nestedindexes';" 2>/dev/null | grep -q '^1$' || {
    echo 0
    return
  }
  sqlite3 "$idx" 'SELECT COUNT(*) FROM "nestedindexes";' 2>/dev/null || echo 0
}

clear_nestedindexes() {
  local idx=$1
  [[ -f "$idx" ]] || return 0
  sqlite3 "$idx" 'DROP TABLE IF EXISTS "nestedindexes";' 2>/dev/null || true
}

# ---- build fixtures ---------------------------------------------------------
echoerr "==> Fixture: outer.tar with store ZIP of $N_FILES members"
ZDATA="$WORKDIR/zdata"
mkdir -p "$ZDATA"
for i in $(seq 1 "$N_FILES"); do
  # Fixed-size-ish payload so zip layout is stable
  printf 'nested-bench-file-%06d-payload-xxxxxxxxxxxxxxxx\n' "$i" >"$ZDATA/f$(printf '%06d' "$i").txt"
done
INNER_ZIP="$WORKDIR/inner.zip"
(cd "$ZDATA" && zip -q -0 "$INNER_ZIP" ./*.txt)
OUTER_TAR="$WORKDIR/outer-zip.tar"
tar -cf "$OUTER_TAR" -C "$WORKDIR" inner.zip
echoerr "  outer-zip.tar size=$(stat -c%s "$OUTER_TAR") zip=$(stat -c%s "$INNER_ZIP")"

OUTER_7Z_TAR=""
if [[ "$INCLUDE_7Z" == "1" ]]; then
  SEVEN=
  for b in 7z 7za; do
    if command -v "$b" >/dev/null 2>&1; then SEVEN=$b; break; fi
  done
  if [[ -n "$SEVEN" ]]; then
    echoerr "==> Fixture: outer.tar with store 7z of $N_FILES members"
    INNER_7Z="$WORKDIR/inner.7z"
    rm -f "$INNER_7Z"
    # store/non-solid for fast outer member open
    (cd "$ZDATA" && "$SEVEN" a -t7z -mx0 -y "$INNER_7Z" ./*.txt >/dev/null)
    OUTER_7Z_TAR="$WORKDIR/outer-7z.tar"
    tar -cf "$OUTER_7Z_TAR" -C "$WORKDIR" inner.7z
    echoerr "  outer-7z.tar size=$(stat -c%s "$OUTER_7Z_TAR") 7z=$(stat -c%s "$INNER_7Z")"
  else
    echoerr "  skip 7z leg: no 7z/7za"
    INCLUDE_7Z=0
  fi
fi

echo "tool;mode;archive;metric;value;unit;notes" >"$CSV"
csv() {
  # tool mode archive metric value unit notes
  printf '%s;%s;%s;%s;%s;%s;%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "${7:-}" >>"$CSV"
}

run_leg() {
  local archive=$1
  local label=$2 # zip | 7z
  local idx="$WORKDIR/${label}.index.sqlite"
  local times n_stored n_after_warm n_after_clear

  echoerr ""
  echoerr "==== leg=$label archive=$(basename "$archive") runs=$RUNS ===="

  # --- cold_first: recreate outer + store nestedindexes ---
  times=""
  for r in $(seq 1 "$RUNS"); do
    rm -f "$idx"
    t=$(time_cmd "$BIN" -c -r --no-mount \
      --index-file "$idx" \
      --index-minimum-file-count 0 \
      --parallel-nested 1 \
      "$archive")
    times+="$t "
    echoerr "  cold_first run $r: ${t}s nestedindexes=$(count_nestedindexes "$idx")"
  done
  med=$(printf '%s\n' $times | median_f)
  n_stored=$(count_nestedindexes "$idx")
  csv "rust" "cold_first" "$label" "median_s" "$med" "s" "nestedindexes=$n_stored"
  csv "rust" "cold_first" "$label" "nestedindexes_n" "$n_stored" "count" ""
  echoerr "  cold_first median=${med}s nestedindexes=$n_stored"
  if [[ "$n_stored" -lt 1 ]]; then
    echoerr "ERROR: expected nestedindexes after cold_first (durable store missing)"
    exit 1
  fi

  # Ensure index is populated once more for stable warm baseline
  rm -f "$idx"
  "$BIN" -c -r --no-mount --index-file "$idx" --index-minimum-file-count 0 \
    --parallel-nested 1 "$archive" >/dev/null
  n_stored=$(count_nestedindexes "$idx")

  # --- warm_with_nested: remount; nestedindexes present ---
  times=""
  for r in $(seq 1 "$RUNS"); do
    t=$(time_cmd "$BIN" -r --no-mount \
      --index-file "$idx" \
      --index-minimum-file-count 0 \
      --parallel-nested 1 \
      "$archive")
    times+="$t "
    echoerr "  warm_with_nested run $r: ${t}s nestedindexes=$(count_nestedindexes "$idx")"
  done
  med=$(printf '%s\n' $times | median_f)
  n_after_warm=$(count_nestedindexes "$idx")
  csv "rust" "warm_with_nested" "$label" "median_s" "$med" "s" "nestedindexes=$n_after_warm"
  echoerr "  warm_with_nested median=${med}s"

  # --- warm_without_nested: DROP nestedindexes; outer files table stays warm ---
  # Rebuild outer+nested once so baseline index is complete, then each sample:
  # clear nested side table only and remount without -c.
  rm -f "$idx"
  "$BIN" -c -r --no-mount --index-file "$idx" --index-minimum-file-count 0 \
    --parallel-nested 1 "$archive" >/dev/null
  times=""
  for r in $(seq 1 "$RUNS"); do
    clear_nestedindexes "$idx"
    # Without -c: outer warm; nested cold-rebuilds and re-stores nestedindexes
    t=$(time_cmd "$BIN" -r --no-mount \
      --index-file "$idx" \
      --index-minimum-file-count 0 \
      --parallel-nested 1 \
      "$archive")
    times+="$t "
    echoerr "  warm_without_nested run $r: ${t}s (post nestedindexes=$(count_nestedindexes "$idx"))"
  done
  med=$(printf '%s\n' $times | median_f)
  csv "rust" "warm_without_nested" "$label" "median_s" "$med" "s" "outer_warm_nested_rebuild"
  echoerr "  warm_without_nested median=${med}s"

  # --- cold_no_durable: pure :memory: outer (no nestedindexes home) ---
  times=""
  for r in $(seq 1 "$RUNS"); do
    t=$(time_cmd "$BIN" -c -r --no-mount \
      --index-file :memory: \
      --index-minimum-file-count 0 \
      --parallel-nested 1 \
      "$archive")
    times+="$t "
    echoerr "  cold_no_durable run $r: ${t}s"
  done
  med=$(printf '%s\n' $times | median_f)
  csv "rust" "cold_no_durable" "$label" "median_s" "$med" "s" "index=:memory:"
  echoerr "  cold_no_durable median=${med}s"
}

run_leg "$OUTER_TAR" "zip"
if [[ "$INCLUDE_7Z" == "1" && -n "$OUTER_7Z_TAR" ]]; then
  run_leg "$OUTER_7Z_TAR" "7z"
fi

# ---- markdown summary -------------------------------------------------------
python3 - "$CSV" "$MD" "$N_FILES" "$RUNS" "$STAMP" <<'PY'
import csv, sys
from collections import defaultdict
from pathlib import Path

csv_path, md_path, n_files, runs, stamp = sys.argv[1:6]
rows = list(csv.DictReader(open(csv_path), delimiter=";"))
by = defaultdict(dict)
for r in rows:
    if r["metric"] == "median_s":
        by[r["archive"]][r["mode"]] = float(r["value"])
    if r["metric"] == "nestedindexes_n":
        by[r["archive"]]["nestedindexes_n"] = int(float(r["value"]))

lines = []
lines.append(f"# Nested durable index benchmark ({stamp})\n")
lines.append(f"- **N_FILES** (nested members): `{n_files}`")
lines.append(f"- **RUNS** (median of): `{runs}`")
lines.append("- **Binary**: `ratarmount -r --no-mount` (eager AutoMount nested open, no FUSE)")
lines.append("")
lines.append("## Modes\n")
lines.append("| Mode | Meaning |")
lines.append("|------|---------|")
lines.append("| `cold_first` | `-c -r`: cold outer + cold nested; **stores** `nestedindexes` |")
lines.append("| `warm_with_nested` | remount `-r` with outer index + **nestedindexes** present (import hit) |")
lines.append("| `warm_without_nested` | remount `-r` after `DROP nestedindexes` (outer warm, nested cold rebuild) |")
lines.append("| `cold_no_durable` | `-c -r --index-file :memory:` (no durable nested home) |")
lines.append("")
lines.append("## Results (median wall seconds)\n")
lines.append("| Archive | cold_first | warm_with_nested | warm_without_nested | cold_no_durable | speedup warm with/without |")
lines.append("|---------|------------|------------------|---------------------|-----------------|---------------------------|")
for arch in sorted(by.keys()):
    d = by[arch]
    w = d.get("warm_with_nested")
    wo = d.get("warm_without_nested")
    if w and wo and w > 0:
        sp = f"{wo/w:.2f}×"
    else:
        sp = "—"
    lines.append(
        f"| {arch} | {d.get('cold_first', float('nan')):.4f} | "
        f"{d.get('warm_with_nested', float('nan')):.4f} | "
        f"{d.get('warm_without_nested', float('nan')):.4f} | "
        f"{d.get('cold_no_durable', float('nan')):.4f} | {sp} |"
    )
lines.append("")
lines.append("**speedup** = `warm_without_nested / warm_with_nested` (>1 means durable nested helps).")
lines.append("")
lines.append(f"CSV: `{Path(csv_path).name}`\n")
Path(md_path).write_text("\n".join(lines) + "\n")
print("\n".join(lines))
PY

echoerr ""
echoerr "Wrote $CSV"
echoerr "Wrote $MD"
echoerr "Nested durable compare OK"
