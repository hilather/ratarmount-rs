#!/usr/bin/env bash
# Phase 11: lightweight performance smoke gates (not full archivemount comparison).
# Records timings under test-harness/bench-results/ and fails only on hard errors.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

OUT_DIR="$SCRIPT_DIR/bench-results"
mkdir -p "$OUT_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
JSON="$OUT_DIR/smoke-$STAMP.json"
ARCHIVE="$RATARMOUNT_PY_ROOT/tests/nested-tar.tar"
WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-bench-$$"
mkdir -p "$WORKDIR"
IDX="$WORKDIR/bench.index.sqlite"
MP="$WORKDIR/mnt"
mkdir -p "$MP"

cleanup() {
    set +e
    ratar_unmount "$MP"
    [[ -n "${MNT_PID:-}" ]] && kill "$MNT_PID" 2>/dev/null || true
    rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

echo "==> Phase 11 bench smoke ($ARCHIVE)"

# 1) Cold index create (outer only, no -r)
rm -f "$IDX"
start=$(date +%s.%N)
"$RATARMOUNT_CMD" -c --no-mount --index-file "$IDX" "$ARCHIVE" >/dev/null
end=$(date +%s.%N)
index_create_s=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')
echo "  index_create_s=$index_create_s"

# 2) Index reload
start=$(date +%s.%N)
"$RATARMOUNT_CMD" --no-mount --index-file "$IDX" "$ARCHIVE" >/dev/null
end=$(date +%s.%N)
index_load_s=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')
echo "  index_load_s=$index_load_s"

# 3) Mount + read nested path
"$RATARMOUNT_CMD" -f -r --index-file "$IDX" "$ARCHIVE" "$MP" >"$WORKDIR/mnt.log" 2>&1 &
MNT_PID=$!
for i in $(seq 1 80); do
    mount 2>/dev/null | grep -F -q "$MP" && break
    sleep 0.05
done
start=$(date +%s.%N)
# warm + timed reads
for i in $(seq 1 50); do
    cat "$MP/foo/fighter/ufo" >/dev/null
    cat "$MP/foo/lighter.tar/fighter/bar" >/dev/null
done
end=$(date +%s.%N)
read_loop_s=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')
echo "  read_100_ops_s=$read_loop_s"

got=$(md5sum "$MP/foo/fighter/ufo" | awk '{print $1}')
want=2709a3348eb2c52302a7606ecf5860bc
if [[ "$got" != "$want" ]]; then
    echo "[FAIL] correctness md5 $got"
    exit 1
fi

# 4) Nested durable index with vs without (synthetic multi-file ZIP in TAR)
#    Full matrix: benchmarks/compare-nested-durable.sh
N_NESTED="${PHASE11_NESTED_FILES:-400}"
echo "==> Nested durable with/without (N_FILES=$N_NESTED, -r --no-mount)"
ZDATA="$WORKDIR/zdata"
mkdir -p "$ZDATA"
for i in $(seq 1 "$N_NESTED"); do
    printf 'p11-%05d-xxxxxxxx\n' "$i" >"$ZDATA/f$(printf '%05d' "$i").txt"
done
(cd "$ZDATA" && zip -q -0 "$WORKDIR/inner.zip" ./*.txt)
tar -cf "$WORKDIR/outer-nested.tar" -C "$WORKDIR" inner.zip
IDX_N="$WORKDIR/nested-durable.index.sqlite"
rm -f "$IDX_N"
start=$(date +%s.%N)
"$RATARMOUNT_CMD" -c -r --no-mount --index-file "$IDX_N" --index-minimum-file-count 0 \
    --parallel-nested 1 "$WORKDIR/outer-nested.tar" >/dev/null
end=$(date +%s.%N)
nested_cold_first_s=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')
nested_n=$(sqlite3 "$IDX_N" 'SELECT COUNT(*) FROM "nestedindexes";' 2>/dev/null || echo 0)
echo "  nested_cold_first_s=$nested_cold_first_s nestedindexes=$nested_n"
if [[ "${nested_n:-0}" -lt 1 ]]; then
    echo "[FAIL] expected nestedindexes row after -c -r"
    exit 1
fi
start=$(date +%s.%N)
"$RATARMOUNT_CMD" -r --no-mount --index-file "$IDX_N" --index-minimum-file-count 0 \
    --parallel-nested 1 "$WORKDIR/outer-nested.tar" >/dev/null
end=$(date +%s.%N)
nested_warm_with_s=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')
echo "  nested_warm_with_durable_s=$nested_warm_with_s"
sqlite3 "$IDX_N" 'DROP TABLE IF EXISTS "nestedindexes";' 2>/dev/null || true
start=$(date +%s.%N)
"$RATARMOUNT_CMD" -r --no-mount --index-file "$IDX_N" --index-minimum-file-count 0 \
    --parallel-nested 1 "$WORKDIR/outer-nested.tar" >/dev/null
end=$(date +%s.%N)
nested_warm_without_s=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.3f", e-s}')
echo "  nested_warm_without_durable_s=$nested_warm_without_s"

# Soft gates (very loose — catch catastrophic regressions only)
# index create of nested-tar should be well under 30s on any reasonable machine
python3 - <<PY
import json, sys
create=float("$index_create_s")
load=float("$index_load_s")
reads=float("$read_loop_s")
n_cold=float("$nested_cold_first_s")
n_with=float("$nested_warm_with_s")
n_without=float("$nested_warm_without_s")
soft_fail=False
# catastrophic only
if create > 30: print("WARN: index_create_s > 30"); soft_fail=True
if load > 5: print("WARN: index_load_s > 5"); soft_fail=True
if reads > 30: print("WARN: read_loop_s > 30"); soft_fail=True
if n_cold > 60: print("WARN: nested_cold_first_s > 60"); soft_fail=True
data={
  "stamp": "$STAMP",
  "archive": "tests/nested-tar.tar",
  "index_create_s": create,
  "index_load_s": load,
  "read_100_ops_s": reads,
  "md5_ufo": "$got",
  "ratarmount_cmd": "$RATARMOUNT_CMD",
  "nested_durable": {
    "n_files": int("$N_NESTED"),
    "cold_first_s": n_cold,
    "warm_with_durable_s": n_with,
    "warm_without_durable_s": n_without,
    "nestedindexes_n": int("$nested_n"),
  },
}
open("$JSON","w").write(json.dumps(data, indent=2)+"\n")
print("wrote $JSON")
# Always pass if correct; warnings only
sys.exit(0)
PY

echo "Phase 11 bench OK"
