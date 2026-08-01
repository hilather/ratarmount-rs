#!/usr/bin/env bash
# Compare gzip backends: Rust G3 vs Rust rapidgzip (POC) vs Python rapidgzip.
#
# Usage:
#   ./benchmarks/compare-gzip-backends.sh
#
# Env:
#   RUST_BIN     binary with gzip-rapidgzip feature (default: target/release/ratarmount)
#   SKIP_BUILD=1 do not cargo build
#   RUNS=3       timed cold-index samples (median)
#   CORPUS_MIB=64 uncompressed large blob size
#   THREADS=8    -P gzip:N / rapidgzip-gzip:N
#   OUT_DIR      results dir (default: benchmarks/gzip-backend-results)
#   COMPARE_KEEP=1 keep workdir
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../test-harness/env.sh
source "$ROOT/test-harness/env.sh"

RUST_BIN="${RUST_BIN:-$ROOT/target/release/ratarmount}"
RUNS="${RUNS:-3}"
CORPUS_MIB="${CORPUS_MIB:-64}"
THREADS="${THREADS:-8}"
OUT_DIR="${OUT_DIR:-$ROOT/benchmarks/gzip-backend-results}"
PY_ROOT="${RATARMOUNT_PY_ROOT:-$ROOT/../ratarmount}"

if [[ -x "$ROOT/benchmarks/.venv-py/bin/python" ]]; then
  PY_PYTHON="${PY_PYTHON:-$ROOT/benchmarks/.venv-py/bin/python}"
else
  PY_PYTHON="${PY_PYTHON:-python3}"
fi
if [[ -x "$(dirname "$PY_PYTHON")/ratarmount" ]]; then
  PY_BIN="${PY_BIN:-$(dirname "$PY_PYTHON")/ratarmount}"
else
  PY_BIN="${PY_BIN:-}"
fi
export PYTHONPATH="${PY_ROOT}${PYTHONPATH:+:$PYTHONPATH}"
export PATH="${HOME}/.cargo/bin:${PATH}"

py_ratarmount() {
  if [[ -n "${PY_BIN}" ]]; then
    env PYTHONPATH="$PY_ROOT" "$PY_BIN" "$@"
  else
    env PYTHONPATH="$PY_ROOT" "$PY_PYTHON" -u -m ratarmount "$@"
  fi
}

WORKDIR="${TMPDIR:-/tmp}/ratarmount-gzip-bench-$$"
mkdir -p "$WORKDIR/data" "$WORKDIR/mnt" "$OUT_DIR"
CSV="$OUT_DIR/results.csv"
MD="$OUT_DIR/results.md"
LOG="$OUT_DIR/run.log"

cleanup() {
  for mp in "$WORKDIR"/mnt-*; do
    [[ -d "$mp" ]] || continue
    ratar_unmount "$mp" 2>/dev/null || true
  done
  pkill -f "ratarmount.*$WORKDIR" 2>/dev/null || true
  if [[ "${COMPARE_KEEP:-0}" != "1" ]]; then
    rm -rf "$WORKDIR"
  else
    echo "Kept $WORKDIR" >&2
  fi
}
trap cleanup EXIT

echoerr() { echo "$@" | tee -a "$LOG" >&2; }

median_of() {
  # stdin: one float per line → median
  local n mid
  mapfile -t vals < <(sort -n)
  n=${#vals[@]}
  if [[ $n -eq 0 ]]; then
    echo "nan"
    return
  fi
  mid=$((n / 2))
  if (( n % 2 == 1 )); then
    echo "${vals[$mid]}"
  else
    awk -v a="${vals[$((mid - 1))]}" -v b="${vals[$mid]}" 'BEGIN{printf "%.6f", (a+b)/2}'
  fi
}

# ---- build ----
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echoerr "Building release with --features gzip-rapidgzip..."
  (cd "$ROOT" && cargo build --release -p ratarmount --features gzip-rapidgzip 2>&1 | tee -a "$LOG" | tail -5)
fi
if [[ ! -x "$RUST_BIN" ]]; then
  echoerr "Missing RUST_BIN=$RUST_BIN"
  exit 1
fi

# ---- corpora ----
echoerr "Generating corpora (${CORPUS_MIB} MiB large blob)..."
DATA="$WORKDIR/data"
# compressible + random mix so inflate is real work
mkdir -p "$DATA/large-src"
# 50% zeros (highly compressible) + 50% urandom for a realistic mix
half=$((CORPUS_MIB / 2))
dd if=/dev/zero of="$DATA/large-src/blob.bin" bs=1M count="$half" status=none 2>/dev/null
dd if=/dev/urandom bs=1M count="$half" status=none 2>/dev/null >>"$DATA/large-src/blob.bin"
tar -C "$DATA/large-src" -cf "$DATA/large-${CORPUS_MIB}m.tar" blob.bin
gzip -c -1 "$DATA/large-${CORPUS_MIB}m.tar" >"$DATA/large-${CORPUS_MIB}m.tar.gz"
gzip -c -1 "$DATA/large-src/blob.bin" >"$DATA/large-${CORPUS_MIB}m.bin.gz"

# many small files (index + random access)
mkdir -p "$DATA/small-100"
for i in $(seq 0 99); do
  dd if=/dev/urandom of="$DATA/small-100/f$(printf '%03d' "$i").bin" bs=65536 count=1 status=none 2>/dev/null
done
tar -C "$DATA/small-100" -cf "$DATA/small-100.tar" .
gzip -c -1 "$DATA/small-100.tar" >"$DATA/small-100.tar.gz"

ls -lah "$DATA"/*.gz "$DATA"/*.tar 2>/dev/null | tee -a "$LOG" >&2

echo "tool;scenario;archive;metric;value;unit" >"$CSV"

# ---- cold index (no FUSE) ----
# Args: tool archive then command prefix words (binary + flags, no archive path).
run_cold_index() {
  local tool=$1 archive=$2
  shift 2
  local -a cmd=("$@")
  local base times=() wall i idx start end med
  base=$(basename "$archive")
  echoerr "=== cold-index $tool $base ==="
  for i in $(seq 1 "$RUNS"); do
    idx="$WORKDIR/${base}.${tool}.cold${i}.index.sqlite"
    rm -f "$idx"
    start=$(date +%s.%N)
    if ! "${cmd[@]}" -c --no-mount --index-file "$idx" --index-minimum-file-count 0 \
      "$archive" >/dev/null 2>"$WORKDIR/${tool}-cold-${base}-${i}.err"; then
      echoerr "FAIL cold-index $tool $base run $i"
      tail -20 "$WORKDIR/${tool}-cold-${base}-${i}.err" >&2 || true
      echo "$tool;cold;$base;cold_index_fail;1;bool" >>"$CSV"
      return 1
    fi
    end=$(date +%s.%N)
    wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.4f", e-s}')
    times+=("$wall")
    echoerr "  run $i: ${wall}s"
  done
  med=$(printf '%s\n' "${times[@]}" | median_of)
  echo "$tool;cold;$base;cold_index_median_s;$med;s" >>"$CSV"
  echoerr "  median: ${med}s"
}

# ---- FUSE mount suite ----
wait_mount() {
  local mp=$1 i
  for i in $(seq 1 200); do
    if mountpoint -q "$mp" 2>/dev/null || mount 2>/dev/null | grep -F -q "$mp"; then
      if ls "$mp" &>/dev/null; then
        return 0
      fi
    fi
    sleep 0.05
  done
  return 1
}

unmount_mp() {
  local mp=$1 i
  ratar_unmount "$mp" 2>/dev/null || true
  for i in $(seq 1 50); do
    if ! mountpoint -q "$mp" 2>/dev/null && ! mount 2>/dev/null | grep -F -q "$mp"; then
      break
    fi
    sleep 0.05
    ratar_unmount "$mp" 2>/dev/null || true
  done
}

measure_fuse() {
  local tool=$1 archive=$2 bw_relpath=$3
  shift 3
  local -a cmd=("$@")
  local base mp idx log start end wall rss pid
  base=$(basename "$archive")
  echoerr "=== fuse $tool $base ==="
  mp=$(mktemp -d "$WORKDIR/mnt-XXXXXX")
  idx="$WORKDIR/${base}.${tool}.fuse.index.sqlite"
  log="$WORKDIR/${tool}-fuse-${base}.log"
  rm -f "$idx"

  # cold mount
  start=$(date +%s.%N)
  "${cmd[@]}" -f -c --index-file "$idx" --index-minimum-file-count 0 \
    "$archive" "$mp" >"$log" 2>&1 &
  pid=$!
  if ! wait_mount "$mp"; then
    echoerr "FAIL fuse cold $tool $base"
    tail -30 "$log" >&2 || true
    kill "$pid" 2>/dev/null || true
    unmount_mp "$mp"
    rmdir "$mp" 2>/dev/null || true
    echo "$tool;cold;$base;mount_fail;1;bool" >>"$CSV"
    return 1
  fi
  end=$(date +%s.%N)
  wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.4f", e-s}')
  rss=$(awk '/VmHWM/ {print $2}' /proc/$pid/status 2>/dev/null || echo 0)
  echo "$tool;cold;$base;mount_s;$wall;s" >>"$CSV"
  echo "$tool;cold;$base;mount_rss_kib;$rss;KiB" >>"$CSV"
  echoerr "  cold mount: ${wall}s rss=${rss}KiB"

  # sequential bandwidth
  local f size mibs tstart tend twall
  f="$mp/$bw_relpath"
  if [[ ! -f "$f" ]]; then
    f=$(find "$mp" -type f -printf '%s %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2- || true)
  fi
  if [[ -n "${f:-}" && -f "$f" ]]; then
    size=$(stat -c %s -- "$f")
    tstart=$(date +%s.%N)
    cat -- "$f" >/dev/null
    tend=$(date +%s.%N)
    twall=$(awk -v s="$tstart" -v e="$tend" 'BEGIN{printf "%.6f", e-s}')
    mibs=$(awk -v sz="$size" -v w="$twall" 'BEGIN{ if(w<=0) print "nan"; else printf "%.2f", (sz/1048576.0)/w }')
    echo "$tool;cold;$base;bandwidth_mibs;$mibs;MiB/s" >>"$CSV"
    echo "$tool;cold;$base;seq_read_s;$twall;s" >>"$CSV"
    echo "$tool;cold;$base;file_size_b;$size;B" >>"$CSV"
    echoerr "  seq read: ${mibs} MiB/s (${twall}s, ${size} B)"
  fi

  # random access median (15 cats)
  mapfile -t files < <(find "$mp" -type f 2>/dev/null | head -n 200)
  if [[ ${#files[@]} -gt 0 ]]; then
    local times=() i ff
    for i in $(seq 1 15); do
      ff="${files[$((RANDOM % ${#files[@]}))]}"
      tstart=$(date +%s.%N)
      cat -- "$ff" >/dev/null
      tend=$(date +%s.%N)
      times+=("$(awk -v s="$tstart" -v e="$tend" 'BEGIN{printf "%.6f", e-s}')")
    done
    local med
    med=$(printf '%s\n' "${times[@]}" | median_of)
    echo "$tool;cold;$base;rand_access_median_s;$med;s" >>"$CSV"
    echoerr "  rand access median: ${med}s"
  fi

  unmount_mp "$mp"
  wait "$pid" 2>/dev/null || true
  rmdir "$mp" 2>/dev/null || true

  # warm mount
  mp=$(mktemp -d "$WORKDIR/mnt-XXXXXX")
  start=$(date +%s.%N)
  "${cmd[@]}" -f --index-file "$idx" --index-minimum-file-count 0 \
    "$archive" "$mp" >"$log" 2>&1 &
  pid=$!
  if wait_mount "$mp"; then
    end=$(date +%s.%N)
    wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.4f", e-s}')
    rss=$(awk '/VmHWM/ {print $2}' /proc/$pid/status 2>/dev/null || echo 0)
    echo "$tool;warm;$base;mount_s;$wall;s" >>"$CSV"
    echo "$tool;warm;$base;mount_rss_kib;$rss;KiB" >>"$CSV"
    echoerr "  warm mount: ${wall}s rss=${rss}KiB"
    # warm seq
    f="$mp/$bw_relpath"
    if [[ ! -f "$f" ]]; then
      f=$(find "$mp" -type f -printf '%s %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2- || true)
    fi
    if [[ -n "${f:-}" && -f "$f" ]]; then
      size=$(stat -c %s -- "$f")
      tstart=$(date +%s.%N)
      cat -- "$f" >/dev/null
      tend=$(date +%s.%N)
      twall=$(awk -v s="$tstart" -v e="$tend" 'BEGIN{printf "%.6f", e-s}')
      mibs=$(awk -v sz="$size" -v w="$twall" 'BEGIN{ if(w<=0) print "nan"; else printf "%.2f", (sz/1048576.0)/w }')
      echo "$tool;warm;$base;bandwidth_mibs;$mibs;MiB/s" >>"$CSV"
      echoerr "  warm seq: ${mibs} MiB/s"
    fi
  else
    echoerr "FAIL fuse warm $tool $base"
    tail -20 "$log" >&2 || true
    echo "$tool;warm;$base;mount_fail;1;bool" >>"$CSV"
  fi
  unmount_mp "$mp"
  wait "$pid" 2>/dev/null || true
  rmdir "$mp" 2>/dev/null || true
}

# Command prefixes
# Rust G3: no env, no use-backend
# Rust rapidgzip: env + use-backend (feature compiled in)
# Python: wrapper script (venv CLI + PYTHONPATH)

ARCH_LARGE_TGZ="$DATA/large-${CORPUS_MIB}m.tar.gz"
ARCH_LARGE_GZ="$DATA/large-${CORPUS_MIB}m.bin.gz"
ARCH_SMALL_TGZ="$DATA/small-100.tar.gz"

cat >"$WORKDIR/py-ratarmount" <<'WRAP'
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PY_ROOT}${PYTHONPATH:+:$PYTHONPATH}"
if [[ -n "${PY_BIN:-}" ]]; then
  exec "$PY_BIN" "$@"
else
  exec "$PY_PYTHON" -u -m ratarmount "$@"
fi
WRAP
chmod +x "$WORKDIR/py-ratarmount"
export PY_ROOT PY_BIN PY_PYTHON

# Cold index (no FUSE)
run_cold_index "rust-g3" "$ARCH_LARGE_TGZ" \
  env -u RATARMOUNT_GZIP_BACKEND "$RUST_BIN" -P "gzip:${THREADS}"
run_cold_index "rust-rapidgzip" "$ARCH_LARGE_TGZ" \
  env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN" -P "gzip:${THREADS}" --use-backend rapidgzip
run_cold_index "python" "$ARCH_LARGE_TGZ" \
  env PY_ROOT="$PY_ROOT" PY_BIN="${PY_BIN:-}" PY_PYTHON="$PY_PYTHON" "$WORKDIR/py-ratarmount" -P "$THREADS"

run_cold_index "rust-g3" "$ARCH_LARGE_GZ" \
  env -u RATARMOUNT_GZIP_BACKEND "$RUST_BIN" -P "gzip:${THREADS}"
run_cold_index "rust-rapidgzip" "$ARCH_LARGE_GZ" \
  env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN" -P "gzip:${THREADS}" --use-backend rapidgzip
run_cold_index "python" "$ARCH_LARGE_GZ" \
  env PY_ROOT="$PY_ROOT" PY_BIN="${PY_BIN:-}" PY_PYTHON="$PY_PYTHON" "$WORKDIR/py-ratarmount" -P "$THREADS"

run_cold_index "rust-g3" "$ARCH_SMALL_TGZ" \
  env -u RATARMOUNT_GZIP_BACKEND "$RUST_BIN" -P "gzip:${THREADS}"
run_cold_index "rust-rapidgzip" "$ARCH_SMALL_TGZ" \
  env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN" -P "gzip:${THREADS}" --use-backend rapidgzip
run_cold_index "python" "$ARCH_SMALL_TGZ" \
  env PY_ROOT="$PY_ROOT" PY_BIN="${PY_BIN:-}" PY_PYTHON="$PY_PYTHON" "$WORKDIR/py-ratarmount" -P "$THREADS"

# FUSE (needs /dev/fuse)
if [[ -e /dev/fuse ]]; then
  measure_fuse "rust-g3" "$ARCH_LARGE_TGZ" "blob.bin" \
    env -u RATARMOUNT_GZIP_BACKEND "$RUST_BIN" -P "gzip:${THREADS}"
  measure_fuse "rust-rapidgzip" "$ARCH_LARGE_TGZ" "blob.bin" \
    env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN" -P "gzip:${THREADS}" --use-backend rapidgzip
  measure_fuse "python" "$ARCH_LARGE_TGZ" "blob.bin" \
    env PY_ROOT="$PY_ROOT" PY_BIN="${PY_BIN:-}" PY_PYTHON="$PY_PYTHON" "$WORKDIR/py-ratarmount" -P "$THREADS"

  measure_fuse "rust-g3" "$ARCH_LARGE_GZ" "large-${CORPUS_MIB}m.bin" \
    env -u RATARMOUNT_GZIP_BACKEND "$RUST_BIN" -P "gzip:${THREADS}"
  measure_fuse "rust-rapidgzip" "$ARCH_LARGE_GZ" "large-${CORPUS_MIB}m.bin" \
    env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN" -P "gzip:${THREADS}" --use-backend rapidgzip
  measure_fuse "python" "$ARCH_LARGE_GZ" "large-${CORPUS_MIB}m.bin" \
    env PY_ROOT="$PY_ROOT" PY_BIN="${PY_BIN:-}" PY_PYTHON="$PY_PYTHON" "$WORKDIR/py-ratarmount" -P "$THREADS"

  measure_fuse "rust-g3" "$ARCH_SMALL_TGZ" "f000.bin" \
    env -u RATARMOUNT_GZIP_BACKEND "$RUST_BIN" -P "gzip:${THREADS}"
  measure_fuse "rust-rapidgzip" "$ARCH_SMALL_TGZ" "f000.bin" \
    env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN" -P "gzip:${THREADS}" --use-backend rapidgzip
  measure_fuse "python" "$ARCH_SMALL_TGZ" "f000.bin" \
    env PY_ROOT="$PY_ROOT" PY_BIN="${PY_BIN:-}" PY_PYTHON="$PY_PYTHON" "$WORKDIR/py-ratarmount" -P "$THREADS"
else
  echoerr "SKIP FUSE suite: /dev/fuse missing"
fi

# ---- markdown summary (avoid nested backticks inside { } groups) ----
{
  echo "# Gzip backend comparison (G3 vs rapidgzip POC vs Python)"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo
  echo "| Setting | Value |"
  echo "|---------|-------|"
  echo "| HOST | $(hostname) |"
  echo "| nproc | $(nproc) |"
  echo "| THREADS (-P gzip:N) | ${THREADS} |"
  echo "| CORPUS_MIB | ${CORPUS_MIB} |"
  echo "| RUNS (cold index) | ${RUNS} |"
  echo "| RUST_BIN | ${RUST_BIN} |"
  echo "| feature | gzip-rapidgzip |"
  echo "| rustc | $(rustc --version) |"
  echo
  echo "## Results (CSV)"
  echo
  echo '```'
  column -t -s';' "$CSV" 2>/dev/null || cat "$CSV"
  echo '```'
  echo
  echo "## Cold index median (seconds, lower is better)"
  echo
  echo "| Archive | rust-g3 | rust-rapidgzip | python |"
  echo "|---------|---------|----------------|--------|"
  for arch in "large-${CORPUS_MIB}m.tar.gz" "large-${CORPUS_MIB}m.bin.gz" "small-100.tar.gz"; do
    g3=$(awk -F";" -v a="$arch" '$1=="rust-g3" && $2=="cold" && $3==a && $4=="cold_index_median_s"{print $5}' "$CSV")
    rg=$(awk -F";" -v a="$arch" '$1=="rust-rapidgzip" && $2=="cold" && $3==a && $4=="cold_index_median_s"{print $5}' "$CSV")
    py=$(awk -F";" -v a="$arch" '$1=="python" && $2=="cold" && $3==a && $4=="cold_index_median_s"{print $5}' "$CSV")
    echo "| ${arch} | ${g3:--} | ${rg:--} | ${py:--} |"
  done
  echo
  echo "## FUSE cold mount + sequential bandwidth"
  echo
  echo "| Archive | metric | rust-g3 | rust-rapidgzip | python |"
  echo "|---------|--------|---------|----------------|--------|"
  for arch in "large-${CORPUS_MIB}m.tar.gz" "large-${CORPUS_MIB}m.bin.gz" "small-100.tar.gz"; do
    for metric in mount_s bandwidth_mibs rand_access_median_s mount_rss_kib; do
      g3=$(awk -F";" -v a="$arch" -v m="$metric" '$1=="rust-g3" && $2=="cold" && $3==a && $4==m{print $5}' "$CSV")
      rg=$(awk -F";" -v a="$arch" -v m="$metric" '$1=="rust-rapidgzip" && $2=="cold" && $3==a && $4==m{print $5}' "$CSV")
      py=$(awk -F";" -v a="$arch" -v m="$metric" '$1=="python" && $2=="cold" && $3==a && $4==m{print $5}' "$CSV")
      if [[ -z "${g3}${rg}${py}" ]]; then
        continue
      fi
      echo "| ${arch} | ${metric} | ${g3:--} | ${rg:--} | ${py:--} |"
    done
  done
  echo
  echo "## Notes"
  echo
  echo "- **rust-g3**: default seekable miniz checkpoints (no env)."
  echo "- **rust-rapidgzip**: RATARMOUNT_GZIP_BACKEND=rapidgzip + --use-backend rapidgzip (path-only POC)."
  echo "- **python**: sibling tree + venv rapidgzip."
  echo "- Cold index uses --no-mount -c; FUSE uses -f foreground."
  echo "- Large corpora are half zeros + half urandom, gzip -1 (single-member)."
  echo "- Parallel marker path typically needs enough size + threads (here -P gzip:${THREADS})."
  echo "- rust-rapidgzip uses in-process IndexedReader (Send via exclusive ownership; no worker IPC)."
} >"$MD"

echoerr ""
echoerr "Wrote $CSV"
echoerr "Wrote $MD"
cat "$MD"
