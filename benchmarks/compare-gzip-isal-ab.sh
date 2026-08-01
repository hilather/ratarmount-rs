#!/usr/bin/env bash
# Fair rapidgzip inflate A/B: zlib-rs vs ISA-L (two separate builds).
#
# Same binary twice is wrong — gzip-rapidgzip (zlib-rs) and gzip-rapidgzip-isal
# (ISA-L) must be compiled into distinct executables and timed independently.
#
# Usage:
#   ./benchmarks/compare-gzip-isal-ab.sh
#
# Env:
#   CORPUS_MIB=256     uncompressed large-blob size (default 256; override for smoke)
#   THREADS=8          -P gzip:N for parallel marker path
#   RUNS=3             timed cold-index samples (median)
#   SKIP_BUILD=1       use existing binaries (see RUST_BIN_ZLIB / RUST_BIN_ISAL)
#   RUST_BIN_ZLIB      prebuilt path for gzip-rapidgzip (zlib-rs inflater)
#   RUST_BIN_ISAL      prebuilt path for gzip-rapidgzip-isal (ISA-L inflater)
#   OUT_DIR            default: benchmarks/gzip-backend-results (gitignored)
#   SKIP_PYTHON=1      skip Python baseline
#   SKIP_FUSE=1        decode-only (cold index + optional decode micro); no FUSE
#   SKIP_G3=1          skip rust-g3 baseline
#   COMPARE_KEEP=1     keep workdir
#   ISAL_INSTALL_PREFIX  prefix with lib/libisal.so + include (auto-detect sibling
#                        rapidgzip-rust/.isal-prefix when present)
#   RATARMOUNT_PY_ROOT   Python ratarmount tree (default: ../ratarmount)
#
# Outputs (under OUT_DIR, gitignored):
#   results-isal-ab.csv
#   results-isal-ab.md   — zlib vs isal delta summary
#   bin/ratarmount-rgz-zlib
#   bin/ratarmount-rgz-isal
#
# Build requirements:
#   - rustc ≥ 1.87 (rapidgzip-core edition 2024)
#   - ISA-L: system libisal-dev, or ISAL_INSTALL_PREFIX pointing at a prefix with
#     lib/libisal.so (and headers). The isal build fails without it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RUNS="${RUNS:-3}"
CORPUS_MIB="${CORPUS_MIB:-256}"
THREADS="${THREADS:-8}"
OUT_DIR="${OUT_DIR:-$ROOT/benchmarks/gzip-backend-results}"
BIN_DIR="$OUT_DIR/bin"
RUST_BIN_ZLIB="${RUST_BIN_ZLIB:-$BIN_DIR/ratarmount-rgz-zlib}"
RUST_BIN_ISAL="${RUST_BIN_ISAL:-$BIN_DIR/ratarmount-rgz-isal}"

# test-harness/env.sh requires RATARMOUNT_CMD + (unless ALLOW_NO_PY) a Python tree.
# Dual-build A/B creates its own binaries and can skip Python (SKIP_PYTHON=1).
# Default ALLOW_NO_PY=1 so decode-only A/B works without a sibling checkout.
export RATARMOUNT_ALLOW_NO_PY="${RATARMOUNT_ALLOW_NO_PY:-1}"
export RATARMOUNT_ENV_QUIET="${RATARMOUNT_ENV_QUIET:-1}"
# Placeholder until dual build installs bin/*; env.sh only checks existence at source time.
if [[ -z "${RATARMOUNT_CMD:-}" ]]; then
  if [[ -x "$ROOT/target/release/ratarmount" ]]; then
    export RATARMOUNT_CMD="$ROOT/target/release/ratarmount"
  else
    export RATARMOUNT_CMD=/bin/true
  fi
fi
# Optional Python auto-detect for baselines (not required for zlib↔isal A/B).
if [[ -z "${RATARMOUNT_PY_ROOT:-}" ]]; then
  if [[ -d "$ROOT/../ratarmount/tests" ]]; then
    RATARMOUNT_PY_ROOT="$(cd "$ROOT/../ratarmount" && pwd)"
  elif [[ -d "$HOME/projects/ratarmount/tests" ]]; then
    RATARMOUNT_PY_ROOT="$(cd "$HOME/projects/ratarmount" && pwd)"
  fi
fi
export RATARMOUNT_PY_ROOT="${RATARMOUNT_PY_ROOT:-}"
# shellcheck source=../test-harness/env.sh
source "$ROOT/test-harness/env.sh"

PY_ROOT="${RATARMOUNT_PY_ROOT:-$ROOT/../ratarmount}"

# Prefer a known ISA-L prefix when system libisal is missing.
if [[ -z "${ISAL_INSTALL_PREFIX:-}" ]]; then
  for cand in \
    "$ROOT/../rapidgzip-rust/.isal-prefix" \
    "$HOME/projects/rapidgzip-rust/.isal-prefix" \
    "$HOME/projects/rapidgzip-rust/target/isal-prefix"; do
    if [[ -f "$cand/lib/libisal.so" ]]; then
      ISAL_INSTALL_PREFIX="$cand"
      break
    fi
  done
fi
if [[ -n "${ISAL_INSTALL_PREFIX:-}" ]]; then
  export ISAL_INSTALL_PREFIX
  export LIBRARY_PATH="${ISAL_INSTALL_PREFIX}/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
  export LD_LIBRARY_PATH="${ISAL_INSTALL_PREFIX}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export PKG_CONFIG_PATH="${ISAL_INSTALL_PREFIX}/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
  export CPATH="${ISAL_INSTALL_PREFIX}/include${CPATH:+:$CPATH}"
fi

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

WORKDIR="${TMPDIR:-/tmp}/ratarmount-gzip-isal-ab-$$"
mkdir -p "$WORKDIR/data" "$WORKDIR/mnt" "$OUT_DIR" "$BIN_DIR"
CSV="$OUT_DIR/results-isal-ab.csv"
MD="$OUT_DIR/results-isal-ab.md"
LOG="$OUT_DIR/run-isal-ab.log"
: >"$LOG"

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

# ---- dual build (fair A/B) ----
build_one() {
  local features=$1 dest=$2 label=$3
  echoerr "Building release --features ${features} → ${dest} (${label})..."
  (cd "$ROOT" && cargo build --release -p ratarmount --features "${features}" 2>&1 | tee -a "$LOG" | tail -20)
  if [[ ! -x "$ROOT/target/release/ratarmount" ]]; then
    echoerr "FAIL: cargo build --features ${features} did not produce target/release/ratarmount"
    return 1
  fi
  cp -f "$ROOT/target/release/ratarmount" "$dest"
  chmod +x "$dest"
  echoerr "  installed $(ls -lah "$dest" | awk '{print $5, $9}')"
}

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  if [[ -n "${ISAL_INSTALL_PREFIX:-}" ]]; then
    echoerr "ISAL_INSTALL_PREFIX=${ISAL_INSTALL_PREFIX}"
  else
    echoerr "ISAL_INSTALL_PREFIX unset (using system libisal if available)"
  fi
  # zlib-rs first so a failed isal build still leaves a usable zlib binary for partial runs.
  build_one "gzip-rapidgzip" "$RUST_BIN_ZLIB" "rust-rgz-zlib"
  build_one "gzip-rapidgzip-isal" "$RUST_BIN_ISAL" "rust-rgz-isal"
else
  echoerr "SKIP_BUILD=1 — expecting prebuilt binaries"
fi

need_bin() {
  local p=$1 name=$2
  if [[ ! -x "$p" ]]; then
    echoerr "Missing ${name}=$p"
    echoerr "Build with (from repo root):"
    echoerr "  cargo build --release -p ratarmount --features gzip-rapidgzip"
    echoerr "  cp target/release/ratarmount ${BIN_DIR}/ratarmount-rgz-zlib"
    echoerr "  # ISA-L needs libisal or ISAL_INSTALL_PREFIX:"
    echoerr "  cargo build --release -p ratarmount --features gzip-rapidgzip-isal"
    echoerr "  cp target/release/ratarmount ${BIN_DIR}/ratarmount-rgz-isal"
    echoerr "Or re-run without SKIP_BUILD=1."
    exit 1
  fi
}
need_bin "$RUST_BIN_ZLIB" "RUST_BIN_ZLIB"
need_bin "$RUST_BIN_ISAL" "RUST_BIN_ISAL"

# G3 baseline uses either binary with backend unset (default G3 path).
RUST_BIN_G3="${RUST_BIN_G3:-$RUST_BIN_ZLIB}"

# ---- corpora ----
echoerr "Generating corpora (${CORPUS_MIB} MiB large blob)..."
DATA="$WORKDIR/data"
mkdir -p "$DATA/large-src"
half=$((CORPUS_MIB / 2))
if (( half < 1 )); then
  half=1
fi
dd if=/dev/zero of="$DATA/large-src/blob.bin" bs=1M count="$half" status=none 2>/dev/null
dd if=/dev/urandom bs=1M count="$half" status=none 2>/dev/null >>"$DATA/large-src/blob.bin"
tar -C "$DATA/large-src" -cf "$DATA/large-${CORPUS_MIB}m.tar" blob.bin
gzip -c -1 "$DATA/large-${CORPUS_MIB}m.tar" >"$DATA/large-${CORPUS_MIB}m.tar.gz"
gzip -c -1 "$DATA/large-src/blob.bin" >"$DATA/large-${CORPUS_MIB}m.bin.gz"

mkdir -p "$DATA/small-100"
for i in $(seq 0 99); do
  dd if=/dev/urandom of="$DATA/small-100/f$(printf '%03d' "$i").bin" bs=65536 count=1 status=none 2>/dev/null
done
tar -C "$DATA/small-100" -cf "$DATA/small-100.tar" .
gzip -c -1 "$DATA/small-100.tar" >"$DATA/small-100.tar.gz"

ls -lah "$DATA"/*.gz "$DATA"/*.tar 2>/dev/null | tee -a "$LOG" >&2

echo "tool;scenario;archive;metric;value;unit" >"$CSV"

# ---- cold index (decode-heavy, no FUSE) ----
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

# Decode-only micro: after a warm index exists, re-run --no-mount (no -c) to
# measure index load + open cost without full rebuild. Optional second metric.
run_warm_open() {
  local tool=$1 archive=$2
  shift 2
  local -a cmd=("$@")
  local base idx times=() wall i start end med
  base=$(basename "$archive")
  idx="$WORKDIR/${base}.${tool}.warm-open.index.sqlite"
  rm -f "$idx"
  echoerr "=== warm-open (index reuse, no FUSE) $tool $base ==="
  # Build once
  if ! "${cmd[@]}" -c --no-mount --index-file "$idx" --index-minimum-file-count 0 \
    "$archive" >/dev/null 2>"$WORKDIR/${tool}-warmbuild-${base}.err"; then
    echoerr "FAIL warm-open index build $tool $base"
    tail -20 "$WORKDIR/${tool}-warmbuild-${base}.err" >&2 || true
    echo "$tool;warm;$base;warm_open_fail;1;bool" >>"$CSV"
    return 1
  fi
  for i in $(seq 1 "$RUNS"); do
    start=$(date +%s.%N)
    if ! "${cmd[@]}" --no-mount --index-file "$idx" --index-minimum-file-count 0 \
      "$archive" >/dev/null 2>"$WORKDIR/${tool}-warmopen-${base}-${i}.err"; then
      echoerr "FAIL warm-open $tool $base run $i"
      tail -20 "$WORKDIR/${tool}-warmopen-${base}-${i}.err" >&2 || true
      echo "$tool;warm;$base;warm_open_fail;1;bool" >>"$CSV"
      return 1
    fi
    end=$(date +%s.%N)
    wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.4f", e-s}')
    times+=("$wall")
    echoerr "  run $i: ${wall}s"
  done
  med=$(printf '%s\n' "${times[@]}" | median_of)
  echo "$tool;warm;$base;warm_open_median_s;$med;s" >>"$CSV"
  echoerr "  median: ${med}s"
}

# ---- FUSE mount suite (optional sequential cat after warm) ----
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

  unmount_mp "$mp"
  wait "$pid" 2>/dev/null || true
  rmdir "$mp" 2>/dev/null || true

  # warm mount + sequential cat (decode after index reuse)
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
      echo "$tool;warm;$base;seq_read_s;$twall;s" >>"$CSV"
      echoerr "  warm seq: ${mibs} MiB/s (${twall}s)"
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

# Tool command prefixes (array via function to avoid eval)
# rust-rgz-zlib / rust-rgz-isal: dedicated binary + rapidgzip backend
# rust-g3: G3 path on zlib binary (no backend env)
# python: wrapper

run_tool_cold() {
  local tool=$1 archive=$2
  case "$tool" in
    rust-rgz-zlib)
      run_cold_index "$tool" "$archive" \
        env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN_ZLIB" -P "gzip:${THREADS}" --use-backend rapidgzip
      ;;
    rust-rgz-isal)
      run_cold_index "$tool" "$archive" \
        env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN_ISAL" -P "gzip:${THREADS}" --use-backend rapidgzip
      ;;
    rust-g3)
      run_cold_index "$tool" "$archive" \
        env -u RATARMOUNT_GZIP_BACKEND "$RUST_BIN_G3" -P "gzip:${THREADS}"
      ;;
    python)
      run_cold_index "$tool" "$archive" \
        env PY_ROOT="$PY_ROOT" PY_BIN="${PY_BIN:-}" PY_PYTHON="$PY_PYTHON" "$WORKDIR/py-ratarmount" -P "$THREADS"
      ;;
  esac
}

run_tool_warm_open() {
  local tool=$1 archive=$2
  case "$tool" in
    rust-rgz-zlib)
      run_warm_open "$tool" "$archive" \
        env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN_ZLIB" -P "gzip:${THREADS}" --use-backend rapidgzip
      ;;
    rust-rgz-isal)
      run_warm_open "$tool" "$archive" \
        env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN_ISAL" -P "gzip:${THREADS}" --use-backend rapidgzip
      ;;
    rust-g3)
      run_warm_open "$tool" "$archive" \
        env -u RATARMOUNT_GZIP_BACKEND "$RUST_BIN_G3" -P "gzip:${THREADS}"
      ;;
    python)
      run_warm_open "$tool" "$archive" \
        env PY_ROOT="$PY_ROOT" PY_BIN="${PY_BIN:-}" PY_PYTHON="$PY_PYTHON" "$WORKDIR/py-ratarmount" -P "$THREADS"
      ;;
  esac
}

run_tool_fuse() {
  local tool=$1 archive=$2 bw=$3
  case "$tool" in
    rust-rgz-zlib)
      measure_fuse "$tool" "$archive" "$bw" \
        env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN_ZLIB" -P "gzip:${THREADS}" --use-backend rapidgzip
      ;;
    rust-rgz-isal)
      measure_fuse "$tool" "$archive" "$bw" \
        env RATARMOUNT_GZIP_BACKEND=rapidgzip "$RUST_BIN_ISAL" -P "gzip:${THREADS}" --use-backend rapidgzip
      ;;
    rust-g3)
      measure_fuse "$tool" "$archive" "$bw" \
        env -u RATARMOUNT_GZIP_BACKEND "$RUST_BIN_G3" -P "gzip:${THREADS}"
      ;;
    python)
      measure_fuse "$tool" "$archive" "$bw" \
        env PY_ROOT="$PY_ROOT" PY_BIN="${PY_BIN:-}" PY_PYTHON="$PY_PYTHON" "$WORKDIR/py-ratarmount" -P "$THREADS"
      ;;
  esac
}

TOOLS=()
TOOLS+=("rust-rgz-zlib")
TOOLS+=("rust-rgz-isal")
if [[ "${SKIP_G3:-0}" != "1" ]]; then
  TOOLS+=("rust-g3")
fi
if [[ "${SKIP_PYTHON:-0}" != "1" ]]; then
  if [[ -n "${RATARMOUNT_PY_ROOT:-}" && -d "${RATARMOUNT_PY_ROOT}" ]]; then
    TOOLS+=("python")
  else
    echoerr "SKIP python baseline: set RATARMOUNT_PY_ROOT to a Python ratarmount checkout (or SKIP_PYTHON=1)"
  fi
fi

echoerr "Tools: ${TOOLS[*]}"
echoerr "Decode-only section (cold index + warm open, no FUSE)..."

for arch in "$ARCH_LARGE_TGZ" "$ARCH_LARGE_GZ" "$ARCH_SMALL_TGZ"; do
  for tool in "${TOOLS[@]}"; do
    run_tool_cold "$tool" "$arch" || true
  done
done

# Warm open only on large tar.gz (decode-heavy index build already done above;
# this isolates reopen cost).
for tool in "${TOOLS[@]}"; do
  run_tool_warm_open "$tool" "$ARCH_LARGE_TGZ" || true
done

if [[ "${SKIP_FUSE:-0}" != "1" && -e /dev/fuse ]]; then
  echoerr "FUSE suite (cold/warm mount + sequential cat)..."
  for tool in "${TOOLS[@]}"; do
    run_tool_fuse "$tool" "$ARCH_LARGE_TGZ" "blob.bin" || true
  done
  for tool in "${TOOLS[@]}"; do
    run_tool_fuse "$tool" "$ARCH_LARGE_GZ" "large-${CORPUS_MIB}m.bin" || true
  done
  for tool in "${TOOLS[@]}"; do
    run_tool_fuse "$tool" "$ARCH_SMALL_TGZ" "f000.bin" || true
  done
elif [[ "${SKIP_FUSE:-0}" == "1" ]]; then
  echoerr "SKIP FUSE suite: SKIP_FUSE=1"
else
  echoerr "SKIP FUSE suite: /dev/fuse missing"
fi

# ---- helpers for markdown deltas ----
csv_val() {
  local tool=$1 scenario=$2 archive=$3 metric=$4
  awk -F";" -v t="$tool" -v s="$scenario" -v a="$archive" -v m="$metric" \
    '$1==t && $2==s && $3==a && $4==m {print $5; exit}' "$CSV"
}

# speedup = zlib/isal ( >1 ⇒ isal faster for time metrics)
delta_line() {
  local label=$1 zlib=$2 isal=$3 higher_is_better=${4:-0}
  if [[ -z "$zlib" || -z "$isal" || "$zlib" == "nan" || "$isal" == "nan" ]]; then
    echo "| ${label} | ${zlib:--} | ${isal:--} | — | — |"
    return
  fi
  local ratio pct note
  if [[ "$higher_is_better" == "1" ]]; then
    # bandwidth: isal/zlib
    ratio=$(awk -v z="$zlib" -v i="$isal" 'BEGIN{
      if (z<=0) {print "nan"; exit}
      printf "%.3f", i/z
    }')
    pct=$(awk -v z="$zlib" -v i="$isal" 'BEGIN{
      if (z<=0) {print "nan"; exit}
      printf "%+.1f%%", 100.0*(i-z)/z
    }')
    note="× vs zlib (throughput)"
  else
    # time: zlib/isal (>1 isal faster)
    ratio=$(awk -v z="$zlib" -v i="$isal" 'BEGIN{
      if (i<=0) {print "nan"; exit}
      printf "%.3f", z/i
    }')
    pct=$(awk -v z="$zlib" -v i="$isal" 'BEGIN{
      if (z<=0) {print "nan"; exit}
      printf "%+.1f%%", 100.0*(z-i)/z
    }')
    note="zlib/isal (time)"
  fi
  echo "| ${label} | ${zlib} | ${isal} | ${ratio} ${note} | ${pct} |"
}

# ---- markdown summary ----
{
  echo "# Fair rapidgzip A/B: zlib-rs vs ISA-L"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo
  echo "Two **separate** release builds (not the same binary re-run):"
  echo
  echo "| Tool label | Cargo features | Inflate | Binary |"
  echo "|------------|----------------|---------|--------|"
  echo "| \`rust-rgz-zlib\` | \`gzip-rapidgzip\` | zlib-rs | \`${RUST_BIN_ZLIB}\` |"
  echo "| \`rust-rgz-isal\` | \`gzip-rapidgzip-isal\` | Intel ISA-L | \`${RUST_BIN_ISAL}\` |"
  if [[ "${SKIP_G3:-0}" != "1" ]]; then
    echo "| \`rust-g3\` | (same as zlib binary, backend unset) | G3 miniz checkpoints | \`${RUST_BIN_G3}\` |"
  fi
  if [[ "${SKIP_PYTHON:-0}" != "1" ]]; then
    echo "| \`python\` | n/a | Python rapidgzip | \`RATARMOUNT_PY_ROOT\` |"
  fi
  echo
  echo "## Settings"
  echo
  echo "| Setting | Value |"
  echo "|---------|-------|"
  echo "| HOST | $(hostname) |"
  echo "| nproc | $(nproc) |"
  echo "| THREADS (-P gzip:N) | ${THREADS} |"
  echo "| CORPUS_MIB | ${CORPUS_MIB} |"
  echo "| RUNS | ${RUNS} |"
  echo "| ISAL_INSTALL_PREFIX | ${ISAL_INSTALL_PREFIX:-"(system/default)"} |"
  echo "| SKIP_FUSE | ${SKIP_FUSE:-0} |"
  echo "| rustc | $(rustc --version 2>/dev/null || echo unknown) |"
  echo
  echo "### ISAL_INSTALL_PREFIX"
  echo
  echo "The \`gzip-rapidgzip-isal\` build links against shared \`libisal\`. Options:"
  echo
  echo "1. Install distro package (e.g. \`libisal-dev\` / \`isa-l-devel\`)."
  echo "2. Build ISA-L into a prefix and export:"
  echo
  echo '```bash'
  echo "export ISAL_INSTALL_PREFIX=/path/to/prefix   # must contain lib/libisal.so"
  echo "export LD_LIBRARY_PATH=\"\$ISAL_INSTALL_PREFIX/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\""
  echo "./benchmarks/compare-gzip-isal-ab.sh"
  echo '```'
  echo
  echo "This harness auto-detects \`../rapidgzip-rust/.isal-prefix\` when present."
  echo
  echo "## Decode-only (no FUSE)"
  echo
  echo "Cold index: \`ratarmount -c --no-mount\` (full inflate while building index)."
  echo "Warm open: reuse SQLite index with \`--no-mount\` (open cost, not full decode)."
  echo
  echo "### Cold index median (seconds, lower is better)"
  echo
  echo "| Archive | rust-rgz-zlib | rust-rgz-isal | rust-g3 | python |"
  echo "|---------|---------------|---------------|---------|--------|"
  for arch in "large-${CORPUS_MIB}m.tar.gz" "large-${CORPUS_MIB}m.bin.gz" "small-100.tar.gz"; do
    z=$(csv_val rust-rgz-zlib cold "$arch" cold_index_median_s)
    i=$(csv_val rust-rgz-isal cold "$arch" cold_index_median_s)
    g=$(csv_val rust-g3 cold "$arch" cold_index_median_s)
    p=$(csv_val python cold "$arch" cold_index_median_s)
    echo "| ${arch} | ${z:--} | ${i:--} | ${g:--} | ${p:--} |"
  done
  echo
  echo "### Warm open median (seconds, large tar.gz)"
  echo
  arch="large-${CORPUS_MIB}m.tar.gz"
  echo "| Archive | rust-rgz-zlib | rust-rgz-isal | rust-g3 | python |"
  echo "|---------|---------------|---------------|---------|--------|"
  z=$(csv_val rust-rgz-zlib warm "$arch" warm_open_median_s)
  i=$(csv_val rust-rgz-isal warm "$arch" warm_open_median_s)
  g=$(csv_val rust-g3 warm "$arch" warm_open_median_s)
  p=$(csv_val python warm "$arch" warm_open_median_s)
  echo "| ${arch} | ${z:--} | ${i:--} | ${g:--} | ${p:--} |"
  echo
  echo "## zlib vs isal delta (primary A/B)"
  echo
  echo "Time metrics: **ratio = zlib/isal** (>1 ⇒ ISA-L faster). **%** = relative wall reduction for isal."
  echo "Throughput: **ratio = isal/zlib** (>1 ⇒ ISA-L higher MiB/s)."
  echo
  echo "| Metric | rust-rgz-zlib | rust-rgz-isal | ratio | delta |"
  echo "|--------|---------------|---------------|-------|-------|"
  for arch in "large-${CORPUS_MIB}m.tar.gz" "large-${CORPUS_MIB}m.bin.gz" "small-100.tar.gz"; do
    z=$(csv_val rust-rgz-zlib cold "$arch" cold_index_median_s)
    i=$(csv_val rust-rgz-isal cold "$arch" cold_index_median_s)
    delta_line "cold_index ${arch}" "$z" "$i" 0
  done
  arch="large-${CORPUS_MIB}m.tar.gz"
  z=$(csv_val rust-rgz-zlib warm "$arch" warm_open_median_s)
  i=$(csv_val rust-rgz-isal warm "$arch" warm_open_median_s)
  delta_line "warm_open ${arch}" "$z" "$i" 0
  for arch in "large-${CORPUS_MIB}m.tar.gz" "large-${CORPUS_MIB}m.bin.gz" "small-100.tar.gz"; do
    z=$(csv_val rust-rgz-zlib cold "$arch" mount_s)
    i=$(csv_val rust-rgz-isal cold "$arch" mount_s)
    if [[ -n "${z}${i}" ]]; then
      delta_line "fuse cold mount ${arch}" "$z" "$i" 0
    fi
    z=$(csv_val rust-rgz-zlib cold "$arch" bandwidth_mibs)
    i=$(csv_val rust-rgz-isal cold "$arch" bandwidth_mibs)
    if [[ -n "${z}${i}" ]]; then
      delta_line "fuse cold seq MiB/s ${arch}" "$z" "$i" 1
    fi
    z=$(csv_val rust-rgz-zlib warm "$arch" bandwidth_mibs)
    i=$(csv_val rust-rgz-isal warm "$arch" bandwidth_mibs)
    if [[ -n "${z}${i}" ]]; then
      delta_line "fuse warm seq MiB/s ${arch}" "$z" "$i" 1
    fi
  done
  echo
  echo "## FUSE cold mount + sequential bandwidth"
  echo
  echo "| Archive | metric | rust-rgz-zlib | rust-rgz-isal | rust-g3 | python |"
  echo "|---------|--------|---------------|---------------|---------|--------|"
  for arch in "large-${CORPUS_MIB}m.tar.gz" "large-${CORPUS_MIB}m.bin.gz" "small-100.tar.gz"; do
    for metric in mount_s bandwidth_mibs seq_read_s mount_rss_kib; do
      z=$(csv_val rust-rgz-zlib cold "$arch" "$metric")
      i=$(csv_val rust-rgz-isal cold "$arch" "$metric")
      g=$(csv_val rust-g3 cold "$arch" "$metric")
      p=$(csv_val python cold "$arch" "$metric")
      if [[ -z "${z}${i}${g}${p}" ]]; then
        continue
      fi
      echo "| ${arch} | ${metric} | ${z:--} | ${i:--} | ${g:--} | ${p:--} |"
    done
  done
  echo
  echo "## Raw CSV"
  echo
  echo '```'
  column -t -s';' "$CSV" 2>/dev/null || cat "$CSV"
  echo '```'
  echo
  echo "## Notes"
  echo
  echo "- **Fair A/B**: \`rust-rgz-zlib\` and \`rust-rgz-isal\` are different binaries from two cargo builds."
  echo "- Both select the rapidgzip path via \`RATARMOUNT_GZIP_BACKEND=rapidgzip\` and \`--use-backend rapidgzip\`."
  echo "- Inflate backend is a **compile-time** choice (\`gzip-rapidgzip\` vs \`gzip-rapidgzip-isal\`); runtime env cannot switch ISA-L on/off."
  echo "- Cold index is the primary decode-only microbench (full inflate, no FUSE)."
  echo "- Warm sequential \`cat\` after FUSE warm mount measures decode after index reuse."
  echo "- Large corpora: half zeros + half urandom, \`gzip -1\` (single-member)."
  echo "- Results dir is gitignored; re-run the script to regenerate."
  echo "- Related multi-backend harness (single build): \`compare-gzip-backends.sh\`."
} >"$MD"

echoerr ""
echoerr "Wrote $CSV"
echoerr "Wrote $MD"
cat "$MD"
