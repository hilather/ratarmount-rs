#!/usr/bin/env bash
# Fair disk sequential baseline + FUSE kernel / mount-option tuning A/B.
#
# Measures:
#   1) Disk (same filesystem as the probe file):
#        - O_DIRECT sequential write (fdatasync / oflag=direct)
#        - O_DIRECT sequential read
#        - hot page-cache sequential read (labeled cache — NOT disk)
#   2) FUSE configs on a generated .tar.gz (default G3 path):
#        - baseline (CLI defaults; auto readahead for gzip)
#        - -o noatime
#        - --readahead 0 / 1M / 4M
#        - raised max_background / congestion_threshold (per-connection sysfs)
#        - combo: noatime + readahead 4M + max_background=64
#   3) Workloads per FUSE config:
#        - sequential cat of the large member (warm mount, index already built)
#        - parallel: PARALLEL readers each cat the same member
#
# Usage:
#   ./benchmarks/compare-fuse-kernel-tuning.sh
#   SIZE_MIB=256 PARALLEL=8 SKIP_BUILD=1 ./benchmarks/compare-fuse-kernel-tuning.sh
#
# Env:
#   RUST_BIN       default: target/release/ratarmount
#   SIZE_MIB       probe / payload size (default 64)
#   PARALLEL       parallel cat workers (default 4)
#   RUNS           samples per metric (default 2; median reported)
#   SKIP_BUILD     1 = do not cargo build
#   SKIP_FUSE      1 = disk only
#   SKIP_DISK      1 = FUSE only
#   OUT_DIR        default: benchmarks/fuse-kernel-results (gitignored)
#   DATA_DIR       where to put probe+corpus (default: OUT_DIR/data — real FS preferred)
#   DROP_CACHES    1 = try `echo 3 > /proc/sys/vm/drop_caches` before cold disk read (needs root)
#   KEEP           1 = keep workdir
#
# Requires: Linux + /dev/fuse for FUSE section; dd with iflag=direct preferred.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../test-harness/env.sh
source "$ROOT/test-harness/env.sh"

RUST_BIN="${RUST_BIN:-$ROOT/target/release/ratarmount}"
# Prefer a default-features binary (no libisal). Override with RUST_FEATURES if needed.
RUST_FEATURES="${RUST_FEATURES:-}"
SIZE_MIB="${SIZE_MIB:-64}"
PARALLEL="${PARALLEL:-4}"
RUNS="${RUNS:-2}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_FUSE="${SKIP_FUSE:-0}"
SKIP_DISK="${SKIP_DISK:-0}"
DROP_CACHES="${DROP_CACHES:-0}"
FORCE_REBUILD="${FORCE_REBUILD:-0}"
OUT_DIR="${OUT_DIR:-$ROOT/benchmarks/fuse-kernel-results}"
DATA_DIR="${DATA_DIR:-$OUT_DIR/data}"
KEEP="${KEEP:-0}"

export PATH="${HOME}/.cargo/bin:${PATH}"

# Optional ISA-L runtime for feature builds
if [[ -z "${ISAL_INSTALL_PREFIX:-}" && -d "$ROOT/../rapidgzip-rust/.isal-prefix" ]]; then
  ISAL_INSTALL_PREFIX="$ROOT/../rapidgzip-rust/.isal-prefix"
fi
if [[ -n "${ISAL_INSTALL_PREFIX:-}" && -d "$ISAL_INSTALL_PREFIX/lib" ]]; then
  export LD_LIBRARY_PATH="$ISAL_INSTALL_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

WORKDIR="${TMPDIR:-/tmp}/ratarmount-fuse-kernel-$$"
mkdir -p "$WORKDIR" "$OUT_DIR" "$DATA_DIR"

CSV_OUT="${CSV_OUT:-$OUT_DIR/results.csv}"
MD_OUT="${MD_OUT:-$OUT_DIR/results.md}"
LOG="${LOG:-$OUT_DIR/run.log}"

echoerr() { echo "$@" | tee -a "$LOG" >&2; }

cleanup() {
  for mp in "$WORKDIR"/mnt-*; do
    [[ -d "$mp" ]] || continue
    ratar_unmount "$mp"
  done
  pkill -f "ratarmount.*$WORKDIR" 2>/dev/null || true
  if [[ "$KEEP" != "1" ]]; then
    rm -rf "$WORKDIR"
  else
    echoerr "Kept $WORKDIR"
  fi
}
trap cleanup EXIT

: >"$LOG"
: >"$CSV_OUT"
echo "section;config;metric;value;unit;notes" >>"$CSV_OUT"

csv() {
  # section;config;metric;value;unit;notes
  printf '%s;%s;%s;%s;%s;%s\n' "$1" "$2" "$3" "$4" "$5" "${6:-}" >>"$CSV_OUT"
}

median_of() {
  # stdin: numbers one per line → median
  sort -n | awk '
    { a[NR]=$1 }
    END {
      if (NR==0) { print "nan"; exit }
      if (NR%2) print a[(NR+1)/2]
      else printf "%.6f", (a[NR/2]+a[NR/2+1])/2
    }'
}

wall_mibs() {
  # args: size_bytes wall_s → MiB/s
  local sz=$1 w=$2
  awk -v sz="$sz" -v w="$w" 'BEGIN{
    if (w+0 <= 0) print "nan"
    else printf "%.2f", (sz/1048576.0)/w
  }'
}

timed_sec() {
  # run command, print wall seconds to stdout
  local start end
  start=$(date +%s.%N)
  "$@" >/dev/null 2>&1 || return $?
  end=$(date +%s.%N)
  awk -v s="$start" -v e="$end" 'BEGIN{printf "%.6f", e-s}'
}

# ---- build ----
need_build=0
if [[ ! -x "$RUST_BIN" || "$FORCE_REBUILD" == "1" ]]; then
  need_build=1
elif ! "$RUST_BIN" --help >/dev/null 2>&1; then
  # e.g. existing binary linked against libisal but LD_LIBRARY_PATH not set
  echoerr "WARN: $RUST_BIN failed to start; rebuilding default features"
  need_build=1
fi
if [[ "$need_build" == "1" ]]; then
  if [[ "$SKIP_BUILD" == "1" ]]; then
    echoerr "ERROR: RUST_BIN not usable: $RUST_BIN (and SKIP_BUILD=1)"
    exit 1
  fi
  echoerr "Building release ratarmount (features='${RUST_FEATURES:-default}')..."
  if [[ -n "$RUST_FEATURES" ]]; then
    (cd "$ROOT" && cargo build --release -p ratarmount --features "$RUST_FEATURES" 2>&1 | tee -a "$LOG" | tail -25)
  else
    # Explicit default features only — avoid a workspace default that pulls isal.
    (cd "$ROOT" && cargo build --release -p ratarmount 2>&1 | tee -a "$LOG" | tail -25)
  fi
fi
if ! "$RUST_BIN" --help >/dev/null 2>&1; then
  echoerr "ERROR: $RUST_BIN still fails to start (missing shared libs?)"
  echoerr "  Hint: unset RUST_BIN and rebuild without gzip-rapidgzip-isal, or set"
  echoerr "  ISAL_INSTALL_PREFIX / LD_LIBRARY_PATH for libisal.so"
  ldd "$RUST_BIN" 2>/dev/null | grep -i 'not found' || true
  exit 1
fi

HOST=$(hostname 2>/dev/null || echo unknown)
NPROC=$(nproc 2>/dev/null || echo 1)
FSTYPE=$(findmnt -T "$DATA_DIR" -n -o FSTYPE 2>/dev/null || echo unknown)
SOURCE=$(findmnt -T "$DATA_DIR" -n -o SOURCE 2>/dev/null || echo unknown)
KERNEL=$(uname -r 2>/dev/null || echo unknown)

echoerr "=== fuse kernel tuning bench ==="
echoerr "HOST=$HOST nproc=$NPROC kernel=$KERNEL"
echoerr "DATA_DIR=$DATA_DIR ($FSTYPE on $SOURCE)"
echoerr "SIZE_MIB=$SIZE_MIB PARALLEL=$PARALLEL RUNS=$RUNS"
echoerr "RUST_BIN=$RUST_BIN"

# ---- fair disk probe ----
disk_probe() {
  local mib=$1
  local probe="$DATA_DIR/disk-probe-${mib}m.bin"
  local size=$((mib * 1024 * 1024))
  local times med mibs wall

  echoerr "=== disk probe ${mib} MiB on $DATA_DIR ==="
  csv "meta" "disk" "probe_path" "$probe" "path" "$FSTYPE $SOURCE"
  csv "meta" "disk" "probe_mib" "$mib" "MiB" ""

  # Sequential write (prefer O_DIRECT; fall back to fdatasync-only)
  times=()
  for _ in $(seq 1 "$RUNS"); do
    rm -f "$probe"
    if wall=$(timed_sec dd if=/dev/zero of="$probe" bs=1M count="$mib" oflag=direct status=none 2>/dev/null); then
      times+=("$wall")
    else
      wall=$(timed_sec dd if=/dev/zero of="$probe" bs=1M count="$mib" conv=fdatasync status=none)
      times+=("$wall")
    fi
  done
  med=$(printf '%s\n' "${times[@]}" | median_of)
  mibs=$(wall_mibs "$size" "$med")
  csv "disk" "odirect_write" "bandwidth_mibs" "$mibs" "MiB/s" "median of $RUNS"
  csv "disk" "odirect_write" "wall_s" "$med" "s" "median of $RUNS"
  echoerr "  O_DIRECT write: ${mibs} MiB/s (${med}s)"

  # Ensure file exists for reads
  if [[ ! -f "$probe" ]]; then
    dd if=/dev/zero of="$probe" bs=1M count="$mib" conv=fdatasync status=none
  fi

  if [[ "$DROP_CACHES" == "1" ]] && sudo -n true 2>/dev/null; then
    sudo -n sh -c 'echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null || true
    echoerr "  dropped page caches (DROP_CACHES=1)"
  fi

  # O_DIRECT sequential read (fair disk)
  times=()
  for _ in $(seq 1 "$RUNS"); do
    if wall=$(timed_sec dd if="$probe" of=/dev/null bs=1M iflag=direct status=none 2>/dev/null); then
      times+=("$wall")
    else
      # no O_DIRECT — still report but note
      wall=$(timed_sec dd if="$probe" of=/dev/null bs=1M status=none)
      times+=("$wall")
    fi
  done
  med=$(printf '%s\n' "${times[@]}" | median_of)
  mibs=$(wall_mibs "$size" "$med")
  csv "disk" "odirect_read" "bandwidth_mibs" "$mibs" "MiB/s" "median of $RUNS; fair media baseline"
  csv "disk" "odirect_read" "wall_s" "$med" "s" "median of $RUNS"
  echoerr "  O_DIRECT read:  ${mibs} MiB/s (${med}s)  [fair disk]"

  # Hot page-cache read (NOT disk — for contrast)
  # Prime cache
  cat "$probe" >/dev/null 2>&1 || dd if="$probe" of=/dev/null bs=1M status=none
  times=()
  for _ in $(seq 1 "$RUNS"); do
    wall=$(timed_sec dd if="$probe" of=/dev/null bs=1M status=none)
    times+=("$wall")
  done
  med=$(printf '%s\n' "${times[@]}" | median_of)
  mibs=$(wall_mibs "$size" "$med")
  csv "disk" "pagecache_read" "bandwidth_mibs" "$mibs" "MiB/s" "median of $RUNS; RAM — not disk"
  csv "disk" "pagecache_read" "wall_s" "$med" "s" "median of $RUNS"
  echoerr "  page-cache read: ${mibs} MiB/s (${med}s)  [NOT disk]"
}

if [[ "$SKIP_DISK" != "1" ]]; then
  disk_probe "$SIZE_MIB"
fi

# ---- corpus for FUSE ----
build_corpus() {
  local mib=$1
  local plain="$DATA_DIR/payload-${mib}m.bin"
  local tar="$DATA_DIR/large-${mib}m.tar"
  local tgz="$DATA_DIR/large-${mib}m.tar.gz"
  if [[ -f "$tgz" && -f "$tar" ]]; then
    # reuse if size matches
    local sz
    sz=$(stat -c %s -- "$plain" 2>/dev/null || echo 0)
    if [[ "$sz" -eq $((mib * 1024 * 1024)) ]]; then
      echoerr "Reusing corpus $tgz"
      CORPUS_TGZ="$tgz"
      CORPUS_MEMBER="payload-${mib}m.bin"
      return 0
    fi
  fi
  echoerr "Building ${mib} MiB corpus under $DATA_DIR..."
  dd if=/dev/urandom of="$plain" bs=1M count="$mib" status=none
  # deterministic-ish compressible variant: zero + sparse header for faster gzip optional?
  # urandom = worst-case gzip; good stress. For thruput closer to real tars use /dev/zero mix:
  dd if=/dev/zero of="${plain}.z" bs=1M count="$mib" status=none
  # Prefer compressible payload for realistic gzip FUSE (matches prior benches style)
  mv -f "${plain}.z" "$plain"
  # stamp so content is not all zeros identical across machines
  printf 'ratarmount-fuse-kernel-bench-%s\n' "$mib" | dd of="$plain" conv=notrunc bs=1 seek=0 status=none
  tar -C "$DATA_DIR" -cf "$tar" "payload-${mib}m.bin"
  gzip -c -1 "$tar" >"$tgz"
  CORPUS_TGZ="$tgz"
  CORPUS_MEMBER="payload-${mib}m.bin"
  echoerr "  wrote $tgz ($(stat -c %s -- "$tgz") bytes compressed)"
}

wait_mount() {
  local mp=$1 i
  for i in $(seq 1 200); do
    if ratar_is_mounted "$mp" 2>/dev/null || mountpoint -q "$mp" 2>/dev/null; then
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
  for i in $(seq 1 40); do
    if ! ratar_is_mounted "$mp" 2>/dev/null && ! mountpoint -q "$mp" 2>/dev/null; then
      break
    fi
    sleep 0.05
    ratar_unmount "$mp" 2>/dev/null || true
  done
}

# FUSE connection id = minor device number of the mount (maj:min → min).
fuse_conn_id() {
  local mp=$1
  local majmin min line
  # Canonicalize (symlinks /tmp vs /var/tmp, etc.)
  mp=$(readlink -f "$mp" 2>/dev/null || echo "$mp")
  majmin=$(findmnt -n -r -o MAJ:MIN --target "$mp" 2>/dev/null | head -1 | tr -d '[:space:]' || true)
  if [[ -z "$majmin" ]]; then
    # Fallback: parse /proc/self/mountinfo (field 3 is maj:min).
    line=$(awk -v mp="$mp" '$5 == mp { print $3; exit }' /proc/self/mountinfo 2>/dev/null || true)
    majmin=$(echo "$line" | tr -d '[:space:]')
  fi
  if [[ -z "$majmin" ]]; then
    return 1
  fi
  min=${majmin#*:}
  min=${min//[^0-9]/}
  if [[ -n "$min" && -d "/sys/fs/fuse/connections/$min" ]]; then
    echo "$min"
    return 0
  fi
  return 1
}

tune_fuse_conn() {
  local mp=$1 max_bg=$2 cong=$3
  local id path
  id=$(fuse_conn_id "$mp") || {
    echoerr "  warn: could not resolve fuse connection for $mp"
    return 1
  }
  path="/sys/fs/fuse/connections/$id"
  if [[ ! -w "$path/max_background" ]]; then
    echoerr "  warn: $path/max_background not writable"
    return 1
  fi
  echo "$max_bg" >"$path/max_background"
  echo "$cong" >"$path/congestion_threshold"
  echoerr "  fuse conn $id: max_background=$max_bg congestion_threshold=$cong"
  csv "fuse_sysfs" "conn_$id" "max_background" "$max_bg" "count" "applied"
  csv "fuse_sysfs" "conn_$id" "congestion_threshold" "$cong" "count" "applied"
  return 0
}

# Mount once (warm index path), apply optional sysfs tune, run workloads.
# Args: config_name  extra CLI args...
# Uses global CORPUS_TGZ CORPUS_MEMBER
measure_fuse_config() {
  local config=$1
  shift
  local -a extra=("$@")
  local mp idx log pid start end wall f size
  local times med mibs
  local i p

  echoerr "=== fuse config: $config ==="
  mp=$(mktemp -d "$WORKDIR/mnt-XXXXXX")
  idx="$WORKDIR/${config}.index.sqlite"
  log="$WORKDIR/${config}.log"
  rm -f "$idx"

  # Cold index build without FUSE thruput noise: --no-mount first for stable warm path
  "$RUST_BIN" -c --no-mount --index-file "$idx" --index-minimum-file-count 0 \
    "${extra[@]}" "$CORPUS_TGZ" >"$log" 2>&1 || {
    echoerr "  FAIL index $config"
    tail -20 "$log" >&2 || true
    csv "fuse" "$config" "index_fail" "1" "bool" ""
    rmdir "$mp" 2>/dev/null || true
    return 1
  }

  # Warm mount
  start=$(date +%s.%N)
  "$RUST_BIN" -f --index-file "$idx" --index-minimum-file-count 0 \
    "${extra[@]}" "$CORPUS_TGZ" "$mp" >>"$log" 2>&1 &
  pid=$!
  if ! wait_mount "$mp"; then
    echoerr "  FAIL mount $config"
    tail -30 "$log" >&2 || true
    kill "$pid" 2>/dev/null || true
    unmount_mp "$mp"
    rmdir "$mp" 2>/dev/null || true
    csv "fuse" "$config" "mount_fail" "1" "bool" ""
    return 1
  fi
  end=$(date +%s.%N)
  wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.4f", e-s}')
  csv "fuse" "$config" "warm_mount_s" "$wall" "s" ""
  echoerr "  warm mount: ${wall}s"

  # Optional sysfs: config name contains maxbg64
  if [[ "$config" == *maxbg64* ]]; then
    tune_fuse_conn "$mp" 64 48 || true
  elif [[ "$config" == *maxbg12* ]]; then
    # force default-ish low concurrency for contrast
    tune_fuse_conn "$mp" 12 9 || true
  fi

  f="$mp/$CORPUS_MEMBER"
  if [[ ! -f "$f" ]]; then
    f=$(find "$mp" -type f -printf '%s %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2- || true)
  fi
  if [[ -z "${f:-}" || ! -f "$f" ]]; then
    echoerr "  FAIL no member file under $mp"
    csv "fuse" "$config" "member_missing" "1" "bool" ""
    unmount_mp "$mp"
    wait "$pid" 2>/dev/null || true
    rmdir "$mp" 2>/dev/null || true
    return 1
  fi
  size=$(stat -c %s -- "$f")

  # Sequential cat (RUNS)
  times=()
  for _ in $(seq 1 "$RUNS"); do
    start=$(date +%s.%N)
    cat -- "$f" >/dev/null
    end=$(date +%s.%N)
    wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.6f", e-s}')
    times+=("$wall")
  done
  med=$(printf '%s\n' "${times[@]}" | median_of)
  mibs=$(wall_mibs "$size" "$med")
  csv "fuse" "$config" "seq_bandwidth_mibs" "$mibs" "MiB/s" "median of $RUNS; uncompressed"
  csv "fuse" "$config" "seq_read_s" "$med" "s" "median of $RUNS"
  echoerr "  seq cat: ${mibs} MiB/s (${med}s)"

  # Parallel partial reads (same file, different offsets) — stresses max_background
  # without N full-file decompresses (slow and can starve FUSE under heavy load).
  times=()
  local chunk=$((1024 * 1024)) # 1 MiB per reader
  [[ "$chunk" -gt "$size" ]] && chunk=$size
  local par_timeout="${PARALLEL_TIMEOUT_S:-60}"
  local max_skip=$(( size / chunk ))
  [[ "$max_skip" -lt 1 ]] && max_skip=1
  for _ in $(seq 1 "$RUNS"); do
    start=$(date +%s.%N)
    if timeout "$par_timeout" bash -c '
      f="$1"; chunk="$2"; parallel="$3"; max_skip="$4"
      for p in $(seq 0 $((parallel - 1))); do
        skip=$(( (p * max_skip / parallel) ))
        dd if="$f" of=/dev/null bs="$chunk" count=1 skip="$skip" status=none 2>/dev/null &
      done
      wait
    ' bash "$f" "$chunk" "$PARALLEL" "$max_skip"; then
      end=$(date +%s.%N)
      wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.6f", e-s}')
      times+=("$wall")
    else
      echoerr "  warn: parallel workload timed out after ${par_timeout}s"
      csv "fuse" "$config" "parallel_timeout" "1" "bool" "PARALLEL_TIMEOUT_S=$par_timeout"
      times+=("$par_timeout")
    fi
  done
  med=$(printf '%s\n' "${times[@]}" | median_of)
  # Aggregate thruput: PARALLEL * chunk / wall
  mibs=$(awk -v ch="$chunk" -v w="$med" -v n="$PARALLEL" 'BEGIN{
    if (w+0<=0) print "nan"; else printf "%.2f", (n*ch/1048576.0)/w
  }')
  csv "fuse" "$config" "parallel_agg_bandwidth_mibs" "$mibs" "MiB/s" "PARALLEL=$PARALLEL ×1MiB windows"
  csv "fuse" "$config" "parallel_wall_s" "$med" "s" "PARALLEL=$PARALLEL median of $RUNS"
  echoerr "  parallel×${PARALLEL} (1MiB each): ${mibs} MiB/s aggregate (${med}s wall)"

  # Random 4 KiB samples (16 points) — latency-ish
  times=()
  local blocks=$((size / 4096))
  [[ "$blocks" -lt 16 ]] && blocks=16
  for _ in $(seq 1 "$RUNS"); do
    start=$(date +%s.%N)
    for i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
      local off=$(( (i * blocks / 16) ))
      dd if="$f" of=/dev/null bs=4096 count=1 skip="$off" status=none 2>/dev/null || true
    done
    end=$(date +%s.%N)
    wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.6f", e-s}')
    times+=("$wall")
  done
  med=$(printf '%s\n' "${times[@]}" | median_of)
  csv "fuse" "$config" "rand16_4k_s" "$med" "s" "16×4KiB reads median of $RUNS"
  echoerr "  random 16×4K: ${med}s"

  unmount_mp "$mp"
  wait "$pid" 2>/dev/null || true
  rmdir "$mp" 2>/dev/null || true
}

if [[ "$SKIP_FUSE" != "1" ]]; then
  if [[ ! -e /dev/fuse ]]; then
    echoerr "SKIP FUSE: /dev/fuse missing"
    csv "fuse" "skip" "no_fuse_device" "1" "bool" ""
  else
    build_corpus "$SIZE_MIB"
    # Config matrix (G3 default; no rapidgzip feature required)
    measure_fuse_config "baseline" \
      || true
    measure_fuse_config "noatime" \
      -o noatime \
      || true
    measure_fuse_config "readahead0" \
      --readahead 0 \
      || true
    measure_fuse_config "readahead1M" \
      --readahead 1M \
      || true
    measure_fuse_config "readahead4M" \
      --readahead 4M \
      || true
    measure_fuse_config "noatime_readahead4M" \
      -o noatime --readahead 4M \
      || true
    measure_fuse_config "maxbg12_readahead1M" \
      --readahead 1M \
      || true
    measure_fuse_config "maxbg64_readahead1M" \
      --readahead 1M \
      || true
    measure_fuse_config "combo_noatime_ra4M_maxbg64" \
      -o noatime --readahead 4M \
      || true
  fi
fi

# ---- markdown report ----
python3 - "$CSV_OUT" "$MD_OUT" "$HOST" "$KERNEL" "$FSTYPE" "$SOURCE" "$SIZE_MIB" "$PARALLEL" "$RUNS" "$RUST_BIN" <<'PY'
import csv, sys, statistics
from pathlib import Path
from collections import defaultdict

csv_path, md_path = sys.argv[1], sys.argv[2]
host, kernel, fstype, source = sys.argv[3:7]
size_mib, parallel, runs, rust_bin = sys.argv[7:11]

rows = []
with open(csv_path, newline="") as f:
    r = csv.DictReader(f, delimiter=";")
    for row in r:
        rows.append(row)

def find(section, config, metric):
    for row in rows:
        if row["section"] == section and row["config"] == config and row["metric"] == metric:
            return row["value"], row.get("unit", ""), row.get("notes", "")
    return None, "", ""

def fnum(v):
    try:
        return float(v)
    except Exception:
        return None

lines = []
lines.append("# FUSE kernel tuning + fair disk baseline\n")
lines.append(f"Generated by `benchmarks/compare-fuse-kernel-tuning.sh`.\n")
lines.append("## Environment\n")
lines.append("| Setting | Value |")
lines.append("|---------|-------|")
lines.append(f"| HOST | {host} |")
lines.append(f"| kernel | {kernel} |")
lines.append(f"| filesystem | `{fstype}` on `{source}` |")
lines.append(f"| SIZE_MIB | {size_mib} |")
lines.append(f"| PARALLEL | {parallel} |")
lines.append(f"| RUNS (median) | {runs} |")
lines.append(f"| RUST_BIN | `{rust_bin}` |")
lines.append("")
lines.append("## Fairness notes\n")
lines.append("- **O_DIRECT read/write** is the media baseline (bypasses page cache).")
lines.append("- **page-cache read** is RAM bandwidth after a warm read — **not** disk; listed only for contrast.")
lines.append("- FUSE bandwidth is **uncompressed** member bytes / wall time (same definition as other ratarmount benches).")
lines.append("- Sysfs `max_background` is applied **after** mount on the connection minor for that mountpoint.")
lines.append("- Do not invent thruput claims beyond this table; re-run the script to refresh numbers.")
lines.append("")

# Disk table
lines.append("## Disk baseline (same FS as probe)\n")
lines.append("| Config | MiB/s | wall s | Notes |")
lines.append("|--------|------:|-------:|-------|")
for cfg, label in [
    ("odirect_write", "O_DIRECT write"),
    ("odirect_read", "O_DIRECT read (**fair disk**)"),
    ("pagecache_read", "page-cache read (NOT disk)"),
]:
    bw, _, notes = find("disk", cfg, "bandwidth_mibs")
    wall, _, _ = find("disk", cfg, "wall_s")
    if bw is None:
        continue
    lines.append(f"| {label} | {bw} | {wall or '—'} | {notes} |")
lines.append("")

disk_r, _, _ = find("disk", "odirect_read", "bandwidth_mibs")
disk_r_f = fnum(disk_r)

# FUSE table
lines.append("## FUSE configs (warm mount, G3 default gzip path)\n")
lines.append("| Config | seq MiB/s | parallel agg MiB/s | rand16×4K s | warm mount s |")
lines.append("|--------|----------:|-------------------:|------------:|-------------:|")

# preserve run order from csv
seen = []
for row in rows:
    if row["section"] == "fuse" and row["metric"] == "seq_bandwidth_mibs":
        c = row["config"]
        if c not in seen:
            seen.append(c)

for cfg in seen:
    seq, _, _ = find("fuse", cfg, "seq_bandwidth_mibs")
    par, _, _ = find("fuse", cfg, "parallel_agg_bandwidth_mibs")
    rnd, _, _ = find("fuse", cfg, "rand16_4k_s")
    mnt, _, _ = find("fuse", cfg, "warm_mount_s")
    lines.append(f"| `{cfg}` | {seq or '—'} | {par or '—'} | {rnd or '—'} | {mnt or '—'} |")
lines.append("")

if disk_r_f and seen:
    lines.append("## vs fair disk (O_DIRECT read)\n")
    lines.append(f"Disk O_DIRECT read ≈ **{disk_r} MiB/s**. Ratio = FUSE seq / disk ( >1 means FUSE reports higher uncompressed thruput than media O_DIRECT — usually decompress+cache effects, not 'faster disk').\n")
    lines.append("| Config | seq / disk |")
    lines.append("|--------|-----------:|")
    for cfg in seen:
        seq, _, _ = find("fuse", cfg, "seq_bandwidth_mibs")
        s = fnum(seq)
        if s is None:
            continue
        lines.append(f"| `{cfg}` | {s/disk_r_f:.2f}× |")
    lines.append("")

lines.append("## Suggested reading\n")
lines.append("Operator guide: [`docs/fuse-kernel-tuning.md`](../docs/fuse-kernel-tuning.md).\n")
lines.append("## Raw CSV\n")
lines.append("```")
with open(csv_path) as f:
    lines.append(f.read().rstrip())
lines.append("```")
lines.append("")

Path(md_path).write_text("\n".join(lines) + "\n")
print(f"Wrote {md_path}", file=sys.stderr)
PY

echoerr "CSV: $CSV_OUT"
echoerr "MD:  $MD_OUT"
echoerr "Done."
