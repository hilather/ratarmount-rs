#!/usr/bin/env bash
# Head-to-head benchmark: Python ratarmount vs Rust ratarmount-rs
# Metrics aligned with benchmarks/ in the Python project:
#   - cold mount (index create) wall time + peak RSS
#   - warm mount (index load) wall time + peak RSS
#   - random file access (median of N cat timings)
#   - find (metadata walk) wall time
#   - sequential read bandwidth of a large file
#
# Usage:
#   RATARMOUNT_PY_ROOT=../ratarmount ./benchmarks/compare-python-vs-rust.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_ROOT="${RATARMOUNT_PY_ROOT:-$ROOT/../ratarmount}"
RUST_BIN="${RUST_BIN:-$ROOT/target/release/ratarmount}"
# Prefer local benchmark venv if present
if [[ -x "$ROOT/benchmarks/.venv-py/bin/python" ]]; then
    PY_PYTHON="${PY_PYTHON:-$ROOT/benchmarks/.venv-py/bin/python}"
else
    PY_PYTHON="${PY_PYTHON:-python3}"
fi
PY_CMD="${PY_CMD:-$PY_PYTHON -X dev -W ignore::DeprecationWarning:fuse -u -m ratarmount}"

export PATH="${HOME}/.cargo/bin:${PATH}"

WORKDIR="${TMPDIR:-/tmp}/ratarmount-compare-$$"
mkdir -p "$WORKDIR/data" "$WORKDIR/mnt" "$WORKDIR/results"
RESULTS="$WORKDIR/results/results.csv"
MD_OUT="${MD_OUT:-$ROOT/benchmarks/python-vs-rust-results.md}"
CSV_OUT="${CSV_OUT:-$ROOT/benchmarks/python-vs-rust-results.csv}"

cleanup() {
    # shellcheck disable=SC2046
    for mp in "$WORKDIR"/mnt-*; do
        [[ -d "$mp" ]] || continue
        fusermount3 -u "$mp" 2>/dev/null || fusermount -u "$mp" 2>/dev/null || true
    done
    pkill -f "ratarmount.*$WORKDIR" 2>/dev/null || true
    # keep workdir for debugging if COMPARE_KEEP=1
    if [[ "${COMPARE_KEEP:-0}" != "1" ]]; then
        rm -rf "$WORKDIR"
    else
        echo "Kept $WORKDIR" >&2
    fi
}
trap cleanup EXIT

echoerr() { echo "$@" >&2; }

if [[ ! -x "$RUST_BIN" ]]; then
    echoerr "Building release binary..."
    (cd "$ROOT" && cargo build --release)
fi
if [[ ! -d "$PY_ROOT/ratarmount" ]]; then
    echoerr "Python tree not found at $PY_ROOT"
    exit 1
fi

# ---- archive construction (mirrors mounting/bandwidth style fixtures) ----
make_archives() {
    local d="$WORKDIR/data"
    # A) nested-tar fixture copy
    cp "$PY_ROOT/tests/nested-tar.tar" "$d/nested-tar.tar"

    # B) many empty files (index-bound), 1k files in 10 folders
    local empty="$d/empty-1k"
    mkdir -p "$empty"
    for i in $(seq 0 9); do
        mkdir -p "$empty/f$i"
        for j in $(seq 0 99); do
            : > "$empty/f$i/file-$(printf '%04d' "$j")"
        done
    done
    tar -C "$empty" -cf "$d/empty-1k.tar" .

    # C) many small files 64KiB each, 100 files (~6.4 MiB) — access + bandwidth mix
    local small="$d/small-100"
    mkdir -p "$small"
    for i in $(seq 0 99); do
        dd if=/dev/urandom of="$small/f$(printf '%03d' "$i").bin" bs=65536 count=1 status=none 2>/dev/null
    done
    tar -C "$small" -cf "$d/small-100.tar" .

    # D) single large file 64 MiB for sequential bandwidth
    local large="$d/large-1"
    mkdir -p "$large"
    dd if=/dev/urandom of="$large/blob.bin" bs=1M count=64 status=none 2>/dev/null
    tar -C "$large" -cf "$d/large-64m.tar" .

    # E) compressions of small-100 for codec comparison
    gzip -c -1 "$d/small-100.tar" > "$d/small-100.tar.gz"
    bzip2 -c -1 "$d/small-100.tar" > "$d/small-100.tar.bz2"
    xz -c -1 -T0 "$d/small-100.tar" > "$d/small-100.tar.xz" 2>/dev/null || xz -c -1 "$d/small-100.tar" > "$d/small-100.tar.xz"
    # multi-frame zstd (seekable) via zstd -T0
    zstd -f -1 -T0 -o "$d/small-100.tar.zst" "$d/small-100.tar" 2>/dev/null || zstd -f -1 -o "$d/small-100.tar.zst" "$d/small-100.tar"

    # F) zip of small files
    (cd "$small" && zip -qr "$d/small-100.zip" .)

    ls -lah "$d" >&2
}

wait_mount() {
    local mp=$1
    local i
    for i in $(seq 1 200); do
        if mountpoint -q "$mp" 2>/dev/null || mount 2>/dev/null | grep -F -q "$mp"; then
            # ensure usable
            if ls "$mp" &>/dev/null; then
                return 0
            fi
        fi
        sleep 0.05
    done
    return 1
}

unmount_mp() {
    local mp=$1
    fusermount3 -u "$mp" 2>/dev/null || fusermount -u "$mp" 2>/dev/null || true
    # wait until gone
    local i
    for i in $(seq 1 50); do
        if ! mountpoint -q "$mp" 2>/dev/null && ! mount 2>/dev/null | grep -F -q "$mp"; then
            break
        fi
        sleep 0.05
        fusermount3 -u "$mp" 2>/dev/null || true
    done
}

# Measure: wall_s,rss_kib for a foreground mount that we background until ready
# Writes: tool;scenario;archive;metric;value;unit
measure_mount() {
    local tool=$1 cmd=$2 archive=$3 scenario=$4 extra_flags=$5
    local mp idx log
    mp=$(mktemp -d "$WORKDIR/mnt-XXXXXX")
    # Same index path for cold and warm so warm reuses cold's SQLite DB
    idx="$WORKDIR/$(basename "$archive").${tool}.index.sqlite"
    log="$WORKDIR/${tool}-${scenario}-$(basename "$archive").log"

    if [[ "$scenario" == "cold" ]]; then
        rm -f "$idx"
        # also remove sidecar next to archive if any
        rm -f "${archive}.index.sqlite" 2>/dev/null || true
    fi

    # shellcheck disable=SC2206
    local -a cmd_arr=($cmd)
    # both use -f for fair process-lifetime measurement of first usable mount
    # RSS via /usr/bin/time of the whole mount process is awkward for fuse;
    # we sample VmHWM of the FUSE process after mount is ready.
    local start end wall_s rss_kib pid
    local -a idx_flags=(--index-file "$idx" --index-minimum-file-count 0)
    if [[ "$scenario" == "cold" ]]; then
        idx_flags=(-c "${idx_flags[@]}")
    fi
    start=$(date +%s.%N)
    # shellcheck disable=SC2086
    "${cmd_arr[@]}" -f "${idx_flags[@]}" \
        $extra_flags "$archive" "$mp" >"$log" 2>&1 &
    pid=$!
    if ! wait_mount "$mp"; then
        echoerr "FAIL mount $tool $scenario $(basename "$archive")"
        cat "$log" >&2 || true
        kill "$pid" 2>/dev/null || true
        unmount_mp "$mp"
        rmdir "$mp" 2>/dev/null || true
        echo "$tool;$scenario;$(basename "$archive");mount_fail;1;bool"
        return 1
    fi
    end=$(date +%s.%N)
    wall_s=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.4f", e-s}')
    rss_kib=$(awk '/VmHWM/ {print $2}' /proc/$pid/status 2>/dev/null || echo 0)

    echo "$tool;$scenario;$(basename "$archive");mount_s;$wall_s;s"
    echo "$tool;$scenario;$(basename "$archive");mount_rss_kib;$rss_kib;KiB"

    # store mp/pid for subsequent metrics in same function via globals
    _CUR_MP=$mp
    _CUR_PID=$pid
    _CUR_TOOL=$tool
    _CUR_ARCH=$(basename "$archive")
    _CUR_SCEN=$scenario
    return 0
}

finish_mount_session() {
    local mp=${1:-$_CUR_MP}
    local pid=${2:-$_CUR_PID}
    unmount_mp "$mp"
    wait "$pid" 2>/dev/null || true
    rmdir "$mp" 2>/dev/null || true
}

# random access: pick N existing files under mount, time each cat, report median
measure_random_access() {
    local mp=$1 tool=$2 arch=$3 scen=$4
    local n=${5:-10}
    mapfile -t files < <(find "$mp" -type f 2>/dev/null | head -n 200)
    if [[ ${#files[@]} -eq 0 ]]; then
        echo "$tool;$scen;$arch;rand_access_median_s;nan;s"
        return
    fi
    local times=()
    local i f start end t
    for i in $(seq 1 "$n"); do
        f="${files[$(( RANDOM % ${#files[@]} ))]}"
        start=$(date +%s.%N)
        cat -- "$f" >/dev/null
        end=$(date +%s.%N)
        t=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.6f", e-s}')
        times+=("$t")
    done
    # median
    local sorted
    sorted=$(printf '%s\n' "${times[@]}" | sort -n)
    local mid=$(( n / 2 ))
    local median
    median=$(printf '%s\n' "$sorted" | sed -n "$((mid+1))p")
    echo "$tool;$scen;$arch;rand_access_median_s;$median;s"
}

measure_find() {
    local mp=$1 tool=$2 arch=$3 scen=$4
    local start end wall
    start=$(date +%s.%N)
    find "$mp" >/dev/null 2>&1
    end=$(date +%s.%N)
    wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.4f", e-s}')
    echo "$tool;$scen;$arch;find_s;$wall;s"
}

measure_bandwidth() {
    local mp=$1 tool=$2 arch=$3 scen=$4 relpath=$5
    local f="$mp/$relpath"
    if [[ ! -f "$f" ]]; then
        # try find largest file
        f=$(find "$mp" -type f -printf '%s %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    fi
    if [[ -z "$f" || ! -f "$f" ]]; then
        echo "$tool;$scen;$arch;bandwidth_mibs;nan;MiB/s"
        return
    fi
    local size start end wall mibs
    size=$(stat -c %s -- "$f")
    start=$(date +%s.%N)
    cat -- "$f" >/dev/null
    end=$(date +%s.%N)
    wall=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.6f", e-s}')
    mibs=$(awk -v sz="$size" -v w="$wall" 'BEGIN{ if(w<=0) print "nan"; else printf "%.2f", (sz/1048576.0)/w }')
    echo "$tool;$scen;$arch;bandwidth_mibs;$mibs;MiB/s"
    echo "$tool;$scen;$arch;seq_read_s;$wall;s"
    echo "$tool;$scen;$arch;file_size_b;$size;B"
}

run_suite_for_tool() {
    local tool=$1
    local cmd=$2
    local archive=$3
    local extra=${4:-}
    local bw_path=${5:-}

    echoerr "=== $tool $(basename "$archive") ==="

    # cold
    if measure_mount "$tool" "$cmd" "$archive" "cold" "$extra"; then
        measure_random_access "$_CUR_MP" "$tool" "$_CUR_ARCH" "cold" 15
        measure_find "$_CUR_MP" "$tool" "$_CUR_ARCH" "cold"
        if [[ -n "$bw_path" ]]; then
            measure_bandwidth "$_CUR_MP" "$tool" "$_CUR_ARCH" "cold" "$bw_path"
        fi
        finish_mount_session
    fi

    # warm (reuse index)
    if measure_mount "$tool" "$cmd" "$archive" "warm" "$extra"; then
        measure_random_access "$_CUR_MP" "$tool" "$_CUR_ARCH" "warm" 15
        measure_find "$_CUR_MP" "$tool" "$_CUR_ARCH" "warm"
        if [[ -n "$bw_path" ]]; then
            measure_bandwidth "$_CUR_MP" "$tool" "$_CUR_ARCH" "warm" "$bw_path"
        fi
        finish_mount_session
    fi
}

# ---- main ----
echoerr "Preparing archives in $WORKDIR ..."
make_archives

: > "$RESULTS"
echo "tool;scenario;archive;metric;value;unit" >> "$RESULTS"

PY_BIN="python3 -X dev -W ignore::DeprecationWarning:fuse -u -m ratarmount"
# run from PY_ROOT so module resolves
py() {
    (cd "$PY_ROOT" && PYTHONPATH="$PY_ROOT${PYTHONPATH:+:$PYTHONPATH}" $PY_BIN "$@")
}
# wrapper script for bash arrays
cat > "$WORKDIR/py-ratarmount" <<EOF
#!/usr/bin/env bash
# Use benchmark venv interpreter (has mfusepy + ratarmount installed)
exec "$PY_PYTHON" -X dev -W ignore::DeprecationWarning:fuse -u -m ratarmount "\$@"
EOF
chmod +x "$WORKDIR/py-ratarmount"
# Sanity: python import must work
if ! "$WORKDIR/py-ratarmount" --help >/dev/null 2>&1; then
    echoerr "Python ratarmount failed to start."
    echoerr "Create venv: uv venv benchmarks/.venv-py && uv pip install -e \$PY_ROOT/core -e \$PY_ROOT mfusepy rapidgzip ..."
    "$WORKDIR/py-ratarmount" --help 2>&1 | head -20 >&2 || true
    exit 1
fi

D="$WORKDIR/data"
declare -a JOBS=(
    # archive|extra_flags|bandwidth_relpath
    "$D/nested-tar.tar||-r|foo/fighter/ufo"
    "$D/empty-1k.tar|||"
    "$D/small-100.tar|||f000.bin"
    "$D/large-64m.tar|||blob.bin"
    "$D/small-100.tar.gz|||f000.bin"
    "$D/small-100.tar.bz2|||f000.bin"
    "$D/small-100.tar.xz|||f000.bin"
    "$D/small-100.tar.zst|||f000.bin"
    "$D/small-100.zip|||f000.bin"
)

for job in "${JOBS[@]}"; do
    IFS='|' read -r arch extra bwpath <<<"$job"
    [[ -f "$arch" ]] || { echoerr "skip missing $arch"; continue; }
    run_suite_for_tool "python" "$WORKDIR/py-ratarmount" "$arch" "$extra" "$bwpath" | tee -a "$RESULTS"
    run_suite_for_tool "rust" "$RUST_BIN" "$arch" "$extra" "$bwpath" | tee -a "$RESULTS"
done

cp "$RESULTS" "$CSV_OUT"

# Produce markdown comparison table via python
python3 - <<'PY' "$RESULTS" "$MD_OUT"
import csv, sys
from collections import defaultdict
from pathlib import Path

results_path, md_path = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(results_path), delimiter=';'))

# key: (archive, scenario, metric) -> {tool: value}
data = defaultdict(dict)
units = {}
for r in rows:
    if r["metric"] == "mount_fail":
        continue
    try:
        v = float(r["value"])
    except ValueError:
        continue
    data[(r["archive"], r["scenario"], r["metric"])][r["tool"]] = v
    units[r["metric"]] = r["unit"]

archives = sorted({k[0] for k in data})
scenarios = ["cold", "warm"]
metrics_order = [
    ("mount_s", "Mount time"),
    ("mount_rss_kib", "Peak RSS"),
    ("rand_access_median_s", "Random cat (median)"),
    ("find_s", "find walk"),
    ("bandwidth_mibs", "Seq. bandwidth"),
    ("seq_read_s", "Seq. read time"),
]

def fmt(v, metric):
    if v is None:
        return "—"
    if metric.endswith("_s"):
        if v < 0.001:
            return f"{v*1000:.3f} ms"
        if v < 1:
            return f"{v*1000:.1f} ms"
        return f"{v:.3f} s"
    if metric == "mount_rss_kib":
        if v >= 1024:
            return f"{v/1024:.1f} MiB"
        return f"{int(v)} KiB"
    if metric == "bandwidth_mibs":
        return f"{v:.1f} MiB/s"
    return f"{v:.4g}"

def relative(py, rs, metric, higher_better=False):
    """Human-readable relative result. Never implies Rust won when it lost."""
    if py is None or rs is None or py == 0 or rs == 0:
        return "—"
    word = "lower" if metric == "mount_rss_kib" else ("better" if higher_better else "faster")
    if higher_better:
        ratio = rs / py
        if ratio >= 1.0:
            return f"Rust **{ratio:.2f}×** {word}"
        return f"Python **{py/rs:.2f}×** {word}"
    # lower is better (time, RSS)
    if rs <= py:
        return f"Rust **{py/rs:.2f}×** {word}"
    return f"Python **{rs/py:.2f}×** {word}"

def rust_advantage(py, rs, higher_better=False):
    """Signed factor: >1 means Rust better, <1 means Python better. For gmean of wins only we track both."""
    if py is None or rs is None or py <= 0 or rs <= 0:
        return None
    if higher_better:
        return rs / py
    return py / rs

lines = []
lines.append("# Python ratarmount vs Rust ratarmount-rs — benchmark comparison")
lines.append("")
lines.append("Generated by `benchmarks/compare-python-vs-rust.sh`.")
lines.append("")
lines.append("Methodology (aligned with upstream mounting/bandwidth benchmarks):")
lines.append("")
lines.append("- **Cold mount**: recreate index (`-c`), wall time until FUSE mount is usable.")
lines.append("- **Warm mount**: reuse SQLite index, wall time until usable.")
lines.append("- **Random access**: median of 15 `cat` timings on randomly chosen files.")
lines.append("- **find**: wall time of `find <mount>` (metadata storm).")
lines.append("- **Bandwidth**: sequential `cat` of a large file, MiB/s.")
lines.append("- Both tools run with `-f` (foreground FUSE) for comparable process measurement.")
lines.append("- Peak RSS sampled from `/proc/<pid>/status` `VmHWM` after mount is ready.")
lines.append("")
lines.append("**Relative** names the **winner** and by how much (never labels a loss as a Rust speedup).")
lines.append("")

for arch in archives:
    lines.append(f"## `{arch}`")
    lines.append("")
    lines.append("| Metric | Scenario | Python | Rust | Relative |")
    lines.append("|--------|----------|--------|------|----------|")
    for metric, label in metrics_order:
        for scen in scenarios:
            py = data.get((arch, scen, metric), {}).get("python")
            rs = data.get((arch, scen, metric), {}).get("rust")
            if py is None and rs is None:
                continue
            hb = metric == "bandwidth_mibs"
            lines.append(
                f"| {label} | {scen} | {fmt(py, metric)} | {fmt(rs, metric)} | {relative(py, rs, metric, higher_better=hb)} |"
            )
    lines.append("")

lines.append("## Summary (geometric mean of Rust-advantage factor across archives)")
lines.append("")
lines.append("Factor **>1 ⇒ Rust better**, **<1 ⇒ Python better** (same scale as before: Py/Rust for times, Rust/Py for bandwidth).")
lines.append("")
lines.append("| Metric | Scenario | Geo-mean factor | Interpretation |")
lines.append("|--------|----------|-----------------|----------------|")
import math
def gmean(xs):
    if not xs: return None
    return math.exp(sum(math.log(x) for x in xs)/len(xs))

for metric, label in metrics_order:
    for scen in scenarios:
        ratios = []
        hb = metric == "bandwidth_mibs"
        for arch in archives:
            py = data.get((arch, scen, metric), {}).get("python")
            rs = data.get((arch, scen, metric), {}).get("rust")
            r = rust_advantage(py, rs, higher_better=hb)
            if r is not None:
                ratios.append(r)
        gm = gmean(ratios)
        if gm:
            if gm >= 1.0:
                interp = f"Rust ahead (~{gm:.2f}×)"
            else:
                interp = f"Python ahead (~{1.0/gm:.2f}×)"
            lines.append(f"| {label} | {scen} | {gm:.2f}× | {interp} |")

lines.append("")
lines.append("## Notes / caveats")
lines.append("")
lines.append("- Values **below 1.0×** in the summary mean **Python is faster / better**, not a Rust win.")
lines.append("- Rust codec path currently **materializes** compressed archives to a temp file before indexing; Python uses seekable native codecs (rapidgzip, etc.). Bandwidth/mount for `.gz/.bz2/.xz/.zst` therefore reflects different architectures.")
lines.append("- Random access and find are the best apples-to-apples comparisons on uncompressed TAR/ZIP.")
lines.append("- Results are single-run wall times on this host; treat as directional, not formal publication numbers.")
lines.append("")

Path(md_path).write_text("\n".join(lines) + "\n")
print("Wrote", md_path)
PY

echoerr "CSV: $CSV_OUT"
echoerr "MD:  $MD_OUT"
cat "$MD_OUT"
