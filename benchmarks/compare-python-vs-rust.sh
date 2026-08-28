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
#
# Env:
#   RATARMOUNT_PY_ROOT  Python ratarmount checkout (default: ../ratarmount)
#   RUST_BIN            Rust binary (default: target/release/ratarmount)
#   PY_PYTHON           Python interpreter (default: benchmarks/.venv-py or python3)
#   CSV_OUT / MD_OUT    result paths under benchmarks/
#   MICRO=1             minimal fixture set for gate CI (empty-1k + small-100{.tar,.tar.gz})
#   BIG=1               published suite: x10-of-medium (640 MiB) + tar.zst/tar.lz4;
#                       writes python-vs-rust-results-big.{csv,md} and copies to
#                       python-vs-rust-results.{csv,md} (the README snapshot)
#   LARGE_MIB           BIG blob size in MiB (default: 640 = 10× large-64m)
#   FRAME_MIB           zstd independent-frame size for large .tar.zst (default: 4)
#   PREPARE_ONLY=1      build fixtures, verify names/frames, exit (no FUSE / no Python)
#   SKIP_PYTHON=1       do not require a Python ratarmount tree (PREPARE_ONLY)
#   SKIP_BUILD=1        do not cargo-build if RUST_BIN is missing (then fail unless PREPARE_ONLY)
#   COMPARE_KEEP=1      keep workdir after run
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Portable unmount / mount helpers (Linux + macOS)
# shellcheck source=../test-harness/env.sh
source "$ROOT/test-harness/env.sh"
PY_ROOT="${RATARMOUNT_PY_ROOT:-$ROOT/../ratarmount}"
RUST_BIN="${RUST_BIN:-$ROOT/target/release/ratarmount}"
MICRO="${MICRO:-0}"
BIG="${BIG:-0}"
LARGE_MIB="${LARGE_MIB:-640}"
FRAME_MIB="${FRAME_MIB:-4}"
PREPARE_ONLY="${PREPARE_ONLY:-0}"
SKIP_PYTHON="${SKIP_PYTHON:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
# Prefer local benchmark venv if present
if [[ -x "$ROOT/benchmarks/.venv-py/bin/python" ]]; then
    PY_PYTHON="${PY_PYTHON:-$ROOT/benchmarks/.venv-py/bin/python}"
else
    PY_PYTHON="${PY_PYTHON:-python3}"
fi
# Prefer installed CLI if present (venv); else -m ratarmount
if [[ -x "$(dirname "$PY_PYTHON")/ratarmount" ]]; then
    PY_CMD="${PY_CMD:-$(dirname "$PY_PYTHON")/ratarmount}"
else
    PY_CMD="${PY_CMD:-$PY_PYTHON -X dev -W ignore::DeprecationWarning:fuse -u -m ratarmount}"
fi

export PATH="${HOME}/.cargo/bin:${PATH}"

WORKDIR="${TMPDIR:-/tmp}/ratarmount-compare-$$"
mkdir -p "$WORKDIR/data" "$WORKDIR/mnt" "$WORKDIR/results"
RESULTS="$WORKDIR/results/results.csv"
if [[ "$MICRO" == "1" ]]; then
    MD_OUT="${MD_OUT:-$ROOT/benchmarks/python-vs-rust-results-micro.md}"
    CSV_OUT="${CSV_OUT:-$ROOT/benchmarks/python-vs-rust-results-micro.csv}"
elif [[ "$BIG" == "1" ]]; then
    MD_OUT="${MD_OUT:-$ROOT/benchmarks/python-vs-rust-results-big.md}"
    CSV_OUT="${CSV_OUT:-$ROOT/benchmarks/python-vs-rust-results-big.csv}"
else
    MD_OUT="${MD_OUT:-$ROOT/benchmarks/python-vs-rust-results.md}"
    CSV_OUT="${CSV_OUT:-$ROOT/benchmarks/python-vs-rust-results.csv}"
fi

cleanup() {
    # shellcheck disable=SC2046
    for mp in "$WORKDIR"/mnt-*; do
        [[ -d "$mp" ]] || continue
        ratar_unmount "$mp"
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

if [[ "$PREPARE_ONLY" != "1" && ! -x "$RUST_BIN" ]]; then
    if [[ "$SKIP_BUILD" == "1" ]]; then
        echoerr "Rust binary not found at $RUST_BIN (SKIP_BUILD=1)"
        exit 1
    fi
    echoerr "Building release binary..."
    (cd "$ROOT" && cargo build --release)
fi
if [[ "$PREPARE_ONLY" != "1" && "$SKIP_PYTHON" != "1" && ! -d "$PY_ROOT/ratarmount" ]]; then
    echoerr "Python tree not found at $PY_ROOT"
    exit 1
fi

# Concatenated independent zstd frames so large .tar.zst stays seekable
# (single-frame zstd of a 64+ MiB blob falls through to full-decode / tmp spool).
zstd_multiframe() {
    local src=$1 dest=$2 frame_bytes=$3
    python3 - "$src" "$dest" "$frame_bytes" <<'PY'
import subprocess, sys
src, dest, frame = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(src, "rb") as inf, open(dest, "wb") as out:
    while True:
        chunk = inf.read(frame)
        if not chunk:
            break
        out.write(subprocess.run(
            ["zstd", "-1", "-c"], input=chunk, stdout=subprocess.PIPE, check=True
        ).stdout)
PY
}

zstd_frame_count() {
    python3 - "$1" <<'PY'
import sys
magic = b"\x28\xb5\x2f\xfd"
data = open(sys.argv[1], "rb").read()
n = data.count(magic)
print(n)
PY
}

lz4_compress() {
    local src=$1 dest=$2
    # -B7 = 4 MiB independent blocks (default independence) — cheap random access
    lz4 -1 -B7 -f -q "$src" "$dest"
}

# ---- archive construction (mirrors mounting/bandwidth style fixtures) ----
make_archives() {
    local d="$WORKDIR/data"
    local frame_bytes=$((FRAME_MIB * 1048576))
    # B) many empty files (index-bound), 1k files in 10 folders — always
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
    gzip -c -1 "$d/small-100.tar" > "$d/small-100.tar.gz"

    if [[ "$MICRO" == "1" ]]; then
        # Enough for rust-gates.json ratio metrics (warm mount, RSS, find, plain-TAR + tar.gz BW)
        ls -lah "$d" >&2
        return 0
    fi

    # A) nested-tar fixture copy
    if [[ -f "$PY_ROOT/tests/nested-tar.tar" ]]; then
        cp "$PY_ROOT/tests/nested-tar.tar" "$d/nested-tar.tar"
    else
        echoerr "WARN: nested-tar.tar missing under $PY_ROOT/tests (skipping)"
    fi

    # D) single large file 64 MiB for sequential bandwidth (the "medium" blob)
    local large="$d/large-1"
    mkdir -p "$large"
    dd if=/dev/urandom of="$large/blob.bin" bs=1M count=64 status=none 2>/dev/null
    tar -C "$large" -cf "$d/large-64m.tar" .

    # E) compressions of small-100 for codec comparison
    bzip2 -c -1 "$d/small-100.tar" > "$d/small-100.tar.bz2"
    xz -c -1 -T0 "$d/small-100.tar" > "$d/small-100.tar.xz" 2>/dev/null || xz -c -1 "$d/small-100.tar" > "$d/small-100.tar.xz"
    # small payload: single-frame zstd is fine (well under the in-memory decode cap)
    zstd -f -1 -T0 -o "$d/small-100.tar.zst" "$d/small-100.tar" 2>/dev/null || zstd -f -1 -o "$d/small-100.tar.zst" "$d/small-100.tar"
    if command -v lz4 >/dev/null 2>&1; then
        lz4_compress "$d/small-100.tar" "$d/small-100.tar.lz4"
    else
        echoerr "WARN: lz4 not found (skipping small-100.tar.lz4)"
    fi

    # F) zip of small files
    (cd "$small" && zip -qr "$d/small-100.zip" .)

    # G) seekable compressions of the 64 MiB blob (multi-frame zstd / independent-block lz4)
    if command -v zstd >/dev/null 2>&1; then
        zstd_multiframe "$d/large-64m.tar" "$d/large-64m.tar.zst" "$frame_bytes"
    else
        echoerr "WARN: zstd not found (skipping large-64m.tar.zst)"
    fi
    if command -v lz4 >/dev/null 2>&1; then
        lz4_compress "$d/large-64m.tar" "$d/large-64m.tar.lz4"
    else
        echoerr "WARN: lz4 not found (skipping large-64m.tar.lz4)"
    fi

    if [[ "$BIG" == "1" ]]; then
        # H) x10 of small-100 file count: 1000 × 64 KiB (~64 MiB) — index + find scale
        local small1k="$d/small-1000"
        mkdir -p "$small1k"
        python3 - "$small1k" <<'PY'
import os, sys
root = sys.argv[1]
for i in range(1000):
    with open(os.path.join(root, f"f{i:04d}.bin"), "wb") as fh:
        fh.write(os.urandom(65536))
PY
        tar -C "$small1k" -cf "$d/small-1000.tar" .

        # I) x10 of medium 64 MiB blob
        local large_big="$d/large-big"
        mkdir -p "$large_big"
        dd if=/dev/urandom of="$large_big/blob.bin" bs=1M count="$LARGE_MIB" status=none 2>/dev/null
        tar -C "$large_big" -cf "$d/large-${LARGE_MIB}m.tar" .
        if command -v zstd >/dev/null 2>&1; then
            zstd_multiframe "$d/large-${LARGE_MIB}m.tar" "$d/large-${LARGE_MIB}m.tar.zst" "$frame_bytes"
        fi
        if command -v lz4 >/dev/null 2>&1; then
            lz4_compress "$d/large-${LARGE_MIB}m.tar" "$d/large-${LARGE_MIB}m.tar.lz4"
        fi
    fi

    ls -lah "$d" >&2
}

# Verify expected fixture names (and multi-frame zstd) then print PREPARE_OK lines.
verify_fixtures() {
    local d="$WORKDIR/data"
    local missing=0
    expect_file() {
        local f=$1
        if [[ -f "$d/$f" ]]; then
            echoerr "PREPARE_OK $f $(stat -c %s "$d/$f")B"
        else
            echoerr "PREPARE_MISSING $f"
            missing=1
        fi
    }
    expect_file "empty-1k.tar"
    expect_file "small-100.tar"
    expect_file "small-100.tar.gz"
    if [[ "$MICRO" != "1" ]]; then
        expect_file "small-100.tar.bz2"
        expect_file "small-100.tar.xz"
        expect_file "small-100.tar.zst"
        expect_file "small-100.zip"
        expect_file "large-64m.tar"
        if command -v lz4 >/dev/null 2>&1; then
            expect_file "small-100.tar.lz4"
            expect_file "large-64m.tar.lz4"
        fi
        if command -v zstd >/dev/null 2>&1; then
            expect_file "large-64m.tar.zst"
            local n
            n=$(zstd_frame_count "$d/large-64m.tar.zst")
            if [[ "$n" -ge 2 ]]; then
                echoerr "PREPARE_OK large-64m.tar.zst frames=$n"
            else
                echoerr "PREPARE_FAIL large-64m.tar.zst frames=$n (want >=2)"
                missing=1
            fi
        fi
    fi
    if [[ "$BIG" == "1" && "$MICRO" != "1" ]]; then
        expect_file "small-1000.tar"
        expect_file "large-${LARGE_MIB}m.tar"
        if command -v lz4 >/dev/null 2>&1; then
            expect_file "large-${LARGE_MIB}m.tar.lz4"
        fi
        if command -v zstd >/dev/null 2>&1; then
            expect_file "large-${LARGE_MIB}m.tar.zst"
            local nbig
            nbig=$(zstd_frame_count "$d/large-${LARGE_MIB}m.tar.zst")
            if [[ "$nbig" -ge 2 ]]; then
                echoerr "PREPARE_OK large-${LARGE_MIB}m.tar.zst frames=$nbig"
            else
                echoerr "PREPARE_FAIL large-${LARGE_MIB}m.tar.zst frames=$nbig (want >=2)"
                missing=1
            fi
        fi
    fi
    return "$missing"
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
    ratar_unmount "$mp"
    # wait until gone
    local i
    for i in $(seq 1 50); do
        if ! mountpoint -q "$mp" 2>/dev/null && ! mount 2>/dev/null | grep -F -q "$mp"; then
            break
        fi
        sleep 0.05
        ratar_unmount "$mp"
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

# 64 KiB preads at random offsets — real random access for large blobs
# (full `cat` of a 640 MiB member is sequential bandwidth, not seeking).
measure_random_pread() {
    local mp=$1 tool=$2 arch=$3 scen=$4 relpath=$5
    local n=${6:-15}
    local f="$mp/$relpath"
    if [[ ! -f "$f" ]]; then
        f=$(find "$mp" -type f -printf '%s %p\n' 2>/dev/null | sort -n | tail -1 | cut -d' ' -f2-)
    fi
    if [[ -z "$f" || ! -f "$f" ]]; then
        echo "$tool;$scen;$arch;rand_pread_64k_median_s;nan;s"
        return
    fi
    local median
    median=$(python3 - "$f" "$n" <<'PY'
import os, random, sys, time
path, n = sys.argv[1], int(sys.argv[2])
size = os.path.getsize(path)
chunk = 65536
times = []
with open(path, "rb") as fh:
    for _ in range(n):
        off = 0 if size <= chunk else random.randrange(0, size - chunk)
        t0 = time.perf_counter()
        fh.seek(off)
        fh.read(chunk)
        times.append(time.perf_counter() - t0)
times.sort()
print(f"{times[len(times)//2]:.6f}")
PY
)
    echo "$tool;$scen;$arch;rand_pread_64k_median_s;$median;s"
}

run_suite_for_tool() {
    local tool=$1
    local cmd=$2
    local archive=$3
    local extra=${4:-}
    local bw_path=${5:-}
    local rand_n=${6:-15}

    echoerr "=== $tool $(basename "$archive") ==="

    # cold
    if measure_mount "$tool" "$cmd" "$archive" "cold" "$extra"; then
        measure_random_access "$_CUR_MP" "$tool" "$_CUR_ARCH" "cold" "$rand_n"
        measure_find "$_CUR_MP" "$tool" "$_CUR_ARCH" "cold"
        if [[ -n "$bw_path" ]]; then
            measure_bandwidth "$_CUR_MP" "$tool" "$_CUR_ARCH" "cold" "$bw_path"
            measure_random_pread "$_CUR_MP" "$tool" "$_CUR_ARCH" "cold" "$bw_path" 15
        fi
        finish_mount_session
    fi

    # warm (reuse index)
    if measure_mount "$tool" "$cmd" "$archive" "warm" "$extra"; then
        measure_random_access "$_CUR_MP" "$tool" "$_CUR_ARCH" "warm" "$rand_n"
        measure_find "$_CUR_MP" "$tool" "$_CUR_ARCH" "warm"
        if [[ -n "$bw_path" ]]; then
            measure_bandwidth "$_CUR_MP" "$tool" "$_CUR_ARCH" "warm" "$bw_path"
            measure_random_pread "$_CUR_MP" "$tool" "$_CUR_ARCH" "warm" "$bw_path" 15
        fi
        finish_mount_session
    fi
}

# ---- main ----
echoerr "Preparing archives in $WORKDIR ..."
make_archives

if [[ "$PREPARE_ONLY" == "1" ]]; then
    if verify_fixtures; then
        echoerr "PREPARE_OK all expected fixtures"
        exit 0
    fi
    echoerr "PREPARE_FAIL missing fixtures"
    exit 1
fi

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
declare -a JOBS=()
if [[ "$MICRO" == "1" ]]; then
    echoerr "MICRO=1: minimal fixture set (empty-1k, small-100.tar, small-100.tar.gz)"
    JOBS=(
        # archive|extra_flags|bandwidth_relpath|rand_n
        "$D/empty-1k.tar||||"
        "$D/small-100.tar||f000.bin|"
        "$D/small-100.tar.gz||f000.bin|"
    )
else
    JOBS=(
        # archive|extra_flags|bandwidth_relpath|rand_n
        "$D/nested-tar.tar|-r|foo/fighter/ufo|"
        "$D/empty-1k.tar||||"
        "$D/small-100.tar||f000.bin|"
        "$D/large-64m.tar||blob.bin|"
        "$D/large-64m.tar.zst||blob.bin|"
        "$D/large-64m.tar.lz4||blob.bin|"
        "$D/small-100.tar.gz||f000.bin|"
        "$D/small-100.tar.bz2||f000.bin|"
        "$D/small-100.tar.xz||f000.bin|"
        "$D/small-100.tar.zst||f000.bin|"
        "$D/small-100.tar.lz4||f000.bin|"
        "$D/small-100.zip||f000.bin|"
    )
    if [[ "$BIG" == "1" ]]; then
        echoerr "BIG=1: x10 fixtures (small-1000 + large-${LARGE_MIB}m.tar{,.zst,.lz4})"
        JOBS+=(
            "$D/small-1000.tar||f0000.bin|"
            "$D/large-${LARGE_MIB}m.tar||blob.bin|3"
            "$D/large-${LARGE_MIB}m.tar.zst||blob.bin|3"
            "$D/large-${LARGE_MIB}m.tar.lz4||blob.bin|3"
        )
    fi
fi

for job in "${JOBS[@]}"; do
    IFS='|' read -r arch extra bwpath rand_n <<<"$job"
    [[ -f "$arch" ]] || { echoerr "skip missing $arch"; continue; }
    run_suite_for_tool "python" "$WORKDIR/py-ratarmount" "$arch" "$extra" "$bwpath" "${rand_n:-15}" | tee -a "$RESULTS"
    run_suite_for_tool "rust" "$RUST_BIN" "$arch" "$extra" "$bwpath" "${rand_n:-15}" | tee -a "$RESULTS"
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
    ("rand_pread_64k_median_s", "Random 64KiB pread (median)"),
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
import datetime
stamp = datetime.date.today().isoformat()
lines.append(f"**Snapshot:** {stamp} · ratarmount-rs vs Python ratarmount (this host).")
lines.append("")
lines.append("**Regenerate published suite:** `BIG=1 ./benchmarks/compare-python-vs-rust.sh` (needs FUSE, `RATARMOUNT_PY_ROOT`, `zstd`, `lz4`).")
lines.append("")
lines.append("Methodology (aligned with upstream mounting/bandwidth benchmarks):")
lines.append("")
lines.append("- **Cold mount**: recreate index (`-c`), wall time until FUSE mount is usable.")
lines.append("- **Warm mount**: reuse SQLite index, wall time until usable.")
lines.append("- **Random access**: median of N `cat` timings on randomly chosen files (N=15; N=3 on BIG blobs).")
lines.append("- **Random 64KiB pread**: median of 15 `seek+read(64KiB)` on the bandwidth member (true random I/O on large blobs).")
lines.append("- **find**: wall time of `find <mount>` (metadata storm).")
lines.append("- **Bandwidth**: sequential `cat` of a large file, MiB/s.")
lines.append("- Both tools run with `-f` (foreground FUSE) for comparable process measurement.")
lines.append("- Peak RSS sampled from `/proc/<pid>/status` `VmHWM` after mount is ready.")
lines.append("- Large `.tar.zst` is **multi-frame** (independent frames); large `.tar.lz4` uses 4 MiB independent blocks.")
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

# Highlight wins / losses (skip tiny nested-tar bandwidth which is a 10-byte member).
WINS_THRESHOLD = 1.20
rust_wins = []
python_wins = []
for metric, label in metrics_order:
    hb = metric == "bandwidth_mibs"
    for scen in scenarios:
        for arch in archives:
            if arch == "nested-tar.tar" and metric in ("bandwidth_mibs", "seq_read_s"):
                continue
            py = data.get((arch, scen, metric), {}).get("python")
            rs = data.get((arch, scen, metric), {}).get("rust")
            r = rust_advantage(py, rs, higher_better=hb)
            if r is None:
                continue
            if r >= WINS_THRESHOLD:
                rust_wins.append((r, arch, label, scen, py, rs, metric, hb))
            elif r > 0 and (1.0 / r) >= WINS_THRESHOLD:
                python_wins.append((1.0 / r, arch, label, scen, py, rs, metric, hb))

rust_wins.sort(reverse=True)
python_wins.sort(reverse=True)

def win_rows(rows, winner):
    out = []
    out.append(f"| Archive | Metric | Scenario | Python | Rust | {winner} advantage |")
    out.append("|---|---|---|---:|---:|---|")
    for factor, arch, label, scen, py, rs, metric, hb in rows:
        word = "better" if hb else ("lower" if metric == "mount_rss_kib" else "faster")
        out.append(
            f"| `{arch}` | {label} | {scen} | {fmt(py, metric)} | {fmt(rs, metric)} | **{factor:.2f}×** {word} |"
        )
    return out

lines.append("## Where Rust is ahead (≥ 1.20×)")
lines.append("")
if rust_wins:
    lines.extend(win_rows(rust_wins, "Rust"))
else:
    lines.append("No metric cleared the 1.20× threshold.")
lines.append("")
lines.append("## Where Python is ahead (≥ 1.20×)")
lines.append("")
if python_wins:
    lines.extend(win_rows(python_wins, "Python"))
else:
    lines.append("No metric cleared the 1.20× threshold.")
lines.append("")
lines.append("## Notes / caveats")
lines.append("")
lines.append("- Values **below 1.0×** in the summary mean **Python is faster / better**, not a Rust win.")
lines.append("- Compressed TAR (`.tar.gz`/`.bz2`/`.xz`/`.zst`/`.lz4`): Rust uses seekable outer codecs (`SeekableBody` / multi-frame maps / independent lz4 blocks) for indexing+mount; plain single-file `.gz` etc. still materialize. Python uses rapidgzip / indexed codecs / block-parallel paths with true bit-block maps in some cases.")
lines.append("- Random access and find on uncompressed TAR/ZIP remain the fairest apples-to-apples metrics.")
lines.append("- `rand_pread_64k` is the right random-I/O metric for `large-*` blobs; full `cat` of those members is sequential bandwidth.")
lines.append("- Sequential-bandwidth geo-mean still includes tiny members when present; prefer `large-*` rows over `nested-tar.tar`.")
lines.append("- Results are single-run wall times on this host; treat as directional, not formal publication numbers.")
lines.append("- Multi‑GiB/s sequential numbers are FUSE + page cache when the blob fits in RAM, not a disk-speed claim.")
lines.append("- Extreme `.tar.lz4` 64 KiB pread ratios mean Python is not using a cheap independent-block seek on the large member.")
lines.append("")

Path(md_path).write_text("\n".join(lines) + "\n")
print("Wrote", md_path)
PY

echoerr "CSV: $CSV_OUT"
echoerr "MD:  $MD_OUT"
if [[ "$BIG" == "1" ]]; then
    # Keep the well-known README snapshot in sync with the named BIG suite output.
    if [[ "$CSV_OUT" != "$ROOT/benchmarks/python-vs-rust-results.csv" ]]; then
        cp "$CSV_OUT" "$ROOT/benchmarks/python-vs-rust-results.csv"
    fi
    if [[ "$MD_OUT" != "$ROOT/benchmarks/python-vs-rust-results.md" ]]; then
        cp "$MD_OUT" "$ROOT/benchmarks/python-vs-rust-results.md"
    fi
    echoerr "Published snapshot: $ROOT/benchmarks/python-vs-rust-results.md"
fi
cat "$MD_OUT"
