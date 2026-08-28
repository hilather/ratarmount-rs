#!/usr/bin/env bash
# Rust-only benches aimed at the 0.1.28 vector wave (paths the FUSE cat/find
# BIG suite does not hit):
#   V-1  CLI find + control-plane search/<glob>
#   V-5  sequential cat in name order vs offsetheader order
#   P2   cold --no-mount index (many members) wall + RSS
#   P2   --hashes sha256 fill (fixed windows, not a full-body Vec)
#   P2   write-overlay create then getattr storm (inode cookies)
#   nested  -c -r --no-mount on a TAR of small ZIPs
#
# Usage:
#   ./benchmarks/compare-vector-wave.sh
#   OLD_BIN=... NEW_BIN=... N_FILES=8000 RUNS=3 ./benchmarks/compare-vector-wave.sh
#   VECTOR_MICRO=1 SKIP_FUSE=1 ./benchmarks/compare-vector-wave.sh
#   VECTOR_REMOTE=1 ./benchmarks/compare-vector-wave.sh   # local HTTP sidecar GET count
#
# Env:
#   OLD_BIN / NEW_BIN   binaries (NEW defaults to target/release/ratarmount)
#   OLD_REF             git ref to worktree-build when OLD_BIN is unset (v0.1.27)
#   SKIP_BUILD=1        do not cargo-build NEW if missing
#   SKIP_FUSE=1         skip overlay + offset-order extract + control search
#   VECTOR_MICRO=1      tiny fixtures (harness smoke)
#   VECTOR_REMOTE=1     fake HTTP remount; sidecar download count (V-3)
#   N_FILES             many-file TAR size (default 8000; 80 in MICRO)
#   RUNS                samples per metric, median (default 3; 1 in MICRO)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export RATARMOUNT_ALLOW_NO_PY=1
if [[ -z "${RATARMOUNT_CMD:-}" && -x "$ROOT/target/release/ratarmount" ]]; then
    export RATARMOUNT_CMD="$ROOT/target/release/ratarmount"
fi
# shellcheck source=../test-harness/env.sh
source "$ROOT/test-harness/env.sh"

VECTOR_MICRO="${VECTOR_MICRO:-0}"
VECTOR_REMOTE="${VECTOR_REMOTE:-0}"
SKIP_FUSE="${SKIP_FUSE:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
OLD_REF="${OLD_REF:-v0.1.27}"
NEW_BIN="${NEW_BIN:-$ROOT/target/release/ratarmount}"
if [[ "$VECTOR_MICRO" == "1" ]]; then
    N_FILES="${N_FILES:-80}"
    HASH_FILES="${HASH_FILES:-20}"
    SHUF_FILES="${SHUF_FILES:-40}"
    OVERLAY_FILES="${OVERLAY_FILES:-40}"
    NESTED_ZIPS="${NESTED_ZIPS:-4}"
    NESTED_EACH="${NESTED_EACH:-8}"
    RUNS="${RUNS:-1}"
else
    N_FILES="${N_FILES:-8000}"
    HASH_FILES="${HASH_FILES:-200}"
    SHUF_FILES="${SHUF_FILES:-2000}"
    OVERLAY_FILES="${OVERLAY_FILES:-400}"
    NESTED_ZIPS="${NESTED_ZIPS:-40}"
    NESTED_EACH="${NESTED_EACH:-25}"
    RUNS="${RUNS:-3}"
fi

OUT_DIR="${OUT_DIR:-$ROOT/benchmarks/vector-wave-results}"
mkdir -p "$OUT_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
CSV_OUT="${CSV_OUT:-$OUT_DIR/results-$STAMP.csv}"
MD_OUT="${MD_OUT:-$OUT_DIR/results-$STAMP.md}"

WORKDIR="${TMPDIR:-/tmp}/ratarmount-vector-wave-$$"
mkdir -p "$WORKDIR/data" "$WORKDIR/mnt" "$WORKDIR/idx"
KEEP_WORK="${KEEP_WORK:-0}"

echoerr() { echo "$@" >&2; }

cleanup() {
    for mp in "$WORKDIR"/mnt-*; do
        [[ -d "$mp" ]] || continue
        ratar_unmount "$mp"
    done
    pkill -f "ratarmount.*$WORKDIR" 2>/dev/null || true
    if [[ "$KEEP_WORK" == "1" ]]; then
        echoerr "Kept $WORKDIR"
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

bin_version() {
    local b=$1
    "$b" --version 2>/dev/null | head -1 | awk '{print $NF}' || echo unknown
}

ensure_new_bin() {
    if [[ -x "$NEW_BIN" ]]; then
        return 0
    fi
    if [[ "$SKIP_BUILD" == "1" ]]; then
        echoerr "NEW_BIN missing: $NEW_BIN (SKIP_BUILD=1)"
        exit 1
    fi
    echoerr "Building NEW release binary..."
    (cd "$ROOT" && cargo build --release -p ratarmount)
}

ensure_old_bin() {
    if [[ -n "${OLD_BIN:-}" && -x "$OLD_BIN" ]]; then
        return 0
    fi
    # Stable path so repeat runs reuse the binary.
    local wt="${OLD_WORKTREE:-/tmp/ratarmount-rs-old-$(echo "$OLD_REF" | tr '/.' '--')}"
    if [[ -x "$wt/target/release/ratarmount" ]]; then
        OLD_BIN="$wt/target/release/ratarmount"
        return 0
    fi
    echoerr "Building OLD ($OLD_REF) in $wt ..."
    if [[ ! -d "$wt" ]]; then
        git -C "$ROOT" worktree add --detach "$wt" "$OLD_REF"
    fi
    (cd "$wt" && cargo build --release -p ratarmount)
    OLD_BIN="$wt/target/release/ratarmount"
}

median_f() {
    python3 -c '
import sys
xs=[float(x) for x in sys.stdin.read().split() if x.strip()]
if not xs:
    print("nan"); raise SystemExit(1)
xs.sort()
print(f"{xs[len(xs)//2]:.6f}")
'
}

# Wall seconds + max RSS KiB of a foreground command (no GNU time required).
time_rss() {
    local out=$1
    shift
    set +e
    python3 - "$out" "$@" <<'PY'
import resource, subprocess, sys, time
out, cmd = sys.argv[1], sys.argv[2:]
t0 = time.perf_counter()
p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
elapsed = time.perf_counter() - t0
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
# Linux: KiB; macOS: bytes
import sys as _s
if _s.platform == "darwin":
    rss = int(rss / 1024)
with open(out, "w") as fh:
    if p.returncode != 0:
        sys.stderr.buffer.write(p.stderr)
        fh.write("nan nan\n")
        sys.exit(p.returncode)
    fh.write(f"{elapsed:.6f} {int(rss)}\n")
PY
    local rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
        echoerr "FAIL: $* (rc=$rc)"
        echo "nan nan" >"$out"
        return "$rc"
    fi
}

emit() {
    # tool;scenario;metric;value;unit
    echo "$1;$2;$3;$4;$5"
}

make_many_tar() {
    local dest=$1 n=$2
    python3 - "$dest" "$n" <<'PY'
import os, sys, tarfile, io
dest, n = sys.argv[1], int(sys.argv[2])
payload = b"x" * 64
with tarfile.open(dest, "w") as t:
    for i in range(n):
        name = f"d{i % 20:02d}/f{i:05d}.bin"
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        t.addfile(info, io.BytesIO(payload))
PY
}

make_hash_tar() {
    local dest=$1 n=$2
    python3 - "$dest" "$n" <<'PY'
import os, sys, tarfile, io
dest, n = sys.argv[1], int(sys.argv[2])
with tarfile.open(dest, "w") as t:
    for i in range(n):
        payload = os.urandom(32768)
        name = f"h{i:04d}.bin"
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        t.addfile(info, io.BytesIO(payload))
PY
}

make_shuffled_tar() {
    # Pack in reverse name order so path-order extract seeks backward.
    local dest=$1 n=$2
    python3 - "$dest" "$n" <<'PY'
import os, sys, tarfile, io
dest, n = sys.argv[1], int(sys.argv[2])
payload = os.urandom(4096)
with tarfile.open(dest, "w") as t:
    for i in range(n - 1, -1, -1):
        name = f"f{i:05d}.bin"
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        t.addfile(info, io.BytesIO(payload))
PY
}

make_nested_tar() {
    local dest=$1 nz=$2 each=$3
    python3 - "$dest" "$nz" "$each" <<'PY'
import io, os, sys, tarfile, zipfile
dest, nz, each = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
payload = b"nested-xxxxxxxx\n"
with tarfile.open(dest, "w") as t:
    for z in range(nz):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            for i in range(each):
                zf.writestr(f"f{i:04d}.txt", payload)
        raw = buf.getvalue()
        info = tarfile.TarInfo(f"inner{z:03d}.zip")
        info.size = len(raw)
        t.addfile(info, io.BytesIO(raw))
PY
}

make_tiny_tar() {
    local dest=$1
    python3 - "$dest" <<'PY'
import io, sys, tarfile
dest = sys.argv[1]
payload = b"seed\n"
with tarfile.open(dest, "w") as t:
    info = tarfile.TarInfo("seed.txt")
    info.size = len(payload)
    t.addfile(info, io.BytesIO(payload))
PY
}

wait_mount() {
    ratar_wait_mounted "$1" 80
}

mount_bg() {
    local bin=$1 archive=$2 extra=$3
    local idx=${4:-}
    local mp log pid
    mp=$(mktemp -d "$WORKDIR/mnt-XXXXXX")
    if [[ -z "$idx" ]]; then
        idx="$WORKDIR/idx/$(basename "$archive").$(basename "$bin").sqlite"
    fi
    log="$WORKDIR/$(basename "$bin")-$(basename "$archive").log"
    # shellcheck disable=SC2086
    "$bin" -f --index-file "$idx" --index-minimum-file-count 0 \
        $extra "$archive" "$mp" >"$log" 2>&1 &
    pid=$!
    if ! wait_mount "$mp"; then
        echoerr "FAIL mount $bin $archive"
        cat "$log" >&2 || true
        kill "$pid" 2>/dev/null || true
        return 1
    fi
    _CUR_MP=$mp
    _CUR_PID=$pid
}

finish_mount() {
    local mp=${1:-$_CUR_MP}
    local pid=${2:-$_CUR_PID}
    ratar_unmount "$mp"
    wait "$pid" 2>/dev/null || true
}

run_median() {
    local n=$1
    shift
    local i acc=""
    for i in $(seq 1 "$n"); do
        acc+="$("$@")"$'\n'
    done
    printf '%s' "$acc" | median_f
}

# ---- fixtures ----
echoerr "Preparing fixtures in $WORKDIR (N_FILES=$N_FILES) ..."
D="$WORKDIR/data"
make_many_tar "$D/many.tar" "$N_FILES"
make_hash_tar "$D/hash.tar" "$HASH_FILES"
make_shuffled_tar "$D/shuf.tar" "$SHUF_FILES"
make_nested_tar "$D/nested.tar" "$NESTED_ZIPS" "$NESTED_EACH"
make_tiny_tar "$D/tiny.tar"
ls -lh "$D" >&2

if [[ "${PREPARE_ONLY:-0}" == "1" ]]; then
    echoerr "PREPARE_OK many.tar hash.tar shuf.tar nested.tar tiny.tar"
    exit 0
fi

ensure_new_bin
ensure_old_bin
OLD_VER=$(bin_version "$OLD_BIN")
NEW_VER=$(bin_version "$NEW_BIN")
echoerr "OLD $OLD_BIN ($OLD_VER)"
echoerr "NEW $NEW_BIN ($NEW_VER)"

: >"$CSV_OUT"
echo "tool;scenario;metric;value;unit" >>"$CSV_OUT"

run_cold_index() {
    local tool=$1 bin=$2 archive=$3 scen=$4 extra=${5:-}
    local idx wall rss line
    idx="$WORKDIR/idx/${tool}-${scen}.sqlite"
    local samples_w=() samples_r=()
    local i out
    for i in $(seq 1 "$RUNS"); do
        rm -f "$idx"
        out=$(mktemp "$WORKDIR/tr.XXXXXX")
        # shellcheck disable=SC2086
        time_rss "$out" "$bin" -c --no-mount --index-file "$idx" \
            --index-minimum-file-count 0 $extra "$archive" || true
        wall=$(awk '{print $1}' "$out")
        rss=$(awk '{print $2}' "$out")
        samples_w+=("$wall")
        samples_r+=("$rss")
    done
    wall=$(printf '%s\n' "${samples_w[@]}" | median_f)
    rss=$(printf '%s\n' "${samples_r[@]}" | median_f)
    emit "$tool" "$scen" "wall_s" "$wall" "s" | tee -a "$CSV_OUT"
    emit "$tool" "$scen" "rss_kib" "$rss" "KiB" | tee -a "$CSV_OUT"
}

run_find() {
    local tool=$1 bin=$2 archive=$3 scen=$4 pattern=$5 extra=${6:-}
    local idx
    idx="$WORKDIR/idx/${tool}-find-base.sqlite"
    if [[ ! -f "$idx" ]]; then
        "$bin" --no-mount --index-file "$idx" --index-minimum-file-count 0 \
            "$archive" >/dev/null
    fi
    local samples=() i out
    for i in $(seq 1 "$RUNS"); do
        out=$(mktemp "$WORKDIR/tr.XXXXXX")
        # shellcheck disable=SC2086
        time_rss "$out" "$bin" find $extra "$pattern" "$archive"
        samples+=("$(awk '{print $1}' "$out")")
    done
    local wall
    wall=$(printf '%s\n' "${samples[@]}" | median_f)
    emit "$tool" "$scen" "wall_s" "$wall" "s" | tee -a "$CSV_OUT"
}

echoerr "=== cold index many ($N_FILES files) ==="
run_cold_index "old" "$OLD_BIN" "$D/many.tar" "cold_index_many"
run_cold_index "new" "$NEW_BIN" "$D/many.tar" "cold_index_many"

echoerr "=== cold index + --hashes sha256 ($HASH_FILES files) ==="
run_cold_index "old" "$OLD_BIN" "$D/hash.tar" "cold_index_hashes" "--hashes sha256"
run_cold_index "new" "$NEW_BIN" "$D/hash.tar" "cold_index_hashes" "--hashes sha256"

echoerr "=== nested -c -r --no-mount ==="
run_cold_index "old" "$OLD_BIN" "$D/nested.tar" "cold_nested_r" "-r"
run_cold_index "new" "$NEW_BIN" "$D/nested.tar" "cold_nested_r" "-r"

# Warm indexes for find (reuse many.tar sidecars from cold_index_many by copying)
cp "$WORKDIR/idx/old-cold_index_many.sqlite" "$WORKDIR/idx/old-find-base.sqlite" 2>/dev/null || true
cp "$WORKDIR/idx/new-cold_index_many.sqlite" "$WORKDIR/idx/new-find-base.sqlite" 2>/dev/null || true
# find uses archive sidecar next to archive unless --index-file. CLI find opens
# the default sidecar beside the archive. Point both at copies next to many.tar.
cp "$WORKDIR/idx/old-cold_index_many.sqlite" "$D/many.tar.old.index.sqlite"
cp "$WORKDIR/idx/new-cold_index_many.sqlite" "$D/many.tar.new.index.sqlite"

run_find_sidecar() {
    local tool=$1 bin=$2 archive=$3 sidecar=$4 scen=$5 pattern=$6 extra=${7:-}
    # `find` is a subcommand; global --index-file before it is parsed as PATHS
    # on v0.1.27. Use the default sibling sidecar name instead.
    cp "$sidecar" "${archive}.index.sqlite"
    local samples=() i out
    for i in $(seq 1 "$RUNS"); do
        out=$(mktemp "$WORKDIR/tr.XXXXXX")
        # shellcheck disable=SC2086
        time_rss "$out" "$bin" find $extra "$pattern" "$archive" || true
        samples+=("$(awk '{print $1}' "$out")")
    done
    local wall
    wall=$(printf '%s\n' "${samples[@]}" | median_f)
    emit "$tool" "$scen" "wall_s" "$wall" "s" | tee -a "$CSV_OUT"
}

echoerr "=== CLI find glob (warm sidecar) ==="
run_find_sidecar "old" "$OLD_BIN" "$D/many.tar" "$D/many.tar.old.index.sqlite" \
    "find_glob" "*.bin"
run_find_sidecar "new" "$NEW_BIN" "$D/many.tar" "$D/many.tar.new.index.sqlite" \
    "find_glob" "*.bin"

echoerr "=== CLI find '*' (warm sidecar) ==="
run_find_sidecar "old" "$OLD_BIN" "$D/many.tar" "$D/many.tar.old.index.sqlite" \
    "find_star" "*"
run_find_sidecar "new" "$NEW_BIN" "$D/many.tar" "$D/many.tar.new.index.sqlite" \
    "find_star" "*"

if "$NEW_BIN" --help 2>&1 | grep -q offset-order; then
    echoerr "=== CLI find --offset-order (new only vs name-order new) ==="
    run_find_sidecar "new" "$NEW_BIN" "$D/many.tar" "$D/many.tar.new.index.sqlite" \
        "find_offset_order" "*" "--offset-order"
fi

extract_in_order() {
    local mp=$1 list=$2
    python3 - "$mp" "$list" <<'PY'
import os, sys
mp, listpath = sys.argv[1], sys.argv[2]
n = 0
with open(listpath) as fh:
    for line in fh:
        rel = line.split("\t", 1)[0].strip().lstrip("/")
        if not rel:
            continue
        path = os.path.join(mp, rel)
        with open(path, "rb") as f:
            while f.read(1 << 16):
                pass
        n += 1
print(n)
PY
}

if [[ "$SKIP_FUSE" != "1" ]]; then
    echoerr "=== control search/*.bin (FUSE) ==="
    for pair in "old:$OLD_BIN:$D/many.tar.old.index.sqlite" "new:$NEW_BIN:$D/many.tar.new.index.sqlite"; do
        IFS=':' read -r tool bin sidecar <<<"$pair"
        mount_bg "$bin" "$D/many.tar" "--control-interface" "$sidecar" || continue
        samples=()
        search_path="$_CUR_MP/.ratarmount-control/search/*.bin"
        for i in $(seq 1 "$RUNS"); do
            start=$(date +%s.%N)
            if ! cat -- "$search_path" >/dev/null 2>"$WORKDIR/cat.err"; then
                echoerr "control search cat failed for $tool: $(head -1 "$WORKDIR/cat.err")"
                samples+=("nan")
            else
                end=$(date +%s.%N)
                samples+=("$(python3 -c "print(f'{float(\"$end\")-float(\"$start\"):.6f}')")")
            fi
        done
        wall=$(printf '%s\n' "${samples[@]}" | median_f)
        rss=$(awk '/VmHWM/ {print $2}' "/proc/$_CUR_PID/status" 2>/dev/null || echo 0)
        emit "$tool" "control_search" "wall_s" "$wall" "s" | tee -a "$CSV_OUT"
        emit "$tool" "control_search" "rss_kib" "$rss" "KiB" | tee -a "$CSV_OUT"
        finish_mount
    done

    echoerr "=== V-5 name-order vs offset-order sequential cat ==="
    # Lists from NEW find (old may lack --offset-order).
    "$NEW_BIN" --index-file "$WORKDIR/idx/shuf.new.sqlite" --no-mount \
        --index-minimum-file-count 0 "$D/shuf.tar" >/dev/null
    cp "$WORKDIR/idx/shuf.new.sqlite" "$D/shuf.tar.index.sqlite"
    "$NEW_BIN" find "*" "$D/shuf.tar" >"$WORKDIR/list-name.tsv"
    if "$NEW_BIN" --help 2>&1 | grep -q offset-order; then
        "$NEW_BIN" find --offset-order "*" "$D/shuf.tar" >"$WORKDIR/list-offset.tsv"
    else
        cp "$WORKDIR/list-name.tsv" "$WORKDIR/list-offset.tsv"
    fi
    "$OLD_BIN" --index-file "$WORKDIR/idx/shuf.old.sqlite" --no-mount \
        --index-minimum-file-count 0 "$D/shuf.tar" >/dev/null

    for pair in "old:$OLD_BIN:$WORKDIR/idx/shuf.old.sqlite" "new:$NEW_BIN:$WORKDIR/idx/shuf.new.sqlite"; do
        IFS=':' read -r tool bin sidecar <<<"$pair"
        mount_bg "$bin" "$D/shuf.tar" "" "$sidecar" || continue
        for order in name offset; do
            samples=()
            for i in $(seq 1 "$RUNS"); do
                start=$(date +%s.%N)
                extract_in_order "$_CUR_MP" "$WORKDIR/list-${order}.tsv" >/dev/null
                end=$(date +%s.%N)
                samples+=("$(python3 -c "print(f'{float(\"$end\")-float(\"$start\"):.6f}')")")
            done
            wall=$(printf '%s\n' "${samples[@]}" | median_f)
            emit "$tool" "extract_${order}_order" "wall_s" "$wall" "s" | tee -a "$CSV_OUT"
        done
        finish_mount
    done

    echoerr "=== overlay create + getattr storm ==="
    for pair in "old:$OLD_BIN" "new:$NEW_BIN"; do
        IFS=':' read -r tool bin <<<"$pair"
        ov="$WORKDIR/ov-$tool"
        rm -rf "$ov"
        mkdir -p "$ov"
        mount_bg "$bin" "$D/tiny.tar" "-w $ov" || continue
        python3 - "$_CUR_MP" "$OVERLAY_FILES" <<'PY'
import os, sys
mp, n = sys.argv[1], int(sys.argv[2])
os.makedirs(os.path.join(mp, "ov"), exist_ok=True)
for i in range(n):
    p = os.path.join(mp, "ov", f"w{i:04d}.txt")
    with open(p, "w") as fh:
        fh.write(f"overlay-{i}\n")
PY
        samples=()
        for i in $(seq 1 "$RUNS"); do
            start=$(date +%s.%N)
            python3 - "$_CUR_MP" <<'PY'
import os, sys
mp = sys.argv[1]
root = os.path.join(mp, "ov")
for name in os.listdir(root):
    os.stat(os.path.join(root, name))
PY
            end=$(date +%s.%N)
            samples+=("$(python3 -c "print(f'{float(\"$end\")-float(\"$start\"):.6f}')")")
        done
        wall=$(printf '%s\n' "${samples[@]}" | median_f)
        rss=$(awk '/VmHWM/ {print $2}' "/proc/$_CUR_PID/status" 2>/dev/null || echo 0)
        emit "$tool" "overlay_getattr" "wall_s" "$wall" "s" | tee -a "$CSV_OUT"
        emit "$tool" "overlay_getattr" "rss_kib" "$rss" "KiB" | tee -a "$CSV_OUT"
        finish_mount
    done
fi

if [[ "$VECTOR_REMOTE" == "1" ]]; then
    echoerr "=== V-3 remote sidecar GET count (local HTTP, VECTOR_REMOTE=1) ==="
    RDIR="$WORKDIR/remote-http"
    mkdir -p "$RDIR/www"
    make_tiny_tar "$RDIR/www/a.tar"
    "$NEW_BIN" --no-mount --index-file "$RDIR/www/a.tar.index.sqlite" \
        --index-minimum-file-count 0 "$RDIR/www/a.tar" >/dev/null
    PORTFILE="$RDIR/port"
    COUNTFILE="$RDIR/sidecar-gets"
    : >"$COUNTFILE"
    python3 - "$RDIR/www" "$PORTFILE" "$COUNTFILE" <<'PY' &
import os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

root, portfile, countfile = sys.argv[1], sys.argv[2], sys.argv[3]

class H(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self._send(True)

    def do_GET(self):
        self._send(False)

    def _send(self, head_only):
        path = self.path.split("?", 1)[0]
        is_index = path.endswith(".index.sqlite") and ".index.sqlite." not in path
        if ".index.sqlite." in path:
            self.send_error(404)
            return
        rel = path.lstrip("/")
        fp = os.path.join(root, rel)
        if not os.path.isfile(fp):
            self.send_error(404)
            return
        data = open(fp, "rb").read()
        if is_index and not head_only:
            with open(countfile, "a") as fh:
                fh.write("1\n")
        rng = self.headers.get("Range")
        start, end = 0, len(data) - 1
        status = 200
        if rng and rng.startswith("bytes="):
            spec = rng.split("=", 1)[1]
            a, _, b = spec.partition("-")
            try:
                start = int(a) if a else 0
                end = int(b) if b else len(data) - 1
            except ValueError:
                start, end = 0, len(data) - 1
            end = min(end, len(data) - 1)
            if start <= end:
                status = 206
        slice_ = data[start : end + 1]
        self.send_response(status)
        self.send_header("Content-Length", str(len(slice_)))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Connection", "close")
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
        self.end_headers()
        if not head_only:
            self.wfile.write(slice_)

    def log_message(self, fmt, *args):
        return

httpd = HTTPServer(("127.0.0.1", 0), H)
with open(portfile, "w") as fh:
    fh.write(str(httpd.server_address[1]))
httpd.serve_forever()
PY
    HTTP_PID=$!
    for _ in $(seq 1 50); do
        [[ -s "$PORTFILE" ]] && break
        sleep 0.05
    done
    if [[ ! -s "$PORTFILE" ]]; then
        echoerr "skip: VECTOR_REMOTE HTTP fixture failed to bind"
        kill "$HTTP_PID" 2>/dev/null || true
    else
        RPORT=$(cat "$PORTFILE")
        sidecar_get_count() { wc -l <"$COUNTFILE" | tr -d ' '; }
        for pair in "old:$OLD_BIN" "new:$NEW_BIN"; do
            IFS=':' read -r tool bin <<<"$pair"
            xdg="$RDIR/xdg-$tool"
            folders="$RDIR/idx-$tool"
            mkdir -p "$xdg" "$folders"
            url="http://127.0.0.1:${RPORT}/a.tar"
            before=$(sidecar_get_count)
            if ! env XDG_CACHE_HOME="$xdg" "$bin" --no-mount \
                --index-folders "$folders" --index-minimum-file-count 0 \
                "$url" >/dev/null 2>"$RDIR/$tool.first.err"; then
                echoerr "VECTOR_REMOTE first mount failed for $tool: $(head -1 "$RDIR/$tool.first.err")"
                emit "$tool" "remote_sidecar_second_get" "count" "nan" "n" | tee -a "$CSV_OUT"
                continue
            fi
            # Drop local well-known copy so the second open cannot short-circuit.
            find "$folders" "$xdg/ratarmount" -name '*.index.sqlite' -delete 2>/dev/null || true
            after_first=$(sidecar_get_count)
            if ! env XDG_CACHE_HOME="$xdg" "$bin" --no-mount \
                --index-folders "$folders" --index-minimum-file-count 0 \
                "$url" >/dev/null 2>"$RDIR/$tool.second.err"; then
                echoerr "VECTOR_REMOTE second mount failed for $tool: $(head -1 "$RDIR/$tool.second.err")"
                emit "$tool" "remote_sidecar_second_get" "count" "nan" "n" | tee -a "$CSV_OUT"
                continue
            fi
            after_second=$(sidecar_get_count)
            delta=$((after_second - after_first))
            echoerr "$tool sidecar GET: first=$((after_first - before)) second=$delta"
            emit "$tool" "remote_sidecar_second_get" "count" "$delta" "n" | tee -a "$CSV_OUT"
        done
        kill "$HTTP_PID" 2>/dev/null || true
        wait "$HTTP_PID" 2>/dev/null || true
    fi
fi

python3 - "$CSV_OUT" "$MD_OUT" "$OLD_VER" "$NEW_VER" "$N_FILES" <<'PY'
import csv, math, sys
from collections import defaultdict
from pathlib import Path

csv_path, md_path, old_ver, new_ver, n_files = sys.argv[1:6]
rows = list(csv.DictReader(open(csv_path), delimiter=";"))
data = defaultdict(dict)
units = {}
for r in rows:
    try:
        v = float(r["value"])
    except ValueError:
        continue
    data[(r["scenario"], r["metric"])][r["tool"]] = v
    units[r["metric"]] = r["unit"]

def fmt(v, metric):
    if v is None:
        return "—"
    if metric.endswith("_s"):
        if v < 0.001:
            return f"{v*1000:.3f} ms"
        if v < 1:
            return f"{v*1000:.1f} ms"
        return f"{v:.3f} s"
    if metric == "rss_kib":
        if v >= 1024:
            return f"{v/1024:.1f} MiB"
        return f"{int(v)} KiB"
    return f"{v:.4g}"

def rel(old, new, metric):
    if old is None or new is None or old <= 0 or new <= 0:
        return "—"
    # lower is better for time and RSS
    if new <= old:
        return f"new **{old/new:.2f}×** better"
    return f"old **{new/old:.2f}×** better"

lines = []
lines.append("# Vector-wave benches — ratarmount-rs old vs new")
lines.append("")
lines.append(f"OLD **{old_ver}** vs NEW **{new_ver}**. Catalog N={n_files}.")
lines.append("")
lines.append("These paths are what the FUSE `cat`/`find` BIG suite missed:")
lines.append("")
lines.append("- `cold_index_many` — P2 SQLite bulk staging (`-c --no-mount`)")
lines.append("- `cold_index_hashes` — P2 fingerprint windows (`--hashes sha256`)")
lines.append("- `cold_nested_r` — nested `-c -r --no-mount`")
lines.append("- `find_glob` / `find_star` — V-1 CLI locate (streaming SQL)")
lines.append("- `control_search` — V-1 live `search/<glob>`")
lines.append("- `extract_*_order` — V-5 name-order vs offset-order sequential cat")
lines.append("- `overlay_getattr` — P2 overlay inode cookies after create")
lines.append("- `remote_sidecar_second_get` — V-3 XDG LRU (VECTOR_REMOTE=1; 0 extra sidecar GETs)")
lines.append("")
lines.append("| Scenario | Metric | Old | New | Relative |")
lines.append("|----------|--------|-----|-----|----------|")
keys = sorted(data)
for scen, metric in keys:
    o = data[(scen, metric)].get("old")
    n = data[(scen, metric)].get("new")
    lines.append(f"| `{scen}` | {metric} | {fmt(o, metric)} | {fmt(n, metric)} | {rel(o, n, metric)} |")
lines.append("")
lines.append("Single-run medians of `RUNS` samples. Treat <10% as noise except RSS on overlay/index.")
lines.append("")
Path(md_path).write_text("\n".join(lines) + "\n")
print("Wrote", md_path)
PY

echoerr "CSV: $CSV_OUT"
echoerr "MD:  $MD_OUT"
cat "$MD_OUT"
