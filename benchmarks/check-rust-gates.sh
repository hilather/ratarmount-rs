#!/usr/bin/env bash
# Enforce benchmarks/baselines/rust-gates.json against a pure-Rust microbench
# and (optionally) head-to-head CSV results.
#
# Default (CI): cold-index empty-1k TAR via `ratarmount -c --no-mount`.
#   No FUSE mount, no Python, no /dev/fuse required at runtime.
#   Hard-fails if cold index exceeds cold_index_empty_1k_tar_sec.max_seconds.
#
# RUN_FULL_BENCH=1:
#   Also evaluate ratio gates (warm mount, RSS, find, sequential read) from a
#   results CSV (default: benchmarks/python-vs-rust-results.csv). Soft-skips
#   individual ratio checks when the CSV or required rows are missing.
#
# Env:
#   RUST_BIN           path to ratarmount binary (default: target/release/ratarmount)
#   GATES_JSON         path to gates file (default: benchmarks/baselines/rust-gates.json)
#   RESULTS_CSV        CSV for ratio gates (default: benchmarks/python-vs-rust-results.csv)
#   RUN_FULL_BENCH     set to 1 to evaluate vs-Python ratio gates from CSV
#   SKIP_BUILD         set to 1 to skip cargo build if binary missing (then fail)
#   COLD_INDEX_RUNS    number of timed cold-index samples (default: 3; use median)
#
# Exit codes:
#   0  all hard gates pass (ratio gates skipped or pass)
#   1  hard gate failure or missing required tools/binary
#   2  usage / gates file unreadable
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATES_JSON="${GATES_JSON:-$ROOT/benchmarks/baselines/rust-gates.json}"
RUST_BIN="${RUST_BIN:-$ROOT/target/release/ratarmount}"
# Prefer newest committed compare CSV when RESULTS_CSV is unset.
if [[ -z "${RESULTS_CSV:-}" ]]; then
    if [[ -f "$ROOT/benchmarks/python-vs-rust-results-post-perf-opt.csv" ]]; then
        RESULTS_CSV="$ROOT/benchmarks/python-vs-rust-results-post-perf-opt.csv"
    else
        RESULTS_CSV="$ROOT/benchmarks/python-vs-rust-results.csv"
    fi
fi
COLD_INDEX_RUNS="${COLD_INDEX_RUNS:-3}"
RUN_FULL_BENCH="${RUN_FULL_BENCH:-0}"

echoerr() { echo "$@" >&2; }

if [[ ! -f "$GATES_JSON" ]]; then
    echoerr "ERROR: gates file not found: $GATES_JSON"
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echoerr "ERROR: python3 required to parse gates JSON"
    exit 1
fi

# ---- ensure binary ----
if [[ ! -x "$RUST_BIN" ]]; then
    if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
        echoerr "ERROR: binary missing at $RUST_BIN and SKIP_BUILD=1"
        exit 1
    fi
    echoerr "Building release binary (cargo build --release -p ratarmount)..."
    (cd "$ROOT" && cargo build --release -p ratarmount)
fi
if [[ ! -x "$RUST_BIN" ]]; then
    echoerr "ERROR: binary not executable: $RUST_BIN"
    exit 1
fi

WORKDIR="${TMPDIR:-/tmp}/ratarmount-rust-gates-$$"
mkdir -p "$WORKDIR"
cleanup() {
    rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

# ---- fixture: empty-1k.tar (1000 empty files in 10 dirs; matches compare script) ----
make_empty_1k() {
    local empty="$WORKDIR/empty-1k"
    local out="$WORKDIR/empty-1k.tar"
    mkdir -p "$empty"
    local i j
    for i in $(seq 0 9); do
        mkdir -p "$empty/f$i"
        for j in $(seq 0 99); do
            : >"$empty/f$i/file-$(printf '%04d' "$j")"
        done
    done
    tar -C "$empty" -cf "$out" .
    echo "$out"
}

ARCHIVE="$(make_empty_1k)"
echoerr "==> Cold-index microbench on empty-1k.tar ($COLD_INDEX_RUNS runs, median)"
echoerr "    binary: $RUST_BIN"
echoerr "    gates:  $GATES_JSON"

# Collect wall times for cold index create (--no-mount, no FUSE)
SAMPLES=()
for run in $(seq 1 "$COLD_INDEX_RUNS"); do
    idx="$WORKDIR/cold-$run.index.sqlite"
    rm -f "$idx"
    start=$(date +%s.%N)
    if ! "$RUST_BIN" -c --no-mount \
        --index-file "$idx" \
        --index-minimum-file-count 0 \
        "$ARCHIVE" >/dev/null 2>"$WORKDIR/cold-$run.log"; then
        echoerr "ERROR: cold index failed (run $run)"
        cat "$WORKDIR/cold-$run.log" >&2 || true
        exit 1
    fi
    end=$(date +%s.%N)
    sample=$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.6f", e-s}')
    SAMPLES+=("$sample")
    echoerr "    run $run: ${sample}s"
    # sanity: index file should exist and be non-empty
    if [[ ! -s "$idx" ]]; then
        echoerr "ERROR: index not created at $idx"
        exit 1
    fi
done

# Evaluate cold_index + optional CSV ratio gates in one Python pass
export GATES_JSON RESULTS_CSV RUN_FULL_BENCH
# shellcheck disable=SC2124
export SAMPLES_CSV="${SAMPLES[*]}"
python3 - <<'PY'
import json, math, os, sys, csv
from collections import defaultdict
from pathlib import Path

gates_path = Path(os.environ["GATES_JSON"])
gates = json.loads(gates_path.read_text())
samples = [float(x) for x in os.environ["SAMPLES_CSV"].split()]
samples_sorted = sorted(samples)
n = len(samples_sorted)
if n % 2 == 1:
    median = samples_sorted[n // 2]
else:
    median = 0.5 * (samples_sorted[n // 2 - 1] + samples_sorted[n // 2])

failures = []
skips = []
passes = []

# --- hard gate: cold_index_empty_1k_tar_sec ---
ci = gates.get("cold_index_empty_1k_tar_sec") or {}
max_sec = float(ci.get("max_seconds", 0.5))
print(f"cold_index_empty_1k_tar_sec: median={median:.4f}s  max={max_sec}s  samples={samples}")
if median > max_sec:
    failures.append(
        f"cold_index_empty_1k_tar_sec: median {median:.4f}s > max {max_sec}s"
    )
else:
    passes.append(f"cold_index_empty_1k_tar_sec: {median:.4f}s ≤ {max_sec}s")

def geomean(vals):
    vals = [v for v in vals if v is not None and v > 0]
    if not vals:
        return None
    return math.exp(sum(math.log(v) for v in vals) / len(vals))

def load_csv(path: Path):
    if not path.is_file():
        return None
    rows = list(csv.DictReader(path.open(), delimiter=";"))
    # (archive, scenario, metric) -> {tool: value}
    data = defaultdict(dict)
    for r in rows:
        if r.get("metric") == "mount_fail":
            continue
        try:
            v = float(r["value"])
        except (KeyError, ValueError, TypeError):
            continue
        data[(r["archive"], r["scenario"], r["metric"])][r["tool"]] = v
    return data

def ratio_series(data, metric, scenario, higher_better=False, archive_pred=None):
    """Per-archive Rust/Python ratio (or inverse for lower-is-better time metrics).

    Gate semantics in rust-gates.json:
      max_ratio_vs_python  →  rust/python  must be ≤ max  (time/RSS; lower better)
      min_ratio_vs_python  →  rust/python  must be ≥ min  (bandwidth; higher better)
    So we always report rust/python (bandwidth) or rust/python (times) consistently:
      - for max_ratio gates (time/RSS): ratio = rust/python (want small)
      - for min_ratio gates (bandwidth): ratio = rust/python (want large)
    """
    archives = sorted({a for (a, s, m) in data if s == scenario and m == metric})
    ratios = []
    for arch in archives:
        if archive_pred is not None and not archive_pred(arch):
            continue
        cell = data.get((arch, scenario, metric), {})
        py = cell.get("python")
        rs = cell.get("rust")
        if py is None or rs is None or py <= 0 or rs <= 0:
            continue
        ratios.append(rs / py)
    return ratios

run_full = os.environ.get("RUN_FULL_BENCH", "0") == "1"
if run_full:
    csv_path = Path(os.environ.get("RESULTS_CSV", ""))
    data = load_csv(csv_path)
    if data is None:
        skips.append(
            f"ratio gates: RESULTS_CSV missing ({csv_path}); soft-skip "
            "(generate via benchmarks/compare-python-vs-rust.sh)"
        )
    else:
        # mount_time_warm_vs_python: geo-mean(rust/python warm mount_s) ≤ max
        g = gates.get("mount_time_warm_vs_python") or {}
        max_r = g.get("max_ratio_vs_python")
        if max_r is not None:
            ratios = ratio_series(data, "mount_s", "warm")
            gm = geomean(ratios)
            if gm is None:
                skips.append("mount_time_warm_vs_python: no paired warm mount_s rows")
            else:
                print(f"mount_time_warm_vs_python: geo-mean rust/python={gm:.3f}  max={max_r}")
                if gm > float(max_r):
                    failures.append(
                        f"mount_time_warm_vs_python: {gm:.3f} > max {max_r}"
                    )
                else:
                    passes.append(f"mount_time_warm_vs_python: {gm:.3f} ≤ {max_r}")

        # peak_rss_vs_python: use warm (or cold) RSS geo-mean
        g = gates.get("peak_rss_vs_python") or {}
        max_r = g.get("max_ratio_vs_python")
        if max_r is not None:
            ratios = ratio_series(data, "mount_rss_kib", "warm")
            if not ratios:
                ratios = ratio_series(data, "mount_rss_kib", "cold")
            gm = geomean(ratios)
            if gm is None:
                skips.append("peak_rss_vs_python: no paired RSS rows")
            else:
                print(f"peak_rss_vs_python: geo-mean rust/python={gm:.3f}  max={max_r}")
                if gm > float(max_r):
                    failures.append(f"peak_rss_vs_python: {gm:.3f} > max {max_r}")
                else:
                    passes.append(f"peak_rss_vs_python: {gm:.3f} ≤ {max_r}")

        # find_mounted_vs_python: cold+warm find_s geo-mean rust/python
        g = gates.get("find_mounted_vs_python") or {}
        max_r = g.get("max_ratio_vs_python")
        if max_r is not None:
            ratios = ratio_series(data, "find_s", "cold") + ratio_series(
                data, "find_s", "warm"
            )
            gm = geomean(ratios)
            if gm is None:
                skips.append("find_mounted_vs_python: no paired find_s rows")
            else:
                print(f"find_mounted_vs_python: geo-mean rust/python={gm:.3f}  max={max_r}")
                if gm > float(max_r):
                    failures.append(
                        f"find_mounted_vs_python: {gm:.3f} > max {max_r}"
                    )
                else:
                    passes.append(f"find_mounted_vs_python: {gm:.3f} ≤ {max_r}")

        # sequential_read_uncompressed_tar_vs_python: bandwidth on plain .tar
        g = gates.get("sequential_read_uncompressed_tar_vs_python") or {}
        min_r = g.get("min_ratio_vs_python")
        if min_r is not None:
            def is_plain_tar(a):
                return a.endswith(".tar") and not any(
                    a.endswith(sfx)
                    for sfx in (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst")
                )

            ratios = ratio_series(
                data, "bandwidth_mibs", "cold", archive_pred=is_plain_tar
            ) + ratio_series(
                data, "bandwidth_mibs", "warm", archive_pred=is_plain_tar
            )
            gm = geomean(ratios)
            if gm is None:
                skips.append(
                    "sequential_read_uncompressed_tar_vs_python: no plain-TAR bandwidth rows"
                )
            else:
                print(
                    f"sequential_read_uncompressed_tar_vs_python: "
                    f"geo-mean rust/python={gm:.3f}  min={min_r}"
                )
                if gm < float(min_r):
                    failures.append(
                        f"sequential_read_uncompressed_tar_vs_python: {gm:.3f} < min {min_r}"
                    )
                else:
                    passes.append(
                        f"sequential_read_uncompressed_tar_vs_python: {gm:.3f} ≥ {min_r}"
                    )

        # sequential_read_tar_gz_MBps: bandwidth on .tar.gz
        g = gates.get("sequential_read_tar_gz_MBps") or {}
        min_r = g.get("min_ratio_vs_python")
        if min_r is not None:
            def is_targz(a):
                return a.endswith(".tar.gz") or a.endswith(".tgz")

            ratios = ratio_series(
                data, "bandwidth_mibs", "cold", archive_pred=is_targz
            ) + ratio_series(
                data, "bandwidth_mibs", "warm", archive_pred=is_targz
            )
            gm = geomean(ratios)
            if gm is None:
                skips.append(
                    "sequential_read_tar_gz_MBps: no .tar.gz bandwidth rows"
                )
            else:
                print(
                    f"sequential_read_tar_gz_MBps: geo-mean rust/python={gm:.3f}  min={min_r}"
                )
                if gm < float(min_r):
                    failures.append(
                        f"sequential_read_tar_gz_MBps: {gm:.3f} < min {min_r}"
                    )
                else:
                    passes.append(
                        f"sequential_read_tar_gz_MBps: {gm:.3f} ≥ {min_r}"
                    )
else:
    skips.append(
        "ratio gates: skipped (set RUN_FULL_BENCH=1 to evaluate RESULTS_CSV)"
    )

print("")
print("=== gate summary ===")
for p in passes:
    print(f"  PASS  {p}")
for s in skips:
    print(f"  SKIP  {s}")
for f in failures:
    print(f"  FAIL  {f}")

if failures:
    print(f"\n{len(failures)} hard gate failure(s)", file=sys.stderr)
    sys.exit(1)
print(f"\nOK: {len(passes)} passed, {len(skips)} skipped, 0 failed")
sys.exit(0)
PY
