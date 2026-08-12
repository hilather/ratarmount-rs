# Benchmarks

## Nested durable indexes (with vs without)

Measures eager recursive nested open (`-r --no-mount`) when the outer SQLite
index **stores/loads** nested file tables (`nestedindexes`) versus when nested
indexes are absent (DROP side table or `:memory:` outer).

```bash
# Default: 2000-member store ZIP in TAR (+ 7z leg if 7z/7za present), 3 runs median
./benchmarks/compare-nested-durable.sh
# → benchmarks/nested-durable-results/{results-*.csv,results-*.md}

N_FILES=5000 RUNS=5 INCLUDE_7Z=0 ./benchmarks/compare-nested-durable.sh
```

| Mode | Meaning |
|------|---------|
| `cold_first` | `-c -r`: cold outer + cold nested; **stores** `nestedindexes` |
| `warm_with_nested` | remount `-r` with nestedindexes present (**import hit**) |
| `warm_without_nested` | remount after `DROP nestedindexes` (outer warm, nested rebuild) |
| `cold_no_durable` | `-c -r --index-file :memory:` (no durable nested home) |

Phase 11 smoke also records a smaller with/without nested sample:
`./test-harness/run-phase11-bench.sh`.

## Fair disk + FUSE kernel tuning

**Use this** for media baseline (O_DIRECT) vs FUSE mount knobs (`noatime`,
`--readahead`, per-connection `max_background`). Operator guide:
[`docs/fuse-kernel-tuning.md`](../docs/fuse-kernel-tuning.md).

```bash
# Full matrix (disk O_DIRECT + page-cache contrast + FUSE configs)
./benchmarks/compare-fuse-kernel-tuning.sh
# → benchmarks/fuse-kernel-results/{results.csv,results.md}

# Disk only / FUSE only / larger probe / more parallel readers
SKIP_FUSE=1 SIZE_MIB=512 ./benchmarks/compare-fuse-kernel-tuning.sh
SKIP_DISK=1 PARALLEL=8 SIZE_MIB=64 ./benchmarks/compare-fuse-kernel-tuning.sh

# True cold disk (optional root drop_caches)
DROP_CACHES=1 SIZE_MIB=512 ./benchmarks/compare-fuse-kernel-tuning.sh
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `SIZE_MIB` | `64` | Disk probe + gzip payload size |
| `PARALLEL` | `4` | Concurrent 1 MiB window readers (aggregate thruput) |
| `RUNS` | `2` | Samples per metric (median) |
| `SKIP_DISK` / `SKIP_FUSE` | `0` | Drop a section |
| `DROP_CACHES` | `0` | `1` = try `drop_caches` before O_DIRECT read (needs root) |
| `OUT_DIR` | `benchmarks/fuse-kernel-results` | Gitignored CSV/MD |
| `DATA_DIR` | `$OUT_DIR/data` | Probe + corpus (prefer real block FS, not tmpfs) |

**Fairness:** quote **O_DIRECT** for disk; do not call page-cache multi‑GB/s “disk speed.”
FUSE numbers are **uncompressed** member MiB/s.

## Fair rapidgzip A/B (zlib-rs vs ISA-L)

**Use this for inflate-backend comparisons.** ISA-L vs zlib-rs is a **compile-time**
choice (`gzip-rapidgzip` vs `gzip-rapidgzip-isal`). Timing the same binary twice is
not a fair A/B — this harness builds **two** release binaries and labels them
`rust-rgz-zlib` / `rust-rgz-isal` (plus optional `rust-g3` and `python`).

```bash
# Full A/B (default CORPUS_MIB=256 — can take a while)
# Needs: rustc ≥ 1.87, libisal (or ISAL_INSTALL_PREFIX), optional FUSE + Python
./benchmarks/compare-gzip-isal-ab.sh
# → benchmarks/gzip-backend-results/{results-isal-ab.csv,results-isal-ab.md}
#    + bin/ratarmount-rgz-{zlib,isal}

# Decode-only (cold index + warm open; no FUSE) and skip Python/G3 baselines:
SKIP_FUSE=1 SKIP_PYTHON=1 SKIP_G3=1 CORPUS_MIB=64 RUNS=1 ./benchmarks/compare-gzip-isal-ab.sh

# Prebuilt binaries (no cargo) — both paths must already exist and be executable:
SKIP_BUILD=1 \
  RUST_BIN_ZLIB=benchmarks/gzip-backend-results/bin/ratarmount-rgz-zlib \
  RUST_BIN_ISAL=benchmarks/gzip-backend-results/bin/ratarmount-rgz-isal \
  SKIP_FUSE=1 SKIP_PYTHON=1 \
  ./benchmarks/compare-gzip-isal-ab.sh
```

`SKIP_BUILD=1` **requires** both prebuilt binaries (script exits with install hints if missing).
Python baseline is optional (`SKIP_PYTHON=1`); the script sets `RATARMOUNT_ALLOW_NO_PY=1` by default
so a sibling Python checkout is not required for Rust-only A/B.

| Variable | Default | Meaning |
|----------|---------|---------|
| `CORPUS_MIB` | `256` | Uncompressed large-blob size for generated corpora |
| `THREADS` | `8` | `-P gzip:N` |
| `RUNS` | `3` | Cold-index / warm-open samples (median) |
| `SKIP_BUILD` | `0` | `1` = require `RUST_BIN_ZLIB` + `RUST_BIN_ISAL` |
| `RUST_BIN_ZLIB` | `…/bin/ratarmount-rgz-zlib` | Binary built with `gzip-rapidgzip` |
| `RUST_BIN_ISAL` | `…/bin/ratarmount-rgz-isal` | Binary built with `gzip-rapidgzip-isal` |
| `ISAL_INSTALL_PREFIX` | auto sibling `../rapidgzip-rust/.isal-prefix` if present | Prefix with `lib/libisal.so` + headers |
| `SKIP_FUSE` | `0` | `1` = decode-only (no mount / seq cat) |
| `SKIP_PYTHON` / `SKIP_G3` | `0` | Drop baselines |
| `OUT_DIR` | `benchmarks/gzip-backend-results` | Gitignored output dir |

### What is measured

| Section | How | FUSE? |
|---------|-----|-------|
| **Cold index** | `ratarmount -c --no-mount` (full inflate while indexing) | No |
| **Warm open** | Reuse SQLite index with `--no-mount` (open cost) | No |
| **FUSE cold/warm** | Mount + sequential `cat` bandwidth after warm | Yes |

`results-isal-ab.md` includes a **zlib vs isal delta** table (time ratio zlib/isal and % wall change; throughput ratio isal/zlib).

### ISA-L install

```bash
# Distro package, e.g.:
#   sudo apt install libisal-dev
# Or a custom prefix:
export ISAL_INSTALL_PREFIX=/path/to/prefix   # lib/libisal.so + include/
export LD_LIBRARY_PATH="$ISAL_INSTALL_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
./benchmarks/compare-gzip-isal-ab.sh
```

Results under `benchmarks/gzip-backend-results/` are **gitignored** — re-run the script to regenerate; do not commit large blobs.

## Gzip backends (G3 vs rapidgzip POC vs Python)

Multi-tool compare with a **single** Rust build (not a fair zlib↔ISA-L A/B — use
[`compare-gzip-isal-ab.sh`](compare-gzip-isal-ab.sh) for that):

```bash
# Default harness builds with gzip-rapidgzip-isal (needs libisal or ISAL_INSTALL_PREFIX).
./benchmarks/compare-gzip-backends.sh
# → benchmarks/gzip-backend-results/{results.csv,results.md}
# knobs: CORPUS_MIB=64 THREADS=8 RUNS=3 SKIP_BUILD=1 RUST_FEATURES=gzip-rapidgzip-isal
# zlib-rs only: RUST_FEATURES=gzip-rapidgzip
```

Requires FUSE, Python ratarmount (`RATARMOUNT_PY_ROOT`), and a binary with `gzip-rapidgzip` (optionally `gzip-rapidgzip-isal`).

## Head-to-head (Python vs Rust)

Latest committed numbers: [`python-vs-rust-results.md`](python-vs-rust-results.md) (**2026-07-28**, ratarmount-rs **v0.1.3** area).

```bash
export RATARMOUNT_PY_ROOT=../ratarmount   # sibling checkout with Python package
cargo build --release
# Optional: python -m venv benchmarks/.venv-py && pip install -e "$RATARMOUNT_PY_ROOT"
./benchmarks/compare-python-vs-rust.sh
# → benchmarks/python-vs-rust-results.{csv,md}

# Minimal fixture set (empty-1k + small-100{.tar,.tar.gz}) for gate CI:
MICRO=1 ./benchmarks/compare-python-vs-rust.sh
# → benchmarks/python-vs-rust-results-micro.{csv,md}
```

Requires FUSE, a Python ratarmount install (or venv under `benchmarks/.venv-py`), and the usual system deps. The compare script sources `test-harness/env.sh` for portable unmount helpers.

## CI gates (`rust-gates.json`)

Thresholds live in [`baselines/rust-gates.json`](baselines/rust-gates.json).  
[`check-rust-gates.sh`](check-rust-gates.sh) enforces them:

| Mode | What runs | Fail behavior |
|------|-----------|---------------|
| **Default (CI)** | Pure-Rust **cold index** of a generated `empty-1k.tar` via `ratarmount -c --no-mount` (no `/dev/fuse`, no Python) | **Hard fail** if median wall time exceeds `cold_index_empty_1k_tar_sec.max_seconds` |
| `RUN_FULL_BENCH=1` | Also evaluates warm-mount, RSS, find, and sequential-read **ratio** gates vs Python from a results CSV | Fail when ratios miss thresholds or CSV cannot be obtained |
| `+ ALLOW_RATIO_SKIP=1` | Same path, but soft-skips ratio evaluation when CSV/Python/FUSE are unavailable | Cold index still hard; missing ratios do not fail the job |
| `+ GENERATE_RESULTS=1` | Force `MICRO=1` `compare-python-vs-rust.sh` even if a CSV already exists | Needs `RATARMOUNT_PY_ROOT` + importable Python ratarmount + `/dev/fuse` |

### Env knobs

| Variable | Default | Meaning |
|----------|---------|---------|
| `RUST_BIN` | `target/release/ratarmount` | Binary under test |
| `GATES_JSON` | `benchmarks/baselines/rust-gates.json` | Gate thresholds |
| `RESULTS_CSV` | post-perf-opt CSV if present, else `python-vs-rust-results.csv` | Input for ratio gates |
| `RUN_FULL_BENCH` | `0` | `1` = evaluate vs-Python ratio gates |
| `ALLOW_RATIO_SKIP` | `0` | `1` = skip (exit 0) when ratios cannot run |
| `GENERATE_RESULTS` | `0` | `1` = force micro compare regenerate |
| `RATARMOUNT_PY_ROOT` | `../ratarmount` | Python tree for generation |
| `COLD_INDEX_RUNS` | `3` | Timed cold-index samples (median) |
| `SKIP_BUILD` | `0` | `1` = do not `cargo build` if binary missing |

When `RUN_FULL_BENCH=1` and `RESULTS_CSV` is missing (or `GENERATE_RESULTS=1`), the script tries:

```bash
MICRO=1 RATARMOUNT_PY_ROOT=... CSV_OUT=benchmarks/python-vs-rust-results-micro.csv \
  ./benchmarks/compare-python-vs-rust.sh
```

If generation fails and `ALLOW_RATIO_SKIP=1`, ratio gates are skipped with a clear `SKIP` line.

```bash
# Local / CI microbench (few seconds after a release build; no FUSE)
./benchmarks/check-rust-gates.sh

# Ratio gates against the newest committed CSV (hard-fail if CSV missing)
RUN_FULL_BENCH=1 ./benchmarks/check-rust-gates.sh

# CI optional full job: never red when Python fixtures / CSV absent
RUN_FULL_BENCH=1 ALLOW_RATIO_SKIP=1 ./benchmarks/check-rust-gates.sh

# Force live micro regenerate then gate (needs Python + FUSE)
RUN_FULL_BENCH=1 GENERATE_RESULTS=1 RATARMOUNT_PY_ROOT=../ratarmount \
  ./benchmarks/check-rust-gates.sh
```

### GitHub Actions

| Job | Env | Role |
|-----|-----|------|
| `benchmark-gates` | default | Cold-index **hard** gate; PR-safe, FUSE-free |
| `benchmark-gates-full` | `RUN_FULL_BENCH=1 ALLOW_RATIO_SKIP=1` | Exercises ratio path when a results CSV is present (committed or generated); soft-skips if not |
