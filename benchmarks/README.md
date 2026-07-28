# Benchmarks

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
