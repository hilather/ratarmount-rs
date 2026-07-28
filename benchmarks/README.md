# Benchmarks

## Head-to-head (Python vs Rust)

```bash
export RATARMOUNT_PY_ROOT=../ratarmount   # sibling checkout with Python package
cargo build --release
./benchmarks/compare-python-vs-rust.sh
# → benchmarks/python-vs-rust-results.{csv,md}
```

Requires FUSE, a Python ratarmount install (or venv under `benchmarks/.venv-py`), and the usual system deps.

## CI gates (`rust-gates.json`)

Thresholds live in [`baselines/rust-gates.json`](baselines/rust-gates.json).  
[`check-rust-gates.sh`](check-rust-gates.sh) enforces them:

| Mode | What runs | Fail behavior |
|------|-----------|---------------|
| **Default (CI)** | Pure-Rust **cold index** of a generated `empty-1k.tar` via `ratarmount -c --no-mount` (no `/dev/fuse`, no Python) | **Hard fail** if median wall time exceeds `cold_index_empty_1k_tar_sec.max_seconds` |
| `RUN_FULL_BENCH=1` | Also parses a results CSV (default: `python-vs-rust-results-post-perf-opt.csv` if present, else `python-vs-rust-results.csv`) for warm-mount, RSS, find, and sequential-read **ratio** gates vs Python | Fail when ratios miss thresholds; **soft-skip** individual checks if the CSV or rows are missing |

```bash
# Local / CI microbench (few seconds after a release build)
./benchmarks/check-rust-gates.sh

# Also check ratio gates against the latest CSV
RUN_FULL_BENCH=1 ./benchmarks/check-rust-gates.sh
```

The GitHub Actions `benchmark-gates` job runs the default path only so PRs stay fast and FUSE-free.
