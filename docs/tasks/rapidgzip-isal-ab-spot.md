# Spot: fair rapidgzip zlib-rs vs ISA-L A/B (smoke)

**Date:** 2026-08-01  
**Harness:** [`benchmarks/compare-gzip-isal-ab.sh`](../../benchmarks/compare-gzip-isal-ab.sh)  
**Gitignored full run:** `benchmarks/gzip-backend-results/{results-isal-ab.md,results-isal-ab.csv,run-isal-ab.log}`  
**Purpose:** Commit text-only numbers from a real dual-build A/B so docs do not invent ISA-L wins.  
**Related batch:** [`rapidgzip-perf-batch.md`](rapidgzip-perf-batch.md) **P3**.

## Run command

```bash
export ISAL_INSTALL_PREFIX="${ISAL_INSTALL_PREFIX:-$HOME/projects/rapidgzip-rust/.isal-prefix}"
export LD_LIBRARY_PATH="$ISAL_INSTALL_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LIBRARY_PATH="$ISAL_INSTALL_PREFIX/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
export PKG_CONFIG_PATH="$ISAL_INSTALL_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CPATH="$ISAL_INSTALL_PREFIX/include${CPATH:+:$CPATH}"
SKIP_FUSE=0 SKIP_PYTHON=1 CORPUS_MIB=64 RUNS=2 \
  ./benchmarks/compare-gzip-isal-ab.sh
```

## Environment

| Setting | Value |
|---------|-------|
| Generated (UTC) | 2026-08-01T04:58Z |
| Host | mbrewer-ThinkPad-X1-Extreme |
| nproc | 12 |
| rustc | rustc 1.97.1 (8bab26f4f 2026-07-14) |
| CORPUS_MIB | 64 |
| RUNS (median) | 2 |
| THREADS (`-P gzip:N`) | 8 |
| SKIP_FUSE | 0 |
| SKIP_PYTHON | 1 |
| SKIP_G3 | 0 (G3 baseline included) |
| ISAL_INSTALL_PREFIX | `/home/mbrewer/projects/rapidgzip-rust/.isal-prefix` |
| ISA-L binary | **built and run** (not skipped) |
| Corpus | half zeros + half urandom, `gzip -1` single-member |

Two **separate** release builds:

| Label | Cargo features | Inflate |
|-------|----------------|---------|
| `rust-rgz-zlib` | `gzip-rapidgzip` | zlib-rs |
| `rust-rgz-isal` | `gzip-rapidgzip-isal` | Intel ISA-L (`libisal`) |
| `rust-g3` | same zlib binary, backend unset | G3 miniz checkpoints |

## Decode-only

### Cold index median (seconds, lower is better)

| Archive | rust-rgz-zlib | rust-rgz-isal | rust-g3 |
|---------|---------------|---------------|---------|
| large-64m.tar.gz | 0.539100 | 0.626750 | 0.089750 |
| large-64m.bin.gz | 0.945800 | 0.736250 | 0.098200 |
| small-100.tar.gz | 0.277450 | 0.260450 | 0.142250 |

### Warm open median (seconds, large tar.gz)

| Archive | rust-rgz-zlib | rust-rgz-isal | rust-g3 |
|---------|---------------|---------------|---------|
| large-64m.tar.gz | 0.060450 | 0.058200 | 0.081700 |

## zlib vs isal delta (primary A/B)

Time metrics: **ratio = zlib/isal** (>1 ⇒ ISA-L faster). **%** = relative wall reduction for isal.  
Throughput: **ratio = isal/zlib** (>1 ⇒ ISA-L higher MiB/s).

| Metric | rust-rgz-zlib | rust-rgz-isal | ratio | delta |
|--------|---------------|---------------|-------|-------|
| cold_index large-64m.tar.gz | 0.539100 | 0.626750 | 0.860 zlib/isal (time) | -16.3% |
| cold_index large-64m.bin.gz | 0.945800 | 0.736250 | 1.285 zlib/isal (time) | +22.2% |
| cold_index small-100.tar.gz | 0.277450 | 0.260450 | 1.065 zlib/isal (time) | +6.1% |
| warm_open large-64m.tar.gz | 0.060450 | 0.058200 | 1.039 zlib/isal (time) | +3.7% |
| fuse cold mount large-64m.tar.gz | 0.4590 | 0.3864 | 1.188 zlib/isal (time) | +15.8% |
| fuse cold seq MiB/s large-64m.tar.gz | 216.09 | 150.86 | 0.698 × vs zlib (throughput) | -30.2% |
| fuse warm seq MiB/s large-64m.tar.gz | 124.43 | 146.80 | 1.180 × vs zlib (throughput) | +18.0% |
| fuse cold mount large-64m.bin.gz | 0.5823 | 0.5084 | 1.145 zlib/isal (time) | +12.7% |
| fuse cold seq MiB/s large-64m.bin.gz | 201.41 | 229.18 | 1.138 × vs zlib (throughput) | +13.8% |
| fuse warm seq MiB/s large-64m.bin.gz | 239.45 | 173.28 | 0.724 × vs zlib (throughput) | -27.6% |
| fuse cold mount small-100.tar.gz | 0.2458 | 0.2758 | 0.891 zlib/isal (time) | -12.2% |
| fuse cold seq MiB/s small-100.tar.gz | 1.81 | 0.65 | 0.359 × vs zlib (throughput) | -64.1% |
| fuse warm seq MiB/s small-100.tar.gz | 1.46 | 0.75 | 0.514 × vs zlib (throughput) | -48.6% |

## FUSE cold mount + sequential bandwidth

| Archive | metric | rust-rgz-zlib | rust-rgz-isal | rust-g3 |
|---------|--------|---------------|---------------|---------|
| large-64m.tar.gz | mount_s | 0.4590 | 0.3864 | 0.1985 |
| large-64m.tar.gz | bandwidth_mibs | 216.09 | 150.86 | 263.63 |
| large-64m.tar.gz | seq_read_s | 0.296172 | 0.424227 | 0.242764 |
| large-64m.tar.gz | mount_rss_kib | 53220 | 53840 | 16004 |
| large-64m.bin.gz | mount_s | 0.5823 | 0.5084 | 0.1091 |
| large-64m.bin.gz | bandwidth_mibs | 201.41 | 229.18 | 342.08 |
| large-64m.bin.gz | seq_read_s | 0.317762 | 0.279258 | 0.187092 |
| large-64m.bin.gz | mount_rss_kib | 53224 | 53848 | 14164 |
| small-100.tar.gz | mount_s | 0.2458 | 0.2758 | 0.1777 |
| small-100.tar.gz | bandwidth_mibs | 1.81 | 0.65 | 2.28 |
| small-100.tar.gz | seq_read_s | 0.034458 | 0.095433 | 0.027434 |
| small-100.tar.gz | mount_rss_kib | 45288 | 45584 | 16016 |

## Key takeaways (from this smoke only)

1. **No universal ISA-L win** on this 64 MiB single-member smoke (`RUNS=2`, busy host). Mixed deltas:
   - Cold index: **+22% wall cut** on plain `large-64m.bin.gz`, but **−16%** (ISA-L slower) on `large-64m.tar.gz`.
   - FUSE seq: **+18%** warm MiB/s on large tar, **−30%** cold MiB/s on same archive; plain bin cold **+14%**, warm **−28%**.
2. **G3 still dominates** cold index (~6–10× lower wall than either rapidgzip inflate) and is usually highest FUSE sequential MiB/s on large corpora.
3. **RSS** for rapidgzip cold mounts stays ~**52–54 MiB** vs G3 ~**14–16 MiB** (inflate backend does not close that gap).
4. **small-100** seq MiB/s numbers are noise-dominated (64 KiB files); do not use them to claim inflate ranking.
5. **Do not flip default-on** to ISA-L or rapidgzip from this smoke alone. Re-run with `CORPUS_MIB=256 RUNS=3` on an idle host for publication-grade deltas.

## Residual / how to re-run

| Item | Status |
|------|--------|
| Fair dual-build harness | **done** — `compare-gzip-isal-ab.sh` |
| Smoke numbers committed | **this doc** (text tables only) |
| Full 256 MiB multi-run artifact | **not** committed; regenerate under gitignored `gzip-backend-results/` |
| Python rapidgzip baseline | skipped (`SKIP_PYTHON=1`) |
| Default feature / product flip | **not** justified by this smoke |

```bash
# Fuller A/B (longer):
SKIP_FUSE=0 SKIP_PYTHON=1 CORPUS_MIB=256 RUNS=3 \
  ./benchmarks/compare-gzip-isal-ab.sh
```
