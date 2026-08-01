# Rapidgzip Tier D — performance improvement batch

**Date:** 2026-08-01  
**Base:** main with ISA-L pin (`75c5a24`), compress from_reader/GZIDX, factory hooks.  
**Canonical decision / residual:** [`docs/gzip-binding-decision.md`](../gzip-binding-decision.md) (Tier D POC + **feature** vs **performance** residuals).  
**Parity row:** [`docs/parity-todo.md`](../parity-todo.md) — gzip capability `[x]` with thruput residual `~` vs Python rapidgzip.

## Problem summary

Verified `kind=gzip-rapidgzip` FUSE path is slower than default **G3** on a **64 MiB single-member** gzip (local spot check; not a committed harness artifact):

| Metric | G3 | rapidgzip + ISA-L |
|--------|----|-------------------|
| Cold index | ~0.05 s | ~0.15 s |
| Cold seq MiB/s | ~1100 | ~500 |
| Peak RSS | ~15 MiB | ~52 MiB |

**Do not treat these as CI gates.** Full A/B (G3 / rust-rapidgzip zlib-rs / rust-rapidgzip+ISA-L / Python rapidgzip) lives in:

```bash
./benchmarks/compare-gzip-backends.sh
# → benchmarks/gzip-backend-results/{results.csv,results.md} when generated
# knobs: CORPUS_MIB=64|256 THREADS=8 RUNS=3 RUST_FEATURES=gzip-rapidgzip[-isal]
```

See [`benchmarks/README.md`](../../benchmarks/README.md). If `gzip-backend-results/` is absent, regenerate rather than inventing numbers.

Root causes mix **architecture** (`keep_index` full decode, windowed seek index, per-open `IndexedReader`) with **integration gaps** (factory not yet calling compress `from_reader` / GZIDX import/export on all paths) and **tuning** (cache/prefetch, fair ISA-L A/B, FUSE readahead alignment).

## Status matrix (subagents)

| ID | Owner | Goal | Status |
|----|-------|------|--------|
| **P1** | `ratarmount/src/factory.rs` | Wire live compress APIs: GZIDX import/export, nested/Range `from_reader` | **open** — path cold open + prefer/fallback **done**; import/export hooks residual; nested/Range still prefer → G3 |
| **P2** | `ratarmount-compress/src/gzip_rapidgzip.rs` | Open-cost + seek thruput: cache/prefetch, clone reduction, optional fast index build | **open** |
| **P3** | `benchmarks/**` | Fair A/B harness: ISA-L on/off, decode-only, 256 MiB corpus | **partial** — `compare-gzip-backends.sh` exists; commit/publish `gzip-backend-results` when re-run |
| **P4** | `ratarmount-fuse/**` | Align FUSE readahead with rapidgzip short reads / window size | **open** |
| **P5** | `docs/**` | Perf residual matrix + parity note (no code) | **done** (this doc + binding decision residual split + parity gzip thruput note) |

## Residual checklist (honest)

### Feature wiring (not thruput)

| Item | Notes |
|------|--------|
| Path GZIDX import | Compress API exists; factory still load+rebuild path |
| Path GZIDX persist | Compress `export_gzidx_blob` exists; factory persist hook no-op |
| Nested `from_reader` | Prefer-backend → **G3 residual** until factory wires compress |
| Nested imported index | Compress API exists; not wired |
| HTTP/S3 Range | Same as nested `from_reader` |

Detail table: [Factory ↔ compress API matrix](../gzip-binding-decision.md#factory--compress-api-matrix-tier-d).

### Performance (thruput / cost)

| Item | Spot / expected residual |
|------|--------------------------|
| Cold open / index vs G3 | ~3× wall on 64 MiB single-member (~0.15 s vs ~0.05 s) — `keep_index` full decode |
| Sequential FUSE MiB/s vs G3 | ~0.5× on same corpus (~500 vs ~1100 MiB/s with ISA-L) |
| RSS vs G3 | ~3× (~52 MiB vs ~15 MiB) |
| vs **Python** rapidgzip | Still `~` / behind on compressed-TAR random+seq geo-mean in head-to-head benches; see `benchmarks/python-vs-rust-results.md` and regenerate `gzip-backend-results` for same-corpus backend A/B |
| Seek / open amortisation | Per-open FD + `IndexedReader`; clone/cache knobs (P2) |
| Inflate backend A/B | zlib-rs default vs optional ISA-L — fair harness (P3); do not claim ISA-L win without results |
| FUSE readahead fit | Global `--readahead` may not match rapidgzip window/short-read behavior (P4) |
| Default-on | **Not** default; opt-in feature + env/`--use-backend` until benches justify flipping |

## Measured numbers policy

| Source | Use for |
|--------|---------|
| Table in **Problem summary** above | Order-of-magnitude residual vs G3 (64 MiB, ISA-L) |
| `benchmarks/gzip-backend-results/*` | Authoritative multi-backend compare **when generated** |
| `benchmarks/python-vs-rust-results.md` | Broader Python vs Rust (default G3 path; not always `gzip-rapidgzip`) |
| Binding decision residual sections | Product language for feature vs perf gaps |

**Do not invent** new absolute MiB/s or wall times in README/parity without a results file or a re-run of the harness.

## Done when

- [ ] Factory uses compress `from_reader` + GZIDX import/export (no residual stubs for existing APIs). — **P1**
- [ ] Compress has measurable thruput knobs + tests. — **P2**
- [ ] Harness can A/B zlib-rs vs ISA-L fairly; results published under `gzip-backend-results` when useful. — **P3**
- [ ] FUSE readahead aligned or residual documented with numbers. — **P4**
- [x] Docs state honest residual vs G3 **and** vs Python rapidgzip thruput. — **P5**
