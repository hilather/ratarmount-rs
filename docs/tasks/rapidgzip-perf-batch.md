# Rapidgzip Tier D — performance improvement batch

**Date:** 2026-08-01  
**Base:** main with ISA-L pin (`75c5a24`), compress from_reader/GZIDX, factory hooks.  
**Canonical decision / residual:** [`docs/gzip-binding-decision.md`](../gzip-binding-decision.md) (Tier D POC + **feature** vs **performance** residuals).  
**Parity row:** [`docs/parity-todo.md`](../parity-todo.md) — gzip capability `[x]` with thruput residual `~` vs Python rapidgzip.  
**Post-batch residuals:** [`docs/tasks/rapidgzip-residual-batch.md`](rapidgzip-residual-batch.md) (**R1–R5**).

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
# fair zlib vs ISA-L dual-build:
./benchmarks/compare-gzip-isal-ab.sh
```

See [`benchmarks/README.md`](../../benchmarks/README.md). If `gzip-backend-results/` is absent, regenerate rather than inventing numbers.

Root causes mix **architecture** (`keep_index` full decode, windowed seek index, per-open `IndexedReader` / index clone) with **integration** (now largely wired — path/nested/Range + GZIDX) and **tuning** (seek-cache/prefetch and FUSE readahead **landed** in P2/P4; thruput vs G3 still needs a **post-P2/P4 re-bench** before claiming improvement).

## Status matrix (subagents)

| ID | Owner | Goal | Status |
|----|-------|------|--------|
| **P1** | `ratarmount/src/factory.rs` | Wire live compress APIs: GZIDX import/export, nested/Range `from_reader` | **done** — path/nested/Range prefer + GZIDX import/export; G3 fallback on path/Range fail; nested imported-index still not wired (no side table) |
| **P2** | `ratarmount-compress/src/gzip_rapidgzip.rs` | Open-cost + seek thruput: cache/prefetch, clone reduction, optional fast index build | **done** — `Arc` index hold, FUSE-oriented seek cache / readahead / prefetch knobs, optional no-CRC keep_index; residual: per-open index clone + shared-reader mutex (see **R2**) |
| **P3** | `benchmarks/**` | Fair A/B harness: ISA-L on/off, decode-only, 256 MiB corpus | **done** (harness) — `compare-gzip-backends.sh` + `compare-gzip-isal-ab.sh`; publish numbers under `gzip-backend-results` / residual **R3** when re-run |
| **P4** | `ratarmount-fuse/**` | Align FUSE readahead with rapidgzip short reads / window size | **done** — short-read sequential window + random exact-size; `RECOMMENDED_READAHEAD_BYTES` (1 MiB); auto-enable when prefer + default 0 is residual **R4** |
| **P5** | `docs/**` | Perf residual matrix + parity note (no code) | **done** (this doc + binding decision residual split + parity gzip thruput note; **R5** refresh) |

## Residual checklist (honest)

### Feature wiring (post-P1)

| Item | Notes |
|------|--------|
| Path GZIDX import | **Done** — factory imports warm blob |
| Path GZIDX persist | **Done** — factory exports after cold keep_index |
| Nested `from_reader` | **Done** — prefer rapidgzip; fail path has no G3 rewind (residual **R1**) |
| Nested imported index | Not wired (no nested side table) |
| HTTP/S3 Range | **Done** — prefer + import; reopen on fail → rebuild / G3 |

Detail table: [Factory ↔ compress API matrix](../gzip-binding-decision.md#factory--compress-api-matrix-tier-d).

### Performance (thruput / cost)

| Item | Spot / expected residual |
|------|--------------------------|
| Cold open / index vs G3 | Spot ~3× wall on 64 MiB single-member (~0.15 s vs ~0.05 s) — `keep_index` full decode; **re-bench after P2** before updating figures |
| Sequential FUSE MiB/s vs G3 | Spot ~0.5× on same corpus (~500 vs ~1100 MiB/s with ISA-L); **open pending re-bench** after P2/P4 |
| RSS vs G3 | Spot ~3× (~52 MiB vs ~15 MiB); P2 enables compressed index windows — re-measure |
| vs **Python** rapidgzip | Still `~` / behind on compressed-TAR random+seq geo-mean in head-to-head benches; see `benchmarks/python-vs-rust-results.md` and regenerate `gzip-backend-results` for same-corpus backend A/B |
| Seek / open amortisation | P2: seek-cache/prefetch **landed**; residual per-open FD + `IndexedReader` / index clone |
| Inflate backend A/B | P3 harness **landed** (`compare-gzip-isal-ab.sh`); do not claim ISA-L win without published results (**R3**) |
| FUSE readahead fit | P4 **landed** (short-read sequential window); auto 1 MiB when prefer + user left 0 is **R4** |
| Default-on | **Not** default; opt-in feature + env/`--use-backend` until benches justify flipping |

Further work tracked in [`rapidgzip-residual-batch.md`](rapidgzip-residual-batch.md) (**R1–R5**).

## Measured numbers policy

| Source | Use for |
|--------|---------|
| Table in **Problem summary** above | Order-of-magnitude residual vs G3 (64 MiB, ISA-L) — pre–P2/P4 spot; refresh after re-bench |
| `benchmarks/gzip-backend-results/*` | Authoritative multi-backend compare **when generated** |
| `benchmarks/compare-gzip-isal-ab.sh` → results note | Fair zlib-rs vs ISA-L dual-build when run (**R3**) |
| `benchmarks/python-vs-rust-results.md` | Broader Python vs Rust (default G3 path; not always `gzip-rapidgzip`) |
| Binding decision residual sections | Product language for feature vs perf gaps |

**Do not invent** new absolute MiB/s or wall times in README/parity without a results file or a re-run of the harness.

## Done when

- [x] Factory uses compress `from_reader` + GZIDX import/export (no residual stubs for existing path/nested/Range APIs). — **P1**
- [x] Compress has measurable thruput knobs + tests. — **P2**
- [x] Harness can A/B zlib-rs vs ISA-L fairly; results published under `gzip-backend-results` when useful. — **P3** (harness; numbers optional)
- [x] FUSE readahead aligned or residual documented with numbers. — **P4**
- [x] Docs state honest residual vs G3 **and** vs Python rapidgzip thruput. — **P5** / **R5**
