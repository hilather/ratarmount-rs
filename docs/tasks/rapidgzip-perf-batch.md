# Rapidgzip Tier D — performance improvement batch

**Date:** 2026-08-01  
**Base:** main with ISA-L pin (`75c5a24`), compress from_reader/GZIDX, factory hooks.

## Problem summary

Verified `kind=gzip-rapidgzip` FUSE path is slower than G3 on 64 MiB single-member gzip:

| Metric | G3 | rapidgzip+ISA-L |
|--------|----|-----------------|
| Cold index | ~0.05 s | ~0.15 s |
| Cold seq MiB/s | ~1100 | ~500 |
| RSS | ~15 MiB | ~52 MiB |

Root causes mix **architecture** (keep_index full decode, windowed seek index) with **integration gaps** (factory not calling compress from_reader/import/export yet) and **tuning** (cache/prefetch, fair isal A/B).

## Task split (subagents)

| ID | Owner | Goal |
|----|-------|------|
| P1 | `ratarmount/src/factory.rs` | Wire live compress APIs: import, export, nested/Range from_reader |
| P2 | `ratarmount-compress/src/gzip_rapidgzip.rs` | Open-cost + seek thruput: cache/prefetch, clone reduction, optional fast index build |
| P3 | `benchmarks/**` | Fair A/B harness: isal on/off, decode-only, 256 MiB corpus |
| P4 | `ratarmount-fuse/**` | Align FUSE readahead with rapidgzip short reads / window size |
| P5 | `docs/**` | Perf residual matrix + parity note (no code) |

## Done when

- Factory uses compress from_reader + GZIDX import/export (no residual stubs for existing APIs).
- Compress has measurable thruput knobs + tests.
- Harness can A/B zlib-rs vs ISA-L fairly.
- Docs state honest residual vs G3.
