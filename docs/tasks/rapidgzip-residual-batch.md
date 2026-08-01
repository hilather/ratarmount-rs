# Rapidgzip residual batch (post P1–P5)

**Date:** 2026-08-01  
**Base:** main with P1–P5 landed (factory GZIDX/from_reader, compress seek-cache/prefetch, ISA-L A/B harness, FUSE short-read readahead, docs).  
**Prior batch:** [`docs/tasks/rapidgzip-perf-batch.md`](rapidgzip-perf-batch.md) — **P1–P5 all done**.  
**Decision residual:** [`docs/gzip-binding-decision.md`](../gzip-binding-decision.md) Tier D POC + performance residual.

## Status

| ID | Residual | Owner | Status |
|----|----------|--------|--------|
| **R1** | Nested prefer rapidgzip fail: rewind + G3 fallback when `Seek` works | factory | **open** |
| **R2** | Shared-reader mutex thruput: materialize small nested gzip into `Arc<[u8]>` ReadAt (no mutex) | compress | **open** |
| **R3** | Run fair zlib vs ISA-L A/B; capture numbers into docs note | benchmarks | **open** (harness exists; numbers not published) |
| **R4** | Auto-enable FUSE readahead (1 MiB) when rapidgzip prefer and user left `--readahead 0` | main.rs (+ fuse const) | **open** |
| **R5** | Docs: mark P1–P5 done; refresh residual checklist | docs | **done** (this batch status + perf-batch / binding decision refresh) |

## Open residuals (detail)

| ID | Notes |
|----|--------|
| **R1** | Nested prefer has no reopen path today — rapidgzip fail surfaces as error instead of G3. Path/Range already fall back when reopen remains. |
| **R2** | Nested / shared `from_reader` serializes decode on one mutex; small members may be cheaper as `Arc<[u8]>` + ReadAt. |
| **R3** | `./benchmarks/compare-gzip-isal-ab.sh` (and `compare-gzip-backends.sh`); write results under `gzip-backend-results` / residual note — do not invent thruput. |
| **R4** | P4 aligned short-read behavior when readahead &gt; 0; default remains off. Auto 1 MiB (`RECOMMENDED_READAHEAD_BYTES`) only when backend prefer is rapidgzip. |
| **R5** | Docs-only refresh of P1–P5 completion and residual pointers. |

## Out of scope this batch

- Default-on rapidgzip (needs published benches + product call)
- Upstream `Arc<GzipIndex>` API in rapidgzip-core
- Nested SQLite side table for imported index
- Claiming thruput win vs G3 without re-bench after P2/P4
