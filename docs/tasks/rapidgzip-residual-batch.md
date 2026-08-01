# Rapidgzip residual batch (post P1–P5)

**Date:** 2026-08-01  
**Base:** main with P1–P5 landed (factory GZIDX/from_reader, compress seek-cache/prefetch, ISA-L A/B harness, FUSE short-read readahead, docs).  
**Prior batch:** [`docs/tasks/rapidgzip-perf-batch.md`](rapidgzip-perf-batch.md) — **P1–P5 all done**.  
**Decision residual:** [`docs/gzip-binding-decision.md`](../gzip-binding-decision.md) Tier D POC + performance residual.

## Status

| ID | Residual | Owner | Status |
|----|----------|--------|--------|
| **R1** | Nested prefer rapidgzip fail: rewind + G3 fallback when `Seek` works | factory | **done** (`00c70a3`) |
| **R2** | Shared-reader mutex thruput: materialize small nested gzip into `Arc<[u8]>` ReadAt (no mutex) | compress | **done** (`4dcc234` — small bodies slurp; large residual still mutex) |
| **R3** | Run fair zlib vs ISA-L A/B; capture numbers into docs note | benchmarks | **done** (`f11c7da` + harness; smoke tables [`rapidgzip-isal-ab-spot.md`](rapidgzip-isal-ab-spot.md)) |
| **R4** | Auto-enable FUSE readahead (1 MiB) when rapidgzip prefer and user left `--readahead` omitted | main.rs (+ fuse const) | **done** (`7f5edd6` / `76bee8d`) — also covers default G3 gzip-ish inputs ([G3-C](g3-polish-batch.md)) |
| **R5** | Docs: mark P1–P5 done; refresh residual checklist | docs | **done** (this batch + perf-batch / binding decision; re-aligned after accidental open-marker regression) |

## Residuals (detail)

| ID | Notes |
|----|--------|
| **R1** | **Landed.** Nested prefer fail recovers Arc-held reader, rewinds, falls through to G3 when Seek works. Path/Range already had G3 fallback. |
| **R2** | **Landed** for small `from_reader` (slurp → Arc ReadAt). Oversized nested streams still mutex-serialize (documented residual). |
| **R3** | **Landed.** Fair A/B harness + published smoke note; re-bench after major thruput work still recommended before product claims. |
| **R4** | **Landed.** Auto 1 MiB (`RECOMMENDED_READAHEAD_BYTES`) when `--readahead` omitted and (rapidgzip preferred **or** any mount input looks like gzip). Explicit `--readahead 0` / `N` overrides. |
| **R5** | Docs-only refresh of P1–P5 completion and residual pointers (P-matrix must stay **done**, not open). |

## Out of scope this batch

- Default-on rapidgzip (needs published benches + product call)
- Upstream `Arc<GzipIndex>` API in rapidgzip-core
- Nested SQLite side table for imported index
- Claiming thruput win vs G3 without post-P2/P4 re-bench (spot table in perf batch remains pre-tuning order-of-magnitude only)
