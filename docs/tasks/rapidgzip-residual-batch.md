# Rapidgzip residual batch (post P1–P5)

**Date:** 2026-08-01  
**Base:** main ahead of origin with P1–P5 merged (`8fa155f` tip area).

## Open residuals

| ID | Residual | Owner |
|----|----------|--------|
| **R1** | Nested prefer rapidgzip fail: rewind + G3 fallback when `Seek` works | factory |
| **R2** | Shared-reader mutex thruput: materialize small nested gzip into `Arc<[u8]>` ReadAt (no mutex) | compress |
| **R3** | Run fair zlib vs ISA-L A/B; capture numbers into docs note | benchmarks |
| **R4** | Auto-enable FUSE readahead (1 MiB) when rapidgzip prefer and user left `--readahead 0` | main.rs (+ fuse const) |
| **R5** | Docs: mark P1–P5 done; refresh residual checklist | docs |

## Out of scope this batch

- Default-on rapidgzip (needs published benches + product call)
- Upstream `Arc<GzipIndex>` API in rapidgzip-core
- Nested SQLite side table for imported index
