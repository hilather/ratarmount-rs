# G3 gzip polish batch (high / medium)

**Date:** 2026-08-01  
**Policy:** G3 remains **default**. Tier D rapidgzip stays opt-in. These tasks polish G3, not replace it.  
**Decision doc:** [`docs/gzip-binding-decision.md`](../gzip-binding-decision.md) (Tier A+B+C + **G3 polish** subsection).  
**CLI note:** [`docs/mount-options-parity.md`](../mount-options-parity.md) (`-g` / `-gs` / `--gzip-seek-point-spacing`).

## Status matrix

| ID | Task | Owner | Status |
|----|------|--------|--------|
| **G3-A** | Decoded-window LRU cache on `SeekableGzipReader` | `gzip_seek.rs` | **done** — per-reader LRU (`G3_SEEK_CACHE_CHUNKS`=256 / `G3_SEEK_CACHE_BYTES`=16 MiB at 64 KiB chunks); reverse/nearby seeks hit cache; concurrent `Shared` readers keep private caches (`adc4b82`, budget fix `71469d5`) |
| **G3-B** | Ensure RGZI warm remount always on default path mounts | factory | **done** — plain `.gz` + path/live Range persist RGZI via `open_or_create_writable_index` shell; units `plain_gzip_rgzi_*` / `gzip_rgzi_*` (`3ba0c93`) |
| **G3-C** | Auto FUSE readahead (1 MiB) for gzip/`.tar.gz` when `--readahead` omitted | `main.rs` | **done** — auto 1 MiB when flag omitted and rapidgzip preferred **or** input looks like `.gz`/`.tgz`/`.tar.gz`/`.gzip`; explicit `--readahead 0`/`N` overrides (`76bee8d` / Tier D **R4**) |
| **G3-D** | Full **GZIDX window** apply on import (not soft rehydrate only) | `gzip_seek.rs` | **done** — hard path via `zlib-rs` `set_dictionary` when mid-stream points have windows and `bits==0`; soft rehydrate fallback for nonzero bits / mid-block / missing windows (`289eb39`) |
| **G3-E** | **Export GZIDX** for Python round-trip (optional alongside RGZI) | `gzip_seek.rs` | **done** — export API + hard reimport tests; **RGZI remains primary** warm remount; pure Python zran without rehydrate still best-effort for mid-block G3 points (`289eb39`) |
| **G3-F** | Docs: denser `--gzip-seek-point-spacing` guidance + G3 polish residual | docs | **done** — this file + binding-decision **G3 polish** + mount-options `-gs` note |

Legend: **done** · **partial** · **open**. Status refreshed after A–E merge (`289eb39` G3-D/E hard apply + export polish).

## High value (detail)

| ID | Notes |
|----|--------|
| **G3-A** | **Landed.** Per-reader decoded-window LRU (256×64 KiB chunks, 16 MiB byte cap). Sequential FUSE re-seeks still use the working buffer; reverse/nearby hit LRU. |
| **G3-B** | **Landed.** Plain `.gz` cold open creates index shell + RGZI; warm import on remount. Nested in-memory still has no side table (by design). |
| **G3-C** | **Landed.** Auto 1 MiB readahead for gzip-ish inputs and rapidgzip prefer when `--readahead` omitted. |

## Medium value (detail)

| ID | Notes |
|----|--------|
| **G3-D** | **Landed.** Hard GZIDX import when windows usable (`bits==0`); dual `LiveInflate` (miniz cold/RGZI, zlib-rs hard restore). Soft fallback otherwise. |
| **G3-E** | **Landed.** GZIDX export + hard reimport tests; RGZI primary warm path. Residual: mid-block G3 points / pure zran without rehydrate. |
| **G3-F** | Spacing guidance only (no thruput claims). See binding decision + mount-options note. |

## Operator guidance (spacing)

Default **`--gzip-seek-point-spacing` is 16 MiB** (uncompressed checkpoint distance; Python `-gs` parity).

| Workload | Suggested `-gs` / `--gzip-seek-point-spacing` |
|----------|-----------------------------------------------|
| General / sequential heavy | **16** (default) |
| Random-heavy FUSE (many small seeks) | **1–4** MiB — denser checkpoints, less decode-from-checkpoint work per seek; trades higher **open time** and **RSS** (more cloned inflate states) |
| Memory-tight / rare random access | leave default or go larger |

Do **not** invent absolute MiB/s numbers for denser spacing; measure on your corpus if you need gates. **G3-A–E** are landed for default G3 polish; residual is nonzero bit residual (no public `inflatePrime` on stable zlib-rs) and pure Python zran mid-block interop.

## Deferred

- Full miniz → zlib-rs swap for cold G3 checkpoints (state-clone constraint; high risk / low proven ROI) — hard GZIDX path uses zlib-rs only at restore
- Public bit-residual prime on hard path when zlib-rs exposes it
- Parallel single-member inflate (use Tier D instead)
- Default-on rapidgzip (separate Tier D residual; needs published benches)

## Related

- Binding decision / Tier D residual: [`docs/gzip-binding-decision.md`](../gzip-binding-decision.md)
- Rapidgzip perf / residual batches: [`rapidgzip-perf-batch.md`](rapidgzip-perf-batch.md), [`rapidgzip-residual-batch.md`](rapidgzip-residual-batch.md)
- Parity gzip row: [`docs/parity-todo.md`](../parity-todo.md)
