# G3 gzip polish batch (high / medium)

**Date:** 2026-08-01  
**Policy:** G3 remains **default**. Tier D rapidgzip stays opt-in. These tasks polish G3, not replace it.  
**Decision doc:** [`docs/gzip-binding-decision.md`](../gzip-binding-decision.md) (Tier A+B+C + **G3 polish** subsection).  
**CLI note:** [`docs/mount-options-parity.md`](../mount-options-parity.md) (`-g` / `-gs` / `--gzip-seek-point-spacing`).

## Status matrix

| ID | Task | Owner | Status |
|----|------|--------|--------|
| **G3-A** | Decoded-window LRU cache on `SeekableGzipReader` | `gzip_seek.rs` | **open** — reader keeps a single decode buffer (`buf` / `buf_start`); no multi-entry LRU yet |
| **G3-B** | Ensure RGZI warm remount always on default path mounts | factory | **partial** — path **`.tar.gz`** cold open persists RGZI and warm import works (unit `gzip_rgzi_blob_persisted_and_reimported`); plain **`.gz`** path open imports when a blob is present but does **not** call `persist_gzip_index_blob` after cold open |
| **G3-C** | Auto FUSE readahead (1 MiB) for gzip/`.tar.gz` when `--readahead` omitted | `main.rs` | **open** — auto 1 MiB (`RECOMMENDED_READAHEAD_BYTES`) only when **rapidgzip** is preferred; default G3 still leaves readahead `0` unless the user passes `--readahead` |
| **G3-D** | Full **GZIDX window** apply on import (not soft rehydrate only) | `gzip_seek.rs` (same agent as G3-A) | **open** — import parses header/points; 32 KiB window payloads and bit residuals are **skipped**; inflate state soft-rehydrated by forward scan |
| **G3-E** | **Export GZIDX** for Python round-trip (optional alongside RGZI) | `gzip_seek.rs` (same agent as G3-A) | **open** — export stays **`RGZI` only**; Python `indexed_gzip` consumers need a separate converter |
| **G3-F** | Docs: denser `--gzip-seek-point-spacing` guidance + G3 polish residual | docs | **done** — this file + binding-decision **G3 polish** + mount-options `-gs` note |

Legend: **done** · **partial** · **open**. Status reflects **this worktree’s main tip** when G3-F landed; sibling implementers may flip A–E without re-touching this matrix until the orchestrator refreshes.

## High value (detail)

| ID | Notes |
|----|--------|
| **G3-A** | Random seeks within a spacing window re-inflate from the nearest checkpoint. An LRU of recent decoded windows would cut repeat-read cost without denser checkpoints. |
| **G3-B** | Tier C path import/export is wired for default G3 (not only rapidgzip). Residual: plain single-file `.gz` (and any non-TAR path that skips `persist_gzip_index_blob`) should store RGZI for warm remount symmetry. |
| **G3-C** | Sequential FUSE scanners benefit from a small readahead window on G3 the same way rapidgzip does; product choice is whether default gzip mounts auto-enable 1 MiB or stay opt-in. |

## Medium value (detail)

| ID | Notes |
|----|--------|
| **G3-D** | Today: best-effort GZIDX → offset list → soft rehydrate (`strict_compressed_match == false`). Full window-dict apply would align mid-stream inflate with Python `indexed_gzip` / zran without a full spacing rebuild. |
| **G3-E** | SQLite side table stores opaque blobs; G3 writes `RGZI`. Exporting `GZIDX` is optional interop for Rust→Python (import path already accepts both magics). |
| **G3-F** | Spacing guidance only (no thruput claims). See binding decision + mount-options note. |

## Operator guidance (spacing)

Default **`--gzip-seek-point-spacing` is 16 MiB** (uncompressed checkpoint distance; Python `-gs` parity).

| Workload | Suggested `-gs` / `--gzip-seek-point-spacing` |
|----------|-----------------------------------------------|
| General / sequential heavy | **16** (default) |
| Random-heavy FUSE (many small seeks) | **1–4** MiB — denser checkpoints, less decode-from-checkpoint work per seek; trades higher **open time** and **RSS** (more cloned inflate states) |
| Memory-tight / rare random access | leave default or go larger |

Do **not** invent absolute MiB/s numbers for denser spacing; measure on your corpus if you need gates. Related polish when landed: **G3-A** (decoded-window LRU) and **G3-D/E** (full GZIDX window interop); until then those remain residuals above.

## Deferred

- miniz → zlib-rs swap (state-clone constraint; high risk / low proven ROI)
- Parallel single-member inflate (use Tier D instead)
- Default-on rapidgzip (separate Tier D residual; needs published benches)

## Related

- Binding decision / Tier D residual: [`docs/gzip-binding-decision.md`](../gzip-binding-decision.md)
- Rapidgzip perf / residual batches: [`rapidgzip-perf-batch.md`](rapidgzip-perf-batch.md), [`rapidgzip-residual-batch.md`](rapidgzip-residual-batch.md)
- Parity gzip row: [`docs/parity-todo.md`](../parity-todo.md)
