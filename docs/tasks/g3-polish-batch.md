# G3 gzip polish batch (high / medium)

**Date:** 2026-08-01  
**Policy:** G3 remains **default**. Tier D rapidgzip stays opt-in. These tasks polish G3, not replace it.

## High value

| ID | Task | Owner |
|----|------|--------|
| **G3-A** | Decoded-window LRU cache on `SeekableGzipReader` | `gzip_seek.rs` |
| **G3-B** | Ensure RGZI warm remount always on default path mounts | factory |
| **G3-C** | Auto FUSE readahead (1 MiB) for gzip/`.tar.gz` when `--readahead` omitted | `main.rs` |

## Medium value

| ID | Task | Owner |
|----|------|--------|
| **G3-D** | Full **GZIDX window** apply on import (not soft rehydrate only) | `gzip_seek.rs` (same agent as G3-A) |
| **G3-E** | **Export GZIDX** for Python round-trip (optional alongside RGZI) | `gzip_seek.rs` (same agent as G3-A) |
| **G3-F** | Docs: denser `--gzip-seek-point-spacing` guidance + G3 polish residual | docs |

## Deferred

- miniz → zlib-rs swap (state-clone constraint; high risk / low proven ROI)
- Parallel single-member inflate (use Tier D instead)
