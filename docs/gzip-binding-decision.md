# Gzip binding decision (PR-08a / PR-08b)

**Date:** 2026-07-25 (updated 2026-07-26)  
**Decision:** **G3** (pure Rust Tier A+B via `flate2` / `miniz_oxide`).

## Options considered

| Option | Description | Status |
|--------|-------------|--------|
| **G1** | Existing crate / C API over rapidgzip | Deferred; optional later if seek-table interop needed |
| **G2** | In-tree C++ shim over rapidgzip | Not default |
| **G3** | Pure `flate2`/`miniz_oxide` + own seek checkpoints | **Chosen** |

## Implementation (current)

### Tier A — sequential decode
- Detect gzip magic `1f 8b`.
- Decode with `flate2::read::MultiGzDecoder` (materialize path) or raw deflate via `miniz_oxide` (seekable path).

### Tier B — rebuild-only seek index (`.tar.gz` / `.tgz`)
1. Build checkpoints by scanning the stream once, cloning `miniz_oxide::inflate::stream::InflateState` every `gzip_seek_point_spacing` uncompressed bytes (default 16 MiB).
2. Multi-member gzip: checkpoint at each member start; skip CRC32/ISIZE trailers.
3. Random access restores the nearest checkpoint and inflates forward (≤ ~spacing work per seek).
4. TAR indexing and member open use `SharedSeekableGzip` — **no full materialize** of the decompressed TAR body.
5. Checkpoints are **in-memory for the mount lifetime** (rebuild-on-load). Python-compatible `gzipindexes` / `gztoolindex` blob import is **Tier C** (not required for 1.0).

### Plain `.gz` (non-TAR)
- Seekable gzip body + `SingleFileMountSource::from_seekable_body` — **no full materialize**
  (same checkpoint random access as TAR path). Residual path-only formats still materialize.

### CLI
- `--gzip-seek-point-spacing` controls checkpoint distance (bytes uncompressed).

## Kill criteria

- [x] `tests/simple.gz` mounts and md5 matches golden content.
- [x] Random seek on synthetic multi-checkpoint gzip (unit test).
- [x] `.tar.gz` mounts via seekable path (`packed-5-times.tar.gz` harness).
- [x] No dependency on rapidgzip C ABI.

## Related codecs (2026-07-31)

| Codec | Path |
|-------|------|
| bzip2 | multi-stream + file-backed bit-block maps + `bzip2blocks`; full decode fallback |
| xz | Stream Footer + Index **footer-first** range map (multi-stream / multi-block / pixz; small single-block Index); units &gt; ~256 MiB fall through to full decode + temp spill; multi-stream decode-map fallback (`xz_seek.rs`) |
| zstd | multi-frame + seek-table + `zstdblocks`; single-frame full decode — [guide](zstd-random-access.md) |

Shared (from-reader / nested) gzip, zstd, and xz hold compressed **seek+read** under one mutex per range (zstd/gzip also track a private compressed offset per open; xz locks header+block pairs together) so concurrent FUSE opens do not interleave cursors.

### xz single-block residual

Default `xz -c` emits **one block**. Open can still parse Index with a few range reads, but random access decodes that whole block. Maps with any unit larger than `DEFAULT_MEMORY_CAP` (~256 MiB) use full decode + temp spill instead of an unbounded per-reader `Vec` cache. For multi‑GiB mounts, compress with `--block-size` / pixz (or multiple streams).

## Post-1.0

- **Tier C:** import Python `gzipindexes` / `gztoolindex` without rebuild.
- **Tier D:** parallel decode / rapidgzip-class throughput.
- Persist Rust checkpoints into SQLite for faster remount without full re-scan.
- ~~Seekable single-file `.gz` without materialize~~ — done (`from_seekable_body`).
- ~~xz Stream Index maps without full compressed load~~ — done (range reads for header/Index/footer + magic windows).
- True bzip2 open-time size discovery polish. (Zstd seek-table / multi-frame: see [zstd-random-access.md](zstd-random-access.md).)
