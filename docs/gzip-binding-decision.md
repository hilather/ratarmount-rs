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
- Still materialize to a temp file for `SingleFileMountSource` (simple and fast for small files).

### CLI
- `--gzip-seek-point-spacing` controls checkpoint distance (bytes uncompressed).

## Kill criteria

- [x] `tests/simple.gz` mounts and md5 matches golden content.
- [x] Random seek on synthetic multi-checkpoint gzip (unit test).
- [x] `.tar.gz` mounts via seekable path (`packed-5-times.tar.gz` harness).
- [x] No dependency on rapidgzip C ABI.

## Related codecs (2026-07-26)

| Codec | Path |
|-------|------|
| bzip2 | `SeekableBody` via one-shot decode → RAM (≤256 MiB) or temp |
| xz | same (multi-decoder for concatenated streams) |
| zstd | multi-frame restart map; single-frame same as bzip2/xz |

## Post-1.0

- **Tier C:** import Python `gzipindexes` / `gztoolindex` without rebuild.
- **Tier D:** parallel decode / rapidgzip-class throughput.
- Persist Rust checkpoints into SQLite for faster remount without full re-scan.
- Seekable single-file `.gz` without materialize.
- True bzip2 bit-block map; xz liblzma stream index; zstd seek-table.
