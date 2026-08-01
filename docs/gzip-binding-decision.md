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

## Tier D POC — pure-Rust rapidgzip (`gzip-rapidgzip`)

**Status:** opt-in path-backed backend with factory wiring hooks (2026-08-01). Does **not** replace G3 as default.

| Item | Detail |
|------|--------|
| Crate | [`hilather/rapidgzip-rust`](https://github.com/hilather/rapidgzip-rust) `rapidgzip-core` **v0.2.1** (git pin `75c5a24`; crates.io 0.1.0 is an incomplete stub) |
| Feature | `gzip-rapidgzip` (+ optional `gzip-rapidgzip-isal`) on `ratarmount-compress` / `ratarmount` (requires **rustc ≥ 1.87**, edition 2024 dep) |
| Open gate | `RATARMOUNT_GZIP_BACKEND=rapidgzip` or `--use-backend rapidgzip` / `rapidgzip-gzip` |
| Code | `ratarmount-compress/src/gzip_rapidgzip.rs` → `SharedRapidgzip` + `SeekableBody` (+ from_reader / GZIDX); factory `open_shared_rapidgzip_path` / `persist_rapidgzip_index_blob` |
| Scope | **Path** rapidgzip when preferred; nested/Range factory branches prefer-backend with G3 residual until wired to compress from_reader |
| Index build | Full decode to sink with `keep_index` (parallel when `-P` allows); each FUSE open reopens FD + `IndexedReader` |
| Inflate | Default: zlib-rs. With **`gzip-rapidgzip-isal`**: Intel ISA-L sequential inflater (`rapidgzip-core/isal`; needs shared `libisal`, or `ISAL_INSTALL_PREFIX`) |
| Fallback | On rapidgzip open failure, factory falls back to G3 seekable gzip |
| Factory (done) | Path open keeps typed `Arc<SharedRapidgzip>`; warm SQLite blob load (no panic on garbage); TAR/plain via `open_from_seekable_body` |
| Residual | Factory must call compress `from_reader` / `with_imported_index` / `export_gzidx_blob` (API exists in compress); open cost vs G3; seek-cache tuning; fair isal A/B; default-on after benches; per-open index clone; exclusive-ownership `Send` |
| Default CI | Feature **off** (workspace MSRV stays 1.74; ISA-L needs system lib) |

### Factory ↔ compress API matrix (Tier D)

| Capability | Factory status | Compress API |
|------------|----------------|--------------|
| Path cold open | **Done** | `open_seekable_gzip_rapidgzip` |
| Path prefer + G3 fallback | **Done** | — |
| Path GZIDX import | Hook only (load + rebuild) | **Exists:** `open_seekable_gzip_rapidgzip_with_imported_index` — wire in factory |
| Path GZIDX persist | Hook only (no-op) | **Exists:** `SharedRapidgzip::export_gzidx_blob` — wire in factory |
| Nested `from_reader` | Prefer → G3 residual | **Exists:** `open_seekable_gzip_rapidgzip_from_reader` — wire in factory |
| Nested imported index | Not wired | `…_with_imported_index_from_reader` exists in compress |
| HTTP/S3 Range | Prefer → G3 residual | same `from_reader` APIs |

```bash
# Build with the POC backend (rustc ≥ 1.87)
cargo build -p ratarmount --features gzip-rapidgzip
# With ISA-L (install libisal-dev, or set ISAL_INSTALL_PREFIX to a prefix with lib/libisal.so)
cargo build -p ratarmount --features gzip-rapidgzip-isal

# Select at mount time
RATARMOUNT_GZIP_BACKEND=rapidgzip cargo run --features gzip-rapidgzip-isal -- archive.tar.gz /mnt
# or
cargo run --features gzip-rapidgzip-isal -- --use-backend rapidgzip -P gzip:8 archive.tar.gz /mnt
# Explicit rapidgzip worker budget (optional):
cargo run --features gzip-rapidgzip-isal -- --use-backend rapidgzip -P rapidgzip-gzip:16 archive.tar.gz /mnt
```
