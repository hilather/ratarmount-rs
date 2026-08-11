# Gzip binding decision (PR-08a / PR-08b)

**Date:** 2026-07-25 (updated 2026-08-01)  
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
- `--gzip-seek-point-spacing` / `-g` / `--gs` (Python `-gs`) controls checkpoint distance in **MiB** uncompressed (CLI), stored as bytes in `OpenOptions`. **Default: 16 MiB.**

## G3 polish

**Default remains G3.** Tier D rapidgzip stays opt-in (`gzip-rapidgzip` + env / `--use-backend`); polish work below improves the default path rather than replacing it. Task split: [`tasks/g3-polish-batch.md`](tasks/g3-polish-batch.md).

### `--gzip-seek-point-spacing` guidance

Checkpoint spacing is a **latency vs open-cost** knob (no thruput claims here — measure on your corpus if needed):

| Setting | When |
|---------|------|
| **16 MiB** (default) | General mounts; sequential-heavy reads; lowest open-time / checkpoint RSS |
| **1–4 MiB** | Random-heavy FUSE (many small seeks into large `.gz` / `.tar.gz`) — denser restart points, less decode-from-checkpoint work per seek; **trades higher open time and RSS** (more cloned `InflateState`s) |
| Larger than default | Rare random access / memory-tight; more work per seek |

Example: `ratarmount -gs 4 archive.tar.gz /mnt` (or `--gzip-seek-point-spacing 4`).

### Residual polish (not thruput)

| Item | Status (see [G3 batch](tasks/g3-polish-batch.md)) |
|------|-----------------------------------------------------|
| Decoded-window **LRU** on `SeekableGzipReader` (G3-A) | **done** — 256×64 KiB chunks / 16 MiB per reader; reverse/nearby seeks skip re-inflate |
| RGZI warm remount on all default path mounts (G3-B) | **done** — plain `.gz` + path/live Range create index shell and persist RGZI |
| Auto FUSE readahead 1 MiB for default gzip when `--readahead` omitted (G3-C) | **done** — auto when rapidgzip preferred **or** input looks like gzip; `--readahead 0`/`N` overrides |
| Full **GZIDX window** apply on import (G3-D) | **done** — hard path via `zlib-rs` dict restore when windows + `bits==0`; soft rehydrate fallback otherwise |
| **Export GZIDX** for Python round-trip (G3-E) | **done** — export API + hard reimport tests; **RGZI remains primary** warm path; pure zran mid-block still best-effort |

With G3-A–E landed, prefer denser `-gs` only where random-seek cost still dominates open-time/RSS. Spacing remains the operator-facing control for cold open cost.

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

**Status:** opt-in path / nested / Range rapidgzip when preferred (factory wired to compress from_reader + GZIDX; 2026-08-01). Does **not** replace G3 as default.

| Item | Detail |
|------|--------|
| Crate | [`hilather/rapidgzip-rust`](https://github.com/hilather/rapidgzip-rust) `rapidgzip-core` **v0.2.2** (git pin `cea43ef`; crates.io 0.1.0 is an incomplete stub) |
| Feature | `gzip-rapidgzip` (+ optional `gzip-rapidgzip-isal`) on `ratarmount-compress` / `ratarmount` (requires **rustc ≥ 1.87**, edition 2024 dep) |
| Open gate | `RATARMOUNT_GZIP_BACKEND=rapidgzip` or `--use-backend rapidgzip` / `rapidgzip-gzip` |
| Code | `ratarmount-compress/src/gzip_rapidgzip.rs` → `SharedRapidgzip` + `SeekableBody` (+ from_reader / GZIDX); factory `open_shared_rapidgzip_path` / `persist_rapidgzip_index_blob` |
| Scope | **Path / nested / HTTP·S3 Range** rapidgzip when preferred (`--use-backend rapidgzip` / env); G3 fallback on path open failure and Range reopen when available |
| Index build | Full decode to sink with `keep_index` (parallel when `-P` allows); warm remount imports SQLite GZIDX and skips keep_index; each FUSE open reopens FD + `IndexedReader` |
| Inflate | Default: zlib-rs. With **`gzip-rapidgzip-isal`**: Intel ISA-L sequential inflater (`rapidgzip-core/isal`; needs shared `libisal`, or `ISAL_INSTALL_PREFIX`) |
| Fallback | On rapidgzip open failure, factory falls back to G3 seekable gzip: **path** and **Range** (reopen when available); **nested** prefer recovers Arc-held reader, rewinds when `Seek` works, then opens G3 ([R1](tasks/rapidgzip-residual-batch.md) **done** `00c70a3`) |
| Factory (done) | Path/nested/Range prefer rapidgzip; typed `Arc<SharedRapidgzip>` + GZIDX import/export; invalid blob rebuild (no panic); TAR/plain via `open_from_seekable_body` |
| Residual | Nested imported-index not wired (nested uses temp-spill SQLite / no side table); thruput vs G3 needs re-bench before product claims; default-on rapidgzip after benches; per-open index clone; large nested `from_reader` still mutex (small-body slurp [R2](tasks/rapidgzip-residual-batch.md) **done**); R1/R3/R4 **done** |
| Default CI | Feature **off** (workspace MSRV stays 1.74; ISA-L needs system lib) |

### Residual — performance (thruput / cost)

Separate from wiring (path/nested/Range + GZIDX **done**; nested fail→G3 **R1 done**): even on the verified path FUSE open, **rapidgzip is not yet claimed G3-competitive** on small single-member corpora without a post-P2/P4 re-bench, and **default remains G3**. Python rapidgzip thruput parity is still a thruput residual (not a missing wire). Integration knobs from [P1–P5](tasks/rapidgzip-perf-batch.md) **all done**; batch residuals [R1–R5](tasks/rapidgzip-residual-batch.md) **all done** — remaining product gaps are thruput re-bench, large nested mutex, nested imported-index side table, and default-on policy.

| Residual | Spot range / note |
|----------|-------------------|
| Cold index wall vs G3 | Spot ~**0.15 s** rapidgzip+ISA-L vs ~**0.05 s** G3 on **64 MiB** single-member gzip — thruput residual; **re-bench after P2** before updating figures |
| Cold sequential MiB/s vs G3 | Spot ~**500** vs ~**1100** MiB/s (same corpus, ISA-L feature) — thruput residual **pending re-bench** after P2/P4 (P2/P4 code landed; figures not refreshed) |
| Peak RSS vs G3 | Spot ~**52 MiB** vs ~**15 MiB** (P2 compresses index windows — re-measure) |
| vs **Python** rapidgzip | Head-to-head still favors Python on compressed-TAR random/seq in committed results; same-corpus multi-backend CSV is **`benchmarks/gzip-backend-results/` when generated** (see [`benchmarks/README.md`](../benchmarks/README.md)) |
| Open amortisation | Full `keep_index` decode; each FUSE open reopens FD + `IndexedReader` (per-open index clone residual) |
| Seek-cache / prefetch | **Landed (P2)** — FUSE-oriented seek cache (16 chunks / 64 MiB cap), `seek_readahead`, prefetch windows, optional no-CRC keep_index; thruput impact not re-benched |
| Fair ISA-L A/B | **Harness + smoke (P3 / R3)** — `compare-gzip-isal-ab.sh`; committed tables [`tasks/rapidgzip-isal-ab-spot.md`](tasks/rapidgzip-isal-ab-spot.md); mixed deltas — no universal ISA-L win |
| FUSE readahead fit | **Landed (P4 + G3-C / R4)** — sequential short-read window + random exact-size; `RECOMMENDED_READAHEAD_BYTES` (1 MiB); auto-enable 1 MiB when `--readahead` omitted and (rapidgzip preferred **or** any mount input looks like gzip `.gz`/`.tgz`/`.tar.gz`/`.gzip`); explicit `--readahead 0`/`N` overrides |
| Default-on | Flip only after published benches justify it; feature stays opt-in |

**Numbers policy:** ranges above are local spot checks recorded in the [perf batch](tasks/rapidgzip-perf-batch.md) (pre–P2/P4). Prefer `benchmarks/gzip-backend-results/{results.md,results.csv}` when present; do not invent new absolute thruput figures.


### Factory ↔ compress API matrix (Tier D)

| Capability | Factory status | Compress API |
|------------|----------------|--------------|
| Path cold open | **Done** | `open_seekable_gzip_rapidgzip` / `SharedRapidgzip::open_with_threads` |
| Path prefer + G3 fallback | **Done** | — |
| Path GZIDX import | **Done** | `SharedRapidgzip::open_with_imported_index` |
| Path GZIDX persist | **Done** | `SharedRapidgzip::export_gzidx_blob` + `SqliteIndex::set_gzip_index_blob` |
| Nested `from_reader` | **Done** (fail → rewind G3 when Seek) | `open_seekable_gzip_rapidgzip_from_reader` |
| Nested imported index | Not wired (no nested side table) | `…_with_imported_index_from_reader` exists in compress |
| HTTP/S3 Range | **Done** (prefer + import; reopen on fail → rebuild / G3) | same `from_reader` / `…_with_imported_index_from_reader` APIs |

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
