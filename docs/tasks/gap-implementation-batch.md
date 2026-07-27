# Gap implementation batch (vs Python ratarmount)

**Date:** 2026-07-27  
**Python refs:** `core/ratarmountcore/compressions.py`, `mountsource/factory.py`, `automount.py`, `sevenzip` decoder design.

## Landed this batch

### 1. Split multi-volume files (`.001` / `.002` / …)

| Piece | Location |
|-------|----------|
| Detection (decimal/hex/alpha, width-fixed, start 0/1) | `ratarmount-compress/src/split.rs` |
| Lazy join (`JoinedFile`) + materialize for open | same |
| Top-level factory wire-up | `ratarmount/src/factory.rs` `open_split_set` |
| Unit tests (Python `test_factory` / compressions parity) | `split::tests`, `factory::split_open_tests` |
| Fixtures | `tests/simple-file-split.001`, `single-file-split.tar.001` |

**Still open for split:** recursive AutoMount join *inside* a mounted tree (Python lists parent + joins first-part only); materialize-to-temp for multi‑GB volumes (Python keeps lazy FDs only).

### 2. Progressive solid LZMA2 (partial)

| Piece | Location |
|-------|----------|
| Large pure LZMA2 folders: decode only prefix through range end | `Lzma2RandomAccessDecoder::read_range` |
| Small folders (≤4 MiB) still full-cache | `SMALL_FOLDER_FULL_CACHE` |

**Still open for 7z:** BCJ/AES/multi-pack full-folder path; true chunk-resume cache without re-decoding prefix; nested solid spool.

## Not started this batch (next candidates)

| Gap | Python entry points | Effort |
|-----|---------------------|--------|
| GNU incremental TAR semantics | TAR dumpdir / `isGnuIncremental` | M–L |
| HTTP Range-backed format open | `HttpRangeFile` + factory | M |
| Index `--hashes` / xattrs | `hashing.py`, SQLite xattrs | M |
| In-process SquashFS/EXT4 | PySquashfsImage / python-ext4 | L |
| Commit-overlay compressed TAR | CLI + tar pipeline | M |
| SMB/WebDAV | fsspec | L |
| Full `-P` matrix | BlockParallelReaders | L |

## Verify

```bash
cargo test -p ratarmount-compress split
cargo test -p ratarmount open_
cargo test -p ratarmount-formats-sevenzip
# CLI: ratarmount -f tests/simple-file-split.001 mnt/  → cat mnt/simple-file-split
```
