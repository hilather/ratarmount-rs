# Gap implementation batches (vs Python ratarmount)

**Date:** 2026-07-27  
**Python refs:** `compressions.py`, `automount.py`, `factory.py`, `tar.py`, `hashing.py`, sevenzip decoder.

## Batch 1 — sequential (main session)

### Split multi-volume (top-level)

| Piece | Location |
|-------|----------|
| Detection + `JoinedFile` | `ratarmount-compress/src/split.rs` |
| Factory open | `ratarmount/src/factory.rs` |

### Progressive solid LZMA2 (prefix)

| Piece | Location |
|-------|----------|
| Prefix decode for large pure LZMA2 | `ratarmount-formats-sevenzip/src/decode.rs` |

## Batch 2 — five parallel worktree agents (merged)

Non-overlapping crate ownership so agents could not stomp each other:

| Agent | Ownership | Commit (on main) | Result |
|-------|-----------|------------------|--------|
| AutoMount split polish | `ratarmount-compositing/**` only | `b6f3819` | Recursive first-part join + tests |
| HTTP Range | `ratarmount-remote/**` only | `88c62b4` | Prefer Range chunk materialize |
| GNU incremental TAR | `ratarmount-formats-tar/**` only | `041444a` | Detect, prefix strip, dumpdir `D` |
| Index hashes/xattrs | `index` + `core` OpenOptions + CLI | `7618724` | `--hashes`, xattr store/fill |
| 7z LRU windows | `ratarmount-formats-sevenzip/**` only | `9373fbe` | 1 MiB × 64 LRU progressive cache |

**Merge:** cherry-pick from worktree objects onto `main`; `cargo test --workspace` + `clippy -D warnings` green.

## Batch 3 — five parallel worktree agents (merged)

| Agent | Ownership | Result |
|-------|-----------|--------|
| FUSE xattr | fuse + formats-tar | Serve `user.hash.*` via listxattr/getxattr |
| SquashFS | formats-squashfs | `backhand` in-process; unsquashfs fallback |
| Commit-overlay | compositing write_overlay | gzip/bzip2/xz recompress commit |
| EXT4 | formats-ext4 | `ext4-view` pure + debugfs fallback |
| WebDAV | remote | `webdav://` / `webdavs://` file materialize |

## Batch 4 — five parallel worktree agents (merged)

| Agent | Ownership | Result |
|-------|-----------|--------|
| In-FS control | compositing | `/.ratarmount-control/` layer; main wires with socket |
| Codec + `-P` | compress + core | `ParallelizationSpec`, bzip2 threads, zstd seek table |
| Multi-part ZIP | formats-zip | `.z01`+`.zip` / `.zip.001` join + password AES |
| SQLAR encrypt | formats-sqlar | detect + optional `sqlcipher` feature |
| SMB | remote | `smb://` via smbclient CLI |

## Batch 5 — five parallel worktree agents (merged)

| Agent | Ownership | Commit (on main) | Result |
|-------|-----------|------------------|--------|
| Codec threads | `ratarmount-compress/**` | `12ad752` | `open_*_with_threads` for xz/zstd/gzip |
| SquashFS xz | `formats-squashfs` | `8024300` | in-process XZ via workspace `xz2` |
| Remote index | `index` + remote paths | `3e1488e` | materialize http(s)/file:// index |
| use-backend order | `ratarmount/src/factory.rs` (probe order) | `4a60f36` | `--use-backend` reorders format probe |
| CLI polish | `ratarmount` main CLI | `8452153` | color env, OSS attributions, `-P` help |

**Orchestrator glue:** factory opens gzip/xz/zstd/bzip2 via `options.threads_for(...)` + `*_with_threads`.

## Still open (later / batch 6+)

| Gap | Notes |
|-----|--------|
| True Range without materialize for format openers | Formats still need local path after fetch |
| Dropbox / full fsspec | not started |
| Full `-P` for remaining long-tail codecs | gzip/xz/zstd/bzip2 wired; lz4/lzip/… still default |
| True bzip2 bit-block map | multi-stream parallel only |
| lrzip | not started |
| True multi-disk ZIP EOCD | multi-part join exists; EOCD spanning disks limited |

## Verify

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
# split: ratarmount -f tests/simple-file-split.001 mnt/
# hashes: ratarmount --hashes sha256,crc32 --no-mount archive.tar
# threads: ratarmount -P gzip:4,xz:2,zstd:4,bzip2:4 -f archive.tar.gz mnt/
```
