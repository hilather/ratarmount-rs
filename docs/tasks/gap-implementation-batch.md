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

## Still open (later)

| Gap | Notes |
|-----|--------|
| True Range without materialize for format openers | Formats still need local path after fetch |
| SquashFS xz compressor | backhand xz conflicts with workspace lzma |
| SMB / Dropbox | not started |
| Full `-P` backend parallel matrix | reserved flag only |
| In-FS control folder | Unix socket remains |
| Codec depth (true block maps) | Tier B lite remains |

## Verify

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
# split: ratarmount -f tests/simple-file-split.001 mnt/
# hashes: ratarmount --hashes sha256,crc32 --no-mount archive.tar
```
