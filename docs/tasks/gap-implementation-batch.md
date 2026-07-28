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

## Batch 6 — five parallel worktree agents (merged)

| Agent | Ownership | Commit (on main) | Result |
|-------|-----------|------------------|--------|
| Long-tail `-P` | `ratarmount-compress` lz4/lzip/lzo | `cd08144` | `open_*_with_threads` for lz4/lzip/lzo |
| Multi-disk ZIP EOCD | `formats-zip` | `22c7b7b` | normalize multi-disk EOCD after part join |
| Dropbox | `remote` | `33ceae0` | `dropbox://` via `DROPBOX_TOKEN` |
| Compressed index | `index` | `6d46047` | gzip/xz/zstd/bz2 index decompress |
| PDF images | `formats-pdf` | `db9a04b` | XObject images under `images/` |

**Orchestrator glue:** factory opens lz4/lzip/lzo via `options.threads_for(...)` + `*_with_threads`.

## Batch 7 — five parallel worktree agents (merged)

| Agent | Ownership | Result |
|-------|-----------|--------|
| bzip2 bit-block | `bzip2_seek.rs` | retained bit-block map + on-demand block decode |
| zlib/lzma/Z + lrzip | compress (excl. bzip2) | `-P` APIs; `Lrzip` detect + `lrzip` CLI materialize |
| remote Range + Dropbox folder | remote | `resolve_http` / `RemoteAccess`; `DropboxMountSource` |
| PDF Flate PNG | formats-pdf | Flate/raw Gray/RGB → PNG |
| tar/zip readers | formats-tar + zip | `open_from_reader` for Range |

**Orchestrator glue:** factory wires zlib/lzma/Z threads, Lrzip materialize, HTTP Range TAR/ZIP via `open_from_reader`, Dropbox folder mount.

## Batch 8 — five parallel worktree agents (merged)

| Agent | Ownership | Result |
|-------|-----------|--------|
| bzip2 large maps | `bzip2_seek.rs` | bit-block map cap 8 MiB → **256 MiB** + faster scan |
| gzip from reader | `gzip_seek.rs` | `open_*_from_reader` for Range / Cursor |
| xz stream/block map | `xz_seek.rs` | Index + multi-stream seek maps |
| Dropbox TTL/Range | `remote/dropbox` | 30s list TTL; chunked content Range |
| PDF CMYK/bpc | `formats-pdf` | CMYK + 1/2/4/16-bpc → PNG |

**Orchestrator glue:** factory HTTP Range path opens **gzip** (incl. `.tar.gz`) via live Range + `SharedSeekableGzip::open_with_threads_from_reader`.

## Batch 9 — five parallel worktree agents (merged)

| Agent | Ownership | Result |
|-------|-----------|--------|
| xz from reader | `xz_seek.rs` | `open_seekable_xz_*_from_reader` |
| zstd from reader | `zstd_seek.rs` | `open_seekable_zstd_*_from_reader` |
| bzip2 from reader | `bzip2_seek.rs` | `open_seekable_bzip2_*_from_reader` |
| S3 creds | `remote/s3.rs` | IMDS/ECS role + anonymous GET |
| PDF Indexed/ICC | `formats-pdf` | Indexed + ICCBased N=1/3/4 → PNG |

**Orchestrator glue:** factory HTTP Range opens gzip/bzip2/xz/zstd (+ TAR/ZIP) via live Range + from_reader APIs.

## Nested archive random access (no temp spool)

| Option | Status | Notes |
|--------|--------|-------|
| AutoMount open nested via `Read+Seek` | **done** | `OpenNestedReaderFn` + path spool fallback |
| 7z `open_from_reader` / shared pack IO | **done** | `SharedArchiveIo` + `SeekPackSource` |
| TAR nested via `open_from_reader` (stencil) | **done** | factory nested reader opens TAR |
| ZIP store stencil nested open | later | factory already tries ZIP from reader |
| Virtual nested index (lazy child SQLite) | later | `:memory:` used for nested today |
| Flattened recursive TAR index | later | outer absolute offsets |
| 7z store-in-solid nested no-tmp | later | progressive outer + inner reader |
| Tests: nested 7z + nested TAR | **done** | sevenzip + automount unit tests |

## Batch 10 — five parallel worktree agents (merged)

| Agent | Ownership | Result |
|-------|-----------|--------|
| bzip2 large maps | `bzip2_seek.rs` | file-backed maps beyond 256 MiB compressed |
| gzip Tier C | `gzip_seek.rs` | `RGZI` v1 seek-index blob import/export |
| index side tables | `ratarmount-index` | gzipindexes/zstdblocks/bzip2blocks schema + API |
| S3 Range | `remote/s3.rs` | Range GetObject + prefer-range + `S3RangeFile` |
| CI gates | benchmarks + ci.yml | cold-index hard gate from `rust-gates.json` |

## Batch 11 — five parallel worktree agents (merged)

| Agent | Ownership | Result |
|-------|-----------|--------|
| 7z solid nested | formats-sevenzip | progressive solid member reader for nested open |
| TAR nested index | formats-tar | `nestedTarMembers` metadata + stencil open API |
| lrzip libarchive | libarchive + compress + factory | CLI first, libarchive raw/filter fallback |
| factory glue | factory.rs | gzip RGZI↔index + live S3 Range opens |
| CI full gates | benchmarks + ci.yml | `benchmark-gates-full` with `ALLOW_RATIO_SKIP` |

## Still open (later / batch 12+)

| Gap | Notes |
|-----|--------|
| Flattened recursive TAR **path rows** (not only side-list) | foundation done |
| Pure in-process lrzip (no CLI / no libarchive shellout) | rare |
| Python indexed_gzip blob interop (not only RGZI) | open |
| Non-TAR hash xattrs | open |

## Verify

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
./benchmarks/check-rust-gates.sh
RUN_FULL_BENCH=1 ALLOW_RATIO_SKIP=1 ./benchmarks/check-rust-gates.sh
# s3 live Range: AWS_* ratarmount -f s3://bucket/a.tar mnt/
```
