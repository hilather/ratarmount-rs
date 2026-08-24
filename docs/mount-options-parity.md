# Mount options & abilities: Python vs Rust

Last updated: 2026-08-23.

## Summary

**Not full parity yet.** Core day-to-day mount flags (`-r/-l/-s/-w/-f/-u`, indexes, passwords, FUSE `-o`) are present. Gaps are mainly advanced recursion filters, path transforms, union layout, backend selection, and a few index/control options.

Legend: `[x]` parity · `~` partial · `[ ]` missing

---

## CLI mount options

| Option | Python | Rust | Status |
|--------|--------|------|--------|
| `-u` / `--unmount` | yes | yes | `[x]` |
| `-f` / `--foreground` (default daemonize) | yes | yes | `[x]` |
| `-c` / `--recreate-index` | yes | yes | `[x]` |
| `--no-recreate-index` | yes | **added** | `[x]` |
| `--recreate-index-on-errors` | yes | default behavior only | `~` |
| `--no-mount` | yes | yes | `[x]` |
| `-r` / `--recursive` | yes | yes | `[x]` |
| `--recursion-depth` | yes | yes | `[x]` |
| `-l` / `--lazy` | yes | yes | `[x]` |
| `-s` / `--strip-recursive-tar-extension` | yes | yes | `[x]` |
| `--recursive-extensions` | yes | **added** | `[x]` |
| `--transform-recursive-mount-point` | yes | yes | `[x]` |
| `--transform` (member path rewrite) | yes | **added** | `[x]` |
| `-w` / `--write-overlay` / `:temp:` | yes | yes (missing uncompressed `.tar` / `.tar.zst` created as an empty archive; `:temp:` still creates the **archive**) | `[x]` |
| `--commit-overlay` | yes | yes (TAR + gzip/bzip2/xz via GNU tar; `.tar.zst` splice including earlier-frame delete; ZIP full rebuild; create-if-missing for uncompressed `.tar` only) | `[x]` / residual encrypted ZIP |
| `--commit-overlay-on-exit` | no | **added** (uncompressed TAR or `.tar.zst` + durable `-w`; same create-if-missing as `-w`; last-frame zstd rewrite — does not recompress the prefix; persist still copies the compressed file; remount still reindexes the whole TAR; 2× compressed disk headroom; never refuse on size; warn when last-frame uncompressed > 64 MiB; gzip rejected; live still **rejects** prefix-frame mutate — offline `--commit-overlay` is the zstd escape hatch; SIGINT/SIGTERM / serve return) | `[x]` Rust-only |
| `--commit-overlay-interval DURATION` | no | **added** (`0` off; `2s`/`15m`/`1h`; uncompressed TAR or `.tar.zst` + durable `-w`; same create-if-missing as `-w`; in-process; commits overlay files whose host mtime is at least DURATION old **and** that have no open write fd, not a dump of every overlay file on the clock; same last-frame cost model) | `[x]` Rust-only |
| `-p` / `--prefix` | yes | yes | `[x]` |
| `--file-versions` / `--no-file-versions` | yes | **both forms** | `[x]` |
| `--control-interface` | yes (in-FS `/.ratarmount-control/`) | Unix socket | `~` different surface |
| `--nfs` | no | **added** (userspace NFS; NFSv3 default; no FUSE mount required) | `[x]` Rust-only |
| `--nfs-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20490`) | `[x]` |
| `--nfs-vers 3\|4` | no | **added** (default `3`; `4`/`4.1` need `--nfs` + a `nfsv4` binary — Linux/macOS packages compile it; source `--features nfsv4`, rustc ≥ 1.88; ignored without `--nfs`; `4.0` rejected) | `[x]` Rust-only |
| `--nfs-export-name` | no | **added** (MOUNT export name; warned/ignored on `--nfs-vers 4`) | `[x]` |
| `--http` | no | **added** (HTTP GET/HEAD Range export; no FUSE mount required; `--http --no-mount` exits 2) | `[x]` Rust-only |
| `--http-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20491`; required value) | `[x]` |
| `--webdav` | no | **added** (PROPFIND Depth 0/1 + GET; PUT/DELETE/MKCOL/MOVE with `-w`) | `~` LOCK residual |
| `--webdav-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20492`; required value) | `[x]` |
| `--smb` | no | **added** (userspace SMB 2.0.2; share `--smb-share` default `ratarmount`) | `~` signing / Finder residual |
| `--smb-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20445`; required value) | `[x]` |
| `--smb-share NAME` | no | **added** (TREE_CONNECT share; default `ratarmount`) | `[x]` |
| `--ninep` | no | **added** (9P2000.L TCP; canonical flag, not `--9p`) | `[x]` / virtio residual |
| `--ninep-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20493`; required value) | `[x]` |
| `--sftp` | no | **added** (`--features sftp-russh`; packages enable it; else exit 2) | `~` russh MSRV 1.85 / password residual |
| `--sftp-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20222`; required value) | `[x]` |
| `--sftp-authorized-keys PATH` | no | **added** (required when bind is not loopback) | `[x]` |
| `serve` subcommand | no | **added** (optional sugar: `ratarmount serve --nfs --http ARCHIVE`; ≥1 export required; incompatible with `--no-mount`; no `--fuse`; booleans remain the stable interface) | `[x]` Rust-only |
| `-o` / `--fuse` | yes | yes | `[x]` |
| `-e` / `--encoding` | yes | yes | `[x]` |
| `-i` / `--ignore-zeros` | yes | yes (`-i` + long) | `[x]` |
| `--gnu-incremental` / `--detect-gnu-incremental` | yes | **both** | `[x]` |
| `-P` / `--parallelization` | backend matrix string | matrix string (`1`/`0`/`bzip2:4,…`) | `[x]` / `~` sequential codecs API-only |
| `--parallel-nested N` | n/a (Python uses process pool elsewhere) | **added** (`0`/`auto` = cores; `1` = sequential; `N≥2` = cap; FR-6 / #80 eager same-dir only; lazy ignores) | `[x]` |
| `--password` | yes | yes (repeatable) | `[x]` |
| `--password-file` | yes | **added** | `[x]` |
| `--use-backend` | yes | **added** | `[x]` reorders uncompressed format probe (last flag highest priority) |
| `--disable-union-mount` | yes | **added** | `[x]` |
| `--union-mount-cache-max-depth` | yes | yes (folder→sources cache) | `[x]` |
| `--union-mount-cache-max-entries` | yes | yes | `[x]` |
| `--union-mount-cache-timeout` | yes | yes (seconds) | `[x]` |
| `--union-resolve-symlinks` | no (issue #160) | **added** (opt-in multi-hop resolve within winning source; B-4 dir>symlink unchanged; cheap `list_dirents` + per-symlink `lookup`, not fat `list()`) | `~` Rust-only FR-10: `lookup(join(listed_path, name))` may leave `S_IFLNK` on path-keyed archives listed through a symlink-to-dir |
| `--index-file` / `:memory:` / folders | yes | yes | `[x]` |
| Remote/compressed index URL | yes | yes (`http(s)://` / `file://` + gzip/xz/zstd/bz2 decompress; `ratarmount-index` `location.rs`) | `[x]` |
| `--verify-mtime` | yes | yes | `[x]` |
| `--force-folder-index` | yes | accepted (folders still live) | `~` |
| `--hashes` | yes | **added** (crc32/md5/sha1/sha256 → index xattrs; path-backed post-build) | `~` |
| `--index-minimum-file-count` | yes | yes | `[x]` |
| `-g` / `--gs` / `--gzip-seek-point-spacing` (Python `-gs`) | yes | yes | `[x]` MiB uncompressed checkpoint spacing; **default 16**; denser **1–4** for random-heavy mounts (higher open time / RSS) — see note below |
| `--readahead BYTES` | no (issue [#180](https://github.com/mxmlnkn/ratarmount/issues/180)) | **added** | `[x]` sequential FUSE window per open (`0`=off; `K`/`M`/`G`; max 64 MiB/handle; auto 1 MiB when flag omitted and rapidgzip preferred **or** any input looks like gzip `.gz`/`.tgz`/`.tar.gz`/`.gzip`; explicit `--readahead 0`/`N` overrides) |
| `-d` / `--debug` | yes | yes | `[x]` |
| `--log-file` | yes | yes | `[x]` |
| `--color` / `--no-color` | yes | **added** (logging style) | `~` |
| `--oss-attributions` | yes | **added** (short list) | `~` |
| Multi-source union (positional) | yes | yes + folder cache | `[x]` |
| Default mountpoint (strip extension) | yes | yes | `[x]` |

## Mount abilities (behavior)

| Ability | Python | Rust | Status |
|---------|--------|------|--------|
| Single archive FUSE mount | yes | yes | `[x]` |
| NFSv3 userspace export (`--nfs`) | no | yes (IPv4, localhost default; `-w` overlay writes including rename/symlink) | `[x]` Rust-only |
| NFSv4.1 userspace export (`--nfs --nfs-vers 4`) | no | yes (`MountSource` via embednfs; Linux/macOS packages compile `nfsv4`; `-w` overlay create/write/rename/symlink; Linux kernel client **verified** on loopback via privileged Docker; no Kerberos/LAN/Windows/mux) | `~` Rust-only |
| HTTP GET/HEAD export (`--http`) | no | yes (Range 206; fill-loop; bind `127.0.0.1:20491`) | `[x]` Rust-only |
| WebDAV export (`--webdav`) | no | PROPFIND Depth 0/1; overlay PUT/DELETE/MKCOL/MOVE with `-w` | `~` LOCK residual |
| SMB 2.0.2 export (`--smb`) | no | userspace subset; `smbclient` `ls`/`get` localhost | `~` signing / Finder |
| 9P2000.L TCP (`--ninep`) | no | `trans=tcp` port 20493; writes need `-w` | `[x]` / virtio residual |
| SFTP export (`--sftp`) | no | TCP `:20222`; `sftp-russh` (packages on; default CI off) | `~` Rust-only |
| Multi archive/folder union (later wins) | yes | yes | `[x]` |
| Subfolder layout (`--disable-union-mount`) | yes | **added** | `[x]` |
| Recursive nested archives | yes | yes | `[x]` |
| Lazy recursive mount | yes | yes | `[x]` |
| Configurable recursive extension set | yes | **added** | `[x]` |
| Write overlay + whiteouts | yes | yes | `[x]` |
| Commit overlay into TAR | yes | uncompressed + GNU tar (gzip/bzip2/xz); `.tar.zst` splice (offline earlier-frame delete shipped; live last-window only) | `[x]` / residual live prefix-frame |
| File versions virtual dirs | yes | yes | `[x]` |
| Prefix remount | yes | yes | `[x]` |
| Path transform on members | yes | **added** | `[x]` |
| Encrypted 7z/ZIP password(s) | yes | yes | `~` ZIP crypto limited |
| Control channel | in-FS folder | Unix socket | `~` |
| Remote `http(s)/s3/ssh` | yes | yes (live Range for TAR/ZIP/gzip/bzip2/xz/zstd + S3 `S3RangeFile`; ssh_config ProxyJump/Include) | `[x]` / `~` ProxyCommand/Match / cookie jar |
| Remote `gs://` / `az://` / `ftp://` / `oci://` / `ipfs://` / `rclone://` | mixed | yes (factory scheme-prefix; OCI overlayfs union; rclone argv) | `[x]` / residuals in [`phase10-remote.md`](phase10-remote.md) |
| Remote directory mounts (S3 prefix / SSH dir / WebDAV / HTTP index) | yes (fsspec) | yes (F-1 `RemoteFolderMountSource`; GCS/Azure/rclone/IPFS folders too) | `[x]` |

## Implementation notes (this work)

- New CLI flags land in `ratarmount/src/main.rs` and flow through `OpenOptions` / `CompositingOptions`.
- Recursive extension sets live in `ratarmount-compositing` (`is_archive_filename_with` / `parse_recursive_extensions`).
- Path `--transform` is a `TransformMountSource` layer (regex on full path).
- `--disable-union-mount` wraps each source in a basename prefix then unions.
- `--use-backend` reorders factory detection for known backend names (see `--print-features`).
- Export flags (`--http` / `--webdav` / `--smb` / `--ninep` / `--sftp`) are booleans (`ArgAction::SetTrue`) with required-value binds (`num_args = 1`). There is no `serve` subcommand and no `--fuse` flag. See [`export.md`](export.md).

### `-g` / `--gzip-seek-point-spacing` (Python `-gs`)

Clap: short `-g`, long `--gzip-seek-point-spacing`, visible alias `--gs`. Value is **MiB** of **uncompressed** distance between seek checkpoints (default **16.0**); converted to bytes in `OpenOptions.gzip_seek_point_spacing` (factory / compress use 0 → `DEFAULT_GZIP_SEEK_SPACING` = 16 MiB).

| Workload | Suggested value |
|----------|-----------------|
| General / sequential | **16** (default) |
| Random-heavy FUSE | **1–4** — less decode-from-checkpoint work per seek; **higher open time and RSS** (more cloned inflate states) |

Applies to default **G3** seekable gzip (`.gz` / `.tar.gz`) and is also the soft spacing hint for opt-in rapidgzip when preferred. Does not invent thruput; denser spacing is a latency/open-cost tradeoff. G3 polish A–E (decoded-window LRU, RGZI warm, auto readahead, hard GZIDX window apply, GZIDX export) is tracked in [`tasks/g3-polish-batch.md`](tasks/g3-polish-batch.md) and the [G3 polish](gzip-binding-decision.md#g3-polish) subsection of the binding decision.
