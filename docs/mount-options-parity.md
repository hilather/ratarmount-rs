# Mount options & abilities: Python vs Rust

Last updated: 2026-10-17.

## Summary

**Not full parity yet.** Core day-to-day mount flags (`-r/-l/-s/-w/-f/-u`, indexes, passwords, FUSE `-o`) are present. Gaps are mainly advanced recursion filters, path transforms, union layout, backend selection, and a few index/control options.

Legend: `[x]` parity · `~` partial · `[ ]` missing · `[x]` Rust-only = beyond parity

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
| `-w` / `--write-overlay` / `:temp:` | yes | yes (missing uncompressed `.tar` / `.tar.zst` created as an empty archive; `:temp:` still creates the **archive**; a used overlay folder (`.ratarmount-overlay.used` marker; remove it to discard the deletions on purpose; the refusal lists every marker) with a missing (or directory) or table-less database is refused, not recreated; the database and marker names are hidden in the mount and refused for create/delete/rename (`EACCES`) at any depth, ignoring ASCII case; same-named archive members are hidden at any depth) | `[x]` |
| `--commit-overlay` | yes | yes (refuses a used overlay folder whose database is missing, empty or a directory, naming canonical paths (#96; remove the `.ratarmount-overlay.used` marker to discard its deletions on purpose); TAR + gzip/bzip2/xz via GNU tar; `.tar.zst` splice including earlier-frame delete and later complete-TAR-frame delete without `-i`; ZIP full rebuild; create-if-missing for uncompressed `.tar` only) | `[x]` / residual encrypted ZIP |
| `--commit-overlay-mode copy\|append\|auto` | no | **added** (default `copy`; reflink/kernel-copy acceleration; `append` journals adds-only uncompressed TAR / seek-table `.tar.zst` suffixes in place; `auto` also excludes hard-linked archives; other plans copy; in-place readers can observe the write) | `[x]` Rust-only |
| `--commit-overlay-on-exit` | no | **added** (uncompressed TAR or `.tar.zst` + durable `-w`; same create-if-missing as `-w`; last-frame zstd rewrite — does not recompress the prefix; default copy uses reflink/kernel copy when available; opt-in append retains the prefix in place; on-disk sidecar is patched so remount does not rescan prefix frames; `:memory:` still full-rebuild; copy fallback needs 2× compressed disk headroom; append needs old/new suffix space; never refuse on size; warn when last-frame uncompressed > 64 MiB; gzip rejected; live still **rejects** prefix-frame mutate — offline `--commit-overlay` is the zstd escape hatch; later-frame deletes classify past per-frame TAR EOF even when the remount omitted `-i`; SIGINT/SIGTERM / serve return) | `[x]` Rust-only |
| `--commit-overlay-interval DURATION` | no | **added** (`0` off; `2s`/`15m`/`1h`; uncompressed TAR or `.tar.zst` + durable `-w`; same create-if-missing as `-w`; in-process; commits overlay files whose host mtime is at least DURATION old **and** that have no open write fd, not a dump of every overlay file on the clock; same last-frame cost model; later complete-TAR-frame deletes persist even if the remount omitted `-i`) | `[x]` Rust-only |
| `--lower DIR_OR_BUNDLE` | no | **added** (repeatable, bottom to top; sealed read-only layers; optional `-w TOP`; layered commits refused) | `[x]` Rust-only |
| `--allow-unsealed-lower` | no | **added** (explicitly accept unsealed/legacy lowers read-only; stop their writers first) | `[x]` Rust-only |
| `--force-stack-mismatch` | no | **added** (override recorded lower-stack check and record override time) | `[x]` Rust-only |
| `--base-digest sha256:HEX\|none` | no | **added** (trust supplied identity without hashing, or disable identity checking with a warning; requires a writable top) | `[x]` Rust-only |
| `--force-base-mismatch` | no | **added** (override cheap remount identity check, record override time) | `[x]` Rust-only |
| `--overlay-allow GLOBS` | no | **added** (exceptions to read-only rules; most literal components wins, allow wins ties) | `[x]` Rust-only |
| `--journal FILE` | no | **added** (FUSE operation JSONL, including on read-only data mounts; separate from append-commit journal) | `[x]` Rust-only |
| `--journal-reads all\|first` | no | **added** (all coalesced ranges or first nonempty range per handle; complete byte/request counters in either mode) | `[x]` Rust-only |
| `--journal-exclude GLOB` | no | **added** (repeatable root-anchored path rules; marks retained) | `[x]` Rust-only |
| `--journal-sync` | no | **added** (fsync operation journal at unmount) | `[x]` Rust-only |
| `--overlay-readonly GLOBS` | no | **added** (protected overlay paths; EROFS across write frontends) | `[x]` Rust-only |
| `--overlay-quota SIZE` / `--overlay-quota-files N` | no | **added** (shared logical content/file caps including copy-up; EDQUOT; xattr metadata excluded) | `[x]` Rust-only |
| `--sandbox` | no | **added** (allow_other + noatime + caller uid/gid; RAM overlay unless explicit `-w`; Linux) | `[x]` Rust-only |
| `--overlay-tmpfs[=SIZE]` | no | **added** (verified Linux tmpfs; optional logical byte quota, not a RAM reservation; discarded on cleanup) | `[x]` Rust-only |
| `--overlay-tmpfs-allow-commit` | no | **added** (explicitly permits live commit from a RAM overlay) | `[x]` Rust-only |
| `-o uid=UID,gid=GID,umask=MASK` | yes | **added** (reported attrs in FUSE/NFS/9P/SFTP; stored ownership unchanged) | `[x]` |
| `--bind /PATH=SOURCE` | no | **added** (per-source mount path before union; repeatable) | `[x]` Rust-only |
| `--git` / `--git-ref REV` / `repo@REV` | mixed | **added** (explicit worktree Git selection and revision; bad refs fail) | `[x]` Rust-only selectors |
| `--git-prefix PATH` / `--git-synthetic-head` | no | **added** (subtree; history-free one-commit `.git`; private writes with overlay) | `[x]` Rust-only |
| `--roll-every LIMIT` | no | **added** (local TAR / `.tar.zst` numbered union; time, size or both; implies on-exit commit) | `[x]` Rust-only |
| `--commit-manifest` / `--manifest-hashes new|all|none` | no | **added** (opt-in local TAR / `.tar.zst` commit provenance JSONL; default hash policy `new`) | `[x]` Rust-only |
| `--passthrough auto|on|off` | no | **added** (`auto` default; Linux ≥6.9, initial-namespace CAP_SYS_ADMIN, eligible source; daemon fallback) | `[x]` Rust-only |
| `--passthrough-copy` / `--passthrough-copy-max BYTES` / `--passthrough-copy-total-max BYTES` | no | **added** (explicit bounded stored-member copy fallback; default per-member cap 0 disables it) | `[x]` Rust-only |
| `--direct-io` | no | **added** (source-member FOPEN_DIRECT_IO and local TAR/zstd eviction advice; disables passthrough; overlay stays cached) | `[x]` Rust-only |
| `--memory-budget SIZE` | no | **added** (managed RAM pool cap; synchronous fallback under pressure; excludes kernel page cache) | `[x]` Rust-only |
| `overlay-stats OVERLAY [--json]` | no | **added** (overlay usage/deletions without mounting) | `[x]` Rust-only |
| `diff OVERLAY [BASE]` | no | **added** (patch/Git/manifest/hash/stat/names, normalization, `--lower`, `--between`; exits 0 unchanged, 1 changed, 2 error, 3 limit; hash/manifest success is 0) | `[x]` Rust-only |
| `overlay info\|seal\|unseal\|verify\|fsck\|import\|import-upperdir\|pack\|unpack` | no | **added** (offline layer identity, integrity, import and transport) | `[x]` Rust-only |
| `journal summarize\|mark` | no | **added** (operation summaries and root-xattr turn markers) | `[x]` Rust-only |
| `sandbox run` | no | **added** (container attempt, cleanup, hash/manifest/journal report; optional seal/pack) | `[x]` Rust-only |
| `sandbox daemon\|create-base\|new\|list\|diff\|stats\|destroy\|shutdown` | no | **added** (Linux supervisor; Unix socket and pure-Python client) | `[x]` Rust-only |
| `snapshot GIT_BASE OUT.tar.zst [--with-index]` | no | **added** (deterministic committed tree export and optional mount index) | `[x]` Rust-only |
| `snapshot add\|list` | no | **added** (external restic CLI wrapper) | `[x]` Rust-only |
| `corpus MANIFEST MOUNTPOINT` | no | **added** (pinned repository collection) | `[x]` Rust-only |
| `shard` / `export-index --format parquet|jsonl|csv` | no | **added** (dataset packing and index export without FUSE; Parquet is default feature `export-parquet`) | `[x]` Rust-only |
| `-p` / `--prefix` | yes | yes | `[x]` |
| `--file-versions` / `--no-file-versions` | yes | **both forms** | `[x]` |
| `--control-interface` | yes (in-FS `/.ratarmount-control/`) | Unix socket **and** in-FS folder (`status`/`pid`/`unmount`/`help` plus read-only `search/<pattern>` glob locate; quote globs). No FUSE write-then-read `echo pat > search`. With `-w` the folder name is reserved (EACCES). Hidden experimental `--control-socket-only` keeps the socket and omits the folder (used by `sandbox run`). | `[x]` / overlay names not in catalog |
| `--nfs` | no | **added** (userspace NFS; NFSv3 default; no FUSE mount required) | `[x]` Rust-only |
| `--nfs-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20490`) | `[x]` |
| `--nfs-vers 3\|4` | no | **added** (default `3`; `4`/`4.1` need `--nfs` + a `nfsv4` binary — Linux/macOS packages compile it; source `--features nfsv4`, rustc ≥ 1.88; ignored without `--nfs`; `4.0` rejected) | `[x]` Rust-only |
| `--nfs-export-name` | no | **added** (MOUNT export name; warned/ignored on `--nfs-vers 4`) | `[x]` |
| `--http` | no | **added** (HTTP GET/HEAD Range export; no FUSE mount required; `--http --no-mount` exits 2) | `[x]` Rust-only |
| `--http-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20491`; required value) | `[x]` |
| `--webdav` | no | **added** (PROPFIND Depth 0/1 + GET; PUT/DELETE/MKCOL/MOVE/COPY with `-w`; LOCK/UNLOCK; PROPPATCH; Basic env) | `[x]` / mux residual |
| `--webdav-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20492`; required value) | `[x]` |
| `--smb` | no | **added** (userspace SMB 2.0.2 / 3.1.1; share `--smb-share` default `ratarmount`; NTLMv2 + signing when password set; 3.1.1 preauth + optional GCM/CCM encrypt; leases + durable-handle-v1) | `[x]` / Finder not CI |
| `--smb-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20445`; required value) | `[x]` |
| `--smb-share NAME` | no | **added** (TREE_CONNECT share; default `ratarmount`) | `[x]` |
| `--ninep` | no | **added** (9P2000.L TCP; canonical flag, not `--9p`) | `[x]` / virtio residual |
| `--ninep-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20493`; required value) | `[x]` |
| `--sftp` | no | **added** (`--features sftp-russh`; packages enable it; else exit 2; password env `RATARMOUNT_SFTP_PASSWORD` / `_USER`) | `[x]` / russh MSRV 1.85 feature note |
| `--sftp-bind [host:]port` | no | **added** (IPv4 only; default `127.0.0.1:20222`; required value; port 22 is this flag) | `[x]` |
| `--sftp-authorized-keys PATH` | no | **added** (required when bind is not loopback unless password env is set) | `[x]` |
| `--sftp-subsystem` | no | **added** (stdio SFTP v3; exclusive with `--sftp`; ignores bind/keys; needs `sftp-russh`) | `[x]` Rust-only |
| `serve` subcommand | no | **added** (optional sugar: `ratarmount serve --nfs --http ARCHIVE`; ≥1 export required; incompatible with `--no-mount`; no `--fuse`; booleans remain the stable interface) | `[x]` Rust-only |
| `find` sugar | no | **added** (`ratarmount find [--fts] [--hashes] [--xattr NAME[=VALUE]] PATTERN ARCHIVE`; no FUSE; TSV `path\tsize\tmtime`; `--fts` is find-argv only, not a mount flag; `--hashes` includes cheap `user.hash.*` columns / fill when `ALGO` is given) | `[x]` Rust-only |
| `-o` / `--fuse` | yes | yes | `[x]` |
| `-e` / `--encoding` | yes | yes | `[x]` |
| `-i` / `--ignore-zeros` | yes | yes (`-i` + long) | `[x]` |
| `--gnu-incremental` / `--detect-gnu-incremental` | yes | **both** | `[x]` |
| `-P` / `--parallelization` | backend matrix string | matrix string (`1`/`0`/`bzip2:4,…`); CLI default min(cores, 4), reaches zstd decode-ahead | `[x]` |
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
| `--index-id HEX` | no | **added** (required value; `{archive}.index.{sha256}.sqlite` or pointer-named well-known blob; tarstats mismatch / unknown id exit 2) | `[x]` Rust-only |
| `--publish-index` / `--publish-index-to PATH_OR_URL` | no | **added** (local or hf/s3/gs/az blob + pointer publication; local keep-last-2; OCI referrer PUT residual) | `[x]` Rust-only |
| `--publish-revision REV` / `--create-pr` | no | **added** (Hub publication branch / PR; `--create-pr` also supports live Hub archive write-back) | `[x]` Rust-only |
| Remote/compressed index URL | yes | yes (`http(s)://` / `file://` + gzip/xz/zstd/bz2 decompress; auto `Link: describedby` on archive HEAD + http(s) sibling; OCI referrer on local `oci:{digest}` miss) | `[x]` |
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
| Default mountpoint (strip extension; `<folder>.mounted` when the stem is the folder) | yes | yes | `[x]` |
| Mount point inside its own folder / `-w` base refused (exit 2) | yes (self-bind served via fchdir; strictly-inside not handled) | yes, also via symlink, bind mount (either direction) and case/Unicode alias | `[x]` |

## Mount abilities (behavior)

| Ability | Python | Rust | Status |
|---------|--------|------|--------|
| Single archive FUSE mount | yes | yes | `[x]` |
| NFSv3 userspace export (`--nfs`) | no | yes (IPv4, localhost default; `-w` overlay writes including rename/symlink) | `[x]` Rust-only |
| NFSv4.1 userspace export (`--nfs --nfs-vers 4`) | no | yes (`MountSource` via embednfs; Linux/macOS packages compile `nfsv4`; `-w` overlay create/write/rename/symlink; Linux kernel client **verified** on loopback via privileged Docker; no Kerberos/LAN/Windows/mux) | `~` Rust-only |
| HTTP GET/HEAD export (`--http`) | no | yes (Range 206; fill-loop; bind `127.0.0.1:20491`) | `[x]` Rust-only |
| WebDAV export (`--webdav`) | no | PROPFIND Depth 0/1; overlay PUT/DELETE/MKCOL/MOVE/COPY with `-w`; LOCK/UNLOCK; PROPPATCH; Basic env | `[x]` / mux residual |
| SMB 2.0.2 / 3.1.1 export (`--smb`) | no | userspace subset; guest `smbclient -N` unsigned; password env signs; 3.1.1 preauth + optional encrypt; leases + durable-handle-v1 | `[x]` / Finder not CI |
| 9P2000.L TCP (`--ninep`) | no | `trans=tcp` port 20493; writes need `-w` | `[x]` / virtio residual |
| SFTP export (`--sftp` / `--sftp-subsystem`) | no | TCP `:20222` + stdio subsystem; password env; `sftp-russh` (packages on; default CI off) | `[x]` / russh feature note |
| Multi archive/folder union (later wins) | yes | yes | `[x]` |
| Subfolder layout (`--disable-union-mount`) | yes | **added** | `[x]` |
| Recursive nested archives | yes | yes | `[x]` |
| Lazy recursive mount | yes | yes | `[x]` |
| Configurable recursive extension set | yes | **added** | `[x]` |
| Write overlay + whiteouts | yes | yes; FUSE `-w`: file rename via the overlay (copy-up, replace). Directory rename returns EISDIR, same as NFS/9P/SFTP/SMB. `renameat2` NOREPLACE/EXCHANGE return EINVAL (FUSE ABI < 7.23); NOREPLACE onto an existing name gets EEXIST from the VFS first. On FUSE `-w`, a file that is unlinked or replaced while the kernel still holds it keeps returning its old bytes and attrs (`nlink` 0) until the last reference is dropped. A write handle opened before the rename or unlink keeps writing the orphan (those bytes are discarded at commit). A new write `OPEN` or an fh-less `SETATTR` on that nodeid returns `EACCES`. | `[x]` |
| Commit overlay into TAR | yes | uncompressed + GNU tar (gzip/bzip2/xz); `.tar.zst` splice (offline earlier-frame delete shipped; live last-window only) | `[x]` / residual live prefix-frame |
| File versions virtual dirs | yes | yes | `[x]` |
| Prefix remount | yes | yes | `[x]` |
| Path transform on members | yes | **added** | `[x]` |
| Encrypted 7z/ZIP password(s) | yes | yes | `~` ZIP crypto limited |
| Control channel | in-FS folder | Unix socket + in-FS `/.ratarmount-control/` including read-only `search/<pattern>` | `[x]` / no write-then-read search; overlay names not in catalog |
| Remote `http(s)/s3/ssh` | yes | yes (live Range for TAR/ZIP/gzip/bzip2/xz/zstd + S3 `S3RangeFile`; ssh_config ProxyJump/Include) | `[x]` / `~` ProxyCommand/Match / cookie jar |
| Remote `gs://` / `az://` / `ftp://` / `oci://` / `ipfs://` / `rclone://` | mixed | yes (factory scheme-prefix; OCI overlayfs union; rclone argv + `rclone+`; GCS GOOG1 HMAC; FTP LIST/MLSD folders) | `[x]` / residuals in [`phase10-remote.md`](phase10-remote.md) |
| Remote directory mounts (S3 prefix / SSH dir / WebDAV / HTTP index) | yes (fsspec) | yes (F-1 `RemoteFolderMountSource`; GCS/Azure/rclone/IPFS/FTP folders too) | `[x]` |

Local AI option details: [sandbox](sandbox.md), [Git](git-mounts.md),
[Hub publishing](remote-hf.md), [provenance](provenance.md),
[rolling](rolling-archives.md), [shards](shards.md), and
[FUSE tuning](fuse-kernel-tuning.md).

## Implementation notes (this work)

- New CLI flags land in `ratarmount/src/main.rs` and flow through `OpenOptions` / `CompositingOptions`.
- Recursive extension sets live in `ratarmount-compositing` (`is_archive_filename_with` / `parse_recursive_extensions`).
- Path `--transform` is a `TransformMountSource` layer (regex on full path).
- `--disable-union-mount` wraps each source in a basename prefix then unions.
- `--use-backend` reorders factory detection for known backend names (see `--print-features`).
- Export flags (`--http` / `--webdav` / `--smb` / `--ninep` / `--sftp` / `--sftp-subsystem`) are booleans (`ArgAction::SetTrue`) with required-value binds (`num_args = 1`). Optional `serve` sugar requires at least one export; there is no `--fuse` flag. See [`export.md`](export.md).

### `-g` / `--gzip-seek-point-spacing` (Python `-gs`)

Clap: short `-g`, long `--gzip-seek-point-spacing`, visible alias `--gs`. Value is **MiB** of **uncompressed** distance between seek checkpoints (default **16.0**); converted to bytes in `OpenOptions.gzip_seek_point_spacing` (factory / compress use 0 → `DEFAULT_GZIP_SEEK_SPACING` = 16 MiB).

| Workload | Suggested value |
|----------|-----------------|
| General / sequential | **16** (default) |
| Random-heavy FUSE | **1–4** — less decode-from-checkpoint work per seek; **higher open time and RSS** (more cloned inflate states) |

Applies to default **G3** seekable gzip (`.gz` / `.tar.gz`) and is also the soft spacing hint for opt-in rapidgzip when preferred. Does not invent thruput; denser spacing is a latency/open-cost tradeoff. G3 polish A–E (decoded-window LRU, RGZI warm, auto readahead, hard GZIDX window apply, GZIDX export) is tracked in [`tasks/g3-polish-batch.md`](tasks/g3-polish-batch.md) and the [G3 polish](gzip-binding-decision.md#g3-polish) subsection of the binding decision.

### Process-wide memory budget (Rust extension)

`--memory-budget SIZE` limits reservations for optional buffers, decode windows,
and caches across all open sources. The default preserves existing caps. See
[memory-budget.md](memory-budget.md) for pool shares, fallback paths, control
status fields, and exclusions from this retained-buffer budget.
