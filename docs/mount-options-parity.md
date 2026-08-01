# Mount options & abilities: Python vs Rust

Last updated: 2026-08-01.

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
| `-w` / `--write-overlay` / `:temp:` | yes | yes | `[x]` |
| `--commit-overlay` | yes | yes (TAR + gzip/bzip2/xz via GNU tar; ZIP full rebuild) | `[x]` / residual encrypted ZIP |
| `-p` / `--prefix` | yes | yes | `[x]` |
| `--file-versions` / `--no-file-versions` | yes | **both forms** | `[x]` |
| `--control-interface` | yes (in-FS `/.ratarmount-control/`) | Unix socket | `~` different surface |
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
| `--union-resolve-symlinks` | no (issue #160) | **added** (opt-in multi-hop resolve within winning source; B-4 dir>symlink unchanged) | `~` Rust-only FR-10 residual |
| `--index-file` / `:memory:` / folders | yes | yes | `[x]` |
| Remote/compressed index URL | yes | no | `[ ]` |
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
| Multi archive/folder union (later wins) | yes | yes | `[x]` |
| Subfolder layout (`--disable-union-mount`) | yes | **added** | `[x]` |
| Recursive nested archives | yes | yes | `[x]` |
| Lazy recursive mount | yes | yes | `[x]` |
| Configurable recursive extension set | yes | **added** | `[x]` |
| Write overlay + whiteouts | yes | yes | `[x]` |
| Commit overlay into TAR | yes | uncompressed + GNU tar | `~` |
| File versions virtual dirs | yes | yes | `[x]` |
| Prefix remount | yes | yes | `[x]` |
| Path transform on members | yes | **added** | `[x]` |
| Encrypted 7z/ZIP password(s) | yes | yes | `~` ZIP crypto limited |
| Control channel | in-FS folder | Unix socket | `~` |
| Remote `http(s)/s3/ssh` | yes | yes | `~` no Range readers |

## Implementation notes (this work)

- New CLI flags land in `ratarmount/src/main.rs` and flow through `OpenOptions` / `CompositingOptions`.
- Recursive extension sets live in `ratarmount-compositing` (`is_archive_filename_with` / `parse_recursive_extensions`).
- Path `--transform` is a `TransformMountSource` layer (regex on full path).
- `--disable-union-mount` wraps each source in a basename prefix then unions.
- `--use-backend` reorders factory detection for known backend names (see `--print-features`).

### `-g` / `--gzip-seek-point-spacing` (Python `-gs`)

Clap: short `-g`, long `--gzip-seek-point-spacing`, visible alias `--gs`. Value is **MiB** of **uncompressed** distance between seek checkpoints (default **16.0**); converted to bytes in `OpenOptions.gzip_seek_point_spacing` (factory / compress use 0 → `DEFAULT_GZIP_SEEK_SPACING` = 16 MiB).

| Workload | Suggested value |
|----------|-----------------|
| General / sequential | **16** (default) |
| Random-heavy FUSE | **1–4** — less decode-from-checkpoint work per seek; **higher open time and RSS** (more cloned inflate states) |

Applies to default **G3** seekable gzip (`.gz` / `.tar.gz`) and is also the soft spacing hint for opt-in rapidgzip when preferred. Does not invent thruput; denser spacing is a latency/open-cost tradeoff. G3 polish A–E (decoded-window LRU, RGZI warm, auto readahead, hard GZIDX window apply, GZIDX export) is tracked in [`tasks/g3-polish-batch.md`](tasks/g3-polish-batch.md) and the [G3 polish](gzip-binding-decision.md#g3-polish) subsection of the binding decision.
