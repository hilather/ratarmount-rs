# Code review — 2026-07-31 (v0.1.12 / HEAD ~08150d1 era)

Proactive bug hunt on high-risk recent work and classic FUSE/archive footguns.
Read-only review of production paths; no product code changes in this pass.

## 1. Executive summary

Recent fixes for gzip shared-reader races, FUSE short-read assembly, 7z FILETIME,
encrypted-open errno mapping, write-overlay open paths, dumpdir whiteouts, and
B-119 index-minimum-count look **substantially correct and well regression-tested**.
Several residual holes remain, mostly at seams between new helpers and older call
sites.

The strongest production risks found are: (1) **zstd `Shared` backend still races
seek/read** the way gzip used to; (2) **FUSE `getattr` still serves stale
inode-cache sizes** despite `file_info_for_ino` knowing how to refresh under a write
overlay; (3) **on-disk indexes are reused after only `backendName` checks**, with no
`tarstats` size/mtime gate, so an archive replaced in place can serve wrong member
bytes; (4) **union folder cache + B-4 directory-over-symlink** can list children from a
symlink branch that `lookup`/`open` later cannot see when sources are immutable
archives. None of these are style nits — they produce truncated data, wrong sizes,
or silent wrong content.

## 2. Findings table

| Severity | Area | File:line (approx) | Title | Description | Suggested fix |
|----------|------|--------------------|-------|-------------|---------------|
| **high** | compress / nested zstd | `ratarmount-compress/src/zstd_seek.rs` ~621–724 | Shared zstd seek+read race | `CompressedHandle::Shared` locks the mutex for each `seek`/`read` separately and **does not keep a private compressed offset** (unlike the gzip fix in `gzip_seek.rs` ~594–658). `ensure_frame` does `seek` then `read_exact` / stream decode with the lock released between ops. Concurrent nested/from-reader FUSE opens can interleave cursors → truncated/wrong frame payload (same class as fixed gzip `UnexpectedEof`). Path backend is fine (private FD). | Mirror gzip: `Shared { inner, pos }`, re-`seek(Start(pos))` under one lock on every `read`, update `pos`. Add `shared_from_reader_concurrent_readers_full_payload` analogue in `zstd_seek` tests. |
| **high** | fuse / write overlay | `ratarmount-fuse/src/lib.rs` ~227–249 vs ~318–337 | `getattr` ignores overlay refresh helper | `file_info_for_ino` always re-lookups when `overlay.is_some()` (regression-tested). **`getattr` still short-circuits on `cached_fi`** and never calls `file_info_for_ino`. After create (size 0) → write → `stat`/`ls -l`, size can stay 0 until something overwrites the cache. Open/cat may work (overlay FD path) while metadata lies. Test name claims getattr but only exercises the helper. | Make `getattr` use `file_info_for_ino`. Prefer short/zero attr TTL for overlay-backed paths. Extend the regression test to call the getattr path (or assert via a thin wrapper) after write. |
| **high** | fuse / write overlay | `ratarmount-fuse/src/lib.rs` ~173–197, ~647–768 | `dir_cache` never invalidated | `list_mode_cached` caches parent listings for `DIR_CACHE_TTL` (30s). `create` / `mkdir` / `unlink` / `rmdir` never clear `dir_cache`. New files can be missing from `readdir` for up to 30s; deleted names can linger. | On mutating ops, drop the parent path entry (or flush all). Or disable `dir_cache` when `overlay.is_some()`. Add regression: create then readdir must list the name. |
| **high** | index reuse / factory | `ratarmount/src/factory.rs` ~1260–1283; `ratarmount-formats-tar/src/lib.rs` ~250–271; zip `open_existing` ~351–357 | Index reused without archive fingerprint | Warm open loads sibling `*.index.sqlite` when present and only checks **`backendName`**. `tarstats` (size/mtime) is **written** but never compared to the current archive. Replacing `archive.tar` in place (or restoring an old index next to a new archive) yields wrong offsets → wrong/garbage reads without rebuild. Same pattern for ZIP and likely other formats. | On existing-index open: parse `tarstats`, compare `st_size`/`st_mtime` to current `metadata()`; mismatch → rebuild. Optionally hash first/last 512B. Gate RGZI / zstdblocks / bzip2blocks import on the same check. Regression: write index, overwrite archive, remount must rebuild. |
| **high** | compositing / B-4 | `ratarmount-compositing/src/union.rs` ~87–153, ~176–212, ~296–322, ~622–636 | Folder cache drops symlink-branch under immutable sources | `build_folder_cache` only records **real directories** (`S_IFDIR`), not followable symlinks. `sources_for_path` then filters **immutable** sources to those cached indices. B-4 `list` walks all sources (and follows one-hop symlinks), so children from a symlink-only archive branch appear in listings, but `lookup`/`open` for those paths may skip that source → **ENOENT after ls**. Regression test uses mutable `FolderMountSource` (`is_immutable() == false`), which always consults every source — so the cache hole is untested. | When caching, include sources where `list_from_source` succeeds (dir **or** followable symlink). Or: if any source has a non-dir symlink at a path while another has a dir, treat that path as uncached / consult all. Add ImmFolder/archive-style B-4 test that asserts `lookup`+`open` of `file1` and `file2`. |
| **medium** | zip inflate cache | `ratarmount-formats-zip/src/lib.rs` ~98–120 | Sticky inflate errors in `OnceLock` | Failed inflate stores `Err(String)` forever for that header key. Transient I/O (remote Shared backend) permanently poisons the member for the mount lifetime. | On error, remove the slot (or use a one-shot that allows retry). Only cache `Ok`. |
| **medium** | tar parse DoS | `ratarmount-formats-tar/src/lib.rs` ~1289–1310, similar elsewhere | Uncapped `size as usize` allocations | PAX/GNU long-name bodies do `vec![0u8; size as usize]` from header size with no upper bound. Hostile tar can OOM the mounter during index build. | Cap header payload sizes (e.g. multi‑MiB limit); reject or skip absurd members. |
| **medium** | tar dumpdir versions | `ratarmount-formats-tar/src/lib.rs` ~622–638 | `versions()` vs non-zero version lookup | If newest row is a dumpdir tombstone, `versions` returns **0** (absent), but `lookup(path, n)` for older non-tombstone versions can still return data. Versioning API inconsistent for incremental dumps. | Either filter tombstones in `version_count` and renumber live versions, or document that only version 0 is dumpdir-aware and make positive versions also hide deleted names. |
| **medium** | packaging | `.github/workflows/packages.yml` ~85–94 (all jobs) | Tag version not checked against Cargo.toml | `VERSION` comes from tag (`v` strip) or first `Cargo.toml` `version` line. No assert that annotated tag matches workspace version → possible mismatched package names vs binary version. | After resolve: `test "$VERSION" = "$(cargo metadata …)"` or grep workspace version; fail job on mismatch. |
| **medium** | write overlay security | `ratarmount-compositing/src/write_overlay.rs` ~87–93, ~231–247 | Overlay open follows host symlinks | `realpath` is path join + `normpath` only; `libc::open` follows symlinks. A pre-seeded symlink under the overlay root can redirect writes outside the overlay folder. | After resolve, `O_NOFOLLOW` for open/create, or verify canonical path stays under `root`. |
| **low** | compress | `ratarmount-compress/src/gzip_seek.rs` ~1496–1514 | Dead `_lock` on `SharedSeekableGzip` | Comment claims serialisation of concurrent opens; `reader()` never locks `_lock`. Harmless after per-read re-seek fix; misleading. | Remove field or document that safety is in `CompressedHandle`. |
| **low** | tests / B-4 | `union.rs` ~622–636 | B-4 coverage incomplete | Mutable folders hide the cache interaction (see high finding). | Add immutable-source B-4 regression. |
| **low** | docs / residual | `docs/tasks/upstream-bugs-inspection.md` | Multi-archive GNU incremental residual | Single-stream dumpdir MVP is done; multi-archive `.snar` union still residual (documented). Not a regression. | Track only; no code bug in current MVP path. |

## 3. Positive notes

What looks solid after reading the code:

- **Gzip concurrent Shared backend** (`gzip_seek.rs`): private logical compressed
  offset + re-seek under the mutex on every `read`. Concurrent regression test
  `shared_from_reader_concurrent_readers_full_payload` is the right shape.
- **ZIP Shared stream**: `SharedSeekHandle` / `SharedSeekRegion` already re-seek
  under one lock; deflate path holds the mutex for the full compressed read then
  inflates offline. Inflate single-flight (`OnceLock`) is a good FR-4 design for
  success paths.
- **TAR `PositionedSeekReader`**: same private-pos pattern as gzip for nested
  shared stencils.
- **FUSE `fill_read_for_fuse`**: correctly loops short codec reads so FUSE short
  reply ≠ premature EOF; unit tests cover short-window and true-EOF cases.
- **`io_to_errno`**: `PermissionDenied` → `EACCES` (encrypted nested without
  password) with a regression test.
- **7z FILETIME**: delta uses 100 ns ticks (`FILETIME_UNIX_DELTA`); unit + fixture
  mtime tests present.
- **HTTP Basic auth** (`ratarmount-remote`): URL userinfo stripped from wire URL;
  env fallback; Basic on HEAD/GET/Range; 401 messaging; tests for URL vs env
  precedence.
- **B-119 index min count**: discard helpers + factory gate + live-connection
  after unlink tests are coherent.
- **GNU dumpdir whiteouts**: tombstone linkname, list/lookup filter, single-stream
  multi-dumpdir state machine — MVP matches documented intent.
- **Union B-4 list/lookup policy** (rightmost directory beats symlink; merge never
  replaces dir with symlink) is clearly implemented for the non-cached path.
- **Packages**: VERSION is derived per job (no hardcoded `0.1.x`); empty release
  asset filter + `test-release-asset-filter.sh` guard the empty-asset failure mode.
- **Write overlay open path**: RO open of overlay files uses overlay FD (not
  size-0 Empty backend) — addresses the classic write-then-cat empty bug for data
  plane.

## 4. Recommended next actions (ordered)

1. **Fix zstd Shared `CompressedHandle`** (copy gzip’s private-pos pattern) + concurrent
   regression test. Same class of production truncation as the nested gzip bug.
2. **Wire FUSE `getattr` (and preferably setattr replies) through `file_info_for_ino`**;
   zero/short TTL when overlay is active; extend the size-0 regression to the real
   getattr path.
3. **Invalidate `dir_cache` on overlay mutations** (or disable when writable).
4. **Validate `tarstats` (size + mtime) before any warm index / side-table import**
   (TAR, ZIP, 7z, gzip RGZI, zstdblocks, bzip2blocks). Fail closed → rebuild.
5. **Fix union folder cache for B-4** with immutable sources; add ImmFolder/archive
   regression that `lookup`+`open` succeed for both symlink-branch and dir-branch
   children.
6. **InflateCache**: do not permanently cache errors.
7. **Cap TAR pax/long-name payload sizes** during parse.
8. **CI packaging**: assert tag version == workspace `Cargo.toml` version.
9. Optional hardening: overlay `O_NOFOLLOW` / root confinement; dumpdir version
   counting consistency; remove dead gzip `_lock`.

### Suggested verification commands (after fixes)

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings

cargo test -p ratarmount-compress --lib shared_from_reader
cargo test -p ratarmount-compress --lib stenciled_fuse
# after zstd fix:
cargo test -p ratarmount-compress --lib zstd

cargo test -p ratarmount-fuse --lib fill_read
cargo test -p ratarmount-fuse --lib overlay_file_info
cargo test -p ratarmount-fuse --lib io_to_errno

cargo test -p ratarmount-compositing --lib union
cargo test -p ratarmount-formats-tar --lib dumpdir
cargo test -p ratarmount index_minimum_file_count
```

---

*Reviewer: Grok code-review subagent. Scope: main branch high-risk areas listed in
the review brief. Product code not modified.*
