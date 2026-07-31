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
| **high** ✅ | compress / nested zstd | `zstd_seek.rs` | Shared zstd seek+read race | **Fixed** `c20fb64` — private pos + concurrent test | — |
| **high** ✅ | fuse / write overlay | `fuse/lib.rs` | `getattr` ignores overlay refresh | **Fixed** `cd887a5` — getattr → `file_info_for_ino`, overlay attr TTL 0 | — |
| **high** ✅ | fuse / write overlay | `fuse/lib.rs` | `dir_cache` never invalidated | **Fixed** `cd887a5` — invalidate on create/mkdir/unlink/rmdir | — |
| **high** ✅ | index reuse / factory | factory + tar + zip + index | Index reused without fingerprint | **Fixed** `7e8a5c2` — tarstats size/mtime/sample; TAR/ZIP/side-tables | residual: other formats |
| **high** ✅ | compositing / B-4 | `union.rs` | Folder cache drops symlink-branch | **Fixed** `00d2dce` — cache followable symlink dirs + ImmFolder test | — |
| **medium** ✅ | zip inflate cache | zip | Sticky inflate errors | **Fixed** `39c54b3` — drop slot on Err; retry tests | — |
| **medium** ✅ | tar parse DoS | tar | Uncapped header allocations | **Fixed** `92190d5` — 16 MiB cap | — |
| **medium** ✅ | tar dumpdir versions | tar | tombstone vs versions | **Fixed** `92190d5` — hide all versions | — |
| **medium** ✅ | packaging | packages.yml | Tag vs Cargo.toml | **Fixed** `805be10` + `test-version-resolve.sh` | — |
| **medium** ✅ | write overlay security | write_overlay.rs | Symlink escape | **Fixed** `00d2dce` — O_NOFOLLOW + root confinement | — |
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

## 4. Fix batch (2026-07-31) — high/medium locally reproducible items

All high + medium items above that can be fixed without macOS/FUSE kext were
farmed to worktree subagents with regression tests and merged to `main`:

| Finding | Status | Commit (approx) |
|---------|--------|-----------------|
| zstd Shared seek+read race | **fixed** | `c20fb64` |
| FUSE getattr + dir_cache | **fixed** | `cd887a5` |
| Union cache symlink + overlay escape | **fixed** | `00d2dce` |
| ZIP sticky inflate errors | **fixed** | `39c54b3` |
| TAR header size cap + dumpdir versions | **fixed** | `92190d5` |
| Packages tag ≡ Cargo.toml | **fixed** | `805be10` |
| Warm index tarstats fingerprint | **fixed** (TAR/ZIP/factory side-tables) | `7e8a5c2` |

### Residual after fix batch
- Other formats’ `open_existing` (7z, ISO, …) still backendName-only unless they adopt `check_tarstats_matches_archive`.
- Same-size/same-mtime mid-file archive replace on large files (>256 KiB sample) is a thin residual.
- Legacy indexes without `tarstats` still warm-load.
- Dead gzip `_lock` field (low) not cleaned.
- Full fuser Request-mock getattr not exercised (helpers unit-tested).

### Recommended next actions (remaining only)

1. Adopt tarstats check on remaining format open_existing paths (7z, etc.).
2. Optional: remove dead gzip `_lock`; readdirplus entry TTL with overlay.
3. Optional: strengthen large-archive fingerprint (full hash or content sample policy).

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
