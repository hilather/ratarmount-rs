# Code review — fix batch (origin/main..HEAD, 2026-07-31)

**Scope:** 9 commits ahead of `origin/main` (`38534ed`…`d0e4bf1`), ~1.9k LOC across compress / fuse / compositing / zip / tar / index / factory / packaging.

**Verdict:** **Approve with nits.** Fixes match the stated bugs, regression tests are real and symptom-named, and gates (fmt/clippy/scoped tests) are green. Residual risk is documented; nothing blocking merge/push for the intended high/medium remediation.

---

## Commit map

| Commit | Intent |
|--------|--------|
| `c20fb64` | zstd Shared seek+read atomicity |
| `cd887a5` | FUSE getattr refresh + dir_cache invalidation |
| `00d2dce` | Union folder cache symlink dirs + overlay escape |
| `39c54b3` | ZIP inflate non-sticky errors |
| `92190d5` | TAR header size cap + dumpdir version hide |
| `805be10` | packages tag ≡ Cargo.toml |
| `7e8a5c2` | Warm index tarstats fingerprint |
| docs | review notes |

---

## Per-area review

### 1. zstd Shared race — **good**

- Private `pos` + re-`seek(Start(pos))` under one lock on every `read` matches the gzip fix.
- `SeekFrom::End` only locks for size; `Start`/`Current` update logical pos without racing the shared cursor.
- Concurrent test (8 threads × multi-frame body × mid-seek) is the right stress shape.

**Nit:** Path backend still opens a new FD per `ensure_frame` via `open_compressed()`; fine for correctness, not new.

### 2. FUSE getattr / dir_cache — **good**

- `getattr` correctly routes through `file_info_for_ino` (overlay re-lookup).
- Overlay attr TTL 0 is the right kernel-side companion to the inode-cache fix.
- `invalidate_dir_cache` on create/mkdir/unlink/rmdir is complete for listing mutations.
- `ino_for_path_with_fi` now overwrites cached `FileInfo` when fresher data is provided.

**Nits / residual:**

- `readdirplus` still passes bare `TTL` (60s) into `reply.add` for entry attrs, not `attr_ttl()`. Overlay creates may still pin **entry** attrs in the kernel for 60s on readdirplus-heavy clients. Low; data plane/open already fixed.
- Tests exercise helpers rather than full `Filesystem` reply objects (acceptable without a Request mock).

### 3. Union cache + overlay confinement — **good**

- Folder cache now uses `list_from_source` (same one-hop follow as B-4 list).
- Immutable ImmFolder regression asserts lookup+open+content for both branches/orders — this is the hole the first B-4 test missed.
- Overlay: canonicalize root, `O_NOFOLLOW`, refuse final-component symlinks, confine ancestors, COW with `create_new` + `O_NOFOLLOW`.

**Nits:**

- `ensure_under_root` early-`Ok`s when an intermediate ancestor is a symlink that resolves *inside* the root, without re-checking the remaining relative suffix. Escape via `root/link → outside` is blocked; nested “link-inside-root then odd relative” is fine because virtual paths are already `normpath`’d before join. Acceptable.
- `WriteOverlay::new` now requires canonicalize of root (fails if root is deleted mid-flight). Fine.

### 4. ZIP InflateCache — **good**

- Remove failed slot with `Arc::ptr_eq` so concurrent retries do not clobber a newer slot.
- Pre-clean residual `Err` slots before insert.
- Tests cover sticky-error removal and multi-fail then success.

**Nit:** Waiters already blocked on a failed `OnceLock` still see `Err` once (expected); next open retries. Documented by design.

### 5. TAR header cap + dumpdir versions — **good**

- 16 MiB cap before `vec![0u8; size]` on PAX/L/K (main + nested walk + sparse open).
- Dumpdir: if newest is tombstone, **all** `lookup` versions return `None` (matches `versions() == 0`).
- Tests for oversized L/x headers and multi-version hide.

**Nit:** Cap is only on long/pax auxiliary headers, not on regular member `size` for data stencils (correct — those should not allocate full body at index time).

### 6. Packages version resolve — **good**

- Shared `packaging/test-version-resolve.sh` with unit tests (match / mismatch / non-tag).
- All four jobs call the same resolver; no hardcoded `0.1.x`.

**Nit:** `grep -m1 '^version'` matches workspace package version first in root `Cargo.toml` (correct for this repo layout). Would break if a non-workspace `version` appeared above it — not the current layout.

### 7. Warm index tarstats — **good** (highest complexity)

- Shared `TarStats` API: size, mtime, edge SHA-256, full hash ≤256 KiB.
- TAR/ZIP `open_existing` call `check_tarstats_matches_archive`.
- Factory gates gzip RGZI / zstdblocks / bzip2blocks import + stores tarstats on persist.
- Fail closed on mismatch; **missing tarstats still allows warm open** (legacy/Python).

**Residuals (known, acceptable for this batch):**

| Residual | Severity |
|----------|----------|
| Other formats’ `open_existing` (7z, ISO, …) not yet on tarstats | medium product gap |
| Large archive same size+mtime, mid-file change (no edge change) | low/thin |
| Virtual labels / missing path skip fingerprint | intentional |
| Reader import passes `label` as archive path for check (non-existent → skip) | intentional for HTTP |

**Nit:** `try_load_*` on remote Range opens pass `Some(label)`; if a local file accidentally shares that label string as a path, fingerprint could apply oddly. Unlikely for URL-style labels.

---

## Cross-cutting

| Topic | Assessment |
|-------|------------|
| **Test quality** | Symptom-named, exercises the failing path (not only helpers in most crates). |
| **Concurrency** | zstd + zip patterns look race-aware (ptr_eq / private pos). |
| **Security** | Overlay symlink escape addressed; not a full sandbox (no bind-mount). |
| **Perf** | Overlay getattr re-lookup every time is correct; RO mounts keep cache path. |
| **Docs** | Review docs updated; no false “feature complete” claims for 7z fingerprint. |

---

## Must-fix before release? 

**None** of the nits block shipping this batch. Optional follow-ups:

1. `readdirplus` entry TTL → `attr_ttl()` under overlay.  
2. Wire `check_tarstats_matches_archive` into remaining format open_existing paths.  
3. Consider failing warm open when `tarstats` is **missing** on indexes we ourselves just wrote (stricter than Python).

---

## Suggested verify (already run on merge)

```bash
cargo fmt --all -- --check
cargo clippy -p ratarmount-compress -p ratarmount-fuse -p ratarmount-compositing \
  -p ratarmount-formats-zip -p ratarmount-formats-tar -p ratarmount-index -p ratarmount \
  --all-targets -- -D warnings
cargo test -p ratarmount-compress -p ratarmount-fuse -p ratarmount-compositing \
  -p ratarmount-formats-zip -p ratarmount-formats-tar -p ratarmount-index -p ratarmount
./packaging/test-version-resolve.sh
```

---

*Reviewer: orchestrator pass on full `origin/main..HEAD` diff after worktree merges.*
