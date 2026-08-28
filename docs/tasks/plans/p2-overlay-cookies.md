# Plan: P2 overlay file-info cookies (not full `FileInfo`)

| Field | Value |
|-------|--------|
| **Status** | **Implemented** (FUSE-only density + residual hardening; not V-4). SHA `e860a90f91560b7ad7ac83e6a41a20483a3b20d0`. Review: see [Skeptic review](#skeptic-review). |
| **Date** | 2026-08-28 |
| **Source item** | [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md) P2 “Overlay / write path” |
| **Related (do not implement)** | [`vectorize-steal-patterns.md`](../vectorize-steal-patterns.md) **V-4** (commit queue) |
| **First implementation crate** | `ratarmount-fuse` (+ cookie type in `ratarmount-core`) |
| **Existing residual test** | `cargo test -p ratarmount-fuse --lib overlay_file_info` (getattr refresh only — see [Tests](#tests-same-pr-as-the-code-not-this-plan-pr)) |
| **Skeptic review** | Sweep 1 REVISE (folded). Sweep 2 **ACCEPT**. Final: **ACCEPT**. |

This document is an implementation plan. It must not be treated as a license to land code in the same PR as the plan.

---

## One-sentence claim

On **FUSE write-overlay** mounts, store a **Copy cookie plus size/mtime** (and the other getattr scalars) on the inode instead of a fat `FileInfo`, without trusting that cookie for `OpenBackend::Empty` / kernel attr TTL / `MountSource::open`, and without building V-4’s commit queue.

NFS and export-core (9P/SMB/SFTP) inode tables are **follow-on**, not the first PR. HTTP is not an `InodeTable` export.

---

## What the backlog item actually names

From `vectors-optimization.md`:

- Overlay file-info cache: compact cookie + size/mtime, not full `FileInfo` (watch size-0 / create residuals)
- Regression: create then cat empty overlay file

There is **no** `FileInfo` cache inside `WriteOverlay`. `WriteOverlay::overlay_file_info` (`write_overlay.rs` ~L995) `stat`s the host file on every lookup and builds a fresh `FileInfo` whose `userdata` is `UserData::Other("overlay:{path}")`. The caches that retain a fat `FileInfo` after that lookup are:

| Cache | Location | Overlay policy today | This plan |
|-------|----------|----------------------|-----------|
| FUSE inode | `ratarmount-fuse/src/lib.rs` `InodeEntry.file_info` | `file_info_for_ino` / `file_info_for_open` **re-lookup** when `overlay.is_some()`, then `store_fi` the full clone | **First PR** — store cookie, drop fat `FileInfo` |
| NFS inode | `ratarmount-nfs/src/inode.rs` | `file_info_for_id` skips cache when overlay is set, then `store_lookup_fi` | **Follow-on** |
| Export-core inode | `ratarmount-export-core/src/inode.rs` (copy of NFS table; used by 9P/SMB/SFTP) | Same skip-cache-when-overlay pattern (`ratarmount-9p/src/vfs.rs` ~L71) | **Follow-on — do not touch** |
| FUSE dir cache | `DirCacheEntry` `(name, mode, size)` | Already cheap | Not this item |
| NFS / export-core `ReaderLru` | `ReaderSlot.fi: FileInfo` | Per-open handle | Out of this plan |
| FUSE `OpenBackend::Source.file_info` | `#[allow(dead_code)]` | Per-open archive handle | Out of this plan |

P1 already asked Union/AutoMount getattr caches to prefer cookies; that work interned **path keys** and left “No FileInfo cache of nested roots.” This P2 item is the **write-overlay inode cache**, not a second Union pass.

`CompactOpenCookie` (`ratarmount-index`) is the **archive-member** open coordinate (offsets/flags). It is the wrong type to store for overlay host files and must not be imported into `ratarmount-fuse` (fuse does not depend on `ratarmount-index`).

---

## Why NFS / export-core are not in the first PR

Sweep 1: `file_info_for_id` is **not** the only reader of the NFS inode `FileInfo`.

- `ReaderLru::get_or_open` (`ratarmount-nfs/src/reader.rs` ~L254) hits `cached_lookup_fi`. A **non-overlay-tagged** row is trusted as-is, then `if fi.size == 0` opens an empty cursor (FUSE `OpenBackend::Empty` analogue), then `source.open(&fi)` / `member_seek_is_cheap(&fi)`.
- `read_member` (`vfs.rs` ~L480, `v4/adapter.rs` ~L435) also hits `cached_lookup_fi` and treats `fi.size == 0` as EOF.
- Export-core `reader.rs` is the same pattern (~L234 / size-0 empty cursor).
- `InodeTable::store_lookup_fi` has **no overlay flag**. Cookie-vs-fat cannot be decided inside that function alone.

If the first PR stored cookie-only on NFS and reconstructed `FileInfo` without TAR `userdata` (or with create-time size 0), overlay `cat` after write and base-member `open` break.

Therefore:

- First PR is **FUSE-only** (plus a `Copy` type in `ratarmount-core` if it stays unused-elsewhere-clean).
- NFS + export-core (9P/SMB/SFTP) stay fat `FileInfo` until a follow-on that rewires **every** `cached_lookup_fi` consumer (or keeps `file_info` populated for those crates and only adds a cookie beside it). HTTP is not an `InodeTable` export.
- Do **not** imply FUSE+NFS are the only fat inode caches.

`cached_lookup_fi` must remain `file_info.clone()` only — never `cookie.to_file_info(...)`.

---

## Why this is only a density / residual-hardening item (FUSE)

On overlay mounts, FUSE getattr and `file_info_for_open` **already ignore** the cached `FileInfo` when lookup succeeds and re-`lookup`. The immediate win is **RAM per inode**: drop the heap `linkname: String` and `userdata: Vec<UserData>` that every overlay getattr still clones into the map.

The overlay `userdata` tag is `overlay:{path}` — a second copy of `InodeEntry.path`. That is the fat part this plan removes from the **FUSE cache**, not from the `MountSource::lookup` return value.

CPU win is **not** in scope: do **not** stop the overlay re-lookup in the same change as the cookie swap. Re-lookup is the current size-0 fix. A later follow-on may update the cookie on `write`/`truncate` and skip re-lookup; that is a separate residual.

---

## Size-0 / create residual (must stay green)

### The failure mode (already fixed; must not return)

FUSE `create` stored `FileInfo { size: 0, … }` on the inode. A later RO `open` used that cached size, picked `OpenBackend::Empty` (`open_source_backend` when `fi.size == 0`, `lib.rs` ~L531), and `cat` after `write` returned `""`. Comment at `open` ~L928.

Current mitigations (keep all of them):

1. Overlay `open` uses `WriteOverlay::has_file` + `OverlayFd`, not the source/Empty path (`lib.rs` `open`).
2. Overlay getattr/open **re-lookup** when lookup succeeds (`file_info_for_ino`, `file_info_for_open`).
3. Overlay lookup **miss** must **not** fall back to a reconstructed cookie / create-time size 0 (`file_info_for_open` ~L505 and `file_info_for_ino` ~L716). Prefer `None` (ENOENT) over a stale cookie.
4. `OVERLAY_ATTR_TTL = 0` so the kernel does not pin create-time size 0.
5. `write` does **not** set `FOPEN_KEEP_CACHE` on overlay fds.
6. `content_generation` sweep clears every inode `FileInfo` (live commit / V-4-adjacent).

Catalog test (AGENTS.md “Write-overlay create then cat empty (size-0 cache)”):

```bash
cargo test -p ratarmount-fuse --lib overlay_file_info
```

That filter hits **only** `overlay_file_info_for_ino_refreshes_size_after_write` (`lib.rs` ~L1626): create empty → write payload → `file_info_for_ino` size matches payload. It then reads via raw `WriteOverlay::open_overlay_fd`, **not** `Filesystem::open` / `open_source_backend`. It does **not** lock the Empty-backend residual.

**Correct empty-file behavior:** create with no write, then `cat`, **must** return `""`. The bug is create-time size 0 **surviving a later write**, not “empty files are empty.”

The implementation PR must add a helper that follows **production** `open` (`has_file` → `OverlayFd`, else `file_info_for_open` + `open_source_backend`) and assert create → write → read payload. The existing getattr test stays; update it when `cached_fi` no longer returns a fat `FileInfo`.

AGENTS.md already has the `overlay_file_info` catalog row. Do not add a duplicate row with the same filter. Give the new open-path test a **distinct** filter name (e.g. `overlay_open_after_create_write`) and add **that** row in the implementation commit.

### Hard rules for the cookie swap

- Never choose `OpenBackend::Empty` from a **cached** size `0` when `overlay.has_file(path)` is true. Overlay open stays on `OverlayFd`.
- Never start trusting cookie size for getattr while overlay is set. Keep re-lookup + `OVERLAY_ATTR_TTL = 0`.
- After a successful overlay re-lookup, store the **fresh** size on the cookie and set `file_info = None`. Never leave both `Some` on an overlay mount (`store_fi` / `ino_for_path_with_fi` must agree).
- `cached_fi` on overlay mounts: do **not** reconstruct a `FileInfo` for production paths. Tests use `cached_cookie().size` (or a test-only helper). Reconstructing for `file_info_for_*` fallback or `open` is how size-0 / missing TAR userdata return.
- `to_file_info` is a core unit-test helper only, or is omitted until a follow-on that needs it. FUSE production code must not call it.
- `write()` / `setattr(size)` may **optionally** refresh cookie size/mtime from `fstat` on the overlay fd as defense in depth. That is not permission to skip re-lookup.
- Live-commit generation sweep must clear cookies the same way it clears `FileInfo` today (`sweep_if_generation_advanced`). Do not special-case “overlay cookies reconstruct from path” — a stale **base** cookie after a delete-shift is wrong bytes (`overlay_commit_live_delete_shifts`).

---

## V-4 relationship (explicit non-goal)

V-4 is a **single-writer commit queue** (interval / on-exit / offline coalesce). This plan does **not**:

- add a commit job queue or executor
- change `commit_gate`, persist, last-frame splice, or ZIP rebuild
- change when `commit_generation` / `content_generation` bumps

The only shared contract is: **after a live persist, every cached FUSE attr (cookie or `FileInfo`) is invalid**. Implementers who find themselves writing a queue have left this plan.

---

## Goals

1. On FUSE overlay mounts, the inode cache stores a compact, preferably `Copy`, attr cookie (`size`, `mtime`, `mode`, `uid`, `gid`, plus a small discriminant). Not `FileInfo`.
2. Overlay getattr / open / readlink / xattr keep using a **fresh** `source.lookup` `FileInfo` as the source of truth. Cookie is not an open coordinate.
3. Overlay `userdata` is **not** stored in the cookie and is **not** reconstructed for `MountSource::open` from the cookie.
4. Size-0 create residual stays green at **getattr and production open**.
5. Immutable mounts (no overlay) keep today’s `Option<FileInfo>` cache (`readlink_uses_cached_file_info_without_second_lookup`, `immutable_open_reuses_cached_file_info`, `ino_for_path_with_fi_updates_stale_cached_size`).
6. Do not fold P0 `CompactOpenCookie` / fat-map readdir work into this PR.

---

## Non-goals

| Out | Why |
|-----|-----|
| V-4 commit queue | Separate item |
| Stop overlay re-lookup / lengthen `OVERLAY_ATTR_TTL` | Reintroduces size-0 if cookie is stale |
| `WriteOverlay`-internal FileInfo/stat cache | Would add a cache that does not exist; lookup already `stat`s |
| Change `WriteOverlay::overlay_file_info` return type | Callers still need `FileInfo` |
| NFS / export-core (9P/SMB/SFTP) inode cookie | Readers consume `cached_lookup_fi` for open/read (see above) |
| Compact `ReaderLru` / `OpenBackend::Source` | Per-open, not the getattr cache |
| Import `CompactOpenCookie` into fuse | Wrong crate + wrong meaning (TAR offsets) |
| `factory.rs` | FUSE/core only |
| User-visible CLI / mount-option change | Density + residual hardening |
| Nested / tmp / format matrices | No open-path change |

---

## Proposed type (core)

Add a `Copy` struct next to `CheapDirent` in `ratarmount-core` (name bikeshed-ok; implementer may pick `InodeAttrCookie` / `OverlayAttrCookie`):

```rust
/// Compact getattr cache row. No heap `linkname` / `userdata`.
#[derive(Clone, Copy, Debug)]
pub struct InodeAttrCookie {
    pub size: u64,
    pub mtime: f64, // same clock as FileInfo; do not invent a second mtime unit
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Unused. Do not treat any bit as an open key or userdata substitute.
    pub flags: u8,
}
```

Helpers (same crate, keep them tiny):

- `InodeAttrCookie::from_file_info(fi: &FileInfo) -> Self` — copies scalars; may set the overlay bit if `userdata.last()` is `Other` starting with `overlay:`.
- Do **not** ship a production `to_file_info` on the FUSE path. A core unit test may build a `FileInfo` by hand.

`linkname` stays off the cookie. Overlay mounts re-lookup before `readlink` (`file_info_for_ino`). Immutable readlink keeps the fat `FileInfo` cache.

Do **not** store TAR `UserData` in the cookie. A cookie that tried to be `CompactOpenCookie` would be a second, stale offset table and would fight the generation sweep.

### FUSE inode shape

```text
InodeEntry { path: String, file_info: Option<FileInfo> }
  →
InodeEntry { path: String, file_info: Option<FileInfo>, cookie: Option<InodeAttrCookie> }
```

Policy:

- `overlay.is_some()`: `store_fi` / `ino_for_path_with_fi` write **cookie only** and set `file_info = None`.
- Root (`FUSE_ROOT_ID`) may keep `create_root_file_info()` from `RatarmountFs::new`. “Never both `Some`” applies to **child** overlay inodes after `store_fi`, not a requirement to cookie the root.
- `overlay.is_none()`: keep storing `FileInfo`. Cookie unused. `ino_for_path_with_fi_updates_stale_cached_size` stays on this path (it constructs `RatarmountFs` with `overlay: None`) — still overwrite fat size 0 with a fresher `FileInfo`, **not** a cookie.
- `cached_fi`: immutable only. Overlay tests use `cached_cookie()`.
- `sweep_if_generation_advanced`: clear **both** `file_info` and `cookie`.
- `readdirplus` uses `cached_fi(ino)` for `.` (`lib.rs` ~L879). On overlay, that becomes `None` → existing `or_else(|| source.lookup)` still fills `.` attrs. Extra lookup is acceptable; do not reconstruct a cookie `FileInfo` here.

Two `Option`s are enough (MSRV 1.74). Overlay: never leave `file_info` set.

---

## Call-site checklist (implementer)

### FUSE (`ratarmount-fuse/src/lib.rs`) — first PR

| Site | Change |
|------|--------|
| `store_fi` / `ino_for_path_with_fi` | Overlay: cookie from `&FileInfo`, `file_info = None` |
| `cached_fi` | Unchanged meaning: fat `FileInfo` only. Overlay stores none |
| `file_info_for_ino` / `file_info_for_open` | Keep overlay re-lookup; store cookie; on lookup **miss** return `None` (do not serve cookie) |
| `open` overlay `has_file` branch | Unchanged `OverlayFd`; may store cookie from lookup |
| `open_source_backend` Empty | Unchanged `fi.size == 0` on the **re-lookup** `FileInfo` only |
| `create` / `mkdir` | May store cookie size 0; next getattr must re-lookup |
| `write` / `setattr` truncate | Optional cookie size refresh; required: do not skip re-lookup |
| `release` | No cookie change required |
| `sweep_if_generation_advanced` | Clear cookie |
| `readdirplus` `.` attrs | Keep `cached_fi.or_else(lookup)`; no cookie reconstruct |
| `readlink` / xattr | Still `file_info_for_ino` (overlay re-lookup) |

### Not this PR

| Site | Why |
|------|-----|
| NFS `inode.rs` / `vfs.rs` / `v4/adapter.rs` / `reader.rs` | `cached_lookup_fi` feeds open/read |
| `ratarmount-export-core` inode + reader | Same consumers; 9P/SMB/SFTP |
| `write_overlay.rs` | No cache to compact |

---

## Tests (same PR as the code; not this plan PR)

Every behavior change lands with tests in the implementation PR (`AGENTS.md`).

| Test | Layer | Assert |
|------|-------|--------|
| Existing `overlay_file_info_for_ino_refreshes_size_after_write` | FUSE helper | Create → write → `file_info_for_ino` size is payload; `attr_ttl` is `OVERLAY_ATTR_TTL`. Update `cached_fi` assert to `cached_cookie().size` (or drop that assert if cookie is not authoritative). Raw `open_overlay_fd` read may stay as a compositing check. |
| **New** `overlay_open_after_create_write` (name bikeshed-ok) | FUSE helper through **production open** | Create → write payload → helper that mirrors `Filesystem::open` (`has_file` → `OverlayFd`). **Do not call `test_open_ro`** (`lib.rs` ~L466): that helper skips `has_file` and goes `file_info_for_open` + `open_source_backend`. Assert the fh is `OverlayFd` (or `has_file` is true) so the test cannot pass on the else-branch alone. `read_handle` returns payload, **not** `""`. Doc: *Regression: write-then-cat empty when open skipped OverlayFd*. `OpenBackend::Empty` stays locked by re-lookup + no `to_file_info`, not by this helper alone. |
| New: create, **no** write, then production open/read | FUSE helper | Never-written overlay file reads `""`. Opposite polarity of the cache bug. |
| New: cookie density on overlay store | FUSE unit | After overlay lookup/store, `cookie.is_some()`, `file_info.is_none()`, cookie size matches lookup. |
| Existing `ino_for_path_with_fi_updates_stale_cached_size` | FUSE **immutable** | Still fat `FileInfo` size 0 → 42 via `cached_fi`. Not a cookie test. |
| Existing `overlay_commit_live_delete_shifts` | FUSE | Generation sweep still drops cached attrs; open fh re-looks up. |
| Existing `readlink_uses_cached_file_info_without_second_lookup` | FUSE immutable | No second lookup. |
| Existing `immutable_open_reuses_cached_file_info` | FUSE immutable | Unchanged. |

Implementation verification (copy-paste):

```bash
cargo fmt --all
cargo clippy -p ratarmount-core -p ratarmount-fuse --all-targets -- -D warnings
cargo test -p ratarmount-fuse --lib overlay_file_info
cargo test -p ratarmount-fuse --lib overlay_open_after_create_write
cargo test -p ratarmount-fuse --lib overlay_commit_live_delete_shifts
cargo test -p ratarmount-fuse --lib readlink_uses_cached
cargo test -p ratarmount-fuse --lib immutable_open_reuses
cargo test -p ratarmount-fuse --lib ino_for_path_with_fi
```

`cargo test` does not treat `|` as OR — run filters separately.

---

## Docs delta (implementation PR, not this plan)

- Tick the P2 overlay checkboxes in `vectors-optimization.md` when the FUSE cookie lands. Leave a residual line that NFS/export-core inode maps are still fat.
- No README / parity / nested-matrix update (no user-visible capability).
- Do not mark V-4 done.
- AGENTS.md: add a row for the **new** open-path filter only.

This plan file stays as the design note. The parent TODO already points here.

---

## Suggested implementation order

1. Add `InodeAttrCookie` + `from_file_info` + unit tests in `ratarmount-core`.
2. FUSE: overlay store cookie only; keep re-lookup; lookup miss → `None`.
3. Guard: overlay `open` never uses cached size for `Empty`.
4. Add production-open create→write→read regression; update getattr test’s `cached_fi` assert.
5. Generation sweep clears cookies.
6. Run the commands above. Do not start a commit queue. Do not edit NFS/export-core.

One implementation PR. Orchestrator owns `factory.rs` — unused here.

---

## Risks (pre-called)

| Risk | Mitigation |
|------|------------|
| Cookie becomes the getattr/open source of truth | Plan forbids it; re-lookup stays; no production `to_file_info` |
| Overlay lookup miss serves create-time cookie | Return `None` |
| NFS/export-core cookie-only store | Deferred; `cached_lookup_fi` stays fat clone |
| Implementer builds V-4 queue | Non-goal section; stop |
| Existing `overlay_file_info` test goes red | Update `cached_fi` assert; add open-path test |
| `mtime: f64` is not “denser” | Spec asked size/mtime; `f64` matches `FileInfo` and is `Copy` |
| Overlay symlink `linkname` missing from cookie | Re-lookup on overlay `readlink` already |
| `readdirplus` `.` extra lookup | Acceptable; `or_else(lookup)` already there |

---

## Skeptic review

Protocol: never skip sweep 1; each sweep is a **fresh** skeptic (no prior review context); fold blockers into this file; cap **3** sweeps then **BLOCKED**. Stop at **ACCEPT** or **BLOCKED**.

| Sweep | Verdict | Folded into plan |
|-------|---------|------------------|
| 1 | **REVISE** | (1) Defer NFS/export-core: `cached_lookup_fi` feeds `get_or_open` / `read_member` / size-0 empty cursor; no production `to_file_info`. (2) Existing `overlay_file_info` test is getattr + raw fd, not FUSE `open`; add production-open create→write→read test with a distinct filter. (3) Name export-core / 9P / SMB / SFTP as a third fat inode map; do not claim FUSE+NFS are the only caches. Nits: immutable `ino_for_path_with_fi` is not a cookie test; overlay lookup-miss fallback; `readdirplus` `.` uses `cached_fi`; never leave both Options `Some`; do not duplicate the AGENTS.md `overlay_file_info` row. |
| 2 | **ACCEPT** | Nits folded as clarifications only (do not use `test_open_ro`; HTTP has no `InodeTable`; root may stay fat; `flags` unused / not an open key; `readdirplus` `.` is ~L879). No blockers. |
| 3 | skipped | Cap unused — stopped at ACCEPT. |

Final: **ACCEPT**.
