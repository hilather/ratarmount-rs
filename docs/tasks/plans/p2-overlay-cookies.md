# Plan: P2 overlay file-info cookies (not full `FileInfo`)

| Field | Value |
|-------|--------|
| **Status** | Plan only — **not implemented**. Review: see [Skeptic review](#skeptic-review). |
| **Date** | 2026-08-28 |
| **Source item** | [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md) P2 “Overlay / write path” |
| **Related (do not implement)** | [`vectorize-steal-patterns.md`](../vectorize-steal-patterns.md) **V-4** (commit queue) |
| **Existing residual test** | `cargo test -p ratarmount-fuse --lib overlay_file_info` |

This document is an implementation plan. It must not be treated as a license to land code in the same PR as the plan.

---

## One-sentence claim

Replace the **FUSE and NFS inode `FileInfo` caches** used on write-overlay mounts with a **Copy cookie plus size/mtime** (and the other getattr scalars), without trusting that cookie for `OpenBackend::Empty` / kernel attr TTL, and without building V-4’s commit queue.

---

## What the backlog item actually names

From `vectors-optimization.md`:

- Overlay file-info cache: compact cookie + size/mtime, not full `FileInfo` (watch size-0 / create residuals)
- Regression: create then cat empty overlay file

There is **no** `FileInfo` cache inside `WriteOverlay`. `WriteOverlay::overlay_file_info` (`write_overlay.rs`) `stat`s the host file on every lookup and builds a fresh `FileInfo` whose `userdata` is `UserData::Other("overlay:{path}")`. The caches that retain a fat `FileInfo` after that lookup are:

| Cache | Location | Overlay policy today |
|-------|----------|----------------------|
| FUSE inode | `ratarmount-fuse/src/lib.rs` `InodeEntry.file_info: Option<FileInfo>` | `file_info_for_ino` / `file_info_for_open` **always re-lookup** when `overlay.is_some()`, then `store_fi` the full clone |
| NFS inode | `ratarmount-nfs/src/inode.rs` `InodeEntry.file_info: Option<FileInfo>` | `file_info_for_id` (v3 `vfs.rs` and v4 `adapter.rs`) **skips the cache** when overlay is set, then `store_lookup_fi` the full clone |
| FUSE dir cache | `DirCacheEntry` `(name, mode, size)` | Already cheap; not this item |
| NFS `ReaderLru` slot | `reader.rs` `ReaderSlot.fi: FileInfo` | Per-open handle, not the getattr cache — **out of this plan** |
| FUSE `OpenBackend::Source.file_info` | marked `#[allow(dead_code)]` | Per-open archive handle — **out of this plan** |

P1 already asked Union/AutoMount getattr caches to prefer cookies; that work interned **path keys** and left “No FileInfo cache of nested roots.” This P2 item is the **write-overlay inode cache**, not a second Union pass.

`CompactOpenCookie` (`ratarmount-index`) is the **archive-member** open coordinate (offsets/flags). It is the wrong type to store for overlay host files and must not be imported into `ratarmount-fuse` (fuse does not depend on `ratarmount-index`).

---

## Why this is only a density / residual-hardening item

On overlay mounts, getattr and open **already ignore** the cached `FileInfo` and re-`lookup`. The immediate win is therefore **RAM per inode**: drop the heap `linkname: String` and `userdata: Vec<UserData>` that every overlay getattr still clones into the map.

The overlay `userdata` tag is `overlay:{path}` — a second copy of `InodeEntry.path`. That is the fat part this plan removes from the cache, not from the `MountSource::lookup` return value.

CPU win is **not** in scope for the first implementation: do **not** stop the overlay re-lookup in the same change as the cookie swap. Re-lookup is the current size-0 fix. A later follow-on may update the cookie on `write`/`truncate` and skip re-lookup; that is a separate residual and must not ship in the first cookie PR.

---

## Size-0 / create residual (must stay green)

### The failure mode (already fixed; must not return)

FUSE `create` stored `FileInfo { size: 0, … }` on the inode. A later RO `open` used that cached size, picked `OpenBackend::Empty` (`open_source_backend` when `fi.size == 0`), and `cat` after `write` returned `""`.

Current mitigations (keep all of them):

1. Overlay `open` uses `WriteOverlay::has_file` + `OverlayFd`, not the source/Empty path (`lib.rs` `open`).
2. Overlay getattr/open **re-lookup** (`file_info_for_ino`, `file_info_for_open`).
3. `OVERLAY_ATTR_TTL = 0` so the kernel does not pin create-time size 0.
4. `write` does **not** set `FOPEN_KEEP_CACHE` on overlay fds.
5. `content_generation` sweep clears every inode `FileInfo` (live commit / V-4-adjacent).

Catalog test (AGENTS.md “Write-overlay create then cat empty (size-0 cache)”):

```bash
cargo test -p ratarmount-fuse --lib overlay_file_info
```

That filter hits `overlay_file_info_for_ino_refreshes_size_after_write`: create empty → write payload → `file_info_for_ino` size must match the payload (not create-time 0).

**Correct empty-file behavior:** create with no write, then `cat`, **must** return `""`. The bug is create-time size 0 **surviving a later write**, not “empty files are empty.”

### Hard rules for the cookie swap

- Never choose `OpenBackend::Empty` from a **cached** size `0` when `overlay.has_file(path)` is true. Overlay open stays on `OverlayFd`.
- Never start trusting cookie size for getattr while overlay is set. Keep re-lookup + `OVERLAY_ATTR_TTL = 0`.
- After re-lookup, the cookie (not a fat `FileInfo`) may store the **fresh** size so tests that read the cache still see the post-write length.
- `write()` / `setattr(size)` may **optionally** refresh cookie size/mtime from `fstat` on the overlay fd as defense in depth. That is not permission to skip re-lookup.
- Live-commit generation sweep must clear cookies the same way it clears `FileInfo` today (`sweep_if_generation_advanced` / NFS `clear_all_lookup_fi`). Do not special-case “overlay cookies reconstruct from path” — a stale **base** cookie after a delete-shift is wrong bytes (`overlay_commit_live_delete_shifts`).

---

## V-4 relationship (explicit non-goal)

V-4 is a **single-writer commit queue** (interval / on-exit / offline coalesce). This plan does **not**:

- add a commit job queue or executor
- change `commit_gate`, persist, last-frame splice, or ZIP rebuild
- change when `commit_generation` / `content_generation` bumps

The only shared contract is: **after a live persist, every cached attr (cookie or `FileInfo`) is invalid**. Implementers who find themselves writing a queue have left this plan.

---

## Goals

1. Overlay-mount inode caches store a compact, preferably `Copy`, attr cookie (`size`, `mtime`, `mode`, `uid`, `gid`, plus a small discriminant). Not `FileInfo`.
2. Reconstruct a `FileInfo` only at the getattr / open / readlink / xattr **boundary** after overlay re-lookup (same as today: lookup is the source of truth).
3. Overlay `userdata` tag is **not** stored in the cookie; if a boundary needs it, rebuild `UserData::Other(format!("overlay:{path}"))` from `InodeEntry.path`.
4. Size-0 create residual stays green; add a named regression that states the symptom.
5. NFS v3 + v4 inode tables use the **same cookie type** (shared in `ratarmount-core`) so the two export paths cannot drift.
6. Immutable mounts (no overlay) may keep today’s `Option<FileInfo>` cache. This item is the write path. Do not fold P0 `CompactOpenCookie` / fat-map readdir work into this PR.

---

## Non-goals

| Out | Why |
|-----|-----|
| V-4 commit queue | Separate item; see above |
| Stop overlay re-lookup / lengthen `OVERLAY_ATTR_TTL` | Reintroduces size-0 if cookie is stale |
| `WriteOverlay`-internal FileInfo/stat cache | Would add a cache that does not exist; lookup already `stat`s |
| Change `WriteOverlay::overlay_file_info` return type | Callers (`lookup`, NFS, FUSE boundary) still need `FileInfo` |
| Compact `ReaderLru` / `OpenBackend::Source` | Per-open, not the getattr cache |
| Import `CompactOpenCookie` into fuse/nfs | Wrong crate + wrong meaning (TAR offsets) |
| `factory.rs` | Overlay cookie is fuse/nfs/core only |
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
    /// bit0: last lookup was overlay-tagged (reconstruct userdata from path)
    pub flags: u8,
}
```

Helpers (same crate, keep them tiny):

- `InodeAttrCookie::from_file_info(fi: &FileInfo) -> Self` — copies scalars; sets the overlay bit if `userdata.last()` is `Other` starting with `overlay:`.
- `InodeAttrCookie::to_file_info(self, path: &str, linkname: String) -> FileInfo` — used only when a caller must synthesize a `FileInfo` **without** a fresh lookup. Overlay bit rebuilds the tag. **Overlay getattr/open must not use this instead of lookup.**

`linkname` stays off the cookie. Overlay mounts re-lookup before `readlink` (`file_info_for_ino`). Immutable `readlink_uses_cached_file_info_without_second_lookup` keeps using the fat `FileInfo` cache (no overlay).

Do **not** store TAR `UserData` in the cookie. Overlay open/getattr re-lookup; base-member open on an overlay mount also re-looks up (`file_info_for_open`). A cookie that tried to be `CompactOpenCookie` would be a second, stale offset table and would fight the generation sweep.

### FUSE inode shape

```text
InodeEntry { path: String, file_info: Option<FileInfo> }
  →
InodeEntry { path: String, file_info: Option<FileInfo>, cookie: Option<InodeAttrCookie> }
```

Recommended policy:

- `overlay.is_some()`: `store_fi` writes **cookie only** and sets `file_info = None`.
- `overlay.is_none()`: keep storing `FileInfo` (immutable open/readlink reuse). Cookie unused.
- `cached_fi` on overlay mounts: if tests still need a `FileInfo`, reconstruct via `to_file_info` **for size/mtime asserts only**, or add `cached_cookie()` and update tests to read `cookie.size`.
- `sweep_if_generation_advanced`: clear **both** `file_info` and `cookie`.

Do not introduce an `enum CachedAttr { Fat, Compact }` unless it simplifies the `overlay.is_some()` branch; two `Option`s are enough and stay MSRV 1.74.

### NFS inode shape

Same cookie field on `ratarmount-nfs` `InodeEntry`. `store_lookup_fi` on overlay mounts stores the cookie and drops the fat `FileInfo`. `clear_lookup_fi` / `clear_all_lookup_fi` / `rebind_path` clear the cookie. v3 and v4 `file_info_for_id` stay “no cache hit when overlay is set.”

---

## Call-site checklist (implementer)

### FUSE (`ratarmount-fuse/src/lib.rs`)

| Site | Change |
|------|--------|
| `store_fi` / `ino_for_path_with_fi` | Overlay: cookie from `&FileInfo`, do not retain `FileInfo` |
| `cached_fi` | Overlay: do not return a fat clone as if it were authoritative |
| `file_info_for_ino` / `file_info_for_open` | Keep overlay re-lookup; after success, store cookie |
| `open` overlay `has_file` branch | Unchanged `OverlayFd`; still `store_fi` from lookup if present |
| `open_source_backend` Empty | Unchanged `fi.size == 0`, but that `fi` must be the **re-lookup** result, never a create-time cookie |
| `create` / `mkdir` | May store cookie size 0; next getattr must re-lookup |
| `write` / `setattr` truncate | Optional cookie size refresh; required: do not skip re-lookup |
| `release` | No cookie change required |
| `sweep_if_generation_advanced` | Clear cookie |
| `readdirplus` stub `FileInfo` | Unrelated (dirent size, not inode cache) |

### NFS

| Site | Change |
|------|--------|
| `inode.rs` store/clear/rebind | Cookie field + tests that today assert `cached_lookup_fi(a).unwrap().size` |
| `vfs.rs` / `v4/adapter.rs` `file_info_for_id` | Keep overlay skip-cache; store cookie after lookup |
| `ReaderLru` | No change |

### Compositing

No `write_overlay.rs` cache. Do not “optimize” `overlay_file_info` by memoizing `FileInfo`.

---

## Tests (same PR as the code; not this plan PR)

Every behavior change lands with tests in the implementation PR (`AGENTS.md`).

| Test | Layer | Assert |
|------|-------|--------|
| Existing `overlay_file_info_for_ino_refreshes_size_after_write` | FUSE helper | Create → write payload → `file_info_for_ino` size is payload length; `attr_ttl` is `OVERLAY_ATTR_TTL`; overlay fd reads payload. **Must stay green.** Name/doc already: *Regression: … create-time size 0*. |
| New: create, **no** write, then open/read | FUSE helper | `cat` of a never-written overlay file is empty (`""`). Documents that Empty/empty-fd is correct when the file is actually empty. |
| New: cookie density on overlay store | FUSE unit | After overlay lookup/store, inode holds `Some(cookie)` and `file_info.is_none()` (or equivalent). Cookie size matches lookup. |
| Existing `ino_for_path_with_fi_updates_stale_cached_size` | FUSE | Still overwrites size 0 when a fresher attr is provided (cookie.size 0 → 42). |
| Existing `overlay_commit_live_delete_shifts` | FUSE | Generation sweep still drops cached attrs; open fh re-looks up. |
| Existing NFS `overlay_*` / `overlay_commit_live_delete_shifts` | NFS | Stay green if inode table type changes. |
| Existing `readlink_uses_cached_file_info_without_second_lookup` | FUSE immutable | **Must not** start looking up twice (immutable fat cache stays). |
| Existing `immutable_open_reuses_cached_file_info` | FUSE immutable | Unchanged. |

Add an AGENTS.md catalog row in the **implementation** commit (not this plan):

| Symptom / fix | Command |
|---------------|---------|
| Overlay inode cookie / create-then-cat empty | `cargo test -p ratarmount-fuse --lib overlay_file_info` |

Implementation verification (copy-paste):

```bash
cargo fmt --all
cargo clippy -p ratarmount-core -p ratarmount-fuse -p ratarmount-nfs --all-targets -- -D warnings
cargo test -p ratarmount-fuse --lib overlay_file_info
cargo test -p ratarmount-fuse --lib overlay_commit_live_delete_shifts
cargo test -p ratarmount-fuse --lib readlink_uses_cached
cargo test -p ratarmount-fuse --lib ino_for_path_with_fi
cargo test -p ratarmount-nfs --lib overlay_
cargo test -p ratarmount-nfs --lib overlay_commit_live_delete_shifts
```

`cargo test` does not treat `|` as OR — run filters separately.

---

## Docs delta (implementation PR, not this plan)

- Tick the P2 overlay checkboxes in `vectors-optimization.md` when the code lands.
- No README / parity / nested-matrix update (no user-visible capability).
- Do not mark V-4 done.

This plan file stays as the design note; the implementer may add a one-line pointer under the P2 overlay bullets.

---

## Suggested implementation order

1. Add `InodeAttrCookie` + `from_file_info` / overlay-tag helper + unit tests in `ratarmount-core`.
2. FUSE: store cookie on overlay mounts; keep re-lookup; update `overlay_file_info_*` and `cached_fi` helpers.
3. Guard: overlay `open` never uses cached size for `Empty`.
4. NFS inode table twin (v3 + v4 store/clear).
5. Generation sweep clears cookies (FUSE + NFS).
6. Run the commands above. Do not start a commit queue.

One implementation PR. Orchestrator owns `factory.rs` — unused here.

---

## Risks (pre-called)

| Risk | Mitigation |
|------|------------|
| Cookie becomes the getattr source of truth | Plan forbids it; re-lookup stays |
| `to_file_info` used for overlay `open` of a base member | Overlay `file_info_for_open` re-looks up; cookie has no TAR offsets |
| NFS left fat | Same core type, same-PR inode field |
| Implementer builds V-4 queue | Non-goal section; stop |
| Test helpers still clone `FileInfo` from cookie and hide a fat store | Assert `file_info.is_none()` on overlay after store |
| `mtime: f64` is not “denser” | Spec asked size/mtime; `f64` matches `FileInfo` and is `Copy`. Do not change the `FileInfo` clock in this item |
| Overlay symlink `linkname` missing from cookie | Re-lookup on overlay `readlink` already |

---

## Skeptic review

Protocol: never skip sweep 1; each sweep is a **fresh** skeptic (no prior review context); fold blockers into this file; cap **3** sweeps then **BLOCKED**. Stop at **ACCEPT** or **BLOCKED**.

| Sweep | Verdict | Folded into plan |
|-------|---------|------------------|
| 1 | *(pending)* | |
| 2 | *(if needed)* | |
| 3 | *(if needed)* | |

Final: **ACCEPT** or **BLOCKED** — pending sweep 1.
