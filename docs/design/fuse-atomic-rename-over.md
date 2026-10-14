# Design: atomic rename-over on `-w` mounts (#88)

Status: **proposal, awaiting architecture LGTM**. Docs and a measurement
harness only; no product code changes in this PR.

## Problem

`write tmp; mv tmp final` onto an existing `final` must be atomic for
concurrent readers: under POSIX, `final` always resolves to the old or the
new file, never to nothing. On a FUSE `-w` mount, readers see `ENOENT`.

### Measurement (main `203d0378ffba6608a44004323ae408b9760795da`, 2026-10-14)

Release build, Linux, `ratarmount -f -w ov a.tar mnt`. The archive holds
only `d/base.txt`; the harness seeds `d/final` with `open(w)`, so the
target is **overlay-backed from the start** (an archive-member target is
not measured here; see Acceptance). One in-process poller loops
`open(final)` + `read` while writers loop `write .tmp-<id>-<n>;
rename(.tmp, final)`. Control: the same harness on a plain host directory.
Harness: [`rrs88/poll.py`](rrs88/poll.py), [`rrs88/measure.sh`](rrs88/measure.sh).

| Target | Writers × cycles | Run | Attempts | open ENOENT | read ENOENT (after a successful open) | ENOENT rate |
|---|---|---|---|---|---|---|
| FUSE `-w` | 1 × 400 | 1 | 866 | 47 | 131 | 20.6% |
| FUSE `-w` | 1 × 400 | 2 | 829 | 40 | 134 | 21.0% |
| FUSE `-w` | 1 × 400 | 3 | 889 | 17 | 145 | 18.2% |
| FUSE `-w` | 8 × 100 | 1 | 448 | 66 | 72 | 30.8% |
| FUSE `-w` | 8 × 100 | 2 | 491 | 71 | 95 | 33.8% |
| FUSE `-w` | 8 × 100 | 3 | 501 | 66 | 85 | 30.1% |
| plain dir | 1 × 400 | 1–3 | 3,325 | 0 | 0 | 0% |
| plain dir | 8 × 100 | 1–3 | 641 | 0 | 0 | 0% |

No writer errors and no leftover temp names. This tight single-process
poller sees more than the 2–14% reported from Robo-Ilya's shell harness on
#87 and #84 (those runs are not in this tree; the table above is the
reproducible number). The plain directory is 0 in every run.

### Request trace (same SHA, [`rrs88/trace.sh`](rrs88/trace.sh), 1 × 200)

`RUST_LOG=fuser=debug`, poller result: 432 attempts, **41 open ENOENT,
53 read ENOENT**. Per file nodeid:

- 432 `OPEN`: 391 succeed, **41 fail** (`open error kind=2`, i.e.
  `open_inode` on a `"\0stale-…"` inode). The 41 open ENOENTs the poller
  saw are exactly these failed `OPEN`s: apart from the initial
  `LOOKUP final` miss before the seed `CREATE`, no `LOOKUP` of `final`
  failed in this run (negative `LOOKUP`s of fresh `.tmp-*` names before `CREATE` are
  normal, as are the mount-time `.Trash`/`.Trash-1000` lookups; renamed-away
  temp names are also looked up again and miss).
- The next request on a nodeid after each successful `OPEN` is a
  **`GETATTR` on that nodeid** (391/391, counted per nodeid from the log),
  before any `READ`. Only 338 `READ`s arrive; 391 − 338 = **53 = the read
  ENOENT count**. `GETATTR` failures are not logged individually, so "53
  failed `GETATTR`s" is inferred from that arithmetic. The kernel's read path refreshes attrs because the
  overlay attr TTL is 0 and the read extends past the cached `i_size`
  (`fuse_file_read_iter` → `fuse_update_attributes`); the `GETATTR`
  resolves the stale path and fails, so `READ` is never sent. fuser 0.15
  negotiates `FUSE_ASYNC_READ | FUSE_BIG_WRITES` only (no
  `FUSE_AUTO_INVAL_DATA`); the size check alone triggers it.
- `READ` itself (`read_handle` → `pread` on the `OverlayFd`) never failed.
- 274 `FORGET`s arrived for file nodeids; `forget` is a no-op today.

## Causes

1. **FUSE inodes resolve through their path** (all measured failures).
   `rebind_after_rename` sets the replaced destination inode's path to
   `"\0stale-{ino}"`. Any later request on that nodeid that goes through
   `path_for_ino` fails: `OPEN` (open_inode), `GETATTR`
   (getattr_reply → file_info_for_ino), and likewise `SETATTR`,
   `READLINK`, `GETXATTR`, `LISTXATTR`.
2. **Core delete-then-rename window** (not hit at the FUSE lookup level in
   the trace, but real for every frontend and for crashes).
   `WriteOverlay::rename` runs `unlink_inner(&to)` (host `remove_file`,
   then `mark_deleted(to)`), then `fs::rename(from_real, to_real)`, then
   `mark_deleted(from)` and `mark_present(to)`. Between `remove_file` and
   `fs::rename`, `lookup(to)` returns `None`. A crash there leaves the old
   destination deleted and the new content at `from` (not lost, but `to`
   is gone).
3. **Read-after-unlink** on main has the same root cause as 1: `unlink`
   leaves the inode bound to the name it no longer has, and `GETATTR`
   before `READ` on a held fd fails once the host file is gone.

## Design

### 1. Core: rename onto the target, no delete step

`WriteOverlay::rename(from, to)` for a non-directory, under the existing
`commit_gate` read lock and reserved-name checks (#99):

1. COW `from` into the overlay (unchanged; a failure leaves `to` untouched).
2. If `to` is a directory: `AlreadyExists` (unchanged).
3. **Park hook** (for section 2): if `to_real` exists, open it
   (`O_RDONLY | O_NOFOLLOW | O_CLOEXEC`; symlinks are not opened, their
   `FileInfo` incl. `linkname` is snapshotted instead) **before** the host
   rename, and return that handle to the caller with the result. This is
   the only point where the old inode is still reachable by path.
4. `fs::rename(from_real, to_real)` **directly over** `to_real` (atomic on
   the host). No `unlink_inner(to)`:
   - `to` overlay-backed: replaced in one step.
   - `to` archive-only: the new host file shadows the member (`lookup`
     prefers `overlay_file_info` over the base); no tombstone for `to`.
   - `to` tombstoned (deleted earlier): stays invisible until step 5.
5. One SQLite transaction on the already-locked connection (new SQL, not
   the self-locking `mark_present` / `mark_deleted` helpers): set `to`
   present (clearing its tombstone row) and tombstone `from` iff the base
   has `from`. After `COMMIT`, update the in-memory tombstone `HashSet` in
   one critical section of its own lock: `to` out, then `from` in **only if
   the base has `from`** (same rule as `mark_deleted`; an overlay-only
   `from` just loses its row). If the transaction fails after the host
   rename (disk full, I/O error), the host rename cannot be undone safely
   (an overlay-backed old destination is already unlinked, and `linkat`
   cannot relink an `nlink == 0` inode that was not opened `O_TMPFILE`). So
   core still applies the in-memory update, logs the error, and returns
   **success**: this session's view is the completed rename, FUSE rebinds as
   normal, and the persisted DB is in the "between 4 and 5" state of the
   crash table (the same result as a crash at that point). That
   set, not the DB, is what `lookup`'s `is_deleted` reads; lock order stays
   `db` → tombstones (no path takes them the other way).

Reader view (one rename versus `lookup`; `commit_gate` is a shared lock, so
two concurrent mutations of the same names are not ordered by it):

- `to` previously **visible**: old file until 4, new file after 4. Never
  `None`.
- `to` previously **tombstoned**: `None` until 5, then the new file.
- `from` archive-backed: after 4 and until 5, `lookup(from)` shows the
  **archive** member (the overlay copy moved away, no tombstone yet). This
  is overlay lag, not a POSIX state; it closes at 5. An overlay-only
  `from` is `None` after 4 (its `deleted=0` row is dropped at 5).

Crash consistency (host files are content, the DB holds tombstones):

| Crash point | Result |
|---|---|
| before 4 | unchanged (maybe a COW copy of `from`, as today) |
| between 4 and 5, `to` was visible | `to` = new content. Archive `from` reappears from the archive (duplicate, not loss). |
| between 4 and 5, overlay-only `from` | `to` = new content; `lookup(from)` is `None`; a stale `deleted=0` row for `from` with no host file remains (harmless: `lookup` needs the host file; dropped by the next create/unlink of that name). |
| between 4 and 5, `to` was tombstoned | new content is on disk under a tombstoned name: hidden from `lookup`, but `collect_overlay_commit_plan` still appends host files, so a later commit publishes it. Same window as today's `create_file`. Not fixed here; recovery must not delete such a host file. |

Option (open question 1): a one-row rename journal in the DB written before
4 and cleared in 5's transaction, replayed on open, would close the last
two rows.

Same code serves FUSE, NFS, 9P, SFTP and SMB (all call
`WriteOverlay::rename`; 9P/SFTP/SMB via
`ratarmount_export_core::overlay_rename`).

### 2. FUSE: replaced and unlinked inodes keep answering

Goal: a nodeid the kernel still holds keeps answering with the old file
until the kernel `FORGET`s it.

- **Detach on rename.** `rename_paths` receives the parked handle from
  core step 3 and, in `rebind_after_rename`, stores it on the replaced
  inode as `detached: Some(Detached { fd: Option<OwnedFd>, last_fi })`
  (path stays `"\0stale-{ino}"`, `path_to_ino` entry removed, as today).
  `last_fi` is snapshotted **before** anything clears it: `rename_paths`
  copies the destination's `FileInfo` before `drop_stable_attr(replaced)`
  (which drops a stable archive member's fat `FileInfo`) and before calling
  core rename (after the host rename, `lookup(to)` is the new file and the
  old archive `FileInfo` cannot be reloaded). Archive member: the fat
  `FileInfo` from the inode entry, or a `source.lookup(to)` if none is
  cached. Overlay file or symlink: `overlay_file_info` (incl. `linkname`,
  which the attr cookie does not hold). An archive-only target has
  `fd: None`; `GETATTR`/`OPEN`/`READLINK` use `last_fi`, and
  `GETXATTR`/`LISTXATTR` call `source.get_xattr`/`list_xattr` on it
  (overlay files have none and reply `ENODATA`, as today).
  `from == to` keeps today's behaviour (core rejects it; FUSE returns
  success when the name exists).
- **Detach on unlink.** `remove_entry` snapshots `last_fi` exactly as
  `rename_paths` does, **before** calling core `unlink` (which tombstones
  the name, so `lookup` is `None` afterwards) and before
  `note_dir_changed` (whose `drop_stable_attr` drops a fat archive
  `FileInfo`). Core `unlink` gets the park hook (open before
  `remove_file`) and **returns** the parked handle to `remove_entry`, which
  stores fd + `last_fi` in the same `inodes` update that removes the name
  from `path_to_ino` and sets `"\0stale-{ino}"`. The fd is never dropped
  before that store (dropping it would free the unlinked host inode), and
  is closed only when `nlookup` reaches zero. A later create of that name
  gets a **new** nodeid, never the detached one.
- **Park open.** A raw `open` with the section-1 flags, done inside
  `rename`/`unlink` while they hold the `commit_gate` read lock. Not
  `open_overlay_fd`: it takes that lock again (`std::sync::RwLock` is not
  reentrant) and also clears tombstones.
- **Requests on a detached nodeid:**
  - `GETATTR`: `fstat(fd)` (or `last_fi`), `nlink = 0`, TTL 0. This is what
    fixes the measured read ENOENT.
  - `OPEN` read-only: `OverlayFd` from `dup`-free reopen of the parked fd
    (`open("/proc/self/fd/N", O_RDONLY)`, **without** `O_NOFOLLOW`, since
    that path is a symlink); reads use `pread`, so no shared offset
    matters. Archive-only: a `Source` backend from `last_fi`. macOS (no
    `/proc`): `fcntl(F_DUPFD_CLOEXEC)`, safe because reads are `pread`.
  - Write is decided by the existing test `(flags & (O_WRONLY | O_RDWR)) !=
    0`; reader opens arrive as `0x8000` (`O_RDONLY | O_LARGEFILE`) in the
    trace and must stay read-only opens.
  - `OPEN` for write, `SETATTR`, xattr writes: `EACCES` (open question 2:
    POSIX allows writing an unlinked file; supporting it needs `O_RDWR`
    parking and exclusion from commit busy-tracking, which is not worth it
    for phase 2).
  - `READLINK`, `GETXATTR`, `LISTXATTR`: served from `last_fi`.
  - Archive-only detached `Source` handles: the "old bytes" guarantee
    holds until a live commit bumps `content_generation`;
    `refresh_source_handle_if_stale` re-resolves by path after that. Phase
    2 marks such fhs at open time (`OpenBackend::Source` gains a
    `detached: bool`; today it stores only the old path) and skips that
    refresh for them, so they keep their reader.
  - `READ` on an already-open `OverlayFd`: unchanged (`pread` on its own
    fd; the trace shows it never failed).
- **Lookup counts and `FORGET`.** fuser 0.15 at `abi-7-12` delivers
  `forget(ino, nlookup)` only (`batch_forget` needs `abi-7-16`; not
  enabled, no ABI bump in this work). New per-inode `nlookup`: +1 on every
  reply that hands the kernel a reference (`LOOKUP`, `CREATE`, `MKDIR`,
  `SYMLINK`, and `READDIRPLUS` if it is ever enabled), −`nlookup` on
  `FORGET` (the root starts at 1 for the mount reference, which is not a
  `LOOKUP` reply), counted from the first reply for that nodeid and never reset at
  detach. The trace shows a partial `FORGET` on a still-linked file (ino 7:
  `FORGET nlookup 1`, later used, then `FORGET nlookup 5`), so an entry is
  only dropped at zero, never on the first `FORGET`. A detached inode's
  parked fd is closed at zero, and the inode entry is dropped. Unmount closes the rest. (fuser notes FORGET is not
  guaranteed for every inode; unmount covers that.)
- **No silent fallback.** There is no LRU that closes a parked fd early.
  If parking fails (`EMFILE`/`ENFILE`), the rename or unlink itself fails
  with that errno before the destination is touched (a rename's source
  copy-up from step 1 may remain, as with any failed rename today), rather than answering a live
  nodeid with ENOENT later. Parked fds are bounded by the kernel's own
  inode references.
- **Interval commit busy-tracking** (`write_fds`, `(dev, ino)`): parked fds
  are read-only and point at unlinked host inodes, so they are not
  registered as busy writers and are invisible to the commit walk.

**New read-after-unlink semantics** (to be added to
`docs/mount-options-parity.md` when phase 2 lands): on FUSE `-w`, a file
that is unlinked or replaced while the kernel still holds it keeps
returning its old bytes and attrs (`nlink` 0) until the last reference is
dropped, like a local filesystem; it cannot be written through that
reference.

### 3. Kernel cache invalidation (#84, #91, #92)

Unchanged rules:

- `rename_paths` still queues `note_entry_changed` for the old name and
  `drop_stable_attr` for both parents and the replaced inode, and flushes
  **after** the reply (the kernel holds both directories' `i_rwsem` across
  `FUSE_RENAME`).
- Still **no** `INVAL_ENTRY` for the destination name (#91); the kernel has
  `d_move`d the source dentry there. `tests/fuse_rename.rs` (held source
  fd keeps its new path, never "(deleted)") stays green; `nlink = 0` is
  only reported for the replaced/unlinked nodeid, not the moved one.
- #92 `attr_advertised` only records non-zero TTLs. An overlay-backed
  replaced inode (the measured case) has TTL 0 and is not in it; the
  kernel revalidates on its own (the `GETATTR` in the trace). For a 60 s
  archive member that is replaced, #92's `Inode` invalidation still fires,
  and the following revalidation now lands on the detached `GETATTR`.
- #84's stable-attr cache never applies to a detached inode (`file_info`
  cleared on detach, as today).

### 4. 9P, SFTP, SMB and NFS

- Phase 1 (core) removes the window where `lookup(to)` is `None` for all
  of them.
- Phase 1 does **not** make held ids survive. Their reads are
  path-based: `ReaderLru::get_or_open` drops overlay-tagged slots and
  re-resolves `path_for_id` (`export-core/src/reader.rs`); SMB/9P
  `file_info` and SFTP `read` look up the path; NFS `read_member` resolves
  `path_for_id` then `source.lookup`. After `InodeTable::rebind_path`
  (export-core) or NFS's own inode table detaches the replaced id to
  `"\0stale-…"`, a held 9P fid / SMB file id / NFS handle gets
  `ENOENT` / `NFS3ERR_STALE`. All four `bump` the replaced id before
  `overlay_rename` (9P `renameat`, SMB/SFTP `rename`, NFS `rename_sync`);
  keep it.
- Phase 3 (optional): the same `Detached` parking in
  `export-core::InodeTable` (9P, SMB, SFTP) and in `ratarmount-nfs`'s inode
  table, using the core park hook. Parking the reader slot alone is not
  enough: each frontend's `file_info` / `read_member` must consult the
  `Detached` entry **before** its path lookup (SFTP `read` calls
  `file_info` first; 9P returns `ESTALE` on a stale id; NFS v3 and v4 both
  bump before rename). SFTP is path-based, so only its open handles
  benefit.

### 5. #96 tombstone / marker invariants

- Rename and unlink run under the `commit_gate` read lock; a live commit
  (write lock) sees the state before or after the whole operation.
- `from`'s tombstone and `to`'s present row commit in one transaction
  (today: `mark_deleted(to)` inside `unlink_inner` before the host rename,
  then `mark_deleted(from)` and `mark_present(to)` as two autocommit
  statements after it).
- A tombstone is cleared only after the host file for that name exists.
- The marker and the DB file are never touched. Reserved names (any
  component, any ASCII case, #99) are refused before the park hook, so a
  parked fd never points at bookkeeping.
- Parked fds reference unlinked host inodes only, never a name the commit
  walk can see.

### 6. Robo-Ilya's note (#87 QA)

Covered: concurrent readers of a rename-over target (section 2 removes
the `OPEN`/`GETATTR` ENOENT on the old nodeid that the trace shows; section
1 removes the core lookup window and narrows the crash window to the rows
in its table, see open question 1), and the shared read-after-unlink root
cause. Residual, unchanged: a file held open **from
the archive** before a rename keeps serving the archive bytes afterwards
(correct for the old inode).

## Acceptance

- Core unit tests: rename over overlay-backed, archive-only and tombstoned
  targets. Oracle: a visible target never goes `Some`→`None` in a
  concurrent `lookup` loop; a tombstoned target goes `None`→`Some` once.
  Fault injection between steps 4 and 5 matches the crash table.
- FUSE unit tests: detached `GETATTR`/`OPEN`/`READLINK`/xattr after rename
  and after unlink; `FORGET` with `nlookup` closes the parked fd only at
  zero; a create after unlink gets a new nodeid; park failure fails the
  rename with the errno and leaves the destination unchanged (a source
  copy-up from step 1 may remain); a park failure on unlink changes
  nothing. Unlink of a held archive member and of a held overlay file
  keeps serving old attrs and bytes.
- Kernel-path test: `docs/design/rrs88/measure.sh`, or an in-tree
  equivalent under `ratarmount-fuse/tests`, shows **0** ENOENT for 1×400
  and 8×100, 3 runs each, for both an overlay-backed seed and an
  **archive-member** target (the tar contains `d/final`, the writers
  rename onto it, and the poller starts only once it resolves; skipping
  the seed write is **not** this case, since `final` would be missing
  until the first rename), plus `trace.sh` showing no failed
  `GETATTR`/`OPEN`. Existing `fuse_rename` suite and churn harness green.
- AGENTS.md rows for #88.

## Phasing

1. Core rename (section 1) with the park hook returning a handle (unused by
   frontends yet) + tests.
2. FUSE detached inodes, `nlookup`/`FORGET` tracking, parity doc row.
3. Optional: export-core and NFS detached ids.

## Open questions for review

1. Add the one-row rename journal (closes the remaining crash rows), or
   accept the table as is?
2. Write opens on a detached inode: refuse (`EACCES`, proposed) or support
   POSIX writes to an unlinked file?
3. Keep the harness under `docs/design/rrs88/`, or move it into
   `ratarmount-fuse/tests` as an ignored-by-default test in phase 2?
