# #328 option A: no `files` transaction for overlay-only names

Follow-up to [`issue-328-overlay-create-unlink-profile.md`](issue-328-overlay-create-unlink-profile.md)
(fix A1). `--overlay-durability relaxed` (#334) made every overlay mutation
cheap at the price of power-loss corruption risk; this note asks whether the
default `full` path can drop the transaction for creates and unlinks of names
that exist only in the write overlay, without weakening any guarantee.

**Verdict: sound in a narrow form, implemented.** A regular-file create and
an unlink/rmdir of a name the lower view does not have write no `files` row
when no row of any kind exists for that name and no earlier row update is
queued. Every consumer that would read such a row derives the same answer
from the host tree.

## What the `files` row of an overlay-only path is used for

"Overlay-only" here means: `current_base().exists(path)` is false (the base
composed with any `--lower` layers; a lower tombstone already makes it
false), so the top has nothing to hide or replace. For such a path,
`PendingFilesOp::Present` writes `files(path,name,mode=S_IFREG|perm,deleted=0)`
and deletes any `overlay_metadata` row; `PendingFilesOp::Deleted { hides_base:
false }` deletes `files`, `overlay_metadata` and `xattrs` rows and inserts an
`xattrs(path,'',NULL)` reset row.

| Consumer | Reads the row for | Row-less overlay-only regular file |
|----------|-------------------|------------------------------------|
| Mount lookup / listing (`overlay_file_info`, `has_file`, `list`) | nothing: presence, type, size and mode come from `symlink_metadata` of the host entry, mode overridden only by `overlay_metadata` | identical |
| Tombstone cache (`is_deleted`) | `deleted = 1` rows only | no tombstone either way (`hides_base == false` always forgets) |
| `create_file_inner` mode | host file gets `mode & 0o7777` by `set_permissions`; the row stored the same bits | identical |
| Rename (`commit_rename_rows`) | `mode` from host `lstat` of `to`, `hides_from` from the base | unchanged: a rename still writes its rows |
| chmod / utime (`set_metadata`) | upserts `files` + `overlay_metadata` | unchanged: writes its rows |
| xattrs (`change_xattr`, `merge_xattr_rows`) | `xattrs` rows; the reset row clears inherited **base** xattrs | base has none at that path; the reset row of an overlay-only delete was a no-op (and grew the table without bound, profile A2) |
| Commit plan (`collect_overlay_commit_plan_from_conn`; offline, live, interval, on-exit, ZIP, `.tar.zst`) | `deleted = 1` rows (deletions); `deleted = 0` **directory** rows (which host dirs are intentional members); `overlay_metadata`, `xattrs` | regular files come from the host walk; the plan never reads a regular file's row. Directories are *not* elided (see below) |
| Commit cleanup (`forget_committed_overlay_rows`) | deletes rows of committed paths | no-op on a missing row |
| `diff`, canonical hash, manifest, `--between` (`overlay_changes::mentioned_paths`) | `files` ∪ `overlay_metadata` ∪ host walk | mentioned by the host walk since the SBX-COW fix; same `Change` (Added, host mode) |
| `overlay fsck` | rows vs host: `missing_content`, `type_mismatch`, `missing_parent`; host entries without a row count as `unrowed`, which is not an error | `unrowed` +1 per such file; `result: ok` |
| `overlay seal` / `verify` | fsck (above); `walk_modes` pins modes of **host** entries into `overlay_metadata`; `seal_rows` from the change set | identical digest; modes pinned from the host |
| `overlay pack` / `unpack` | DB snapshot plus the host tree; verify recomputes from the change set | identical |
| Read-only layers (`ReadOnlyOverlayLayer`, `--lower`) | `deleted` flag and `mentions` (row/metadata/xattr ⇒ provenance tag "metadata") | host entry served by `host_info`; provenance for a host entry is "host" either way |
| `overlay-stats` | tombstone count; usage from a host walk | identical |
| Quota (`account_path`, `policy_file_size`) | host sizes | identical |
| #88 pending-row queue | ordering of row updates whose host effect already happened | see below |
| Operation journal (`--journal`), NFS/9P/SFTP/SMB frontends | call `create_file` / `unlink` / `rmdir`; never read rows | identical |
| `overlay import`, `import-upperdir` | offline, own connection, write their own rows | not affected |

### What must keep its row

* **mkdir.** The commit plan keeps a host directory only when a
  `deleted = 0` directory row names it (`ensure_parent` materializes base
  parents with host defaults that must not become members). A row-less
  mkdir'd empty directory would silently not be committed. mkdir is never
  elided.
* **Symlinks.** Out of scope; they keep their row.
* **Anything over a base or lower name** (`hides_base`, copy-up, create over
  a tombstone): the row is the tombstone or clears it.
* **A name with any existing row.** `Present` deletes an `overlay_metadata`
  row (an O_TRUNC re-create after `chmod`, or after `overlay unseal` left
  pinned modes); `Deleted` removes `files`/`overlay_metadata`/`xattrs` rows
  of a renamed-in or chmodded file or one with user xattrs. Only a lone
  `xattrs` reset row (name `''`) counts as "no row" for `Deleted`, because
  `Deleted` would rewrite exactly that row. A `Present` never touches `xattrs`,
  so `xattrs` rows do not block eliding a create.

### The #88 queue

`persist_files_op` first replays queued rows, then takes `pending_rows`.
Elision is decided only under that lock and only when the queue is empty.
With a non-empty queue the op is appended exactly as before. Otherwise a
queued `Present p` or `Rename { to: p }` followed by an elided unlink of `p`
would replay into a present row with no host file (`missing_content`), and
a queued `Deleted p` followed by an elided create would be harmless but is
not worth reasoning about. The row probe takes `db` after `pending_rows`,
the documented lock order, and a direct writer holds `pending_rows` across
its whole attempt, so no concurrent row update can slip between the probe and
the decision. A probe error falls back to the normal transaction.

## Crash consistency

| Moment of SIGKILL / power loss | Before | After |
|--------------------------------|--------|-------|
| create: after host `open(O_CREAT)`, before the row | row-less host file (legal, `unrowed`) | same state; it is now also the final state |
| create, power loss after the row commit | the row is fsynced, the payload and its directory entry are not: fsck `missing_content` (an error until `--repair`) | no row; a lost host file leaves nothing behind |
| unlink: after host `unlink`, before the row | `files` row of a missing file: fsck `missing_content` | no row: consistent |
| unlink, power loss | the unlink may come back; the row may be gone | the unlink may come back as a row-less file (`unrowed`, listed, committed as an addition), the same as the "before" create crash |

Nothing new is reachable: a row-less overlay-only host file was already the
state of a create killed before its row, and of COW edits since SBX-COW.
Remount reads host files for presence; offline commit, diff and seal pick
them up from the host walk.

## Candidate designs

1. **(i) Skip rows for overlay-only creates/unlinks — chosen.** Removes the
   only SQLite write of these ops, so no fsync at all; costs one read-only
   probe on cached pages under the queue lock, plus one base lookup per
   create.
2. **(ii) Batch / group commit.** The FUSE daemon replies after the row is
   persisted (reply-after-persist) and serializes requests, so there is
   nothing to batch without delaying replies or replying before persisting.
   The #88 queue already models "host change done, row pending"; widening it
   to every op would make a SIGKILL lose tombstones of base names (archive
   members reappear) — exactly what #88 refuses to do. Rejected.
3. **(iii) Keep the transaction, relax its fsyncs.** `PRAGMA synchronous` is
   per connection and could be toggled between transactions. `NORMAL`
   saves one of four fsyncs (profile: 25%). `OFF` for only "recoverable"
   transactions is not safe in rollback-journal mode: a power loss during an
   unsynced transaction can corrupt pages that hold *other*, durable rows
   (tombstones), not just lose the recent row. That is the risk #334 put
   behind an explicit opt-in and a boot-id marker. Rejected for the default.

## Measurements

`benchmarks/overlay-create-unlink.sh`, N=200, REPS=3, release builds of
f7d4414 and of this change run back to back on the profile's host (aarch64,
ext4 on NVMe under `/var/tmp`). Medians in ms per op:

| Variant | before create | before unlink | after create | after unlink |
|---------|-----:|-----:|-----:|-----:|
| `-w` disk (`full`) | 7.12 | 6.62 | 0.122 | 0.067 |
| `-w` disk + rules | 7.45 | 6.77 | 0.131 | 0.068 |
| `--overlay-tmpfs` | 0.097 | 0.055 | 0.107 | 0.074 |

A second "before" run gave 8.33 / 6.57 ms. The default disk overlay now
matches `--overlay-tmpfs` and `--overlay-durability relaxed` (0.155 / 0.078
in the #334 measurement) for this workload; the tmpfs rows are within
run-to-run noise. Ops on base names (tombstones, copy-up, chmod, renames)
still cost one transaction each.

## Tests

* `regression_328_*` (compositing): no rows for create, unlink,
  unlink-then-recreate; rename still writes rows; mkdir, rmdir and symlinks
  as before; base names, tombstones, a metadata-only row (as `overlay
  unseal` leaves it) and user xattrs still go through the transaction;
  queued #88 rows keep the op queued (fails if the empty-queue check is
  dropped); a row-less overlay and a copy with the old rows agree on change
  set, canonical hash, manifest, layer digest, fsck, commit plan and
  seal/verify; offline `--commit-overlay`, live and interval commits write
  the host mode, and after the base swap an unlink of the committed name
  tombstones it and a re-create writes a row.
* `fuse_cow_agreement`: `regression_overlay_only_names_write_no_rows` (real
  mount, `diff` shows `new file mode 100700`, then the `agree` chain) and
  `regression_overlay_only_churn_sigkill_leaves_consistent_overlay` (three
  SIGKILLs during a create/unlink loop; `overlay fsck` must say `ok`). The
  SIGKILL test fails on f7d4414 with `missing_content: 1`.
* Updated for the new row-less state (assertions about rows the old create
  wrote): `park_open_emfile_leaves_names_unchanged` (the victim is now a base
  name, whose row a wrongly run delete would tombstone),
  `rename_tx_failure_matches_crash_table` (the stale-row case now gets its
  row from a chmod) and `regression_seal_refuses_mounted_and_inconsistent_overlay`
  (removes a symlink, which keeps its row, instead of a plain file).

## Residual risks

* `overlay fsck` reports a larger `unrowed` count; it is informational.
  Scripts that expected `unrowed: 0` after plain creates would notice.
* Overlays written before this change keep their rows; mixed overlays are
  the "rowed copy" case of the agreement test.
* The elision depends on `current_base().exists()` being the same view that
  `mark_deleted`'s `hides_base` uses; both read it from one function.
