# Plan: issues #326–#329 (opened 2026-11-15)

Status: draft plan, nothing implemented. All four issues were filed from cpanmine
runs on 0.2.0; none has comments yet. Each section labels its root cause as
**read from code** (not yet run) or **reproduced**.

Suggested order: #329 → #326 → #327 → #328. The first three are small and
self-contained; #328 needs measurement before any design decision.

Per AGENTS.md, every fix below lands with a `Regression:` test at the lowest
layer, a regression-catalog row in AGENTS.md, and the living-doc updates named
in its section.

---

## #329 overlay import: file → directory patch fails ("parent … is not a directory")

**Root cause (read from code, not yet reproduced).**
`ratarmount/src/overlay_import.rs` `check_parents` looks up every parent in
`[lower, overlay]` separately. The lower view (`stack.view`) still contains `x`
as a regular file after the overlay has tombstoned it, so the parent check for
`x/y` fails whatever order the sections come in. Git emits `delete x` before
`add x/y` (`"x" < "x/y"`), so the delete has already run when the check fails.

The symmetric case also breaks: directory → file emits `add x` before
`delete x/y`. The add hits `"added file already exists"` because `x` is still a
directory in the merged view.

**Why lower is checked on its own.** It came in with the original import work
(#133, commit 42f4fb6). The only test that depends on it is
`regression_import_refuses_lower_and_overlay_symlink_components`. A lower
symlink that this import has not deleted is still visible in the merged
`overlay.lookup`, so checking only the merged view should still refuse it.
Confirm this with the test before deleting the lower lookup.

**Plan.**
1. `check_parents`: look up parents only in the merged overlay view, which
   already applies tombstones. Keep the symlink refusal.
2. Do **not** hoist all deletions globally. The loop reads each preimage from
   the overlay, so a stream that modifies a path and later deletes it works
   today and would break under a reorder. Step 1 alone fixes the reported
   file → directory case in git's order.
   For directory → file (`add x` comes before `delete x/y`), the import must
   also handle the directory that is in the way. When a section adds a
   non-directory at a path that is currently a directory, and later sections
   in the same stream delete all of that directory's children, apply those
   deletions first and remove the emptied directory. Limit this to the
   directory being replaced; pruning every emptied directory would change the
   manifests of imports that work today.
3. `write_entry`: when a parent is missing in the merged view but tombstoned
   (a deleted file), `mkdir` must succeed over the tombstone. Check that
   `WriteOverlay::mkdir` clears the tombstone and the `files` row ends up as a
   directory.
4. `--reject` path: `restore()` must still restore the lower `x` (a file) when
   the `x/y` section is rejected after `x` was turned into a directory. That
   means removing the overlay directory `x` and its children first. Decide
   whether to reject the whole type change together (the existing
   `already_rejected` logic suggests yes).

**Tests** (`ratarmount/src/overlay_import/tests.rs`):
- `regression_import_file_replaced_by_directory`: delete `x` and add `x/y`.
  Assert `x/y` has the right content, `x` is a directory, and `diff --git` →
  `import` → `diff --hash` round-trips.
- `regression_import_directory_replaced_by_file`: delete `x/y` and add `x`.
- `regression_import_modify_then_delete_stream_unchanged`: a stream that
  modifies a path and then deletes it still imports as it does today.
- An import that empties a directory without replacing it keeps that
  directory (manifest unchanged).
- `regression_import_type_change_reject_restores_lower`: `--reject` with a
  failing hunk on `x/y` leaves the lower `x` file in place.
- Keep `regression_import_refuses_lower_and_overlay_symlink_components` green.
  Add a case where the patch deletes a lower symlink `link` and adds `link/f`;
  the expected result is that it is allowed and creates a real directory.
- CLI layer: one case in `ratarmount/tests/overlay_import.rs` covering the
  issue's repro.

**Docs:** `docs/sandbox.md` overlay import section, one sentence on type
changes. Catalog row: "overlay import file↔directory type change".

---

## #326 rmdir of an empty, overlay-created exception root

**Root cause (read from code).** `ReadOnlyGlobs::denies_path`
(`ratarmount-compositing/src/overlay_policy.rs`) refuses Rename, Rmdir and
Reset of any allow-rule root under a protected parent (`exception_root`). This
was a deliberate choice in #133 and is documented in `docs/sandbox.md` ("Rename
endpoint, rmdir, reset | … EROFS" for `t/agent`). The policy is pure path logic
and cannot know whether the directory came from the base.
`WriteOverlay::rmdir` calls `check_mutation` before its own lookups.

**What the anchor protects.** For renames it stops an exception root from being
moved out from under its protected parent, or a protected tree from being moved
into it. For rmdir the only effect is that a **base-provided** `t/agent` cannot
be tombstoned. Mkdir, Unlink and Symlink at `/t/agent` are already allowed, so
an overlay-created root is not protected by anything else. Removing it again
brings back the base state, with nothing in `t/**` changed.

**Plan.**
1. Add a `check_rmdir(path, exists_in_lower: bool)` method on
   `OverlayPolicy` whose default calls `check_mutation(Rmdir)`. Do not add a
   new `OverlayMutation` variant: `check_mutation` names `Rmdir` in two
   `matches!` lists (the `ancestors` flag and the COW-parent guard) and passes
   the op to `cow.mutation`, so a new variant would silently lose both
   protections. For `ReadOnlyGlobs`, when `!exists_in_lower`, skip only the
   `exception_root` clause; ordinary read-only matching, protected
   descendants and the COW-parent guard stay.
2. `WriteOverlay::rmdir`: compute base existence before the policy check,
   using the same source as `mark_deleted`'s `hides_base`
   (`current_base().exists(path)`). **To verify:** `current_base()` returns
   `self.base` or the post-commit replacement. It is not yet confirmed that,
   under `--lower`, this is the composed lower stack. If it is not, use the
   composed view, so that a root provided by a sealed lower stays anchored.
3. After the rmdir, `mark_deleted` with `hides_base == false` must leave **no
   `files` row and no tombstone**. This is the issue's actual downstream
   complaint (the manifest difference). Verify it with
   `diff --manifest`/`--hash`.
4. Rename and Reset stay anchored (no change).

**Tests.**
- `overlay_policy.rs`: update `regression_readonly_allow_per_op_truth_table`
  (the Rmdir row changes on purpose for the overlay-only case). Add
  `regression_rmdir_overlay_created_exception_root` to cover:
  overlay-only + empty → ok; base-provided → EROFS; overlay-only but in a
  sealed lower → EROFS; also with `t/agent` itself in the allow list.
- `write_overlay`: after mkdir, write, unlink and rmdir of `t/agent`, the
  change set is empty (no `files` row).
- FUSE: extend `fuse_rename fuse_sandbox_readonly` with the issue's repro:
  `rm -rf t/agent` exits 0.
- `fuse_cow_agreement`: add a case for this new overlay behaviour (AGENTS.md
  requires one per overlay feature).

**Docs:** `docs/sandbox.md` truth table. Split the rmdir column, or add a
footnote: allowed for an empty exception root that the overlay created.

---

## #327 EPERM on ownership-preserving ops in `--cap-drop ALL` containers

**Root cause (partly read from code; the kernel's part is not yet
reproduced).** The issue assumes the kernel refuses, but ratarmount refuses
too: `validate_metadata` (`write_overlay.rs`) returns `EPERM` for **any**
`uid`/`gid` in a SETATTR, including a chown to the owner already presented.
Two layers are involved:
- The kernel, under `default_permissions`: root without `CAP_CHOWN` may only
  chown to the inode's current uid when its fsuid equals that uid. With files
  presented as uid 1000 and the caller at fsuid 0, the kernel refuses before
  FUSE sees the request.
- Ratarmount: with files presented as `uid=0,gid=0`, the kernel lets the
  request through, and `validate_metadata` then refuses it anyway.

`sed -i`'s "preserving permissions … Operation not permitted" may have a
separate cause. `change_xattr` returns `EPERM` for non-`user.` names, so a
`system.posix_acl_access` copy could be what fails. Confirm with strace.

Correction to the kernel bullet above: `default_permissions` is set only
when it is passed in `-o`, and the supervisor's option string
(`sandbox/process.rs`) does not pass it. Without it the kernel may forward the
chown to the daemon, and `validate_metadata` would then be the only refusal.

**Step 0 (measure).** On a real FUSE mount, run `strace -f -Z` (every failing
syscall, not a preselected list) on both repro commands (`cp -p` round trip and
`sed -i`). Run them inside
`docker run --cap-drop ALL --security-opt no-new-privileges` as root, with:
(a) the default presentation (host uid), and (b) `-o uid=0,gid=0`.
For each case, record which syscall fails and whether the SETATTR reached the
daemon (debug log / journal). The issue also counts "Permission denied"
(EACCES), which has no proposed cause yet; find it in the trace.

**Plan (expected after step 0).**
1. Make a same-owner chown a no-op success. The frontends hold the presented
   IDs (`AttributeMapping` in `ratarmount-core`, applied by
   `RatarmountFs::with_attribute_mapping`), so the comparison belongs there and
   not in compositing. In each frontend SETATTR, drop `uid`/`gid` when they
   equal the **presented** owner of that entry. Leave the rest of the request
   as it is and let compositing refuse any real change. `uid == u32::MAX`
   (`-1`) already arrives as `None`. Frontends: FUSE, NFSv3/v4, 9P, SFTP.
2. If strace shows ACL xattrs: map a `system.posix_acl_*` set whose ACL equals
   the mode-derived ACL to a no-op, or return `EOPNOTSUPP`. coreutils treats
   `EOPNOTSUPP` as "no ACL support" and does not warn. `EOPNOTSUPP` is the
   smaller change; prefer it if it silences `sed`/`cp`.
3. Only if step 0 case (a) shows the kernel refusing before the daemon:
   `BaseOptions` already carries `uid`/`gid` (`sandbox/process.rs` passes
   `-o uid=…,gid=…`), so cpanmine's fix is to pass `uid=0, gid=0` for a root
   container. Document that; no new option is needed. If the SETATTR reaches
   the daemon in case (a), item 1 alone fixes `cp -p` and this recipe is
   unnecessary.

**Tests.**
- `ratarmount-fuse --lib regression_fuse_setattr_same_owner_chown_is_noop`
  (mapped and unmapped), plus a different owner still giving `EPERM`.
- `sandbox_attr_tests` in nfs / 9p / sftp: the same pair.
- `ratarmount --test fuse_chmod` (or `fuse_rename fuse_sandbox_mapped_owners`):
  `cp -p` round trip under `-o uid=$(id -u),gid=$(id -g)` exits 0.
- Opt-in Docker test (`RATARMOUNT_TEST_DOCKER=1`) for the `--cap-drop ALL` root
  case, following the existing `sandbox_run` opt-in pattern.

**Docs:** `docs/sandbox.md` "Ownership and container mounts". Replace
"Ownership changes are refused with `EPERM`" with the same-owner no-op rule.
Add a root-container recipe (`-o uid=0,gid=0` / supervisor
`uid: 0, gid: 0`). Update `docs/mount-options-parity.md` if SETATTR semantics
are listed there.

---

## #328 Write overlay create+unlink ~13 ms/file (~12× tmpfs)

**Root cause: unknown, so plan a measurement, not a fix.** Known so far
(read from code): every create and unlink persists a `files` row through
`persist_files_op`, one SQLite transaction each. The connection uses the
default journal mode, so each commit costs several fsyncs. Publish paths also
fsync parent directories. The supervisor's default overlay is `Disk`. The issue
does not say whether cpanmine used tmpfs or disk.

**Step 1: bisect** (no code changes). Build release, then 50× create+unlink:
- `-w disk-dir` vs `--overlay-tmpfs` (does fsync dominate?);
- `strace -f -c -e trace=fsync,fdatasync,openat,renameat2,unlinkat` per op
  (fsync and transaction count per create and per unlink);
- FUSE request count per op (`user.ratarmount.stats` `fuse_req` counters,
  PR-A1): look for extra LOOKUP/GETATTR round trips and kernel invalidations;
- `perf record` of the daemon for the CPU part (policy lock, tombstone cache,
  `current_base().exists`);
- with and without `--journal` (the issue says no difference).

**Decision gate** after the numbers, choosing among:
- (a) Pure overhead fixes with no durability change: fewer round trips, no
  double `lookup`, cached base-existence. These go in unconditionally.
- (b) An opt-in relaxed durability mode for throwaway attempt overlays, e.g.
  `--overlay-durability=relaxed`: `PRAGMA synchronous=OFF` and directory
  fsyncs skipped. It would be on by default for `--overlay-tmpfs`, where a
  crash loses the overlay anyway. It must be checked against the
  crash-consistency rows (#126 COW crash, fsck, seal, import marker). It must
  also record itself in overlay meta, so that `fsck`/`seal` can warn or refuse
  after an unclean stop.
- **Not WAL:** #239 refuses `-wal`/`-shm` companions on writable mounts, and
  the checked-open and lock machinery assumes DELETE journal. WAL is not a
  cheap lever.
- Batched or group commit across FUSE requests conflicts with
  reply-after-persist semantics and is out of scope unless (a) and (b) are not
  enough.

**Deliverables:** a benchmark script under `benchmarks/` with a `--self-test`
(the pattern of `journal-overhead.sh`), the numbers in the issue, then a
follow-up PR per chosen option with its own regression and crash tests.

**Secondary:** the 3–4× slower cold first grep is probably index or catalog
warm-up. Track it separately unless the profile shows the same cause.
