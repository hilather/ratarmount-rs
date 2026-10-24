# Plan: Fork-N PR2a (CLI, ForkedTops, v1 refusals)

| Field | Value |
|-------|--------|
| **Status** | Plan slice. Sweeps 1–3 were REVISE. Sweep 4 ACCEPT (ready-log wording). Do not run sweep 5. |
| **Base** | `origin/main` `62aa0a4`. Anchors below were read on that tree. |
| **Contract** | The accepted plan [`fork-n-pr2.md`](fork-n-pr2.md) at `d6f63431`, sliced. Design: [`docs/design/fork-n-writable-tops.md`](../../design/fork-n-writable-tops.md). |
| **WIP** | `88567fd3` on `cursor/fork-n-pr2-sessions-98f5` is a cherry-pick source only. Do not push that branch. Do not take this branch's git base from it. |
| **This PR** | 1 of 3. Git base is `main`. PR2b and PR2c are later and are not this diff. |

## In this slice

- CLI: `--top` / `--mount`, the no-`-w` check in both places, the flatten refusal before the find/bind check, one flag per test.
- `ForkedTops` construction and the minimum serve path the three v1 tests drive (locks, `ready`, fusermount recorder, `FAIL_MOUNT`).
- Hardlink `nlink > 1` at start and after handoff, multi-top, nested `top/sub/dir/file`, foreground variant, no `ready`.
- Self-reopen under a mountpoint through the factory CLI, including the absent-component create spy.
- Occupied and non-empty targets, plus partial-start cleanup, including an already-mounted target and an unrelated planted mount.
- Identity: a mount over a top refuses; case and Unicode alias matrices.
- `AGENTS.md` lists this slice's filters.

## Deferred to PR2b

Not in this diff and not in this slice's tests:

- `classify_constructor` returning every admitted kind (`index`, `sqlite`, `bundle-cache`, `range-cache`, `materialized`, `seek-sidecar`, `split-volume`, and the rest of the closed table).
- Range-cache admit, including removing the `.ok()?` drops at `range_cache.rs:262`.
- `NamedTempFile` admit for materialized bodies and repack sidecars.
- Bundle planned-cache path stored in the exclude snapshot, with the verification key kept on miss and hit.
- Excludes, `--index-folders`, and `fork_n_journal_eligibility` / Exclude reopen.
- Journal votes locked across every top row, the step-6 archive inode check, restamp of both tops, incomplete-journal refusal, and Own-becomes-Deferred.

PR2a still admits the paths the self-reopen CLI test opens (QCOW2 backing after `is_file`, an index or sidecar the opener would create, companion symlinks, a symlink loop, a missing ancestor). That is not the PR2b table.

## Deferred to PR2c

- Daemon torrent ban and `fork_n_daemon_sources_`.
- `fork_n_daemon_workers_`, including held-lock `submit` / `fill` / `prefetch` and an append-only phase log.
- SQLite close/reopen around `fork`, the stamp check before any connection goes live, and no `ready` on a WAL or hook failure (`fork_n_daemon_sqlite_`).
- `fork_n_launcher_cancel`, `fork_n_parent_failure`, `fork_n_post_unmount`, `fork_n_quota_handoff`, `fork_n_shared_owner`, `fork_n_lifecycle`, `fuse_fork_n`, `fork_n_inside_base`, `fork_n_daemon_locks`.
- WorkerPhase suppression of speculative work. PR2a may leave the phase `Inactive`. It must not claim the workers row.

The hardlink recheck and partial-start cleanup still fork, lock, and unmount as specified below. Those are the v1 tests, not the PR2c rows.

## CLI

Flags, repeatable, split on the first `=`:

```text
--top NAME=OVERLAY --mount NAME=MOUNTPOINT
```

Require a non-empty name and path, unique names on each flag, equal name sets, N ≥ 1. Match by name, not order. Neither flag means today's CLI.

Either flag is Fork-N. `main` dispatches with `fork_n::run(&args) -> !` when `top` or `mount` is non-empty, before the production call of `split_bound_inputs_mountpoint` at `main.rs:1789`. `fork_n::run` does not return into that call. The function itself is defined at `:4802`.

- All positionals are sources. `fork_n::run` calls `split_bound_inputs_mountpoint` and uses that return value as its positional source list. Bind paths stay in `args.source_binds`; they are not inside the returned vector. When Fork-N is set the function returns `(args.paths.clone(), None)` before the bind-steals-directory rule at `:4805`. On the non-Fork-N path it still calls `split_inputs_mountpoint` (`:4814`, defined at `:4818`). The session mountpoint is the `--mount` path. The unit test calls that same function for two positionals and asserts both positionals are in the vector and the mountpoint is `None`. For `--bind` plus one directory positional it asserts that directory is the sole element of the vector and the mountpoint is `None` (the bind is not expected in the vector). The binary test `fork_n_bind_directory_stays_a_source` uses a directory that contains a file as the only positional, `--bind missing=/no/such`, `--top`, `--mount`, and `STOP_AFTER_ADMIT`. The marker `admitted\n` and exit 0 are required. Stealing the directory leaves only the missing bind, the factory fails, and the marker is not written. Falling through to `main.rs:1789` is that steal. `fork_n::run` must call the helper and use its vector; the unit test locks the vector, and the binary test locks that the directory was opened. Using `args.paths` without the helper has the same vector today, so the binary test does not by itself prove the call instruction. The call is still required so a later change to the helper cannot diverge from the serve path.
- Refuse, exit 2, before the factory and before any mkdir, with `fork-n cannot be combined with {flag}`: `-w`, `--overlay-tmpfs`, `--sandbox`, `--no-mount`, `--nfs`, `--http`, `--webdav`, `--smb`, `--ninep`, `--sftp`, `--sftp-subsystem`, `--control-interface`, `--journal`, find, unmount, repack, and publish. Each flag is its own assertion.
- Commit refusal is not nested under `!args.lower.is_empty()` (`main.rs:924`). When Fork-N is set and any of `--commit-overlay`, `--commit-overlay-on-exit`, a non-zero `--commit-overlay-interval`, or `--roll-every` is set, exit 2 with `commit of a layered stack is not supported; flatten first`.

**No `-w` check, both places.** `--roll-every` is `requires = "write_overlay"` at `main.rs:624`. Drop that `requires`. `conflicts_with_all` at `:624` still lists `commit_overlay`. `:881` is `return Ok(args)`. The corpus guard at `:862`–`:878` does not mention `roll_every`. `:911`–`:920` is the find/bind check (it returns an error). `:922` is the only line in that block that sets `commit_overlay_on_exit`. After the drop, add the same check in both places that already have a parsed `Args`:

1. Inside the corpus branch, after `try_parse_from` and before `return Ok(args)` at `:881`.
2. On the normal path, after `try_parse_from` at `:898` and before the roll block sets `commit_overlay_on_exit` at `:922`.

When Fork-N is not set and `roll_every` is set and `write_overlay` is absent, return `ArgumentConflict` with `--roll-every requires --write-overlay`. That check does not run for Fork-N, so `--top` plus `--mount` plus `--roll-every` and no `-w` still exits 2 with the flatten sentence. `main.rs:8547` is `Args::try_parse_from(["ratarmount", "--roll-every", "1d", "traces.tar"]).is_err()`. Change that assertion to `parse_args_from` and expect `--roll-every requires --write-overlay`. The `parse_args_from` loop at `:8545` already passes `-w`. Do not hang the no-`-w` assertion on it. Add `corpus LIST MOUNT --roll-every` beside it. Both assert the requires-`--write-overlay` text. Nearby `try_parse_from` of `0B` and of `-w` plus `--roll-every` plus `--commit-overlay` stay `try_parse_from`.

**Flatten versus find/bind.** The Fork-N flatten refusal is **before** the find/bind check at `:911`–`:920`. Normal-path order after `try_parse_from`: the non-Fork-N `--roll-every` without `-w` check; then, when Fork-N is set, the flatten refusal for any one of the four commit flags; then the find/bind check and the `commit_overlay_on_exit` assignment, which run only when Fork-N did not return. `--top` plus `--mount` plus `--roll-every` plus `--bind` exits 2 with the flatten sentence, not `--roll-every requires an untransformed archive series...`.

**One flag per test.** Each of the four commit flags is its own `fork_n_` assertion (`--top`, `--mount`, that flag, no `--lower`, no `-w`). Do not pass `--commit-overlay` and `--roll-every` in one argv.

- The corpus branch (`:859`–`:881`) rejects `--top` alone, `--mount` alone, and both, with `ArgumentConflict` `corpus cannot be combined with --top or --mount`, before it sets `corpus_list` and before the existing corpus guard. Ordinary `corpus LIST-FILE MOUNTPOINT` and a literal source `./corpus` stay as they are.
- `wants_identity` is true when `write_overlay` or `lower` or `top` or `mount` is set.
- Add `top` and `mount` to the `overlay_target` group at `main.rs:82`. That group is `.multiple(true)`, so clap still accepts `-w` together with `--top`. The Fork-N conflict check after clap is what returns `fork-n cannot be combined with -w`. Do not describe the group as the refusal.
- `base_flag_needs_target_or_lower` (`main.rs:747`–`:760`) does not read the clap group. It sets `target` only from `write_overlay`, `overlay_tmpfs`, and `sandbox`. Add `!args.top.is_empty() || !args.mount.is_empty()` to that boolean. `--base-digest` (`:536`) and `--force-stack-mismatch` (`:533`) have no `requires = "overlay_target"`. The `fork_n_` row asserts `parse_args_from` returns `Ok` for `--top A=/overlay --mount A=/mnt --base-digest none archive.tar` and for the same pair with `--force-stack-mismatch` and no `--lower`. Today's error `requires -w/--overlay-tmpfs/--sandbox or --lower` fails that assertion.
- `--allow-unsealed-lower` keeps `requires = "lower"`.
- Bad assignments: `fork-n {flag} requires NAME=PATH`, `fork-n --top name {name:?} is repeated`, `fork-n requires --top and --mount with the same names`, `fork-n --top and --mount name sets differ`.

## ForkedTops

`ForkedTops` owns N `TopHandle { name, overlay_dir, mountpoint, overlay }` matched by name. A top is never another top's base. Construction in the parent, after the CLI checks and before any session:

1. Build the name-matched assignments. Create missing top and mountpoint directories. A failure exits 1 and starts no session.
2. Run the identity matrix and the hardlink walk (step 3 of the accepted plan's v1 checks that this slice owns). Failures exit 2 before any top database, marker, fork, or session. `--force-stack-mismatch` writes nothing before this matrix.
3. Open one `WriteOverlay` per top so both database files exist. This slice does not run cohort journal recovery and does not call `recover_mount_journals` (`main.rs:1842`). Factory `recover_journals` stays `false` (`main.rs:1985`). Record locks are not inherited across `fork`.
4. Daemon (no `-f`): the parent drops its top connections, then one `fork`. The child opens its own connections and takes every top lock. The after-locks hold and the hardlink recheck run in the child, then it mounts. This reopen is only so the child holds the locks the hardlink test observes. It is not the PR2c stamp check, and a WAL mismatch is not a refusal in this slice. Foreground does not fork. It runs the recheck on the connections `open` already holds, before any `Session::new`.
5. The child (or the foreground process) writes the line `ready` on the launcher pipe only after that recheck and only if every requested session has started. `RATARMOUNT_TEST_FORK_N_READY_LOG`, when set, receives `ready\n` at that same moment and not before. The after-handoff tests set that path. After handoff the ready-log file exists, contains `fusermount-honored`, and has no `ready` line.

`mount_blocking` stays private in `main.rs`. Fork-N calls it with `foreground=true` so FUSE does not fork again. Do not call `finish_overlay_serve` or `unmount_lazy` on the failure path. Failure unmount is `fusermount3 -u` (fallback `fusermount`), no `-z`. When `RATARMOUNT_TEST_FUSERMOUNT` is set it is `cfg(debug_assertions)` and the argv is that program plus `-u` and the path.

Holds `RATARMOUNT_TEST_FORK_N_HOLD_AFTER_LOCKS`, `RATARMOUNT_TEST_FORK_N_FAIL_MOUNT`, `RATARMOUNT_TEST_FORK_N_HOLD_AFTER_REPORT`, `RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT`, and `RATARMOUNT_TEST_FUSERMOUNT` are `cfg(debug_assertions)` only.

## Identity

New matrix in `fork_n`, not a prefix helper. `relation` (`mount_guard.rs:570`) takes `&MpCtx`. `MpCtx` (`:563`) and its fields are private, so `pub(crate)` on `relation` alone is not callable. Add `pub(crate) fn relation_of(fs, mount: &Path, other: &Path) -> Option<(Relation, Via)>` in `mount_guard`. It builds `MpCtx` inside the module and calls `relation`. The fake filesystem drives `relation_of`: lexical, mountinfo view, and same-view inode. This slice does not assert a hidden bind.

Subjects, and which path is which:

- **On** means `Relation::Equal`: the mountpoint and the top are the same path. **Inside** means `Relation::Inside`: the mountpoint is under the top. **Over** means `Relation::Contains`: the mountpoint contains the top. All three refuse. A disjoint result fails the test.
- The fake-filesystem test asserts those three `relation_of` values.
- The binary test `fork_n_identity_mount_over_top_exits_before_database` runs three CLIs (equal paths, mountpoint a parent directory of the top, mountpoint a subdirectory of the top). Each exits 2 and does not create `.ratarmount.overlay.sqlite` under either top. That is the "before any database, marker, fork, or session" proof. The fake filesystem does not open a database and is not that proof.
- Case: the mountpoint spelling is `/mnt/PhaseA` and the top spelling is `/mnt/phasea` (not two mountpoints). They pass the early read-only check, share an inode after the simulated mkdir, and the rebuilt matrix refuses.
- Unicode: the mountpoint is the NFC spelling and the top is the NFD spelling of the same name. Same early pass, shared inode, rebuilt refusal.

Mount-to-base, mount-to-bind, mount-to-mount, a hidden bind, two tops inside a directory base, and the distinct-directory control stay in a later slice. Do not assert them here.

## Hardlinks

Walk each top with `lstat` only. Do not follow symlinks. Recurse into subdirectories. A symlink is not a regular file, whatever its target's `nlink` is. A directory is not a regular file, even when `st_nlink > 1`. A regular file with `nlink > 1` refuses. The error names the path.

Check before any top database write and before fork. Recheck after every top lock is held, before `ready` and before any `Session::new`. The recheck refusal unmounts nothing this process did not mount. Both after-handoff tests set `RATARMOUNT_TEST_FUSERMOUNT` to a script that appends its argv to a log. When that variable is set, startup appends `fusermount-honored\n` to the ready-log path before the recheck. The test asserts the ready-log file exists, contains `fusermount-honored`, and has no `ready` line, and that the argv log is absent. An ignored variable leaves the honored line absent, so a direct `fusermount3` (including `Operation not permitted`) is not a pass.

The recheck hold is `RATARMOUNT_TEST_FORK_N_HOLD_AFTER_LOCKS`, placed after `WriteOverlay::open` has created both databases and taken their locks, and before the recheck, `ready`, and any `Session::new`. The test fails if either database path is not a regular file when the marker appears. While the hold is blocked, `BEGIN IMMEDIATE` on each database returns a lock error (`SQLITE_BUSY` / "database is locked"), not a missing-file error. The serving process has written `locks-held\n<pid>\n` to `RATARMOUNT_TEST_FORK_N_LOCK_MARKER`. The test creates the extra link during this hold, then releases. The process that exits 2 is the one that wrote the marker. For the daemon that pid is not the launcher pid. After handoff the ready-log file exists, contains `fusermount-honored`, and has no `ready` line. The tests spawn the `ratarmount` binary. They do not call `walk_top`.

The positive file is `<top-a>/sub/dir/file`, not an immediate child of the top. Both after-handoff tests and the at-start test use that nested path and two tops. Controls use the same two-top CLI and `RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT`. They exit 0, the marker is `admitted\n`, and stderr does not contain `hardlinked regular file`. They do not start FUSE, so `fusermount3: Operation not permitted` is not how they pass. The symlink control plants the link at `<top-a>/sub/dir/via`, pointing at a regular file outside the top whose `nlink > 1`. The directory control plants `<top-a>/sub/dir/dir-link` pointing at a directory outside the top that contains such a file. The walk's own `<top-a>/sub` has `st_nlink > 1` and must not refuse; the `admitted` marker is the proof the walk finished.

## Self-reopen

`ForkNStorage::admit` runs before the dependency is opened or created. Uninstalled, admit is a no-op and legacy opens are unchanged.

- `resolve_for_admit` distinguishes three results. A symlink loop or a missing ancestor refuses with `fork-n refuses to resolve {path}: {e}` and does not create a file. A missing final component whose ancestor exists is `Absent`: containment of that ancestor plus the lexical remainder still refuses when the ancestor is under a mountpoint, and the file is not created. A missing final component whose ancestor is outside every mountpoint and top is `Missing`, and the caller may return its own not-found error without admit. An existing path is canonicalized and then refused when it is equal to or under any cohort mountpoint.
- The owning top's own `.ratarmount.overlay.sqlite` and the `-wal` / `-shm` / `-journal` beside it are not a hit. A `-wal` symlink into a mountpoint is a hit even when the database file stays in the owning top.
- Where the caller is about to `File::open`, admit opens and returns the `File`. The caller does not open the path again.
- QCOW2 `open_backing` (`disk.rs:561`) calls `resolve_for_admit` before `is_file`. This is the canonicalize helper, not the PR2b constructor table. A symlink loop or a missing ancestor returns `fork-n refuses to resolve {path}: {e}` and does not call `is_file` or admit. A missing final component outside every mountpoint and top still returns at `path.is_file()` (`:573`) with `qcow2 backing file {path} not found` and does not call admit. The CLI fixture for that not-found text places the missing backing outside every mountpoint and top. A missing backing whose ancestor is under a mountpoint is the containment refusal (`fork-n`), not the not-found sentence.
- Replace `File::open(&path)` at `:579` with `open_admitted`. `open_backing` contains no `File::open`. A library test under this filter `include_str!`s `disk.rs` and asserts the `open_backing` body has no `File::open`. `open_admitted` increments spy `open` by one per call. The accepted control (backing outside every mountpoint and top) logs `open=1`. The under-mountpoint refusal logs `open=0`.
- The absent-final-component subcase is `--index-file` under the mountpoint. It does not use `open_backing`. Exit 2, the error contains `fork-n`, create and truncate spies are 0, and the path is absent.
- Symlink-loop backing, missing-ancestor backing, and `-wal` / `-shm` / `-journal` symlinks into a mountpoint (database file stays in the owning top) are separate CLI assertions. Each exits 2. The loop and the missing ancestor contain `fork-n refuses to resolve` and have `admit` 0. Each companion symlink contains `fork-n` and names that companion, with `open` 0.

The named test spawns the Fork-N binary (`--top`, `--mount`, `-f`). It does not call `open_backing` or `admit` in-process as the proof. Spies are written to `RATARMOUNT_TEST_FORK_N_SPY_LOG` as `admit`, `open`, `create`, and `truncate` counts. `RATARMOUNT_TEST_FORK_N_STOP_AFTER_ADMIT` exits 0 only after the owning-top database and its three companions are admitted, and writes `admitted\n` to `RATARMOUNT_TEST_FORK_N_ADMIT_MARKER`. An exit before that write fails the test. It does not need `/dev/fuse`.

## Cleanup

Before a session, refuse a target that mountinfo already lists as a mountpoint, and a target that is not an empty directory. A directory this process just created is empty and is eligible. Exit 2. The fusermount recorder sees zero calls. The pre-existing mount and the directory's file stay.

`fork_n_cleanup_occupied_target` and `fork_n_cleanup_partial_start` spawn the binary.

Occupied has two subcases. The non-empty directory always runs. The already-mounted subcase creates a real mount on the target; `eprintln!("skip: ...")` only when that mount cannot be created. A skip of the already-mounted subcase does not skip the non-empty subcase.

Partial start uses `RATARMOUNT_TEST_FORK_N_FAIL_MOUNT=B`. B returns after A has reported `(st_dev, st_ino, mount_id)` and before B calls `Session::new`. The recorder sees one `-u` of A and no `-z`. The test plants an unrelated mount that is not a cohort target and asserts that path is absent from the recorder argv. If that plant fails, `skip:` that assertion only; the `-u` of A still runs.

The stomp subcase keeps `FAIL_MOUNT=B`, holds on `RATARMOUNT_TEST_FORK_N_HOLD_AFTER_REPORT=A`, and bind-mounts over A. The recorder sees zero calls. The test then unmounts its own bind. If the bind cannot be created, `skip:` that subcase.

The killed-child case SIGKILLs the child after A's report, keeps `FAIL_MOUNT=B`, has nonzero launcher status, and the recorder sees one `-u` of A and no `-z`. A fresh process can `BEGIN IMMEDIATE` on each top database. A missing database fails the test; do not wrap that assertion in `if db.is_file()`.

Foreground (`-f`) uses the same `FAIL_MOUNT=B`: no fork, one `-u` of A, no `-z`, B never gets `Session::new`, status nonzero.

Missing `/dev/fuse` or `fusermount3` skips the partial-start test with `skip:`. `fusermount3` returning `Operation not permitted` is not a pass and is not a `skip:`.

## Tests

| Filter | Assertion |
|--------|-----------|
| `fork_n_` | `parse_args_from` for assignment errors, N=1, N>1, reordered names, no-lower, and every conflict flag listed above. `parse_args_from` is `Ok` for `--base-digest none` and for `--force-stack-mismatch`, each with `--top` and `--mount` and no `--lower`. `split_bound_inputs_mountpoint` keeps both positionals, including `--bind` plus one directory, and returns no mountpoint. `fork_n_bind_directory_stays_a_source` is exit 0 with `admitted\n`. Each of the four commit flags alone, no `--lower` and no `-w`, exits 2 with the flatten sentence. Flatten plus `--bind` is the flatten sentence. Corpus top-only, mount-only, and paired are `ArgumentConflict` before `corpus_list` is set. Plain corpus and source `./corpus` keep their grammar. Legacy `-w` still parses. Legacy `--roll-every` without `-w`, including `corpus LIST MOUNT --roll-every`, fails inside `parse_args_from` with `--roll-every requires --write-overlay`. The Fork-N form of that flag still gets the flatten sentence. |
| `fork_n_identity_` | `relation_of` on a fake filesystem: Equal (on), Inside, and Contains (over) against a top, plus `/mnt/PhaseA` mount vs `/mnt/phasea` top and NFC mount vs NFD top (early pass, shared inode, rebuilt refusal). The binary `fork_n_identity_mount_over_top_exits_before_database` covers equal, parent mountpoint, and child mountpoint: each exits 2 and creates no `.ratarmount.overlay.sqlite`. |
| `fork_n_hardlink_nlink_at_start` | Two tops. The regular file is `<top-a>/sub/dir/file` and already has `nlink > 1`. Exit 2, stderr names that path, no `ready` line is written, the link and both databases are unchanged. Controls, same two-top CLI and `STOP_AFTER_ADMIT`: the symlink at `<top-a>/sub/dir/via`, the directory symlink at `<top-a>/sub/dir/dir-link`, and `<top-a>/sub` (`st_nlink > 1`) each exit 0 with `admitted\n` and without `hardlinked regular file`. |
| `fork_n_hardlink_nlink_after_handoff` | Two tops, no `-f`. Both database files exist when `locks-held` appears. The extra link is `<top-a>/sub/dir/file`, created during the hold. `BEGIN IMMEDIATE` on each database is a lock error. The ready-log file exists, contains `fusermount-honored`, and has no `ready` line. The fusermount argv log is absent. After release the marker's pid exits 2, stderr names the path, and that pid is not the launcher. |
| `fork_n_hardlink_nlink_after_handoff_foreground` | Same two tops and the same assertions, with `-f`. The marker pid is the foreground pid. A refusal before the marker exists fails the test. |
| `fork_n_self_reopen_backing_under_mountpoint` | Factory CLI, `-f`. Backing under a mountpoint: exit 2, the error names the path, spy `open=0`. Accepted control: `open=1`, and the library `include_str!` test shows `open_backing` has no `File::open`. Missing backing outside every mountpoint and top: `not found`, no `fork-n`, `admit=0`, `open=0`. Missing backing whose ancestor is under a mountpoint: `fork-n`, path absent, `admit=0`. Symlink-loop and missing-ancestor backings: exit 2, `fork-n refuses to resolve`, `admit=0`. Each of `-wal`, `-shm`, and `-journal` symlinked into the mountpoint: exit 2, `fork-n`, `open=0`. `--index-file` whose parent is under the mountpoint: exit 2, `fork-n`, create 0, truncate 0, path absent. `STOP_AFTER_ADMIT` exits 0 only after the marker says `admitted`. |
| `fork_n_cleanup_occupied_target` | Non-empty directory and, unless `skip:`, an already-mounted target. Each exits 2 before a session. The file and the pre-existing mount stay. The recorder sees zero calls. |
| `fork_n_cleanup_partial_start` | `FAIL_MOUNT=B` and `RATARMOUNT_TEST_FUSERMOUNT`. One `-u` of A, no `-z`, and the planted unrelated mount is absent from the argv. Stomp keeps `FAIL_MOUNT=B` and sees zero calls. Killed child: nonzero status, one `-u` of A, no `-z`, and `BEGIN IMMEDIATE` succeeds on each top database. Foreground `-f`: no fork, one `-u` of A, no `-z`, nonzero status. |

## Docs in the same commit

- `AGENTS.md:500` says "design only, PR1/PR2 pending". Replace that sentence with this slice's filters (`fork_n_`, `fork_n_identity_`, `fork_n_bind_directory_stays_a_source`, `fork_n_identity_mount_over_top_exits_before_database`, `fork_n_hardlink_nlink_at_start`, `fork_n_hardlink_nlink_after_handoff`, `fork_n_hardlink_nlink_after_handoff_foreground`, `fork_n_self_reopen_backing_under_mountpoint`, `fork_n_cleanup_occupied_target`, `fork_n_cleanup_partial_start`). State that PR2b and PR2c filters are not in this row yet.
- `README.md`: one sentence and a table row for `--top` / `--mount` (N mountpoints, one process, commits refused).
- `docs/getting-started.md`: one command example.
- `docs/formats.md` Known limits: Fork-N is FUSE-only; hardlink, self-reopen, and occupied-target refusals. Do not document the daemon torrent ban or inside-base visibility here.
- `docs/mount-options-parity.md`: rows for `--top` and `--mount`.
- Do not edit the design doc in this slice.

`cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, and the filters above are the pre-commit bar. `cargo test --workspace` is the merge bar. This VM's `fusermount3: Operation not permitted` does not satisfy a FUSE assertion and is not a `skip:`.

## Gate

Fresh review-plan and a fresh skeptic each sweep. Do not resume an earlier agent. Sweeps 1–3 were REVISE. Matt approved sweep 4 for the ready-log wording only. Do not run sweep 5. A reviewer must not pull a deferred PR2b or PR2c row back into this slice. An in-scope row whose test plan is narrower than the table above is a revise.
