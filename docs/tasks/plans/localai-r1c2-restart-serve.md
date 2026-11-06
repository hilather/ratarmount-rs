# Local AI R1c-2: serve retained attempts after restart

## Goal

After a Linux sandbox supervisor restart, serve the retained attempts that #267
preserved, with the same offline inspection and finalize behavior as the run
that retained them. A retained attempt is still never destroyed.

## Scope

- Restore valid, already-renamed `retained/ID` entries into the supervisor's
  retained map from the existing log and tree. Keep their ID, instance, report
  and recorded lower stack.
- Make `list --all`, `diff`, `stats` and `finalize` work as they did in the
  retaining run, including the existing acknowledged-retained lower exception.
  `destroy {id}` remains `retained`; base destroy, shutdown and daemon exit
  leave retained trees in place.
- This is the sandbox supervisor path only. Preserve its Linux-only rule,
  disk-overlay requirement, unsupported-input `invalid_request` refusals,
  no-forced-stop rule, and #267's Git-ref source-check ordering.

## Out of scope

`forget` and its lock order; reconcile/other recovery redesign; Local-AI
roadmap R2 `retained_damaged` and R3–R4; R5 docs and mount-option parity tests;
#235 part 2's shared symlink-open change; tensors and unrelated mop-up. Also
excluded are the older R1c-2 extras: busy database → `in_use`, T1 row move,
partial fsck progress, strict-normalize oracles, and rewriting interrupted
finalize records from an R1c-1 restart. Do not revive `5b517d2c` or touch
#265's worktree/branch/PR. Coverage outside the sandbox supervisor and
macOS/non-Linux supervisor support are not blockers.

## Code investigation

All citations are to main `56fc9ce2284314245286f52c613d3fa6c1683bcb`.

- The v1 retained record stores ID, instance, base, seal identity, ordered
  prefix, `over`, paths and the complete report (`ratarmount/src/sandbox/retained.rs:92`).
  Parsing checks the envelope and ID/instance but does not validate the report
  or bind the record to a tree (`ratarmount/src/sandbox/retained.rs:160`). Both
  durable logs already use the shared `StateLog` engine
  (`ratarmount/src/sandbox/retained.rs:329`, `ratarmount/src/sandbox/requests.rs:490`).
- Retain syncs the work, appends the record, renames without replacement, then
  syncs `retained/` and `attempts/`; the map entry is unacknowledged until both
  directory syncs succeed (`ratarmount/src/sandbox/retained.rs:828`,
  `ratarmount/src/sandbox/retained.rs:937`). A record alone therefore does not
  prove the rename occurred. `open_retained` checks directory names and keeps
  bare names, but does not restore entries (`ratarmount/src/sandbox/retained.rs:992`).
- `Supervisor::open` holds `daemon.lock`, opens both logs, initializes an empty
  retained map, reconciles stale attempts, pins live record targets and bare
  names, then resolves interrupted requests (`ratarmount/src/sandbox/daemon.rs:398`,
  `ratarmount/src/sandbox/daemon.rs:455`). Reconcile deletes stale `attempts/`
  but does not enter `retained/` (`ratarmount/src/sandbox/daemon.rs:579`).
  The intended seam is before reconcile (`docs/tasks/plans/localai-r1c1-finalize-retain.md:270`,
  `docs/tasks/plans/localai-r1c1-finalize-retain.md:307`); the current restart
  documentation explicitly says entries are not served (`docs/sandbox.md:2963`).
- `served` and `list_all` use the retained map, while `held` includes live log
  IDs and bare names regardless of that map (`ratarmount/src/sandbox/retained.rs:469`,
  `ratarmount/src/sandbox/retained.rs:540`). Retained `diff` classifies and gates
  the base before composing the recorded stack; `stats` reads the overlay
  offline and does **not** gate the base (`ratarmount/src/sandbox/daemon.rs:745`,
  `ratarmount/src/sandbox/daemon.rs:801`, `ratarmount/src/sandbox/process.rs:434`).
  Retained finalize rechecks the recorded lowers, runs durability preflight and
  S again, then returns the stored report (`ratarmount/src/sandbox/retained.rs:952`).
- The protocol's `Attempt` holds only ID, base, paths and status
  (`ratarmount/src/sandbox/protocol.rs:379`); its instance and lower records
  belong in `RetainedEntry` (`ratarmount/src/sandbox/retained.rs:402`). The
  lower exception accepts the exact retained overlay path only after
  acknowledgement (`ratarmount/src/sandbox/lowers.rs:211`). Retain's source
  check tries metadata before splitting an inline Git ref, and splits only on
  `NotFound` (`ratarmount/src/sandbox/finalize.rs:468`).
- A stored `done`/`failed` request replays before target resolution; a retryable
  finalize is bound to its ID **and instance** (`ratarmount/src/sandbox/finalize.rs:559`).
  Startup currently resolves every `running` request to `failed interrupted`
  (`ratarmount/src/sandbox/requests.rs:945`). Destroy refuses held or retained
  IDs and shutdown iterates only live attempts (`ratarmount/src/sandbox/retained.rs:529`,
  `ratarmount/src/sandbox/daemon.rs:1343`).
- The in-process finalize/retain guard returns `invalid_request` off Linux;
  daemon serve itself returns `unsupported` there
  (`ratarmount/src/sandbox/daemon.rs:530`, `ratarmount/src/sandbox/daemon.rs:1563`).

## Design

1. Under `daemon.lock`, after both logs open and before `reconcile`, scan the
   live retained records by ID. A candidate needs the corresponding real
   `retained/ID` and `overlay` directories, using the existing no-symlink
   directory checks. Validate the report's attempt ID and base, the report and
   attempt's `retained` statuses, exact `mnt`/`overlay` paths, and seal fields
   against the record. Check the report's manifest and optional bundle/summary
   paths against their expected names under that tree; check `paths.overlay`
   and `paths.bundle` against the expected paths and report. Do not require
   report output files to exist at startup. Read the top's metadata without
   recovery; require a sealed top with the recorded
   `layer_digest`, `sealed_at` and ordered `lower_layers` prefix. Use the ID,
   instance and exact path as well as the seal identity: never find a tree or
   establish provenance by digest alone. Do not require the base or lower
   contents to be available at startup; their existing request-time checks
   must still decide the answer.
2. If the matching retained tree and `attempts/ID` both exist, validate the
   retained tree first; if valid, restore it and let reconcile remove the stale
   source. A bare name, missing tree, malformed/inconsistent report or
   mismatched seal is not restored; leave its tree and live record untouched,
   reserved and counted.
   Fresh diff/stats/finalize requests get the existing not-served
   `invalid_request`, and destroy gets `retained`; stored requests retain
   their existing replay and instance-checked retry rules. An error reading
   one top leaves that entry unserved and logs the path; retry startup after
   fixing the read failure. Do not append `aborted`, move trees, invent a
   damage state, or guess from a bare directory. The existing reconcile
   behavior for an unrenamed `attempts/ID` is unchanged.
3. Rebuild each valid `RetainedEntry` from the report's attempt, original
   instance and report, and ordered recorded prefix (`None` for an empty
   prefix). Start unacknowledged: the log does not record whether R4 finished.
   Once candidates are checked, repeat R1c-1's commit step R4 once for a
   nonempty batch using the existing strict helper: sync `retained/`, then
   `attempts/`; only after both succeed mark candidates acknowledged. The durable commit record
   was written only after S; these syncs make an observed rename durable. If R4
   fails and the rest of startup succeeds, keep entries unacknowledged and
   served as in the original run: `list --all` shows `finalizing`, use as a
   lower is refused, and a fresh finalize retries S then R4 when storage is
   usable. Preserve the helper's filesystem checks; an fsync failure poisons
   that filesystem until restart, so a finalize touching it is refused. Do not
   run S merely to list or restore entries.
4. Reuse the existing request handlers and their lock order: retained `diff`
   gates the base and composes the saved stack; `stats` is offline;
   `finalize` with no request ID or a fresh/retryable one reruns the retained
   fast path and returns the exact saved report. A `done` or `failed` request
   ID replays its stored answer without another sync. Keep pins based on live
   record ID+instance and bare names, and leave `resolve_interrupted` unchanged:
   an interrupted request ID remains `interrupted`, including one already
   resolved by R1c-1; a fresh ID can finalize the restored attempt. Do not
   re-adopt a process, remount an attempt, or alter the log format. Durable
   writes and compaction remain in the one shared state-log engine.

## Steps

1. Add the narrow startup reconstruction and R4 acknowledgement at the seam;
   retain current `held`, pinning, reconcile and request resolution semantics.
   Run restoration only on Linux; preserve the existing non-Linux
   `Supervisor::open` behavior and the platform refusals above. Reuse the
   retained handlers rather than creating a second service path.
2. Add/update regression tests alongside the behavior change. Update the
   implementation's `docs/sandbox.md` retained/restart passages
   (`docs/sandbox.md:2937`, `docs/sandbox.md:3206`) and affected code comments to
   state the new behavior and the still-unserved cases. Preserve the documented
   durability/lock order and current Git-ref refusal order. Any new protected
   read must follow the existing internal-read inventory rules.

## Tests

Each new or changed regression has a `Regression:` symptom and runs at the
lowest useful layer; use the existing Fake with real sealed overlays plus a
real supervisor/FUSE case.

- Retain plain and layered attempts (including a bundle cache prefix and packed
  report), record the in-run diff, stats, report, target and list, restart the
  same state, and compare. Check v1/v2 list filtering, v1/v2 diff/stats, ordered
  prefixes, exact report paths and bytes, lower use after R4, ID reservation,
  `--max-retained`, and exclusion from `--max-attempts`. Assert no child is
  adopted, stopped or spawned by restoration.
- After restart, alter or make the base unopenable, and remove/reseal a lower:
  assert the existing `diff_failed`/`base_open_failed` and `lower_changed`
  behavior, with offline stats unchanged. For an ID-less/fresh finalize, trace S
  over each recorded lower, retained tree and indexes before the exact report;
  assert a replayed `done` answer has no new sync. Cover retryable matching and
  mismatched instances, previously failed `interrupted`, and `pack` requested
  after an unpacked report.
- Extend the existing real-SIGKILL retain test
  (`ratarmount/src/sandbox/finalize_tests.rs:5101`): after S or the record but
  before rename, do not fabricate a retained entry; after rename and after R4,
  restore it. Repeat restart. Assert R4 order, injected open/fsync failures
  using a test-only fault seam installed before restoration,
  and unacknowledged list/lower behavior. An open failure can be retried in the
  same run; an fsync failure poisons until restart. Check bare names, missing
  trees/metadata, changed seal/prefix, inconsistent
  report/paths, unreadable metadata, and simultaneous source/destination;
  assert no guessed service, lost reservation, or removal of retained data.
  Update the existing restart, retained-lower, sync-poison and pin tests that
  assert an empty retained map; keep coverage of kept-but-unserved retry errors
  and request pins.
- Through the real sandbox daemon and FUSE, retain a changed layered attempt,
  restart on the same state, and check offline diff/stats, fresh finalize,
  v1/v2 `destroy` refusal, base destroy, shutdown and another restart. Use
  `RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE=1` so a skip is not counted as
  evidence. Run the existing `regression_supervisor_retain_`,
  `regression_supervisor_retained_` and `regression_state_log_retained_` filters
  separately, plus the relevant new regression filters. On Linux use
  `TMPDIR=/var/tmp` on an allowed filesystem and the existing cargo lock.
- Before an implementation commit run the repository's full fmt, clippy,
  workspace test and both internal-read policy gates from `AGENTS.md:9`.

## Risks

- A record written before rename is indistinguishable from an orphan without
  a matching tree; this slice leaves it reserved, including its capacity slot.
  No reconciliation or automatic deletion is proposed. An inaccessible top
  remains unserved; a missing or changed lower instead keeps its existing
  request-time error. State moved to a different absolute path cannot pass the
  recorded path checks without a separate migration design.
- Startup now reads one top metadata record per candidate, up to the existing
  retained cap; avoid rescanning lower contents or syncing once per candidate.
  If implementation finds that any item explicitly excluded above is strictly
  required for restart-serve correctness, **stop and raise it as a scope
  question** here and in the Review log instead of folding it into this slice.

## Not taken

- Reconstructing from digest alone, trusting a bare directory, or completing a
  pre-rename retain would infer provenance the log and path do not establish.
- Rewriting old interrupted request records would change the established
  replay contract; use a fresh finalize request ID instead. Treating every
  restored entry as acknowledged without repeating R4 would skip a possible
  interrupted rename sync.

## Review log

- 2026-11-06: R1c-2 as built (restart-serve): validate a retained tree even
  when `attempts/ID` also exists; a valid tree is restored and reconciliation
  removes the stale attempt. An unreadable top remains reserved but unserved.
  Directory checks use `symlink_metadata` without creating paths. Startup R4
  is skipped without candidates; an R4 fsync failure poisons its filesystem
  until restart, as it does during an in-run retain.
- 2026-11-06: Author inspection against `56fc9ce`; no out-of-scope extra was
  found necessary for this design. The supplied `review-plan` guidance says
  not to use it from Codex, so no skeptic-plan review is claimed here.
