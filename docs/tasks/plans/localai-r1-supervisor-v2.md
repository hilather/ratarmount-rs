# Local AI R1: sandbox supervisor v2 (lowers, journal, finalize, retain, request IDs), with R5 docs

**Status:** plan, not started (2026-10-31). Baseline `main` at `2b96837` (v0.1.36 workspace). Branch for the plan: `plan/localai-r1-supervisor-v2`. Revision 7 was a targeted revision at Matt's direction after sweep 6; sweeps 7 and 8 followed (§14 has the full review log).
**Source:** `ratarmount-rs: implementation plan for the local AI features worth doing` (Oct 31, 2026), §4 (R1) and §8 (R5). This plan replaces §4's design wherever the two disagree. Each disagreement is listed in §2 with the code that decides it.
**Requested by:** Matt, relayed by Keystone (2026-10-31 10:56 ET). The scope is locked to the source doc's v1. This file covers R1 only, with R5's documentation folded in, because R5 lands in the same PR.
**Gate:** R1 touches the sandbox, sealing and the operation journal, so the full gate applies with no waivers: every `AGENTS.md` CI command, the internal-read policy scripts, the FUSE tests on a FUSE host, and a regression-catalog row for every fix. A skipped FUSE test does not count as a pass for this gate. CI does **not** enforce that today: every FUSE test in `ratarmount/tests/` skips silently without `/dev/fuse` or `fusermount3`, and no workflow sets the one variable that turns a skip into a failure (`RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE`, `tests/sandbox.rs:365-366`; `ci.yml:102-105` sets only `RATARMOUNT_REQUIRE_XORRISO`). Step 9 adds the variables that make R1's FUSE and namespace tests fail instead of skip in CI (§9, step 9).
**Crates touched:** `ratarmount` (`src/sandbox/*`, a new `src/sandbox/finalize.rs`, a new `src/sandbox/requests.rs`), `ratarmount-compositing` (three small public APIs: `SealOperation::acquire_until`, §6.4; `MountLowerStack::open_no_recovery`, §6.3; `host_stat::chmod_dir_at`, §6.7), `ratarmount-index` (one: `cached_archive_digest_checked`, §6.6), `clients/python`, docs, `packaging/internal-read-clippy/manifest.json`, `AGENTS.md`, `CHANGELOG.md`, and `.github/workflows/ci.yml` (two environment variables on the `check` job's `cargo test` step, §9 step 9).

---

## 1. Scope

**In (R1 + R5):**

- Protocol version 2. `new` gains `lowers`, `journal`, `retain` and `request_id`. Two new operations: `finalize` and `forget`. Version 1 stays byte-for-byte unchanged, and a golden replay test proves it.
- Layered attempts. Each attempt mounts `base + sealed lowers + writable top`, with an optional per-attempt operation journal.
- `finalize`. A normal (non-lazy) unmount, then fsck with repair, a base gate, seal, the canonical hash, an optional pack, and a report. It shares one `finalize_top` function with `sandbox run`.
- Retained attempts under `state-dir/retained/`. Restart reconciliation never deletes them. `forget` deletes one. A separate `--max-retained` caps them.
- Request IDs that survive a restart. They are stored in an append-only log with compaction.
- Python client and CLI support.
- R5: a Journal note in `docs/sandbox.md` ("the journal is not model context") and a hidden-tests section in `docs/recipes/swe-bench-sandboxes.md`.

**Out:**

- R2 (tensors manifest), R3 (expert repack) and R4 (Python `readinto`/`read_many`). Each gets its own plan.
- Everything in the source doc's §9: the episode graph, operation queue, cancel, artifact transfer, object store, canonical-JSON identity profile, new crates, model gateway, sampler, fault worlds, tensor export and the Harbor adapter.
- Re-adopting a running mount after a restart. Mutable attempts stay disposable.
- Attempt-level `allow_globs`. The source doc lists them in `New`, but they loosen the base's read-only policy. The supervisor's rule is "a request cannot loosen a base policy" (`docs/sandbox.md:2335`, `daemon.rs:621`), and allow globs are not in the locked R1 list. Base-level `allow_globs` already exist (`protocol.rs:22`).
- `retain: true` with `overlay: "tmpfs"`. It is refused at `new` (§6.6). A copy-to-disk path can come later. `copy_tree` (`run.rs:696`) exists for that.
- Lowers, `retain` or finalize on bases that use `binds` or `recursive`, unless the step-0 spike (§9, step 0) proves that the finalize classification matches what the mount recorded. Until then these requests get `unsupported`.
- Lowers, `retain` or finalize on bases the factory does not serve locally: remote URLs, OCI, restic or torrent sources (sweep 8, Claude N5).
  - Classifying such a base inside the daemon may download its body again (`RemoteLocal::Fetched`, `ratarmount-remote/src/lib.rs:683-703`), on every finalize and every v2 `diff`, inside the serve loop.
  - `factory::served_without_indexing` refuses remote URLs other than `file://` (`ratarmount-session/src/factory.rs:4610-4614`) and serves a torrent as a remote folder (`:4599-4608`), so neither gives §6.6's digest caching the local archive it needs.
  - These requests get `unsupported` too.
- `unsupported` is decided at **`new`** for `lowers` and `retain`, so a retained slot is never reserved for an attempt that finalize would refuse (sweep 8, Claude N13). It is decided again at finalize.

Any request beyond this list is refused and sent back to Keystone.

**Relation to Fork-N:** `docs/design/fork-n-writable-tops.md:82-83` says "The sandbox supervisor and `sandbox run --top` are not changed" by that design, so R1 neither replaces nor conflicts with an in-repo design.

---

## 2. Corrections to the source doc (verified in the code at `2b96837`)

> **For Keystone: the #240 lock order, as the code has it. Seal takes no archive lock.**
>
> The rule as relayed ("seal takes the exclusive archive lock first, then the overlay DB lock; commit re-checks `layer_sealed` under the archive lock") is wrong on both points. The code at `2b96837`:
>
> - **Seal never acquires an archive lock.** `overlay_seal.rs:276`: "Seal never acquires an archive lock." Its order is:
>   1. the overlay **root** directory flock (`SealCommitGuard`, an `O_RDONLY|O_DIRECTORY` flock on the overlay root, `overlay_seal.rs:409-412`, `write_overlay.rs:7418-7446`);
>   2. the overlay **database** transaction (`BEGIN IMMEDIATE`, `overlay_seal.rs:456`).
>
>   Instead of locking the archive, seal reads it through `SealArchive`, a SQLite-managed reader ("without creating it or taking its archive lock", `overlay_meta.rs:1022-1036`). It checks that the archive's size, mtime and file identity did not change while it waited for the flock, and refuses with "archive changed since its base view was opened; reopen it and retry sealing" if they did (`overlay_seal.rs:406-408`, `425-437`). `unseal` likewise takes only the root flock and then `BEGIN EXCLUSIVE` (`overlay_seal.rs:676-711`).
> - **Commit** takes, in order:
>   1. the same overlay root flock (`OverlayCommitGuard::acquire`, `write_overlay.rs:7357-7363`), and re-checks `layer_sealed` **under that flock** (`:7360-7362`; live commits through `commit_operation`, `:3684-3696`);
>   2. only then the archive guard: `commit_journal::unix::lock`, a `flock(LOCK_EX|LOCK_NB)` on the archive (`ratarmount-compress/src/commit_journal.rs:707-717`), taken for instance by the archive replacement `replace` at `:917` and held until it returns.
>
>   "It always acquires the overlay lock before any archive guard" (`write_overlay.rs:7350`). `docs/sandbox.md:601-616` says the same.
> - **Why the relayed order must not be followed** (reason corrected in sweep 7).
>   - Commit's archive flock is **non-blocking**: `commit_journal::unix::lock` uses `LOCK_EX|LOCK_NB` (`commit_journal.rs:713`), and every caller turns a failure into an error (`:917`, `:1239`, `:1354`). A seal holding that flock would not deadlock commit; it would make every commit fail with a refusal for as long as it held it.
>   - The lock commit waits on **without a bound**, while holding the overlay root flock, is the per-index digest lock `HashGuard`. It polls for an in-process entry and then for a `flock` on the index's lock file (`ratarmount-index/src/digest_cache.rs:444-481`). Commit takes it in the baseline refresh after publishing (`refresh_archive_digest`, `overlay_meta.rs:1541`). A seal takes it when it resolves a `pending` digest for a top that records a writable `base_index_path` (`hash_seal`, `overlay_meta.rs:997-1016`, called from `overlay_seal.rs:445-451`, before `BEGIN IMMEDIATE`).
>   - A seal that took an archive-level lock such as `HashGuard` **before** the overlay root flock would deadlock against such a commit (AB/BA, both waits unbounded; `SealCommitGuard::acquire` also spins without a bound, `write_overlay.rs:7429-7446`).
>   - So the relayed order either makes commits fail or deadlocks them, depending on which archive-level lock is meant.
>
> **How R1 honours the real order.**
>
> 1. **`daemon.lock`** sits above everything: it is held for the supervisor's whole life and serializes all requests (`daemon.rs:319`).
> 2. **Finalize seals the top through the existing API, in the existing order:**
>    - `SealOperation::acquire_until` (the root flock, with a deadline instead of the unbounded spin);
>    - then `finish_if_sealed`;
>    - then classify and gate the base under that flock;
>    - then `SealOperation::seal(self, …)`, which consumes the guard. Seal itself then takes its database transaction.
>
>    So R1 takes exactly the root flock, then seal's own transaction (§6.3, §7).
> 3. **R1 never takes an archive lock and never commits.** Supervisor workers run with `--no-recreate-index`, which refuses every overlay-commit mode (`docs/sandbox.md:2241-2243`), so the commit branch of #240 is not reached at all.
> 4. **R1 never holds two overlay root flocks**, and never takes the top's flock again while holding it. Two flocks on separate open file descriptions conflict even inside one process, so that would deadlock the daemon. Lowers are only read (`OverlayMeta::read_no_recovery`, also when composing them, §6.3) and never locked.
> 5. **R1's seals never take the index `HashGuard`.** Supervisor tops record no writable `base_index_path`: workers run with `--no-recreate-index`, which makes the index read-only (`main.rs:2084`, `:2522`), and only a writable index is recorded (`overlay_identity.rs:276-280`). On top of that, `create_base` caches a local archive's digest at registration (§6.6), so a worker's top records the digest as `present` and finalize's seal has nothing `pending` to resolve.
> 6. **The one place R1 takes `HashGuard` is that registration** (made explicit in sweep 8). `create_base`'s digest caching takes the `HashGuard` of the base's **own** index in `state/indexes/<name>`, with nothing held but `daemon.lock`: no overlay root flock, no database transaction, no archive flock. Its wait is bounded: `check` is polled while waiting and gives up after its own `--timeout` window or on SIGTERM, and giving up only skips the caching (§6.6). With no second lock held, there is no order to violate, and nothing can wait on R1 while R1 waits.

| Source doc says | Code says | Plan |
| --- | --- | --- |
| Record retained attempts in `state.json` | No such file. Bases persist in `bases.json` (`daemon.rs:388-396`). Its `State` is `deny_unknown_fields` and rejects any `version != 1` (`daemon.rs:275-280`, `330`). | Leave `bases.json` alone, so an older daemon can still parse the state. A downgrade **after a crash** also needs `chmod -R u+w` on the leftover `attempts/*` and RAM `ram/*` trees first: the older `reconcile` uses `fs::remove_dir_all` (`daemon.rs:413`, `:426`), which fails on a sealed tree left by K3 or by a non-retained tmpfs finalize. `retained/` is ignored by an older daemon. This is documented in `docs/sandbox.md` and the CHANGELOG (sweep 4, N9). Each retained attempt carries its own `record.json` inside its directory (§5). |
| Retained attempts count toward `--max-attempts` | Keystone #1 overrides this. | They don't count. Only `--max-retained` applies (§10, #1). |
| Store whole request records in `requests.json` with `atomic_json` | `atomic_json` rewrites the whole file and fsyncs twice (`daemon.rs:282-298`). | Use an append log plus compaction (§10, #5). |
| "serde_json with sorted keys is enough" | Sorted only while `preserve_order` is off. | Canonicalize explicitly and test it (§10, #4). |
| "every existing v1 test passes unchanged" | `regression_protocol_rejects_unknown_fields_and_versions` (`tests.rs:123-128`) asserts that `{"version":2,"op":"list"}` returns `unsupported_version`. | That test's version-2 line moves to version 3. Everything else stays (§10, #7). |
| #240 order quoted as "archive lock first, then overlay DB lock; commit re-checks `layer_sealed` under the archive lock" | Seal: overlay root flock, then the database transaction, **no archive lock** (`overlay_seal.rs:276`). Commit: overlay root flock, `layer_sealed` re-checked under it, then the archive flock. Full citations in the callout above. | The relayed rule is wrong on both points and must not be implemented: it would make commits fail, or deadlock them through the index `HashGuard` (callout above). R1 keeps the real order and adds nothing between the layers (callout above, §7). Revision 1 had wrongly counted seal's managed reader as an archive guard; sweep 2 corrected that. |
| Finalize report includes `layer_digest` | `finish` does not report it (`run.rs:1186-1192`). | The supervisor's report adds `layer_digest` from `SealOutcome`. The `sandbox run` report stays unchanged (§6.3). |
| `finish` "lines 1092 onward" can be lifted as is | It builds the base with `OverlayRunContext::default()` (`run.rs:1114`): no index folders. | The supervisor passes its base's index folder and options (§6.3, §9 step 0). |
| `reconcile` deletes attempts with `remove_dir_all` | A sealed overlay has no write bits (`docs/sandbox.md:646-648`), so `remove_dir_all` fails on it, and `reconcile` errors out before the daemon serves (`daemon.rs:413`). | Every supervisor deletion goes through a removal that restores permissions (§6.7). Without that, Keystone #2's crash test cannot pass. |
| `diff`/`stats` "keep working" on finalized attempts | `Diff` renders against the bare base (`daemon.rs:499-516`), so with lowers the patch would contain the lowers' files. `ProcessMounter::deleted_paths` goes offline only for `crashed` (`process.rs:216-223`). | `diff`/`stats` compose the attempt's lowers and go offline for any attempt without a live mount (§6.8). |

---

## 3. What exists today (the parts R1 changes)

- **Wire.** `protocol.rs`: `VERSION = 1` (`:7`). `Operation` (`:38-77`) is `deny_unknown_fields`. `Request::parse` (`:90-106`) removes `version` and rejects anything except 1. `Response::from_result` always writes `version: VERSION` (`:156-173`). The wire `Attempt` is `{id,base,path,overlay_dir,status}` (`:116-123`).
- **Serve loop.** `daemon.rs:885-957`: single-threaded, serial requests, at most 32 connections. Per line it calls `Request::parse(..).and_then(|r| supervisor.handle(r.operation))` and then `send(.., Response::from_result(result))` (`:934-943`).
- **Supervisor.** `open` (`:313-382`) creates `attempts/` and `indexes/`, loads `bases.json` and `ram-root.json`, then calls `reconcile` (`:398-431`), which cleans up and deletes every `attempts/*` and every RAM attempt. Attempts live only in memory (`attempts: BTreeMap<String, Attempt>`, `:303`). `new_attempts` (`:606-726`) checks capacity against `attempts.len()` (`:615`), records each attempt, then spawns. It polls readiness until every attempt is `ready` and rolls the batch back through `destroy` on error. `destroy` (`:728-737`) runs `cleanup` and then `remove_dir_all`.
- **Mounter.** `process.rs`: `Mounter::spawn(base, indexes, attempt, quota, readonly)` (`:27-34`). `mount_args` (`:78-109`) adds `--no-recreate-index`, the inspection socket and `-w`. `cleanup` (`:225-247`) tries a normal unmount, then falls back to a lazy one (`detach` tries `fusermount3 -u -z` and `umount -l`, `:274-310`).
- **Inspection socket.** `inspection.rs` handles a single command, `deleted_paths` (`:93`).
- **`sandbox run`.** `pipeline` (`run.rs:914-1082`) and `finish` (`:1092-1193`): `fsck(top, true)`, then `classify_base` and `gate_base`, then `MountLowerStack::compose`, `seal`, `pack`, `change_set`, `canonical_hash`, the manifest and the journal summary.
- **Seal.** `overlay_seal::seal` / `SealOperation` (`overlay_seal.rs:283-365`) and `seal_impl_locked` (`:375-`). A repeated seal returns the recorded digest (`finish_recorded_seal`, `:321-333`). `unseal` (`:676-711`) takes only the root flock and a `BEGIN EXCLUSIVE`.
- **Lower stack.** `MountLowerStack::open_inner` (`lower_stack.rs:133-219`). The mount child reads each lower's `OverlayMeta` itself, refuses unsealed lowers unless `--allow-unsealed-lower` (`:176-184`), and opens sealed lowers `Immutable`. The base-identity check for lowers is at `main.rs:1478-1540`.
- **Python client.** `clients/python/ratarmount_sandbox.py`: `_VERSION = 1`. A response whose version differs is a protocol error.

---

## 4. Protocol (wire) changes

### 4.1 Versions and dispatch

- `protocol.rs` keeps `VERSION = 1`, `Operation`, `BaseOptions` and the wire `Attempt` **unchanged**: no new fields and no new variants.
- Add `pub const VERSION_2: u32 = 2` and `OperationV2` (`#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]`). It contains `CreateBase`, `List`, `Diff`, `Stats`, `Destroy` and `Shutdown` with the same fields as v1, plus `New` (v2 fields), `Finalize` and `Forget`.
- `Request` becomes `{ version, #[serde(flatten)] operation: Op }` with `#[serde(untagged)] enum Op { V1(Operation), V2(OperationV2) }`. `untagged` is required for serialization: without it the CLI would send `{"V1":{…}}`, and U3 would fail. Deserialization never goes through `Op`'s derive, because `parse` picks the variant from `version` itself. `Request::parse` reads `version`:
  - 1 parses into `Operation`. A v1 `new` carrying `lowers` stays `invalid_request`, with serde's unknown-field message.
  - 2 parses into `OperationV2`.
  - Anything else, or a missing version, returns `unsupported_version` in a **version-1** envelope (see 4.4). The message stays exactly `"version must be 1"`, byte for byte. The golden fixture holds envelope errors too (§10, #7), and a v1 client must see the same bytes it sees today. Version 2 is documented in `docs/sandbox.md`, not announced in this message.
- `Supervisor::handle` takes `Op`. V1 requests take exactly today's paths, with no new behaviour visible to a v1 caller (see 4.5 for `list`).

### 4.2 Version-2 operations

```text
new      { base, count=1, overlay="disk", quota?, readonly_globs=[],
           lowers=[]            // absolute paths, bottom first, ≤ 32
           journal?: { exclude=[], reads="all"|"first", sync=false }
           retain=false, request_id? }
finalize { id, pack=false, request_id? }
forget   { id }
list     { base? }              // same fields as v1; a v2 list shows every status (sweep 6, N4)
```

`request_id` is 1-128 characters with the same character set as base names (`validate_name`, `daemon.rs:23-36`), scoped to the state directory. `JournalSpec` and `JournalReads` are `deny_unknown_fields`.

### 4.3 Version-2 results

- The `new` result is an array of `AttemptV2`: the v1 fields, plus `lowers: [path]`, `journal_path: path|null`, `retain: bool`, and, once finalized, `layer_digest`.
- The `finalize` result is the finalize report (§6.3) plus `status: "finalized"|"retained"`. It carries `layer_digest`, `stack_digest` and `base_digest_state` at **top level**, as the source doc lists them (`source-plan-doc.md:118`), copied from the same values nested in `patch_hash` (sweep 6, N5). The `sandbox run` report keeps its current shape (U10).
  - It also carries **`attempt`**: the `AttemptV2` after finalize, with its final `path`, `overlay_dir` and `status`. For a retained attempt these name `retained/ID/...`. This is what the Python client updates its object from (sweep 8, Claude N9). The `sandbox run` report's `overlay` field (`run.rs:1186-1192`) does not exist in the supervisor's result.
  - It also carries **`base_hashed_by_finalize`**: `true` when the top's base digest was still `pending` before seal, so seal had to hash the base. That makes a failure of §6.6's caching visible in every report. `base_digest_state` is `present` after seal either way, so it cannot show this (sweep 8, Claude N1).
  - On a retry, `fsck_result`, `bytes_written` and `base_hashed_by_finalize` are the first try's values (§6.3). A retry over a top sealed by an earlier try would otherwise see the digest `present` and report `false`, hiding the hash the first try did.
- The `forget` result is `{"forgotten": true}`.
- The `list` result (v2) is an array of `AttemptV2`. `status` is one of `starting` (a rollback leftover, as today), `ready`, `crashed`, `detaching`, `stopped`, `sealed`, `finalized`, `retained`, `retained_damaged` or `forgetting` (§6.7, sweep 8).

### 4.4 Response version

`Response::from_result` takes a `version`. `serve` passes the parsed request's version through, and so does `send`. `send` replaces an oversize reply with a `response_too_large` error built through `Response::from_result` (`daemon.rs:869-883`), so it takes the version as a parameter too: an oversize v2 `diff` gets a v2 envelope (sweep 5, N2; U27 covers it). Parse failures (malformed JSON, unknown version, oversize line) keep today's `version: 1` envelope byte for byte (`daemon.rs:935-951`). An unknown field inside a version-2 request returns `invalid_request` in a **version-2** envelope. Step 0 factors the per-line handling into `fn respond(&mut Supervisor<M>, line: &[u8]) -> Vec<u8>`, used by both `serve` and the golden test (§10, #7).

### 4.5 What v1 callers see once v2 state exists

- **v1 `list`** hides only the new statuses (`detaching`, `stopped`, `sealed`, `finalized`, `retained`, `retained_damaged`, `forgetting`) and shows everything else exactly as today. That includes a `starting` attempt left behind by a failed rollback (`daemon.rs:710-724`), which v1 shows today. A v1 client never created them, and hiding them keeps v1 `destroy` loops from tripping over them.
- **v1 `destroy {base}`** and **`shutdown`** skip retained and `forgetting` attempts (§6.6) and still destroy finalized attempts that were not retained (those are disposable).
- **v1 `destroy {id}`** of a retained attempt returns `invalid_request` ("attempt is retained; use forget").
- **v1 `new` capacity** counts `attempts` only (§10, #1). That includes `stopped`, `sealed` and finalized-but-not-retained attempts, which v1 `list` hides, so a v1 client can get `capacity` without seeing the attempts that use the slots. Only a v2 client can create those attempts, and it can see and destroy them with v2 `list`. This is documented in the v1-callers paragraph of `docs/sandbox.md`.
- A golden test covers v1 replay against a state that holds retained attempts (§11, U4).

### 4.6 New error codes

- `idempotency_conflict`
- `writers_active`
- `interrupted`
- `lower_changed`
An invalid lower (unsealed, relative, missing, inside a live attempt, a damaged retained layer, more than 32) returns the existing `invalid_request`, as the source doc specifies, with the path in the message. A `forget` of a retained layer that a live attempt still uses as a lower returns the existing `in_use`. Existing codes keep their meaning.

---

## 5. On-disk layout

```text
state-dir/                     0700, owned (private_dir)
  daemon.lock                  unchanged
  bases.json                   unchanged (State v1)
  ram-root.json                unchanged
  requests.jsonl               NEW  0600, O_NOFOLLOW|O_APPEND|O_CLOEXEC, append log (§10 #5)
  indexes/BASE/                unchanged
  attempts/ID/                 disposable; deleted by reconcile
    mnt/  overlay/  mount.log  inspect.sock          (as today)
    journal.jsonl              NEW  when journal requested; outside mnt and overlay
    journal.summary.json       NEW  written by finalize
    manifest.jsonl             NEW  written by finalize
    bundle.tar.zst             NEW  when pack
    record.json                NEW  written by finalize just before the commit rename
  retained/                    NEW  0700 (private_dir); never touched by reconcile's delete loop
    ID/                        same tree as attempts/ID, moved by one rename(2)
```

- **`record.json`** (`atomic_json`, version 1, `deny_unknown_fields`): `{version:1, id, base, lowers:[{path, kind:"dir"|"bundle", identity, layer_digest}], journal, retain:true, layer_digest, finalized_at, report}`. Each lower's `layer_digest` is the digest the attempt's mount actually took, so a bundle position can be checked by digest when the retained layer is used as a lower again (§6.2 item 5; sweep 8). `report` is exactly the JSON the finalize request returned. Every path in it already names `retained/ID/...`: finalize computes the final paths before it writes them (§10, #2).
- The journal file sits outside the mountpoint and the overlay, as the journal placement rule requires (`docs/sandbox.md:986-991`). The mount records the journal in the overlay's `meta` table as `journal_path` (`ratarmount-fuse/src/lib.rs:835-841`, `overlay.set_meta("journal_path", …)`), and after the rename that row still names `attempts/ID/journal.jsonl`. That row is informational, is not part of any digest, and is documented as such.
- `retained/` lives on the same filesystem as `attempts/` because both are children of the state directory. `Supervisor::open` checks that the two `st_dev` values are equal and refuses to start if they differ (answers source doc §11 Q3). On the Dells the state directory must sit on the one XFS drive.

---

## 6. Design

### 6.1 Layered spawn (`process.rs`, `daemon.rs`)

- `Mounter::spawn(&mut self, base, indexes, attempt, spec: &SpawnSpec)` with `SpawnSpec { quota, readonly: &[String], lowers: &[PathBuf], journal: Option<(&Path, &JournalSpec)> }`. `mount_args` takes the same struct.
- Before `--` it adds `--lower P` for each lower (bottom first), then `--journal P`, `--journal-exclude G` for each glob, `--journal-reads first` when set, and `--journal-sync` when set. It never adds `--allow-unsealed-lower` or `--force-stack-mismatch`.
- Callers that change with it: `ProcessMounter::spawn` (`process.rs:173-199`), `validate_base` (`daemon.rs:801-825`, which passes the base policy and no lowers), the `Fake` in `tests.rs:43-63`, and `regression_overlay_meta_child_argv_preserves_base_url` (`process.rs:395-416`).
- `base_args` always passes `--no-file-versions` (`process.rs:43`). The bundle verification marker is keyed per view (CHANGELOG Gate-3), so a bundle lower already verified by a plain mount is verified once more under the supervisor. cpanmine's view-flag check must accept this one flag, which the supervisor owns (source doc §4 note).

### 6.1a Attempt IDs unique across `attempts/`, `retained/` and the request log (sweep 5, B1)

Today `new_attempts` draws each ID with `tempfile::Builder::new().prefix("attempt-").tempdir_in(attempts/)` (`daemon.rs:651-655`). tempfile 3.27 uses 6 random characters (`NUM_RAND_CHARS = 6`) and avoids only names that already exist in `attempts/`. R1 adds two more places keyed by attempt ID:
- the `retained` map, where `retained/X` blocks `rename(attempts/X, retained/X)` with `ENOTEMPTY` and makes every map lookup ambiguous;
- the `attempt` field of request-log records, where a `retryable` finalize of a destroyed X would act on a **new** attempt that reused the name X.

**Rule.** After `tempdir_in` creates `attempts/X`, `new_attempts` checks the reserved set. `X` is reserved if any of these holds:
- `X ∈ retained` (including `retained_damaged`).
- `X` is the `attempt` of any live request-log record (a finalize). This holds in any state, including after compaction, because every line carries `attempt` (§10 #5).
- `X` is in the `attempts` list of any live `new` record (sweep 6, N1). A `new` record's `running` line has no IDs yet. Its `done` line carries `"attempts":[…]`, the IDs it returned, and so does a `failed` line from a rollback that kept attempts. A replayed `new` therefore never names an ID that a later `new` has drawn again.
- If `X` is in the reserved set, it removes the just-created empty directory and draws again, up to 16 times. After that it returns `io` ("could not allocate a unique attempt ID").
- The check runs before the attempt is recorded or spawned.
- At about 5.7e10 names and up to about 131,072 reserved IDs, a redraw happens about once per 4×10^5 attempts.

The v1 ID shape (`attempt-XXXXXX`) is unchanged. No v1-visible change. Lengthening the random part instead was rejected: every extra character shortens the longest usable state-directory path, because `attempts/ID/inspect.sock` must fit `sun_path` (`docs/sandbox.md:2383-2388`), and that would be a v1-visible behaviour change.

**Re-verified for revision 7.**
- tempfile 3.27.0 (`Cargo.lock:6787-6788`) draws 6 alphanumeric characters, `NUM_RAND_CHARS = 6` (`tempfile-3.27.0/src/lib.rs:195`, `util.rs:15`), giving 62⁶ ≈ 5.7×10¹⁰ names. It retries only on `AlreadyExists` in `attempts/` (`NUM_RETRIES`, `lib.rs:194`). So the reserved-set check is needed, and the numbers above hold.
- The reserved set is rebuilt at every open from `retained/` and from the request log. Every log line carries `attempt`, `new` `done` lines carry `attempts`, and compaction copies lines verbatim (§10 #5), so the set survives restarts and compactions.
- The commit rename uses `RENAME_NOREPLACE` (§10 #2), so a collision the set did not foresee fails closed instead of replacing a directory.
- The only window left is the documented one: after a record is evicted (§10 #5 caps), its names are drawable again.

**Retry against a destroyed attempt.** A retry of a `retryable` finalize whose attempt no longer exists returns `not_found`, and can never reach a different attempt, because the name stays reserved while its record lives. When the record is evicted (§10 #5 caps), the name becomes reusable. A retry after eviction runs as a new request and finds a different attempt only if the name was redrawn in between. That is the bounded retry window, documented with it.

**Test U35** (`regression_attempt_id_never_reuses_retained_or_logged`): the `#[cfg(test)]` ID source is forced to return a name equal to a retained ID, then one equal to a destroyed attempt's ID still named by a `retryable` record. `new_attempts` redraws in both cases. Retrying the old `request_id` returns `not_found`, and the new attempt is untouched.

### 6.2 Lower validation, before any directory or spawn

This runs in `new_attempts` before the first `tempdir_in`.

1. At most 32 lowers. Each is UTF-8, absolute and NUL-free. `canonicalize` must succeed.
2. The canonical path must not be inside `state/attempts/`, inside the RAM root, or inside `state/` at all, except `state/retained/ID/overlay` or `state/retained/ID/bundle.tar.zst` of a `retained` (not damaged) record.
3. **Directory lower:** `OverlayMeta::read_no_recovery` must return `Some(meta)` with `meta.layer_sealed()`. Snapshot `LowerIdentity::Dir { path, dev, ino (of the root), layer_digest, sealed_at }`.
4. **Regular-file lower (bundle):** snapshot `LowerIdentity::Bundle { path, dev, ino, size, mtime_ns }`. The mount child does the verification itself (`lower_stack.rs:150-169`). A bad bundle shows up as `mount_failed` with the log excerpt.
5. **Stack consistency** (sweep 2, N8; corrected in sweep 3, B3 and N1). **Nothing in the child checks this.** `check_top` compares only the top's recorded lowers with the given ones (`lower_stack.rs:266-299`), and the base check covers only the bottom lower (`main.rs:1478-1540`). So this supervisor check is the only protection. It is applied per directory lower L at position i:
   - **L is a retained layer:** its `record.json` stores the lowers it was finalized over, exactly as the supervisor received them (canonical directory paths and bundle paths with their identities, §5). Those must equal requested lowers 0..i-1, path for path, with each directory's `layer_digest` and each bundle's `(dev, ino, size, mtime_ns)` equal too. Bundles are compared by path, never by the cache directory the child resolved. A retained layer must also have been finalized over the **same registered base** (`record.base == new.base`, sweep 5, N7). That is a cheap check ahead of the child's digest check, which covers only the bottom lower.
   - **L is an external sealed layer** (no record): compare its recorded `lower_layers` (`OverlayMeta::lower_layers`) with requested lowers 0..i-1. The count must match. At each position where the requested lower is a directory, its canonical path and `layer_digest` must match.
   - **Bundle positions, under either kind of L, are completed after `Ready`** (sweep 8, Codex 7). Before the mount, the supervisor has no digest for a bundle: the child resolves it, and the recorded `path` is the child's cache directory (`lower_stack.rs:150-172`, recorded at `:196-208`). After `Ready`, each child reports the records it took (§10 #3). At every bundle position, the child's resolved `layer_digest` must equal what L recorded there: L's `lower_layers` row for an external layer, or the digest `record.json` stores for that bundle for a retained one (§5). A mismatch is `lower_changed`, and the batch is rolled back. Revision 7 checked only the count here, so an external layer finalized over bundle A was accepted over a different bundle B.

   A mismatch found before the mount is `invalid_request`, naming L, and nothing has been created. The bundle-position comparison after `Ready` is `lower_changed` instead, because the batch has already been spawned and is rolled back (§10 #3).
6. **Journal globs** (sweep 2, N7). `journal.exclude` is parsed with `ratarmount_compositing::ReadOnlyGlobs::new` (as the mount does, `main.rs:940`). A bad glob is refused before anything is created.
7. Anything else fails with `invalid_request`, naming the path (or the glob). The batch's state is untouched.

The **canonical** path is what goes into the snapshot, the attempt record and the child's `--lower` argument, so the supervisor's checks and the child's own `OverlayMeta::read` (`lower_stack.rs:173-177`) name the same directory or bundle.

Every check uses the existing read API, so this step adds no new acquisition site. That API is `OverlayMeta::read_no_recovery` (`overlay_meta.rs:274`) plus `symlink_metadata`.
- **Never `OverlayMeta::read` on a lower** (sweep 4, N5). `read` recovers hot journals (`overlay_meta.rs:267-269`), so validating a caller-supplied external lower could write to someone else's overlay (a hot-journal rollback) before refusing it.
- **The same rule covers every supervisor-side lower read:** validation, the post-`Ready` re-check, finalize step 2, and the retained-load check of `retained/ID/overlay`.
- **A lower with a hot journal** is refused as `invalid_request`. A sealed lower never has one in normal operation. The snapshot is kept per attempt (`AttemptSpec.lowers`) for the re-check in §10 #3 and for the `forget` pin in §6.7.

### 6.3 `finalize_top` (new `ratarmount/src/sandbox/finalize.rs`)

```text
pub(crate) struct FinalizeInputs<'a> { top, classify: &'a mut dyn FnMut(Option<&OverlayMeta>) -> Result<ClassifiedBase>,  // FnMut: calls Mounter::classify(&mut self) (sweep 4, N11)
    base_digest: Option<String>, lowers: &[PathBuf], journal: Option<&Path>,
    outputs: FinalizePaths (manifest, journal summary), seal: bool, deadline: Option<Instant>,
    lower_reads: LowerReads /* Recovering: sandbox run, as today; NoRecovery: the supervisor (sweep 7) */,
    check_lowers: Option<&[LowerLayerRecord]> /* the top's recorded rows; Some for the supervisor (sweep 7) */ }
pub(crate) struct FinalizeReport { fsck_result, patch_hash: Value, layer_digest: Option<String>,
    manifest_path, journal_summary: Option<Value>, bytes_written }
/// Owns everything the composed view reads (sweep 7, Codex 1). Kept alive by the
/// caller through `finalize_pack` and until the report is built.
pub(crate) struct Finalized { pub report: FinalizeReport, pub base: ClassifiedBase,
    pub stack: MountLowerStack, pub view: Arc<dyn MountSource> }
pub(crate) fn finalize_top(inputs) -> io::Result<Finalized>
pub(crate) fn finalize_pack(top, bundle, finalized: &Finalized, journal) -> io::Result<PathBuf>
```

**The owner of the base stays alive through pack** (sweep 7, Codex 1). `ClassifiedBase::source()` returns the source without its `_keep_alive` (`overlay_identity.rs:1046-1058`). For a fetched remote base that keep-alive is a `RemoteLocal::Fetched`, which deletes the downloaded file when dropped (`ratarmount-remote/src/lib.rs:698-703`). Path-backed readers such as CPIO's reopen that file on every member open (`ratarmount-formats-cpio/src/lib.rs:128-136`). So returning only the composed view, as revision 7 did, would delete the base's backing file before `finalize_pack` reads it. `finalize_top` therefore returns `Finalized`, which holds the `ClassifiedBase` (and so its keep-alive), the opened lower stack and the view. `run.rs`'s `finish` already keeps its `base` alive for the whole function. Test: U40.

`finalize_top` is **resumable**: running it again on a top it has already sealed finishes the same way (sweep 1, B2). It runs these phases in order:

1. **fsck.**
   - If `OverlayMeta::read(top)` shows the top is **not** sealed, it runs `fsck(top, true)`, exactly as `run.rs:1100` does today.
   - If the top is **already sealed**, it runs `fsck(top, false)` and requires `is_clean()`. `fsck` refuses `--repair` on a sealed overlay ("overlay is sealed; fsck --repair is refused", `overlay_fsck.rs:164-170`), so this branch is mandatory for any retry after the seal.
2. **Seal, under the overlay lock**, in the order `overlay seal` already uses (`overlay_cmd.rs:544-560`):
   - `SealOperation::acquire_until(top, deadline)` (§6.4).
   - `finish_if_sealed()`. If it returns an outcome, the top was sealed by an earlier try, so the layer digest is the recorded one (`overlay_seal.rs:349-356`).
   - Otherwise, still under the guard: `OverlayMeta::read`, `classify`, `gate_base(top, meta, &base, {force_base_mismatch: false, base_digest})`, then open the lower stack (built here, under the guard, and reused in phase 4), then `operation.seal(&base, view.clone())`. `SealOperation::seal(self, …)` consumes the guard, so the lock is released when the seal returns.
   - **Opening the lower stack** (sweep 7, Codex 2 and 3).
     - `sandbox run` keeps today's recovering open (`LowerReads::Recovering`), so its behaviour does not change.
     - The supervisor uses a new `MountLowerStack::open_no_recovery(base.source(), base_key, lowers, services) -> Result<(MountLowerStack, view), String>` in `ratarmount-compositing`. It is `open_inner` with a new `recover` flag set to false, which reads each layer with `OverlayMeta::read_no_recovery` instead of `OverlayMeta::read` (`lower_stack.rs:176-177`). `read` rolls a hot journal back (`overlay_meta.rs:267-269`, `347-353`), which would write to a lower that §6.2 promises only to read. A lower with a hot journal is an error, and the supervisor reports it as `lower_changed`. Every existing caller keeps the recovering read.
     - `compose` is not used by the supervisor, because it discards the stack's records (`lower_stack.rs:61-69`).
   - **The stack about to be sealed against must be the stack the mount took** (sweep 7, Codex 2). With `check_lowers`, the opened stack's records are compared position by position with the top's recorded `lower_layers`. The count must match, and so must each `layer_digest` and `sealed_at`; at directory positions the path must match too. A bundle resolved again at finalize to a different valid layer (contents replaced in place, with its inode, size and mtime unchanged) gets a different `layer_digest`, so it is refused as `lower_changed` before anything is sealed. Revision 7 only copied the mount's digest into the report and would have sealed the top over the new layer.
   - When `seal == false` (a `sandbox run` without `--seal`/`--pack`), no lock is taken. The phase is just classify plus `gate_base`, as today.
3. **Re-gate a top sealed by an earlier try.** When `finish_if_sealed` returned an outcome, the base is still classified and gated with `gate_base`, the same gate `overlay pack` applies to a sealed layer (`overlay_cmd.rs:480-484`, R4-B1). With `force_base_mismatch: false`, `gate_base` writes nothing; only the forced path calls `record_forced_base_rows` (`overlay_cmd.rs:557-560`).
4. **Hash and summarize, after the lock is released**, all read-only and safe to rerun: `change_set` over the view from phase 2 or 3 (phase 3 and the `seal == false` path open the stack right after their gate, in the same way and with the same `check_lowers` comparison), `canonical_hash`, manifest (overwritten, `File::create`), journal summary (overwritten).

Pack is **not** inside `finalize_top`. `finalize_pack` is called by both callers after `finalize_top`, with the `Finalized` owner it returned. `sandbox run` therefore moves pack from between seal and `change_set` (`run.rs:1140-1151`) to after them. Its report does not change: pack reads the sealed layer only, and the report's `bundle` field is the same path.
- `sandbox run` keeps `classify_base(Some(&args.base), …, &OverlayRunContext::default())` and its `--base-digest`, and builds its JSON from `FinalizeReport` plus its own `exit_code`, `timed_out`, `interrupted`, `wall_time_s`, `erofs_denied` and `overlay`.
- The `json!` maps serialize sorted, so U10 (§11) can demand byte-identical `sandbox run` reports before and after the refactor, with one exception. `wall_time_s` is `start.elapsed()` (`run.rs:1188`) and differs on every run. U10 masks it: the report-building function takes the elapsed seconds as a parameter, and the test passes a fixed value on both sides.
- **Supervisor classification:** a new `sandbox::finalize::classify_supervisor_base(base: &Base, indexes: &Path)`. It lives in the sandbox module, not in `base_identity.rs`, so the shared module does not depend on `sandbox::protocol::Base` (sweep 5, N7). It calls `base_identity::FactoryOpener`, which is already `pub` (`base_identity.rs:20`). It uses `FactoryOpener` with the options `open_base` uses (`daemon.rs:828-861`): `index_folders: [indexes]`, `read_only_index: true`, `recover_journals: false`, plus the base's `git_synthetic_head` and `recursive`. Requirement: it must not build an in-memory index of a large base. `classify_offline_in_memory` sets `index_in_memory: true` (`base_identity.rs:208-218`), and step 0 has to show that the prepared index is used instead.
- **Classification test seam** (sweep 3, N6): a new `Mounter::classify(&mut self, base: &Base, indexes: &Path) -> Result<ClassifiedBase>`.
  - `ProcessMounter` calls `classify_supervisor_base`.
  - The `Fake` classifies a real temporary directory held in `FakeState` with `fixtures::classify`. The Fake's own base string `/fake.tar` (`tests.rs:101`) cannot be classified.
  - The supervisor builds `FinalizeInputs.classify` from it. `Mounter` is already the lifecycle test seam (`process.rs:1`), so no `#[cfg(test)]` field on `Supervisor` is needed.
- **Bundle resolver seam** (sweep 8, Claude N12): a new `Mounter::bundle_resolver(&self) -> Arc<BundleResolver>` (`lower_stack.rs:25-26`).
  - `ProcessMounter` returns `main.rs`'s `resolve_lower_bundle`, the resolver of today's `lower_stack_services()` (`main.rs:4969-4975`).
  - The `Fake` returns a resolver held in `FakeState`, which U16 replaces between `new` and finalize.
  - The supervisor builds its `LowerStackServices` locally from that handle plus `overlay_open_error`, for finalize's `open_no_recovery` and for `diff`'s composition (§6.8). The handle is owned (an `Arc`), so no borrow of the mounter outlives the call: the `classify` closure borrows the mounter mutably during the same `finalize_top`.
- **`classify_supervisor_base` keeps `check_offline_journal`** (`base_identity.rs:206`), which `classify_offline_in_memory` runs before its factory open, so an archive base with a pending commit journal is refused read-only, exactly as the offline verbs refuse it (#174).
- **`bytes_written`** (sweep 3, N8; corrected in sweep 4, N4) is **not** computed inside `finalize_top`. Today `sandbox run` measures it after the stop and **before** `finish`'s `fsck --repair` (`run.rs:1064`), and it keeps doing exactly that, so U10 stays byte-identical even on a top where fsck repairs content.
  - The supervisor measures it at the same point: right after finalize step 4, before `finalize_top`, with the same call `OverlayQuota::new(&top, None, None)?.usage().bytes`.
  - **Kept for retries, together with `fsck_result` and `base_hashed_by_finalize`** (sweep 8, Claude N6). Each is stored in the attempt's in-memory spec by the try that first computes it, and a retry reports the stored value. `base_hashed_by_finalize` is decided by the try that reads the top's digest state before sealing; a try that fails before that point (for example `in_use` at the lock) leaves it to the next one.
    - A retry over a sealed top runs `fsck(top, false)` and would report `ok` (`overlay_fsck.rs:48-56`), hiding the first try's `repaired:N`.
    - The top's own `fsck_result` meta row also keeps the first try's value, because fsck writes that row only while the top is unsealed (`:367-378`).
  - U30 asserts that the retry reports the first try's `bytes_written`, `fsck_result` and `base_hashed_by_finalize`.
  - **U10's repair case uses content that repair actually removes** (sweep 8, Codex 5). Host files without a `files` row are normal COW content, which fsck counts as `unrowed` but never removes (`overlay_fsck.rs:15-23`, `:347-350`). Revision 7's "orphan payload" fixture therefore measured the same before and after repair, and would pass with the regression present. The fixture is nonempty host content at a path that has a tombstone (`deleted`) row, which repair unlinks (`:351-363`). U10 asserts that usage after repair is smaller than before, which proves the case exercises repair, and that the report's `bytes_written` is the before-repair value.
- **The supervisor's `classify` closure** calls `Mounter::classify`, which is `classify_supervisor_base` in production. `sandbox run`'s closure calls `classify_base(Some(&args.base), meta, None, &OverlayRunContext::default())`. Classification now happens under the overlay lock, as `SealOperation`'s contract requires ("holds the overlay lock while an offline caller opens and gates its base", `overlay_seal.rs:335-336`).
- **Moved inventory sites:** the internal-read sites `IR-B0131/B0132/B0133` move from `run::finish` to `finalize::finalize_top`. The item identity changes, so the manifest needs a reviewed update (`AGENTS.md`, #201). This is not a new acquisition.

### 6.4 Finalize, state machine and error paths

Finalize goes through these steps. Each step either checks whether it is already done or can safely run again (§6.3 makes `finalize_top` resumable over a sealed top), so a retry resumes where the last try stopped.

| # | Step | Done when | On failure |
| --- | --- | --- | --- |
| 0 | Look up `request_id` (§10, #4-#6) | | `idempotency_conflict`, or a replay |
| 1 | Status check | `ready`, `crashed`, `detaching`, `stopped` or `sealed` continue (`detaching` repeats only step 4(c); `stopped` and `sealed` skip steps 3-4). `finalized`/`retained` return the stored report (`record.json` or the in-memory copy). | `not_found`; `invalid_request` for `starting`; `invalid_request` for `retained_damaged` ("retained attempt ID is damaged; forget it") and for `forgetting` (§6.7) (sweep 8, Claude N13); `unsupported` for a base outside R1's supported kinds (§1) |
| 2 | Re-check lower identities against the lowers themselves (§10, #3) | equal to the snapshot | `lower_changed`. Nothing is touched and the attempt stays as it was. (The later comparison with the top's own rows, in phase 2, leaves it `stopped`; see §10 #3.) |
| 3 | Read `erofs_denied` from the inspection socket, through a new `status` command. **It is read inside step 4, after (a) found no survivor and before (b) unmounts** (§6.4.1; sweep 6, N7). That is the closest the supervisor can get to `sandbox run`, which reads the counter after the container has stopped (`run.rs:1060-1062`). Writers the scan cannot see may still add denials afterwards; this is documented. It is the same counter that `sandbox run` reads, but over a different transport: `sandbox run` asks the mount's control socket (`control_status`/`counters`, `run.rs:855-879`), and supervisor attempts have no control socket. Feasibility is open item §13.2. | skipped when there is no live mount (then `null`) | it is only a counter: log and use `null` |
| 4 | Stop: `Mounter::stop(attempt, exit_wait) -> StopOutcome {Stopped{exit}, Busy{holders}, Detached{holders}}`. It never SIGKILLs and never lazy-unmounts. It runs (a) a survivor test before anything is unmounted, (b) a non-lazy host unmount, (c) a bounded wait for the child to exit. Specified in §6.4.1. | status becomes `stopped` | **`Busy` → `writers_active`**: status stays `ready`, the mount and child stay, nothing has been written (Keystone #6). **`Detached` → `writers_active`**, status `detaching`: the host mount is gone, the child is still alive, nothing is sealed. Details and the `crashed` case in §6.4.1. |
| 5 | `finalize_top` (§6.3: fsck, which repairs only an unsealed top; seal or the recorded seal; gate; hash; manifest; summary) | a `FinalizeReport` with `layer_digest` | **`in_use`** when the error has `io::ErrorKind::WouldBlock`. That is what `acquire_until` returns on a contended lock, and what both `overlay_seal` and `overlay_fsck` already turn a locked SQLite database into ("overlay is in use…", `overlay_seal.rs:38-47`, `overlay_fsck.rs:149-157`). It is not `writers_active`: the child is gone, so the holder is a foreign process. fsck `--repair` may already have run; it is idempotent, but the overlay is no longer byte-untouched (documented). A gate refusal is passed through (the base changed). Any other error is `io`. Status stays `stopped`, or becomes `sealed` (internal, see below) if the seal committed. |
| 6 | `finalize_pack`, when requested, writes `attempts/ID/bundle.tar.zst` with the journal included (`PackOptions.include_journal`) | the file exists **and** a retry has not removed it | `pack` refuses an existing output (`persist_noclobber`, `overlay_pack.rs:523`). On every run of this step, a bundle left over from an earlier try is removed first, then packed again from the sealed layer. No report names it until step 7. Status stays `sealed`. |
| 6a | Retain only: **durability barrier** (sweep 7, Claude B1 and Codex 6; §10 #2). `syncfs` on a descriptor of `attempts/ID`. On Linux this is `rustix::fs::syncfs`; on other platforms `rustix::fs::sync()`, which is used only by tests, because the supervisor refuses to serve off Linux (`daemon.rs:886-891`). `rustix::fs::syncfs` exists only under `linux_kernel` (`rustix-1.1.5/src/fs/fd.rs:327-329`), so the choice needs a target predicate. It therefore lives in `sandbox/daemon.rs`, a reviewed N4 target file (`policy.json:529-546`), next to the commit rename, never in `finalize.rs` (sweep 8, Claude N4). The call flushes everything the attempt wrote: the overlay's payload files, its database and companions, the manifest, the journal and its summary, the bundle, and the directory entries and modes inside `attempts/ID`, including seal's chmod. It is one call and opens no payload or database descriptor, so #149's lock-release hazard does not arise. Not done for an attempt that is not retained: it is disposable and deleted at restart. | `syncfs` returned 0 | `io`, status stays `sealed`, request `retryable`, nothing renamed. A retry repeats 6a. On Linux 5.8 and later, `syncfs` reports writeback errors. |
| 7 | Write `record.json` (retain) or keep the report in memory (no retain) | | `io` |
| 8 | Retain only: the commit rename, `rustix::fs::renameat_with(…, RenameFlags::NOREPLACE)` (§10, #2) | `retained/ID` is durable | **The rename fails** (including EEXIST for a stray `retained/ID`): `io`. The attempt stays at `attempts/ID` with status `sealed`, and a retry continues from step 5 through the sealed branch.<br>**The rename succeeds but `fsync(retained/)` or `fsync(attempts/)` fails** (sweep 4, N1): the tree is already at `retained/ID`, so the attempt moves to the `retained` map with status `retained` whatever happened. The request is `retryable` with `io`. A retry sees status `retained`, repeats only the two directory fsyncs, then appends `done` with `record.report`. If the machine crashes first, K4 applies. |
| 9 | Request record `done` with the report | the line is written and `fdatasync`ed | The request log goes **`Broken`** (§10 #5, sweep 7, Codex 5). The line is truncated away, so the file ends at the durable `running` line. The response is `io`, and every later request-ID'd request is refused until a restart; there, K5 (or K3) resolves the record. The attempt itself is already finalized or retained, and stays so. |

**Statuses and the supervise loop (sweep 1, B1).** `Supervisor::supervise()` (`daemon.rs:433-444`) currently polls every attempt that is not `crashed`. It sets `crashed` on any poll result other than `Ready` or `Starting`, and `ProcessMounter::poll` returns `Crashed` when no child is recorded (`process.rs:201-208`). After `Mounter::stop` the child is gone, so the next request or the next 10 ms tick of `serve` would turn `stopped`/`sealed`/`finalized` into `crashed`. R1 changes `supervise()` to poll **only** `starting` and `ready` and to leave every other status alone. The Fake's `poll` (`tests.rs:64-74`) behaves the same way after `cleanup`/`stop` removes the mount, so U29 catches a regression without FUSE.

**Reaping `detaching` children** (sweep 5, N7). `supervise()` additionally calls a non-blocking `try_wait` on `detaching` children, without changing their status, so an exited child is reaped at once instead of staying a zombie until a retry or `destroy`. `Mounter::stop` records that it exited, and the next retry's step 4(c) sees that.

The internal statuses are: `ready`/`crashed` (as today), `detaching` (host mount gone, child kept alive by another namespace's mount, §6.4 step 4), `stopped` (unmounted, child exited, unsealed), `sealed` (sealed, not yet finalized), `finalized` (not retained), `retained`/`retained_damaged`, and `forgetting` (a forgotten retained attempt renamed back to `attempts/ID`, whose deletion has not finished; §6.7, sweep 8). None of `detaching`, `stopped`, `sealed`, `finalized` or `forgetting` survives a restart: they live under `attempts/` and are deleted.

The seal call uses `SealOperation::acquire_until(dir, deadline)`, a new public function in `ratarmount-compositing` next to `SealOperation::acquire` (`overlay_seal.rs:343-347`). It uses the same `SealCommitGuard`, but a contended lock past the deadline returns `WouldBlock`, which maps to `in_use`. Today `SealCommitGuard::acquire` spins without a bound (`write_overlay.rs:7429-7446`), which would hang the single-threaded daemon. The supervisor must never hold the top's guard and then call plain `seal()`: two flocks on separate open file descriptions conflict inside one process. So the held guard is passed on through `SealOperation::seal` (`:358-364`).

Retained finalize requires `retain: true` at `new` (the retained slot is reserved then; §10, #1). A finalized attempt that was not retained stays under `attempts/`, keeps its `--max-attempts` slot until `destroy`, and is deleted on restart.

#### 6.4.1 Step 4: stop without a lazy unmount, and report only real holders (revision 7)

`Mounter::stop(attempt, exit_wait) -> StopOutcome {Stopped{exit}, Busy{holders}, Detached{holders}}` never SIGKILLs and never lazy-unmounts. The existing `AGENTS.md` rule allows a lazy unmount only in failure-path cleanup, so `cleanup` keeps its lazy fallback for `destroy` and `reconcile`, and finalize never uses it. `ProcessMounter::stop` runs (a), (b) and (c) in order. All of this Linux-only code lives in `sandbox/process.rs`, which is on the N4 reviewed-file list (§6.11).

**What the kernel already decides.** A non-lazy unmount of the host mount (`fusermount3 -u`, which calls `umount2(…, 0)`) also covers every *propagation copy* of that mount. A propagation copy is a copy in another mount namespace whose parent receives mount propagation from the attempt's parent, sitting at the same place:
- The kernel removes such copies together with the host mount (umount propagation, `propagate_umount` in `fs/pnode.c`).
- If a process uses one, the host unmount fails with EBUSY (`propagate_mount_busy`), and (b) reports `Busy`.

Only a copy that is **not** a propagation copy can survive the host unmount. A surviving copy keeps the FUSE superblock alive, and with it the child, because a FUSE server exits only when the last mount of its superblock is gone. Step (a) exists only to find such survivors before anything is unmounted, so that `writers_active` leaves the attempt mounted (Keystone #6).

**Observed vs reasoned.**
- **Observed on Matt's Arch/omarchy host (read-only, unprivileged):**
  - systemd services run in mount namespaces that are slaves of the host's: systemd-resolved, PID 508, has root `shared:19 master:1`, `/tmp` `shared:189 master:185` under a PrivateTmp overmount, and `/home` `shared:201 master:197` under a ProtectHome overmount.
  - Every mount made after such a service started appears in its namespace, including user FUSE mounts: the host's `/run/user/1000/gvfs` (`fuse.gvfsd-fuse`, `shared:620`) is `shared:622 master:620` in `/proc/508/mountinfo`, and the flatpak document portal (`shared:636`) is `shared:638 master:636`.
  - A running Docker container's root and binds carry **no** propagation fields, and its bind lines have sub-path roots (`/proc/3859090/mountinfo`, mount 1203).
  - An unprivileged user can read both of those files.
- **Reasoned from kernel semantics.** Step 0d observes all of these with shell commands before step 5 builds on them. F6b and F6c automate the first three in CI; the last two need an unprivileged user namespace, which CI's `sudo` path does not use:
  - umount propagation removes propagation copies;
  - a busy propagation copy makes the host unmount fail with EBUSY;
  - the FUSE child exits only after the last mount is gone, and `/sys/fs/fuse/connections/<minor>` exists exactly while the superblock does;
  - a propagation copy that the kernel had *locked* is unlocked and removed by the unmount anyway. Before propagating an unmount, the kernel clears `MNT_LOCKED` on the copies at the unmounted place (`propagate_mount_unlock`, `fs/pnode.c`; corrected in sweep 7, Codex 10). Revision 7 wrongly listed locked clones as survivors;
  - a propagation copy that has mounts of its own inside it is left in place by the unmount.

**Why the earlier rules were wrong.** Every finalize on a systemd host would meet copies like the gvfs one above.
- Revision 6 counted every foreign copy of the attempt's device as a writer, so every finalize returned `writers_active` (sweep 6, B1).
- Sweep 6's fix ignored copies tagged `shared:N`/`master:N` with the attempt's own peer group N. That still had false positives and false negatives:
  - A namespace that is itself a slave of a service namespace (a nested sandbox, or snap's per-user namespaces on Ubuntu desktops) carries `master:<intermediate group>`, not `master:N`, so it was still reported as a writer.
  - A bind of the attempt elsewhere carries `shared:N`, which is a peer-group tag and not a propagation tie, so it was wrongly ignored.
- This revision decides the way the kernel does, from each copy's **parent** and **place**.

**(a) Survivor test, before anything is unmounted.**

Inputs:
- the attempt's line A in `/proc/self/mountinfo`: its `major:minor` (field 3), root (field 4) and mount point (field 5);
- A's parent line PA (field 2): its peer group P (from `shared:P`; absent if PA is private), its root and its mount point.

The scan:
1. Read every readable `/proc/PID/mountinfo`, the supervisor's own included. `EACCES`, `ENOENT` and `ESRCH` are skipped.
2. Group processes by mount namespace: by the `/proc/PID/ns/mnt` inode when that link is readable (it needs ptrace access, so often it is not), otherwise by the file's set of mount IDs. Mount IDs are unique across the system, so two files with the same set come from the same namespace.
3. Build one map over all visible lines: peer group → master. A visible line `shared:G master:H` gives G → H. A visible member of G with no `master:` gives G → none. Members of one peer group share their master, so conflicting entries for a group (which should not happen) make every chain through it undecided.

Then, for each line C carrying A's `major:minor`, other than A itself, look up its parent line PC (C's field 2, in the same file) and classify C:

| C is | When | Effect on (a) |
| --- | --- | --- |
| a **propagation copy** | PC is in P's propagation tree: PC carries `shared:P`, or `master:G` and following masters through the map reaches P. **And** C sits at A's place: the same root field as A, and the same path inside the parent filesystem, i.e. PC's root + (C's mount point relative to PC's mount point) = PA's root + (A's mount point relative to PA's mount point). Roots are compared by this formula, never against `/`: btrfs subvolume roots such as `/@` and `/@home` appear in the root field (this host's `/` and `/home`). | ignored: the host unmount removes it, or fails with EBUSY if it is in use |
| a **survivor** | PC is outside P's tree: PC has no `master:` and is not `shared:P` (a private or independent parent), or the master chain ends at a visible group with no master other than P. **Or** PC is in the tree but C sits at another place or shows another root: a bind of the attempt or of a subdirectory (`docker run -v`, recipe `swe-bench-sandboxes.md:75`; `attempt.path + '/repo'`, `:106`; `mount --bind`). | **`Busy`**, naming the PIDs of that namespace |
| **undecided** | The master chain reaches a group with no visible member (a namespace with no process, such as snapd's preserved namespaces; an unreadable `mountinfo`), or PC is not in the file. **Or** C would be a propagation copy but has mounts of its own: lines in the same file whose parent is C. Umount propagation leaves such a copy in place, but exactly when (for example a mount covering C's whole root) is kernel detail, so it is not reported (sweep 7, Claude N11). | ignored; (b) and (c) decide |

If P is absent (the attempt's parent is private), no copy can be a propagation copy, so every copy in another namespace is a survivor. `docs/sandbox.md` therefore says to keep the state directory on a shared mount, which is the systemd default. Mount points and roots are compared after decoding `\ooo` escapes (`unescape_mountinfo_field`, `process.rs:353-375`). `parse_mountinfo` (`:377-387`) is extended to return whole parsed lines instead of only mount points.

What this reports, case by case. U37 replays every case on synthetic and captured `mountinfo`; step 0d and F6c observe the real ones.
- **systemd service namespaces** (resolved, timesyncd, logind…), started before or after the attempt: propagation copies, so ignored.
- **flatpak/bubblewrap sandboxes, snap namespaces, nested namespaces whose intermediate namespace is visible**: propagation copies (the chain is followed), so ignored.
- **Namespaces made with `unshare --propagation unchanged` (a peer) or `--propagation slave`**: propagation copies, so ignored. If a process uses the copy, (b) gets EBUSY and returns `Busy`.
- **A namespace made with `unshare --propagation private`, or a Docker/Podman container with the attempt or `attempt/repo` bound in**: survivors, so `Busy`, and the attempt stays mounted.
- **A `mount --bind` of the attempt in the supervisor's own namespace**: a survivor, so `Busy`.

**Survivors (a) cannot see or decide; all of them end in (c):**
1. A copy in a namespace with no process (an `unshare --mount=FILE` persistent namespace), or in namespaces hidden by `hidepid`.
2. A propagation copy with mounts inside it (undecided above).

Copies the kernel *locked* to their parent are **not** in this list (corrected in sweep 7, Codex 10). A namespace created by an unprivileged user namespace (rootless Podman, unprivileged bubblewrap/flatpak) after the attempt was mounted does hold locked clones. But the unmount first clears the lock on the copies at the unmounted place (`propagate_mount_unlock`), so propagation removes them. Step 0d observes this with an explicit `--propagation slave` namespace (item 6).

A private copy that exists only briefly (a container runtime between `clone` and `pivot_root`, with private root propagation) can give one spurious `Busy`; the retry succeeds.

**Step 3's counter** (`erofs_denied`) is read here, after (a) found no survivor and before (b).

**(b) Non-lazy host unmount** with `ratarmount_fuse::unmount` (`ratarmount-fuse/src/lib.rs:4019-4055`): `fusermount3 -u`, with busy retried every 50 ms for about 1 s so that a desktop watcher probing the new mount does not cause a spurious busy, and never `-z`. Then `mountpoints()` is checked. Still mounted: `Busy`. This covers both a process using the host mount and a process using a propagation copy (EBUSY above).

**(c) Superblock and child** (made exact in sweep 7, Claude N8). A child that is merely slow to exit (dropping the overlay, flushing its journal) must not be mistaken for a hidden survivor. So (c) asks the kernel directly: `/sys/fs/fuse/connections/<minor>`, where `<minor>` comes from A's `major:minor`, exists exactly as long as the FUSE superblock lives.
- **The connection directory is still there** 500 ms after (b): some mount still holds the superblock, which can only be a survivor (a) could not see or decide. The result is `Detached` at once, with no 10 s wait and **no SIGKILL**.
- **The connection directory is gone**: the superblock is dead, so no FUSE writer can exist. Wait up to `exit_wait` = `min(--timeout, 10 s)` (the `CLEANUP_TIMEOUT` of `run.rs:25`) for the child to exit.
  - If it exits, record its exit status.
  - If it does not, the result is `timeout` ("the FUSE connection is closed but the mount process has not exited"). The status stays `detaching` and the request `retryable`; a retry repeats (c).
- **`fusectl` is not mounted** at `/sys/fs/fuse/connections` (the systemd default mounts it; present on the Arch host): fall back to the child alone. A child still running after `exit_wait` is `Detached`, as in revision 7.
- **The child's exit status goes into the report** as `mount_exit: {code, signal}`, or `null` when it is unknown.
  - **It is kept wherever the child is reaped** (sweep 8, Codex 4, Claude N7). Today `ProcessMounter::poll` reaps an exited child and discards its `ExitStatus` (`process.rs:205-207`), so a `crashed` attempt would have none.
    - R1 keeps a map `exited: path → ExitStatus` in `ProcessMounter`, filled by `poll`, by `stop`'s own wait, and by `cleanup`.
    - `StopOutcome::Stopped` carries `exit: Option<ExitStatus>`, and a new `Mounter::exit_status(path)` returns the recorded status for a child reaped earlier. A `crashed` attempt with no child recorded takes this path.
    - The Fake records injected statuses the same way.
  - **Journal completeness is decided conservatively.** The child returns its journal writer's error as a non-zero exit (`ratarmount-fuse/src/lib.rs:4015-4016`). So `journal_summary.complete` is `true` only when a journal was requested and the exit status is **known and 0**. A non-zero, signalled or unknown exit gives `false`, and nothing in the summary is presented as a complete journal.

**Outcomes.**
- **`Busy` → `writers_active`**: status stays `ready`, the mount and child stay, nothing has been written. This is Keystone #6's "leaves the attempt mounted".
- **`Detached` → `writers_active`**, and the status becomes the internal `detaching`. The host mount is gone, but the child and the survivor remain, and writes through the survivor still land in the overlay. Nothing is sealed, because seal (step 5) runs only once the child has exited, when no FUSE writer can exist. A retry of a `detaching` attempt skips (a) and (b) and repeats (c). `destroy` still applies `cleanup`'s kill-and-reap policy. The source doc's rule ("If the mount is busy or the child does not exit: return `writers_active`, change nothing", `source-plan-doc.md:114`) holds exactly for `Busy`. For `Detached`, the only change is the host mount point, which is unavoidable once (a) could not see the survivor. Keystone signs this off in §13.7(c).
- **The message** starts with a stage token: `stage=survivor` for (a), `stage=unmount` for (b), `stage=detached` for (c). It is diagnostic text for logs and tests, not a stable API (sweep 7, Codex 11). It names the holders, so the harness knows what to stop:
  - for survivors, the PIDs and `comm` (`/proc/PID/comm`) of the namespace holding them;
  - for EBUSY, a best-effort `/proc/*/fd` and `cwd` scan (a production copy of the test helper `log_holders`, `ratarmount/tests/support/unmount.rs:18`), plus the PIDs of namespaces holding propagation copies, labelled "may be using it". Anything unreadable is left out.

**`crashed` attempts** (sweep 5, N1; revised in revision 7).
- **No child recorded** (`poll` already removed it, `process.rs:205-206`): the FUSE server is gone, so nothing can write through any copy of the mount. (a) and (c) are skipped. (b) still runs, because the host mount must be gone before the attempt directory is renamed or deleted. If (b) finds the mount busy, the result is `writers_active` with status **kept `crashed`** ("processes still use the dead mount").
- **Child still recorded**: a `crashed` status can also come from a `poll` error (`daemon.rs:441`), and then the attempt takes the normal path through (a), (b) and (c).

### 6.5 Request IDs: summary (details in §10, #4-#6)

- The append log is `requests.jsonl`.
- Only v2 `new` and v2 `finalize` take a `request_id`.
- Before any side effect: append `running` with fdatasync.
- Terminal outcomes append `done` (the result, stored inline) or `failed` (the error).
- Outcomes after which a retry with the same body is safe and can make progress append `retryable`, which keeps `op_hash`. That covers outcomes that changed nothing (`writers_active` from `Busy`, validation, `capacity`, a fully rolled-back `new`). It also covers finalize outcomes that left a **resumable** status (`detaching`, `stopped`, `sealed`; for example `in_use` after the stop, or a pack failure), as listed in §10 #6. Only a `new` whose rollback failed, and `interrupted`, are terminal `failed`.

### 6.6 Retained attempts and restart (`daemon.rs`)

- **`Supervisor::open`:** after `attempts/` and `indexes/`, `private_dir(root/retained)`. Check `st_dev(attempts) == st_dev(retained)`. Run `reconcile`. Load `retained/*`, then replay `requests.jsonl` (§10, #5).
- **New state-root entries are made durable** (sweep 7, Codex 6). When `open` creates `retained/` or `requests.jsonl` for the first time, it fsyncs the state directory itself before serving. A retained rename or a `running` line therefore never depends on a directory entry that a power loss could drop. The fsync handle is the same kind as `atomic_json`'s (`IR-B0109`, §6.11).
- **`create_base` caches a local archive's strong digest** (sweep 7, Claude N7).
  - **The problem.** Without it, every finalize of an archive base would hash the whole archive inside the serve loop. A worker's top records no writable index, its background hasher therefore leaves the digest `pending` (`base_digest.rs:55-64`), and seal then resolves it, uncached. `BaseOptions` has no digest field (`protocol.rs:11-28`) through which a caller could supply one.
  - **The fix.** `create_base` is the exclusive preparer and owns a writable index (`docs/sandbox.md:2207-2209`).
    - **Where it runs:** the work happens inside **`ProcessMounter::prepare`**, after its `--no-mount` child has exited and before it returns, not in `Supervisor::handle`. The `Fake`'s `prepare` stays a no-op, so every unit test's `setup()`, which registers the nonexistent `/fake.tar` (`tests.rs:101`), and the v1 golden that is generated through the Fake keep working byte for byte.
    - **Which index** (corrected in sweep 8, Codex 3). `factory::served_without_indexing(source, &[indexes])` returns `index: IndexProvenance::None`. The prepared index is its **`sidecar_candidate`**: the first existing file among `possible_index_paths(source, [indexes/<name>])`, i.e. `indexes/<name>/<escaped archive path>.index.sqlite`, the file the preparation child just wrote (`ratarmount-session/src/factory.rs:4633-4646`; `ratarmount-index/src/location.rs:645-660`). A base the factory does not serve as a local archive, or one with no candidate, is skipped: it is a folder, Git or unsupported base, and its worker records a non-archive digest kind.
    - **How it stores the digest** (corrected in sweep 8, Claude N1 and N8, Codex 6). It calls a new `ratarmount_index::cached_archive_digest_checked(path, index, check)`, written next to `cached_archive_digest` (`digest_cache.rs:141-153`).
      - Like it, the new call canonicalizes the path (through `cached_with`, `:569`), so the key matches the worker's canonicalized peek (`peek_archive_digest_for_open`, `:174-211`).
      - Unlike it, `check` is polled both while waiting for the `HashGuard` (`:444-481`) and between chunks of the hash stream.
      - Its managed reader is a new reviewed site in `ratarmount-index`, beside `IR-B0419`, so the sandbox code opens no reader.
      - Revision 7's `cached_archive_digest_cancellable_for_snapshot` was the wrong call: its contract requires a locked caller, a canonical path and a caller-supplied reader (`:235-248`).
    - **Deadline and shutdown** (sweep 8, Claude N8, Codex 6). Today the bounded wait covers only the preparation child (`wait_bounded(child, timeout)`, `process.rs:164`).
      - **Its own window.** The hashing phase gets one more `--timeout` window. `check` returns an error once that window has passed, or once SIGTERM was requested (`overlay_commit::term_requested()`, the flag `serve` polls between requests, `daemon.rs:904`), so a held digest lock or a slow hash can neither block the daemon nor delay its shutdown.
      - **Cut short means skipped, never a failure.** The hash is an optimization. A timeout, a cancellation, a held lock or a hashing error **skips** the caching: `create_base` still succeeds, with a warning in `indexes/<name>/prepare.log`. Its workers then record `pending`, finalize hashes (`base_hashed_by_finalize: true`), and nothing is written to the index, because `cached_with` stores only a complete digest.
      - **Why not the preparation's remaining time.** Sharing that deadline would make registrations that succeed today fail on large archives, a v1 regression.
      - **Only the final checkpoint can fail `create_base`.** A failure there, after a digest row *was* written, leaves the index's journal state uncertain, so it fails `create_base` as described next.
    - **There is no reuse across base names** (corrected in sweep 8, Claude B1, Codex 3). The digest is a row in the `overlay_base_digests` table of **that one index file**, and every base name has its own index folder, `state/indexes/<name>` (`daemon.rs:384-386`; `process.rs:41-52`). Registering the same archive under a second name builds a second index and hashes the archive again. `create_base` refuses a name that already exists (`daemon.rs:467-471`), so "again" can only mean a new name. Revision 7's "registering an already-hashed archive again costs nothing" was false.
    - **The effect:** a worker's overlay creation peeks that digest read-only (`prepared_index_for_peek`, `overlay_identity.rs:281`) and records it as `present`, so seal has nothing to resolve.
  - **The index must end checkpointed.** Workers treat an unfinished WAL or rollback journal beside a prepared index as a preparation error (`docs/sandbox.md:2357-2363`). So the digest write is followed by the same finishing checkpoint the preparation performs, and `create_base` returns only once the index has no `-wal` or `-journal` again. A failure fails `create_base` (`base_open_failed`), as a failed preparation does.
  - **The cost** (restated in sweep 8). **One full read and SHA-256 of the archive per registered base name**, on top of that name's full index build, inside the single serve loop. That adds up to one more `--timeout` window to a registration; beyond the window, the caching is skipped, not failed. The v1 `create_base` response bytes do not change, but its run time does for **every** caller, v1 included. That is a v1 behaviour change Keystone signs off in §13.7(d), and it is documented. Step 9 measures it.
  - **To verify.** The step-0c spike confirms that a worker records `present` this way. CI checks it on every run, before any seal can resolve the digest: F4 reads the live mount's root `user.ratarmount.base_digest_state` right after `new` and requires `present` (sweep 8, Claude N1). The finalize report's `base_hashed_by_finalize` (§4.3) shows it in production. If caching does not take, finalize keeps hashing, and the cost is documented and measured in step 9.
- **`reconcile`:** the `attempts/` loop (`daemon.rs:400-414`) and the RAM loop (`:415-429`) are unchanged except that **both** delete through the permission-restoring removal (§6.7). The RAM loop needs it as well (sweep 2, B1): a non-retained finalize of a tmpfs attempt seals `ram/ID`, which is the overlay root itself (`overlay_dir = ram/ID`, `daemon.rs:661-663`). Seal removes its write bits (`docs/sandbox.md:646-648`), so the current `fs::remove_dir_all(entry.path())` (`:426`) would fail with EACCES, and `reconcile`'s `?` would stop `Supervisor::open` after a crash. `destroy`'s separate `remove_dir_all(&attempt.overlay_dir)` (`:731-733`) changes in the same way. `reconcile` **never** enters `retained/`.
- **Retained load:**
  - For each `retained/ENTRY`: `validate_name`, `private_dir` (a symlink or foreign owner refuses the start with `unsafe_path`, the same as `attempts/`), read `record.json`, then `OverlayMeta::read_no_recovery(retained/ID/overlay)`. It never calls `read`, which recovers hot journals (§6.2; sweep 5, N5). A hot journal or an unreadable database means `retained_damaged`.
  - It must be sealed with `layer_digest == record.layer_digest`. Otherwise the status is `retained_damaged`: it is listed, never auto-deleted, and refused as a lower.
  - A missing or unparseable `record.json` also means `retained_damaged`, with a synthesized minimal record `{id}`.
- **`new` with `retain: true` and `overlay: "tmpfs"`** returns `invalid_request` ("retain requires overlay disk").
- **`destroy {id}`** of a retained attempt returns `invalid_request`. **`destroy {base}`** and **`shutdown`** (`destroy_all`, `daemon.rs:739-748`) skip retained attempts. `serve`'s final `destroy_all` (`:956`) skips them too.
- **A `forgetting` entry** (§6.7, sweep 8) is treated like a retained one by `destroy {id}` (`invalid_request`, "retry forget"), `destroy {base}`, `shutdown` and `serve`'s final `destroy_all`. Each of them leaves it to a `forget` retry or to the next start's `reconcile`. It keeps its `--max-retained` slot until its tree is gone, so a new retained finalize cannot exceed the cap while the old layer still uses the disk.

### 6.7 `forget` and permission-restoring removal

- **`forget {id}`**:
  - Works on retained or damaged attempts, and on finalized attempts that were not retained (it then behaves like `destroy`).
  - Refuses with `in_use` while any live attempt (`AttemptSpec.lowers`) **or any other retained record** (`record.json` `lowers`) lists that retained layer or bundle as a lower. Otherwise a retained layer B finalized over `retained/A/overlay` would lose its stack when A was forgotten. Forget the dependents first (top-down).
  - **Grading mounts must be unmounted first; this is the rule, not a check** (corrected in sweep 8, Codex 8).
    - A grading mount `ratarmount --lower … --lower retained/ID/overlay` does **not** keep the layer's database open. A read-only layer reads its rows once, closes the database (`overlay_layer.rs:45-47`, `:177`), and opens host files only while a reader is active. So an idle grading mount holds no descriptor under `retained/ID/`, and no scan can see it. `docs/sandbox.md` states the rule as essential: unmount every mount that uses a retained layer before forgetting it.
    - `forget` still refuses with `in_use` (best effort, Linux) when the holder scan of §6.4.1 finds a process with a descriptor or `cwd` under `retained/ID/` at that moment, i.e. an **active** reader. It promises nothing about idle mounts. Revision 7's claim that the database stays open was wrong.
  - **Deletes crash-safely, and resumably** (sweep 7, Claude N9; in-memory transition fixed in sweep 8, Codex 2):
    1. Rename `retained/ID` back to `attempts/ID` with the same no-replace rename as the commit (§10 #2).
    2. **Immediately after a successful rename**, move the entry out of the `retained` map into a `forgetting` set, which names `attempts/ID`. The disk and memory now agree, whatever happens next. Revision 7 changed memory only after both fsyncs, so a failed fsync left memory pointing at a `retained/ID` that no longer existed.
    3. fsync `retained/` and `attempts/`.
    4. Delete the tree with `remove_tree_restoring_write(path)`.
    5. Drop the entry from `forgetting`.

    **On failure.** A failure in steps 3-5 returns `io` and leaves the entry in `forgetting`:
    - **A retry of `forget {id}`** resumes at step 3, repeating the fsyncs and then the deletion, so it is idempotent and needs no restart.
    - **Meanwhile**, v2 `list` shows the entry as `forgetting` (v1 hides it). `diff`, `stats`, finalize and use as a lower return `invalid_request` ("attempt ID is being forgotten; retry forget"). The ID stays reserved (§6.1a), because `attempts/ID` still exists.
    - **A restart** finds an ordinary `attempts/ID`, which `reconcile` deletes. Revision 7's in-place deletion could instead leave a half-deleted `retained/ID` that a restart would list as `retained_damaged`.
  - Forget is not request-ID'd: forgetting an ID that is already gone returns `not_found`.
- **`remove_tree_restoring_write`** (made complete in sweep 7, Claude N6):
  - It walks with `O_DIRECTORY|O_NOFOLLOW` handles. Before opening a subdirectory, it restores owner `u+rwx` on it. Seal leaves directories without write bits, and an agent's `chmod 000` is applied to the host directory itself (`write_overlay.rs:5224-5244`), so restoring only `u+w` would not let the walk open such a directory.
  - **How the mode is restored** (corrected in sweep 8, Claude N3). Not with a by-name `fchmodat(…, AT_SYMLINK_NOFOLLOW)`:
    - with rustix's default Linux backend, `chmodat(.., SYMLINK_NOFOLLOW)` always returns `EOPNOTSUPP` (`rustix-1.1.5/src/backend/linux_raw/fs/syscalls.rs:123-137`);
    - `libc::fchmodat` with that flag returns `ENOTSUP` on glibc 2.31, the portable tarball's floor;
    - and a failure here would stop `reconcile`, and so the daemon's start.

    Instead there is a new `host_stat::chmod_dir_at(dir, name, expected, mode)` in `ratarmount-compositing/src/host_stat.rs`, a reviewed N4 target file (`policy.json:116`). It is the directory twin of `chmod_entry_at`, which refuses directories (`host_stat.rs:173-186`):
    - on Linux it pins the entry with `O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC`, checks `(dev, ino)` and the directory type against the walk's `statat`, and changes the mode through `/proc/self/fd/N`, exactly as `chmod_entry_at` does for files (`:198-233`);
    - elsewhere, where `fchmodat(…, AT_SYMLINK_NOFOLLOW)` works, it uses that after a name check (`:234-248`).

    Its `O_PATH` pin is a new inventory site (§6.11).
  - It never opens a data descriptor, so #149's lock-release hazard cannot arise. It never follows symlinks.
  - It reuses the descriptor-relative pattern of `overlay_seal::walk_chmod` (`overlay_seal.rs:160-222`).
  - Every supervisor deletion uses it: `reconcile`'s `attempts/` and RAM loops, `destroy`'s attempt root and `overlay_dir` (disk or RAM), and `forget`. It lands in **step 5**, with the first finalize that can seal a tree (§9).
- **Finalize over an unreadable directory** (sweep 7, Claude N6). fsck, seal and the change-set walk open directories in the same way (`overlay_changes.rs:744-751`, `overlay_seal.rs:193-206`). So an attempt that left a directory unreadable to its owner (`chmod 000`, common in test suites) cannot be finalized.
  - Finalize returns `io`, naming the directory: "directory X in the attempt is not readable by its owner (mode 000, set inside the attempt); restore its mode in the attempt, or destroy it".
  - It changes nothing more. The failure is found by fsck after the stop, so the status is `stopped`, and a retry fails the same way until the mode is fixed.
  - Finalize does not chmod the agent's directories itself: their modes are part of the change set.

### 6.8 `diff`, `stats` and `list` on layered or finished attempts

- **`Diff`** (`daemon.rs:499-516`) opens the attempt's lowers over the base with `MountLowerStack::open_no_recovery(open_base(..).source, None, attempt.lowers, &services)` before `render_source`, where `services` is built from `Mounter::bundle_resolver` (§6.3) (sweep 7, Codex 3). `compose` would roll back a hot journal in a lower through `OverlayMeta::read`, and `diff` has no validation step before it. A lower that has a hot journal returns `diff_failed`, naming the lower, and nothing in it is written (U41). The `MountBundle` from `open_base` stays in scope until `render_source` returns, as it does today.
- **`list` size** (sweep 7, Codex 7). v2 `list` items carry each attempt's lowers. With many retained attempts and long lower paths, a full v2 `list` can exceed the 64 MiB response limit and return the existing `response_too_large` (`daemon.rs:869-883`). `list {base}` narrows it. This is documented; pagination is out of R1's scope.
- **`ProcessMounter::deleted_paths`** returns `None` (offline database) for every status except `ready`, `starting` and `detaching`. A `detaching` attempt's child is alive and holds the top's database with exclusive SQLite locking (`write_overlay.rs:3681-3683`), so its `diff`/`stats` keep using the inspection socket. The socket is a file in `attempts/ID/` (`inspection.rs:31-37`) and outlives the host unmount. If the socket is gone, `diff`/`stats` return `in_use` (sweep 3, N5).
- **`Stats`** needs no change beyond the offline branch.
- **Retained attempts** (sweep 5, N6). `Diff` and `Stats` look IDs up through `self.attempt()` (`daemon.rs:573-577`), which sees only `attempts`. R1 adds a lookup that tries `attempts` first, then `retained`. So `diff`/`stats` work on a `retained` attempt from v1 and v2, offline over `retained/ID/overlay` and composed over its recorded lowers. On a `retained_damaged` attempt they return `invalid_request`. IDs are unique across both maps (§6.1a), so the order of the lookup cannot change which attempt is found. U26 covers `diff` and `stats` on a retained attempt.
- **`list`**: v1 as in §4.5. v2 `list` always merges `attempts` and `retained` in ID order and shows every status, as the source doc specifies ("`list` reports `finalized` or `retained`", `source-plan-doc.md:120`). No new `all` field is added (sweep 6, N4).

### 6.9 CLI (`ratarmount/src/sandbox/mod.rs`)

- **`sandbox daemon`** adds `--max-retained N`: default 4096, range `0..=65536`. 0 refuses `retain: true` with `capacity`.
- **`sandbox new`** adds:
  - `--lower PATH` (repeatable, bottom first)
  - `--journal`
  - `--journal-exclude GLOB` (repeatable; implies `--journal`)
  - `--journal-reads all|first`
  - `--journal-sync`
  - `--retain`
  - `--request-id ID`

  The CLI sends version 2 **only** when one of these is used, and otherwise sends exactly today's v1 bytes.
- New subcommands:
  - `sandbox finalize ID [--pack] [--request-id ID]` (v2)
  - `sandbox forget ID` (v2)
  - `sandbox list --all`: a CLI-only flag that sends a **v2** `list`, which shows every status. Without the flag the CLI sends today's v1 bytes. No protocol field is added.
- `call` (`mod.rs:163-192`) accepts a response version equal to the version it sent. It also accepts a **version-1 error envelope** (`ok: false`) answering a version-2 request: that is how an older daemon, or this daemon's envelope parser, answers (`unsupported_version`, malformed line). The structured error is shown to the user instead of "unsupported response version". Every other mismatch is still an error.
- Exit codes are unchanged: 0 on `ok`, 1 on a server error (the JSON is printed), and the existing local errors.
- Subcommand help gets the same "Exit status" block as other verbs. The test `regression_help_states_exit_status` lives in `ratarmount/src/snapshot.rs:558` and checks a fixed list of verbs, so step 7 adds `sandbox finalize` and `sandbox forget` to that list explicitly (sweep 4, N10).

### 6.10 Python client (`clients/python/ratarmount_sandbox.py`)

- `_call(op, version=1, **fields)`. The response must carry the same version, except that a version-1 error envelope answering a version-2 request raises `SandboxError` with its code (e.g. `unsupported_version` from an older daemon), not `protocol`.
- `new(base, count=1, overlay="disk", quota=None, readonly_globs=None, *, lowers=None, journal=None, retain=False, request_id=None)` sends version 2 only when a keyword-only argument is set.
- `Attempt.finalize(pack=False, request_id=None)` returns the report dict. It updates `status`, `path` and `overlay_dir` from the report's **`attempt`** object (§4.3), not from top-level report fields: the report has no `path`, and a retained attempt's paths now name `retained/ID/...` (corrected in sweep 8, Claude N9). It sets `retained = True` when `attempt.status` is `retained` (sweep 7, Codex 9). A test checks the object after a retained finalize against a v2 `list` of the same ID.
- **Retained attempts are never destroyed implicitly** (sweep 7, Claude N10, Codex 9). Today `Attempt.__exit__` calls `destroy()` directly (`ratarmount_sandbox.py:55-57`), and a v1 `destroy` of a retained attempt now returns `invalid_request`.
  - `Attempt.destroy()` and `Attempt.__exit__` skip a retained attempt: a local no-op, with no request sent.
  - Explicit removal is `forget()`, as `Attempt.forget()` or `RatarmountSandbox.forget(id)`.
  - The client context drops a retained attempt from `_owned` once finalize succeeds, and its `close()` never destroys it.
- `RatarmountSandbox.forget(id)` and `list(base=None, all=False)`. `all=True` is client-side: it sends a v2 `list`. The default keeps sending v1 bytes.
- **`list` items are built inside `_call`'s error handling** (sweep 7, Claude N10). An item with missing fields (a `retained_damaged` record may carry only `{id}`) becomes an `Attempt` with those fields `None` and its `status`, instead of raising a bare `KeyError` (`ratarmount_sandbox.py:116`). A malformed envelope still raises `SandboxError("protocol", …)`.
- The context manager still destroys only the unretained attempts it created.
- The docstring's "no request deduplication" sentence is replaced with the request-ID rules.

### 6.11 Policy hooks (internal-read, #201)

Only calls that `packaging/internal-read-clippy/clippy.toml` actually disallows get a narrow `#[expect(clippy::disallowed_methods/types)]`, with a literal `internal-read:v1` reason, creation metadata, and an explicit manifest review in `packaging/internal-read-clippy/manifest.json`. An expectation on a call that is not disallowed is never fulfilled, and Linux Clippy rejects unfulfilled expectations (sweep 3, N2). The list:

- the `requests.jsonl` checked open, used at start and after compaction: `OpenOptions::new`/`open` (policy `create-or-open`, 0600, `O_NOFOLLOW|O_CLOEXEC|O_APPEND`, owner/type/nlink check on the descriptor, as in `lock`, `daemon.rs:80-125`)
- the `requests.jsonl` read at open (`fs::read`, `structured-control-record`)
- the compaction temp file (`NamedTempFile::new_in`, as at `IR-B0108`)
- `record.json` reads during the retained load (`fs::read`). The write reuses `atomic_json`, whose sites `IR-B0108/B0109` already exist, so it adds none.
- each `File::open` of a directory to fsync `retained/`, `attempts/` and the state directory (`directory-handle-or-durability`, as at `IR-B0109`)
- the directory descriptor of `attempts/ID` that the durability barrier passes to `syncfs` (`directory-handle-or-durability`, as at `IR-B0109`/`IR-B0157`; sweep 7). The `syncfs` call itself is not disallowed, but this open is.
- the `O_DIRECTORY` handles of `remove_tree_restoring_write` (as at `IR-B0157`)
- the `O_PATH | O_NOFOLLOW | O_DIRECTORY` pin of the new `host_stat::chmod_dir_at` in `ratarmount-compositing/src/host_stat.rs` (`directory-handle-or-durability`, as at `IR-B0142`, the same pin in `chmod_entry_at`; sweep 8, Claude N3). `host_stat.rs` is already a reviewed N4 target file (`policy.json:116-120`), so its `cfg(target_os = "linux")` alternative needs no `policy.json` change, only the ordinary review that N4 file exceptions always need.
- the managed reader of the new `ratarmount_index::cached_archive_digest_checked` in `ratarmount-index/src/digest_cache.rs` (`managed-read`, as at `IR-B0419` and at `IR-B0154` in `PendingBase::hash`, whose check-polling reader it copies, `overlay_meta.rs:972-986`; sweep 8). Its `regression` field names its own test in `digest_cache.rs`: `check` polled while waiting for the `HashGuard` and between chunks, nothing cached after a cancellation, and the managed reader keeping another connection's lock on the archive.
- step 4(a)'s `fs::read` of `/proc/PID/mountinfo` for other processes (`kernel-or-process-introspection`, as at `IR-B0116`). The supervisor's own `/proc/self/mountinfo` goes through the existing `process::mountpoints()` site (`IR-B0116`), whose parser is extended to return whole lines (§6.4.1).
- the holder scan's `fs::read` of `/proc/PID/comm`

**N4 target predicates** (sweep 4, N3). `ratarmount` is a restricted package (`policy.json:54-55`). N4 refuses any `cfg(target_os …)`/`cfg_attr` target predicate in a production file that is not in `reviewed_target_files`. `sandbox/daemon.rs`, `process.rs` and `run.rs` are on that list (`policy.json:530-545`); the new `finalize.rs` and `requests.rs` are not. Rule for R1:
- All Linux-only code goes in `sandbox/process.rs`, behind `Mounter`: the `/proc/*/mountinfo` survivor test, the holder scan, the whole-line extension of `mountpoints()` and the fusectl check (§6.4.1). There are two exceptions, both in `sandbox/daemon.rs`, which is also on the reviewed list: the commit rename's `rustix::fs::renameat_with(…, RenameFlags::NOREPLACE)` under `overlay_pack.rs`'s cfg (§10 #2), and the durability barrier's `syncfs`/`sync` choice (§6.4 step 6a; sweep 8, Claude N4). `forget`'s rename reuses the same helper.
- Outside the `ratarmount` package, the only new target predicate is `host_stat::chmod_dir_at`'s Linux alternative, in the already reviewed `ratarmount-compositing/src/host_stat.rs` (§6.7).
- `finalize.rs` and `requests.rs` contain **no** target predicates. `mod sandbox` itself has no cfg gate (`main.rs:56`). The `ratarmount` binary is Unix-only in practice, because `sandbox/process.rs` and `daemon.rs` import `std::os::unix` unconditionally, and the new files follow the same convention (sweep 5, N7).
- If an implementer finds a predicate unavoidable in a new file, the `policy.json` `reviewed_target_files` entry lands in the same commit and is added to the per-step table in §9.

**Not listed, because not disallowed:** `fs::read_link` (the holder scan's `/proc/PID/fd/*` and `cwd`, and step 4(a)'s `/proc/PID/ns/mnt`), `fs::read_dir` (coverage is #209), `fs::rename` and the `rustix` no-replace rename used by the commit and by `forget` (§10 #2), `rustix::fs::syncfs`/`sync` (the durability barrier, §6.4 step 6a), `chmod_dir_at`'s `chmod` through `/proc/self/fd/N` (as in `chmod_entry_at`, `host_stat.rs:216-217`, which has no expectation on it), the `fusectl` existence check (`symlink_metadata`, §6.4.1), and the inspection socket's Unix-socket I/O for the new `status` and `lowers` commands (the existing `deleted_paths` handler has no expectation either, `inspection.rs:78-116`). If the implementer finds one of these is disallowed after all, the expectation is added in that step's commit. Run `python3 -I packaging/internal-read-clippy/test_policy.py` and `policy.py` before every commit.

---

## 7. Lock order

R1 never holds two overlay root locks at once, never takes an archive guard (seal takes none: it reads the base through `SealArchive`, a SQLite-managed reader that holds no archive lock, `overlay_meta.rs:1022-1036`), and never commits to a base. Supervisor workers run with `--no-recreate-index`, which refuses commit modes (`docs/sandbox.md:2241-2243`), so the #240 commit branch is untouched.

1. **`daemon.lock`** (`flock LOCK_EX|LOCK_NB`, held for the supervisor's whole life, `daemon.rs:319`). It serializes every request, the `requests.jsonl` appends and compaction, and every change under `attempts/` and `retained/`. No other lock guards those files.
2. **Top overlay root flock** (`SealCommitGuard` through `SealOperation::acquire_until`, finalize step 5 only). It is taken before classify and gate, and released when `SealOperation::seal(self, …)` returns, which consumes the guard (`overlay_seal.rs:358-364`). It is also released when `finish_if_sealed` reports an earlier seal and the operation is dropped.
3. **Overlay database transaction** (`BEGIN IMMEDIATE` inside seal, `overlay_seal.rs:456`; fsck's writer reservation comes before this and is released by then).

**Not taken by R1:**
- **The archive flock.** It is non-blocking, and only commit takes it (`commit_journal.rs:707-717`).
- **The per-index digest `HashGuard` during finalize.** It is unbounded for its other callers (`digest_cache.rs:444-481`); commit's baseline refresh takes it, and so does a seal resolving a `pending` digest of a top with a writable index. R1's tops record no writable index (§2 callout, point 5), and with no index `cached_for_stamp` takes no `HashGuard` at all (`digest_cache.rs:584-610`), so a finalize that does hash a `pending` digest hashes uncached and unlocked.

If a later change ever lets a supervisor seal resolve such a digest, `HashGuard` sits between levels 2 and 3, exactly where seal takes it today (`overlay_seal.rs:445-451`).

**Taken by R1 outside finalize** (sweep 8): `create_base`'s digest caching takes the `HashGuard` of the base's own index, under level 1 only, with no overlay flock or transaction held, and with a bounded wait (§2 callout, point 6; §6.6).

Lowers are only **read** (`OverlayMeta::read_no_recovery`, §6.2) and never locked by the supervisor (§10, #3). Hashing and `finalize_pack` run after the seal, with the top lock released. They read a sealed layer, which is the situation `overlay pack` handles today. `forget` and `reconcile` take no overlay lock: a retained layer is sealed and owned by the supervisor, and `forget` refuses while any live attempt or retained record uses it (§6.7).

---

## 8. Crash and recovery matrix

The kill points are numbered for the tests in §11.

| Kill point | On restart |
| --- | --- |
| K1: `new` after `running` appended, before any mount ready | `reconcile` deletes `attempts/*`. The record is still `running`, so it is resolved to `failed interrupted` and a retry with the same ID returns `interrupted`. |
| K2: `new` after the batch is ready, before `done` | Same as K1: the attempts are discarded and the request reports `interrupted`. |
| K3: finalize after seal, before the rename (Keystone #2) | `attempts/ID` (sealed tree) is deleted by the permission-restoring `reconcile`. `retained/` does not contain it. The request reports `interrupted`. |
| K4: finalize after the rename, before fsync of `retained/` | Either the rename survived (case K5) or it did not (case K3). Both are consistent, because the durability barrier (§6.4 step 6a) made the tree's contents durable **before** `record.json` was written and the rename issued (corrected in sweep 7; revision 7 claimed consistency without that barrier). |
| K5: finalize after the rename and fsync, before `done` | `retained/ID/record.json` exists, so the `running` finalize record (which stores the attempt `id`) resolves to `done` with `record.report`. A retry returns that report. **If `retained/ID` is `retained_damaged`** (no parseable `record.json`, or an unsealed or mismatched layer), there is no report to return: the record resolves to `failed` with code `interrupted` and a message naming the damaged retained ID. That layer stays listed, and is never auto-deleted (sweep 4, N8; test U34). **The body check is applied again here** (sweep 6, N2): if the `running` line has `pack:true` and `record.report` has no bundle, the record resolves to `failed` `invalid_request`, the same answer §10 #6 gives without a crash, never to `done`. |
| K6: torn last line in `requests.jsonl` | It is truncated to the last newline at open. A torn line that is not last refuses the start (`invalid_request`, naming the file and offset; move it aside). |
| K7: a compaction temp file left behind | It is an anonymous `NamedTempFile` in the state directory. Open removes leftovers that match the temp pattern, the way `atomic_json` temps are left today. |
| K8: power loss or kernel panic (not just SIGKILL) at any point of a retained finalize (sweep 7, Claude B1, Codex 6) | **Before the barrier (6a) returns:** nothing was renamed, so the attempt is under `attempts/` and deleted (K3). **After it:** every byte of `attempts/ID` is on disk (payload, database, manifest, journal, summary, bundle, modes); `record.json` is written with its own fsyncs; then the rename and both parent fsyncs follow. A retained attempt found at the next start therefore matches its `record.json` and its seal, and K5 replays it. `requests.jsonl` and `retained/` exist durably from their first creation (§6.6). SIGKILL tests cannot show power-loss durability; the order of the barrier is pinned by U39 instead. |
| K9: the request log went `Broken` (§10 #5) and the daemon is restarted | Nothing special. A failed append is truncated away and nothing is appended after `Broken`, so the file ends at a complete line, or at a single torn **last** line if the truncation itself failed, which K6 truncates. K1-K5 then resolve its last `running` record. |
| K10: `forget` after its rename back to `attempts/ID`, before the deletion finished (sweep 8) | `reconcile` deletes the ordinary `attempts/ID`, and the ID is gone; a later `forget` of it returns `not_found`. `forget` itself is not request-ID'd and leaves no record. Older records naming the ID (its `new`, its finalize) still reserve it (§6.1a), and their replays return the original results. A crash before the rename leaves the attempt `retained`. |

A non-retained finalized attempt is disposable and is deleted by `reconcile` like any other attempt.

---

## 9. Implementation order

Each step is a single commit with its tests. The gates run before every commit, `policy.py` included.

**Per-commit inventory and regression rows** (sweep 3, B4). Every step that adds, moves or removes an internal-read site updates `packaging/internal-read-clippy/manifest.json` in **the same commit**. `AGENTS.md` says an unmanifested expectation, or an approval without a matching expectation, fails `policy.py`. Likewise every step adds its `AGENTS.md` regression-catalog rows in the same commit as its tests ("ship the test in the same commit"). Expected inventory changes per step:

| Step | Inventory change |
| --- | --- |
| 2 | `requests.jsonl` checked open, start-up read, compaction temp file |
| 4 | `IR-B0131/B0132/B0133` moved from `run::finish` to `finalize::finalize_top` |
| 5 | the `/proc/PID/mountinfo` reads of step 4(a) (the supervisor's own goes through the existing `IR-B0116` site); the holder scan's `/proc/PID/comm` reads; the walk handles of `remove_tree_restoring_write` (moved from step 6, sweep 7, Claude N2); the `O_PATH` pin of `host_stat::chmod_dir_at` in `ratarmount-compositing` and the managed reader of `cached_archive_digest_checked` in `ratarmount-index` (sweep 8). Not the inspection `status` handler: socket I/O is not disallowed (§6.11; sweep 7, Claude N11). |
| 6 | `record.json` write and read; directory fsync handles for `retained/`, `attempts/` and the state directory; the `attempts/ID` directory handle for the durability barrier's `syncfs` |
| 9 | no inventory change (the new `ratarmount/tests/sandbox_namespaces.rs` is test code); `.github/workflows/ci.yml` gains two environment variables (see step 9) |

Step 8 is then only a cross-check that the manifest diff matches the review.

0. **Golden v1 and spike** (no behaviour change).
   - (a) Factor `respond()` out of `serve`, and add the `#[cfg(test)]` deterministic ID source (§10, #7).
   - (b) Generate and commit fixtures from the **unchanged** production code:
     - `ratarmount/src/sandbox/testdata/v1-golden.jsonl` (§10, #7);
     - the Python and CLI request-byte goldens;
     - `ratarmount/src/sandbox/testdata/run-report-golden.json`: the `sandbox run` `finish` report for the existing `regression_run_report_hash_manifest_seal_pack` fixture, with temporary paths normalized and `wall_time_s` fixed. U10 compares against it after `finish` is gone (sweep 3, N11);
     - `run-report-repair-golden.json`: the same for U10's repair fixture, tombstoned host content that fsck `--repair` unlinks (§6.3; sweep 8, Codex 5), so the repair case is byte-compared across the refactor too.
   - (c) Spike (not committed if it fails): confirm that `classify_supervisor_base` uses the prepared index and that it agrees with the kind and place a supervisor mount records, for a plain archive, a Git base with `git_synthetic_head`, a directory, a base with `binds` and a `recursive` base. The spike also checks that the classification's view matches the mount's view flags (`--no-file-versions` from `base_args`, `process.rs:43`; `gnu_incremental: Some(false)` as `open_base` sets it, `daemon.rs:837`). On a fixture where file versions or GNU-incremental listings would differ, `change_set` and `canonical_hash` over that view must equal `ratarmount diff --hash --json` run by hand on the finalized layer. Bases that disagree stay `unsupported` for lowers and finalize, and get a follow-up issue.
   - (d) **Observe the kernel behaviours §6.4.1 relies on, with shell commands, before step 5 builds on them** (rewritten in sweep 7, Claude N3).
     - **No R1 code is used.** The classifier and finalize do not exist until step 5, so step 0d asserts only what the kernel does. The classifier and finalize assertions are U37 (step 5) and F6b/F6c (step 9).
     - **Setup.** A plain `ratarmount -f -w OV base.tar MNT &` (today's binary) gives a FUSE mount with a child process, under a `shared` path (`/tmp` or `/home` qualify on both hosts). Its device is the `major:minor` in field 3 of its `/proc/self/mountinfo` line.
     - **Where it runs.**
       - On the CI runner image (Ubuntu, systemd as PID 1, passwordless `sudo`), through a throwaway workflow.
       - On Matt's Arch/omarchy desktop, **run by Matt**: every privileged case needs `sudo`, and an agent session there has no passwordless `sudo`.
     - **Captures.** Every case records the `mountinfo` lines it relies on. The captures, with PIDs and paths normalized, become U37's real fixtures (`ratarmount/src/sandbox/testdata/mountinfo/`), and the results go into the PR.

     Then check:
     1. **Busy host mount.** With a host process holding a file in MNT, `fusermount3 -u MNT` fails with EBUSY and MNT stays mounted. This is what `ratarmount_fuse::unmount` sees after its retry.
     2. **systemd service namespaces, the case that matters.**
        - The stock services' namespaces (systemd-resolved and the other units with `PrivateTmp`/`ProtectSystem`/`ProtectHome`), started at boot, hold a copy of MNT's device with a `master:` field. This is already observed for the gvfs and portal FUSE mounts on the Arch host.
        - A transient unit started before the mount (`sudo systemd-run --collect -p RuntimeMaxSec=300 -p PrivateMounts=yes -p PrivateTmp=yes sleep 300`) holds one too, and so does one started after it (`-p PrivateMounts=yes` only). As an extra data point, record whether a unit started after the mount **with** `PrivateTmp` keeps one.
        - `fusermount3 -u MNT` succeeds. Afterwards no copy of the device is left in any readable `mountinfo`, `/sys/fs/fuse/connections/<minor>` is gone, and the `ratarmount` process exits.
        - With a unit running as the user (`--uid`/`--gid`, `-p PrivateMounts=yes`, **no** `PrivateTmp`) holding a file in its copy, `fusermount3 -u MNT` fails with EBUSY and MNT stays mounted.
     3. **Chains.**
        - A nested slave namespace inside a unit that keeps its own process (`sh -c 'unshare --mount --propagation slave sleep 300 & exec sleep 300'`, run as root): the nested copy's `master:` names the unit's group, and `fusermount3 -u MNT` removes it.
        - The same with a process-free persistent intermediate namespace: the nested copy is removed too.
     4. **Private copies.** Make the namespace with `sudo unshare --mount --propagation private`, then `setpriv --reuid … --regid … --clear-groups` to the user, holding a file. `fusermount3 -u MNT` **succeeds**, but `/sys/fs/fuse/connections/<minor>` stays and the `ratarmount` process keeps running until the holder exits. This is a survivor.
     5. **A persistent private namespace with no process.**
        1. Make the directory: `D=$(sudo mktemp -d /run/rrs-ns.XXXXXX)`, then `sudo mount --bind D D` and `sudo mount --make-private D`.
        2. **Create the mount target**: `sudo touch D/mnt`. `unshare` bind-mounts onto an existing file; it does not create one (`unshare(1)`, EXAMPLES; sweep 7, Codex 8).
        3. Create the namespace: `sudo unshare --mount=D/mnt --propagation private true`.
        4. Check every step's exit status.

        Result: `fusermount3 -u MNT` succeeds, the connection directory stays, and the process keeps running. After `sudo umount D/mnt`, the connection goes and the process exits. Cleanup: `sudo umount D/mnt` (if still mounted), `sudo umount D`, `sudo rmdir D`.
     6. **Locked clones, with the propagation chosen explicitly** (sweep 7, Codex 10). Create an unprivileged `unshare --user --map-root-user --mount --propagation slave sleep 300` **after** the mount, and check that its copy carries `master:`. `unshare` defaults to `--propagation private`, which would make an ordinary private survivor instead of a locked propagation copy.
        - **On the Ubuntu runner** (sweep 8, Claude N13), Ubuntu restricts unprivileged user namespaces through AppArmor since 24.04 (`kernel.apparmor_restrict_unprivileged_userns=1`), so the unprivileged command cannot create the mount namespace there. The throwaway workflow sets that sysctl to 0 for this case only (`sudo sysctl -w`). The committed CI never changes it (step 9), and no committed test needs an unprivileged user namespace (§6.4.1).
        - Expected, from `propagate_mount_unlock`: `fusermount3 -u MNT` removes the locked copy, and the process exits.
        - Second case: inside such a namespace, mount a tmpfs on `MNT/sub`. Expected: the copy, which now has a mount of its own, stays, and the process keeps running.
        - The docs state what is observed.
     7. **Readability.** `/proc/PID/mountinfo` of root-owned and container processes is readable unprivileged (already observed on the Arch host: `/proc/508`, `/proc/3859090`). Also record what `hidepid=2` changes.
     8. **`fusectl`.** `/sys/fs/fuse/connections/<minor>` exists while any copy exists, and disappears at the last unmount (checked in 2, 4, 5 and 6).

     If any observation differs from §6.4.1's expectation, the plan is updated before step 5 lands.
1. **Protocol v2 and response versioning.** Add `OperationV2`, `Op`, `Response` version threading, the version-3 change to the existing test, and v2 parse tests. v1 golden stays green. Until their handlers land (steps 2-6), the v2-only parts are placeholders:
   - `finalize` and `forget` return `unsupported` ("not implemented yet"). A v2 `list` works from step 1, showing only the statuses that exist so far.
   - A v2 `new` that uses `lowers`, `journal`, `retain` or `request_id` is refused the same way.
   - A v2 `new` without those fields behaves like v1 `new`.
   - Step 1 also adds `regression_request_serialization_round_trip_both_versions` (sweep 6, N8). It serializes a `Request` of each version through the `#[serde(flatten)]` field over the `untagged` `Op` for every operation, and asserts flat `{"version":N,"op":…}` JSON with no `V1`/`V2` wrapper. Parsing that JSON back must give an equal value. This pins the flatten-over-untagged shape at step 1 instead of waiting for U3 in step 7.
2. **Request log** (`requests.rs`): log format, replay, compaction, canonical hash, conflict and replay semantics on a no-op v2 `new` through the Fake. Includes tests U5-U8.
3. **`SpawnSpec`, lowers and journal** (needs Keystone's sign-off on §13.7(a), dropping attempt-level `allow_globs`, before it lands), plus the attempt-ID uniqueness rule (§6.1a, U35). Also in this step:
   - validation (§6.2), argv and the post-ready re-check, including the child's records through the new inspection command `lowers` and `Mounter::lower_records` (§10 #3; U47, sweep 8). The inspection change is socket I/O, so it adds no inventory site;
   - `diff` with lowers, through the new non-recovering `MountLowerStack::open_no_recovery` in `ratarmount-compositing` (§6.8; U41's `diff` half);
   - the result-size preflight (§10 #5, U38);
   - the `retain`+tmpfs refusal and `--max-retained` reservation at `new`.
4. **`finalize_top` refactor**, with the `Finalized` owner (§6.3, U40), plus `SealOperation::acquire_until` in `ratarmount-compositing` with U28, because `finalize_top` needs it (sweep 5, N3). `sandbox run` passes no deadline, which behaves like today's `SealOperation::acquire`. `sandbox run` reports must be byte-identical (U10, plus the existing `sandbox_run` tests).
5. **Finalize.** This step adds:
   - `Mounter::stop` with the survivor test, `fusectl` and exit status (§6.4.1);
   - the exit-status plumbing: the `exited` map filled by `poll`, `stop` and `cleanup`, and `Mounter::exit_status` (§6.4.1; U44, sweep 8);
   - the inspection `status` command;
   - the record comparison over `open_no_recovery`, with the resolver from `Mounter::bundle_resolver` (§6.3; U16, U41's finalize half);
   - the state machine (§6.4) and non-retained finalize;
   - `create_base`'s digest caching, with `cached_archive_digest_checked` in `ratarmount-index` (§6.6; U43);
   - `host_stat::chmod_dir_at` in `ratarmount-compositing`, which the removal below needs (§6.7; U42);
   - **`remove_tree_restoring_write`, wired into `destroy` and `reconcile`** (sweep 7, Claude N2). From this step on, a non-retained finalize leaves a sealed tree without write bits (`overlay_seal.rs:551`). Without the new removal, `destroy` (`daemon.rs:731-734`) and `reconcile` (`:413`, `:426`) would fail with EACCES on it, a restart after one finalize could not start, and step-5 tests ending in `destroy_all().unwrap()` would fail the per-commit gate. Revision 7 had scheduled the removal for step 6.

   Two conditions:
   - The supervisor's seal-lock deadline is **5 s**. The top lives in the daemon's private `attempts/ID/overlay`, so contention can only come from an operator running a same-user overlay verb there. Past the deadline the result is `in_use`, and the request is `retryable`.
   - Before this step starts, Keystone signs off §13.7(b) (the `in_use` mapping) and §13.7(c) (`Detached`).
6. **Retained, forget, durability.** `record.json`, the durability barrier (§6.4 step 6a), the commit rename, the retained load and damage, crash-safe and resumable `forget` with the `forgetting` status (§6.7; U45, sweep 8), the state-root fsyncs, and the crash seams K1-K5.
7. **Clients**: CLI flags and subcommands, Python client and its tests.
8. **Docs** (§12) and the CHANGELOG, plus a cross-check that every step's manifest and `AGENTS.md` rows landed with that step.
9. **FUSE tests** (`ratarmount/tests/sandbox.rs`, plus the new `ratarmount/tests/sandbox_namespaces.rs` for F6b/F6c), the CI wiring that makes them count, and the full gate on a FUSE host. The tests CI runs need no `user_allow_other`: supervisor bases default to no `allow_other`, and every holder in F6b/F6c runs as the test user. The one exception is F6b's opt-in Docker variant (`RATARMOUNT_TEST_DOCKER=1`, not set in CI). dockerd runs as root, and root cannot open a FUSE mount without `allow_other`, so that variant registers its base with `allow_other: true` and needs `user_allow_other`, as the recipe's own base does (`swe-bench-sandboxes.md:68`; sweep 7, Claude N11).

   **CI facts this wiring rests on** (re-verified for revision 7 against `.github/workflows/ci.yml` at `2b96837`):
   - The FUSE tests run inside the `check` job's `cargo test --workspace` (`ci.yml:102-105`). That job installs `fuse3` (`ci.yml:20-24`) and sets only `RATARMOUNT_REQUIRE_XORRISO`.
   - No workflow sets `RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE` (the only switch that makes `prepared_fuse_check` refuse to skip, `tests/sandbox.rs:365-366`), configures `user_allow_other`, or changes any sysctl. Every other FUSE test in `ratarmount/tests/` skips silently without `/dev/fuse` or `fusermount3`, so the repository itself never proves that FUSE works in the `check` job.
   - The evidence that it does work is the `fuse-harness` job: on the same `ubuntu-latest` image it fails when a mount does not come up (`ci.yml:300-341`, `test-harness/run-phase2-allowlist.sh:95-100`).

   **The change: two environment variables on the `check` job's `cargo test` step,** next to `RATARMOUNT_REQUIRE_XORRISO: "1"` (`ci.yml:104`), in the same commit as F4-F10, F6b and F6c:
   - `RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE: "1"`: the existing prepared-index tests and the new FUSE tests (which read the same variable) fail instead of skipping when `/dev/fuse` or `fusermount3` is missing.
   - `RATARMOUNT_TEST_PRIVILEGED: "1"`: opts in to `sandbox_namespaces.rs`, which uses passwordless `sudo` (available on GitHub-hosted runners) for `systemd-run`, `unshare` and `mount`. When the variable is set, a missing prerequisite fails the test: `sudo -n true`, `systemd-run`, `setpriv`, `unshare`, systemd as PID 1, or `/` not `shared`. When it is not set (any developer machine), the binary prints one `skip:` line and **never runs `sudo`**. This follows the existing opt-in pattern of `RATARMOUNT_TEST_DOCKER` and `RATARMOUNT_TEST_OVERLAYFS`. The variable is read only by test code, so release binaries gain no `RATARMOUNT_TEST_` string.

   **Deliberately not changed** (revision 7 removes revision 6's extra CI edits):
   - **No `user_allow_other` in `/etc/fuse.conf`.** `tests/sandbox_run.rs:13-29` skips whenever `validate_allow_other` fails, so enabling it in the shared job would switch on a suite that has never run in CI, for no R1 benefit.
   - **No `kernel.apparmor_restrict_unprivileged_userns` sysctl.** CI uses the `sudo` path, which needs no unprivileged user namespace.
   - **No separate `/dev/fuse` step.** The first variable already fails with a message naming the missing prerequisite (`tests/sandbox.rs:375`).

   **First CI run of step 9.** The `cargo test` log must show that the prepared-index tests and both namespace tests ran: no `skip: prepared-index mount integration` line and no `skip:` line from `sandbox_namespaces.rs`. If a reviewer rejects changing the shared `check` job, the alternative is a separate `sandbox-fuse` job with the same two variables that runs `cargo test -p ratarmount --test sandbox --test sandbox_namespaces`; the gate is then "this job is green". **Until one of the two lands, the FUSE half of the gate is met only by a manual run on a FUSE host with passwordless `sudo`**, recorded in the PR, not by CI.

   Also measure the serialization cost (sweep 2, N10), as an ignored timing test like `sandbox_64_attempt_setup_teardown_timing` (`tests/sandbox.rs:319`):
   - Run 16 sequential finalizes, and record the wall time per finalize and how long a concurrent `list` waits. The run must include the two expensive cases (sweep 4, N6):
     - **A bundle lower.** With `base_key: None`, each finalize and each v2 `diff` re-verifies the bundle (`lower_stack.rs:71-79`).
     - **An archive base with no cached digest.** Sealing would hash the whole base on every finalize. `create_base`'s digest caching (§6.6) should make a worker record `present`, so the run must show no seal-time hash. If the step-0c spike found that it does not, the run measures that hash.
     - **The retained durability barrier** (sweep 7, Claude B1): `syncfs` flushes the whole filesystem holding the state directory, so its cost depends on other writers there. Measure retained finalizes with and without a concurrent writer on that filesystem.
     - **The registration hash** (sweep 8, Claude N8). Time `create_base` on a large archive (several GiB) with and without §6.6's caching: the index build, the added digest, and whether the digest fits its extra `--timeout` window. This is the cost Keystone signs off in §13.7(d), and the result goes into `docs/sandbox.md`.
     - **The step 4(a) survivor test** (sweep 6, N6). It reads every `/proc/*/mountinfo` on each finalize, inside the serve loop. Measure it on a host with many processes, and with `ns/mnt` unreadable for most of them (root-owned services, so no de-duplication before reading). If it is slow, the PR may first read the cheap `ns/mnt` links and skip namespaces already read. It may also cap the scan; a namespace left unread counts as undecided (backstop (c)), never as a survivor.
     
     If a cost dominates (corrected in sweep 7, Claude N7):
     - for bundle re-verification, the supervisor passes the base's cached strong digest (from §6.6) as `base_key` to `open_no_recovery`, since a `base_key` is what lets a previous bundle verification be trusted (`lower_stack.rs:71-79`);
     - for base hashing, §6.6's caching is the fix. Revision 7's advice to "register bases with a known digest" was impossible, because `BaseOptions` has no digest field (`protocol.rs:11-28`);
     - anything left is documented in `docs/sandbox.md` with the measured cost.
   - Record the result in the PR.
   - `docs/sandbox.md` states that finalize runs in the single serve loop (fsck, classify, seal, hash, pack, up to 10 s of child wait), so other requests and crash detection wait behind it, and an idle client connection can hit the 30 s drop (`daemon.rs:946-952`).
   - A worker thread for finalize is out of R1 scope.

**Effort: about 15-19 working days** (re-estimated in sweep 8, Claude N14). Revision 1's 9-11 days predated most of the review findings: the survivor test and the namespace tests, the request log's `Broken` state and compaction, the durability barrier, the digest caching and its new index API, the post-`Ready` record check, the resumable `forget` and the permission-restoring removal. Per step:

| Step | Days |
| --- | --- |
| 0: golden harness, spike, kernel observation (0d needs Matt's desktop run) | 2 |
| 1: protocol v2 | 1 |
| 2: request log | 2 |
| 3: `SpawnSpec`, lowers, journal, post-`Ready` checks, `diff` with lowers | 2.5 |
| 4: `finalize_top` refactor, `acquire_until`, U10 | 1.5 |
| 5: finalize, stop, exit status, digest caching, removal | 3.5 |
| 6: retained, forget, durability, crash seams | 2 |
| 7: CLI and Python | 1 |
| 8: docs | 1 |
| 9: FUSE and namespace tests, CI wiring, timing | 2 |
| **Total** | **18.5** |

**What can slip without breaking the gate:** `create_base`'s digest caching, if Keystone declines §13.7(d) (finalize then hashes the base, and the cost is documented); F6b's opt-in Docker variant (not run in CI); the step-9 timing test (it is `#[ignore]`d and records numbers, it gates nothing). Dropping all three saves about 2 days.

---

## 10. Keystone fixes

### #1: retained attempts do not count toward `--max-attempts`

- `new_attempts`' capacity check (`daemon.rs:615`) keeps counting `self.attempts.len()` only. Retained records live in a separate `retained: BTreeMap<String, RetainedRecord>` and never enter `attempts`. The rename in step 8 moves the attempt from one map to the other.
- `--max-retained` is the only cap on retained attempts. It is enforced **at `new`**: `retained.len() + forgetting.len() + live attempts with retain=true + count ≤ max_retained`, otherwise `capacity`. A `forgetting` entry (§6.7) keeps its slot until its tree is deleted (sweep 8). It is never enforced at finalize, because a refusal there would throw away a finished, sealed layer.
- A finalized attempt that was not retained keeps its `attempts` slot until it is destroyed, because it is still under `attempts/`.
- Tests: U11 (`regression_retained_do_not_count_toward_max_attempts`) fills `--max-attempts 2` with two retained attempts and then creates two more. U12 (`regression_max_retained_reserved_at_new`) checks that `retain: true` beyond the cap returns `capacity` before any spawn.

### #2: the rename is the single commit point

- The commit point is `rename(attempts/ID, retained/ID)` followed by `fsync(retained/)` (and `fsync(attempts/)`). Before that durable rename, the attempt is disposable. After it, the attempt is retained. There is no second record that could disagree:
  - `record.json` (with the full report, every path already pointing at `retained/ID/...`) is written with `atomic_json` **inside** `attempts/ID/` before the rename, so the rename publishes the directory and its record together.
  - The retained index in memory is rebuilt from `retained/*` at every open.
  - `bases.json` is untouched.
- The request log's `done` line follows the commit point. It is never a commit itself (K5).
- The rename moves the writable attempt root, never the sealed `overlay/` (whose root has no write bits), so the `..` entry that `rename(2)` updates belongs to a writable directory.
- **The rename never replaces anything** (revision 7; binding corrected in sweep 7, Claude N5).
  - It is `rustix::fs::renameat_with(attempts_fd, ID, retained_fd, ID, RenameFlags::NOREPLACE)`, the call `overlay_pack.rs:1069-1083` already makes, under the same cfg. On Linux and Android that is `renameat2`, and on Apple `renameatx_np(RENAME_EXCL)`. On other platforms it returns `ENOSYS`, but the supervisor refuses to serve there anyway (`daemon.rs:886-891`).
  - It lives in `sandbox/daemon.rs`, a reviewed N4 target file.
  - Revision 7 named `libc::renameat2`, which does not exist on macOS. The macOS CI job builds `ratarmount --all-targets` and runs the sandbox unit tests (`ci.yml:441-481`), so that would have broken it. With `rustix`, U35's EEXIST case runs on macOS too.
- **The tree is durable before the commit point** (sweep 7, Claude B1, Codex 6).
  - **What was missing.** The rename and its parent fsyncs make only directory entries durable. Before it, nothing synced the attempt's data: the payload the FUSE child wrote into `overlay/`, `manifest.jsonl`, `journal.summary.json` and `journal.jsonl`.
    - Seal commits its database and syncs only the sentinel (`overlay_seal.rs:546-551`, `:608`).
    - The manifest and summary are plain `File::create` writes (`run.rs:1163`, `:1179`).
    - The journal is synced only under `--journal-sync` (`oplog.rs:580-583`).
    - Only pack syncs its bundle (`overlay_pack.rs:522`).
    
    After a power loss once the rename was durable, a retained attempt could come back with its seal row but missing bytes. The retained load compares only the seal row with `record.json`, so it would still list the attempt `retained`, and a later attempt would mount a layer whose bytes no longer match its digest.
  - **The barrier.** So step 6a calls `syncfs` on `attempts/ID` before `record.json` is written and before the rename (§6.4).
  - **The full order:**
    1. the barrier;
    2. `record.json` (`atomic_json`: file `sync_all`, then `attempts/ID` fsync);
    3. the no-replace rename;
    4. fsync `retained/` and `attempts/`;
    5. the `done` line.
  - **Tests and timing.** U39 pins this order through a seam that records the calls, and a failing `syncfs` leaves the attempt `sealed` and unrenamed. Step 9's timing includes the barrier, which flushes the whole filesystem the state directory is on. §6.1a already keeps `retained/ID` from being taken by a new attempt. If a `retained/ID` appears anyway (an operator's `mkdir`), the rename fails with EEXIST, the attempt stays `sealed`, and nothing is overwritten. A plain `rename(2)` would silently replace an existing *empty* target directory (U35).
- **Crash between seal and rename (K3):** `reconcile` deletes `attempts/ID` with the permission-restoring removal (`remove_dir_all` would fail on the sealed tree and block the start), nothing appears in `retained/`, and the request reports `interrupted`.
- Test U13 (`regression_crash_between_seal_and_rename_reconciles_and_reports_interrupted`):
  - A real SIGKILL. The test binary re-executes itself (the pattern of `regression_subprocess_deadline_reaps_child`, `process.rs:419-443`). It holds `ratarmount_index::test_process::spawning()` for the child's whole life, as that test does (`process.rs:421`). HEAD `2b96837` (#244) serializes child-spawning tests against the lock probes, and without the guard these tests are flaky. U14 and U20 do the same.
  - The child builds a real overlay with `crate::base_identity::fixtures::overlay_over_with(source, dir, base_path, lower_records, BaseDigestRequest::Compute)` (`base_identity.rs:305-345`; `#[cfg(test)] pub(crate)` in the `ratarmount` crate, so `sandbox/tests.rs` can reach it). It is the fixture the existing `finish` tests use (`run.rs:1791`, `:1864`), and it records the base as a local folder at `base_path`, so `gate_base` checks a recorded place exactly as in production. `fixtures::new_overlay` is not suitable: it records no place (`inputs: Vec::new()`, `location: None`, `base_identity.rs:269-290`), which would test a gate branch production never takes (sweep 2, N4). The fixture is `WriteOverlay::open` over a token from `ClassifiedBase::open`. It runs behind the Fake mounter. **`WriteOverlay::new` must not be re-added**: it is one of the deleted token-free entry points that must stay deleted, pinned by `compile_fail` doctests (`cargo test --doc -p ratarmount-compositing overlay_identity`, `AGENTS.md`). The child then starts `finalize` with `retain:true, request_id:"r1"`. It stops at a `#[cfg(test)]` seam after seal and before the rename, writes a marker and sleeps.
  - The parent SIGKILLs the child, reopens the `Supervisor` on the same root and asserts:
    - `attempts/` and `retained/` are empty;
    - `finalize` with `"r1"` returns `interrupted`;
    - a fresh `new` succeeds.
  - Companion test U14 kills at K5 and asserts the attempt is listed `retained` with the same `layer_digest`, and that a retry with `"r1"` returns `record.report` byte for byte.
  - The seams are `#[cfg(test)]` only, so release binaries contain no `RATARMOUNT_TEST_` string (`packaging/test-no-test-hooks-in-release.sh`).

### #3: the gap between lower validation and spawn. Choice: re-check once mounted

**Choice: re-check once mounted, not holding the #240 overlay root flock.** The decision is not close: holding the flock cannot close the window, and a re-check can. The reasons, from the code:

1. **The mount takes the lower after `spawn` returns, so holding the lock "across validate and spawn" ends too early.** The child reads the lower's metadata and refuses an unsealed lower inside its own startup (`lower_stack.rs:173-184`), at some point after `Command::spawn` and before `MountState::Ready`. To cover that, a held lock would have to last until every attempt in the batch is `Ready`, which can be up to `--timeout` (default 120 s, `mod.rs:45`). During that time every `overlay seal`/`unseal`/commit on a shared prepared layer would block, and `SealCommitGuard::acquire` spins without a bound (`write_overlay.rs:7429-7446`).
2. **A lock cannot cover bundle lowers.** A bundle resolves to a cache directory chosen by the child (`lower_stack.rs:150-169`), so the supervisor has nothing to lock beforehand.
3. **A lock adds nothing the re-check lacks.** The plan does expose the same guard through `SealOperation::acquire_until`, so a public locking type is not the argument. The argument is that the lock excludes only seal, unseal and commit. It does not stop an owner from `chmod u+w` and editing a payload file without touching the database. Neither option can stop that.
4. **Re-checking catches every seal-state change the window allows.** An unsealed lower is already refused by the child itself (it never gets `--allow-unsealed-lower`). That leaves an unseal-reseal inside the window. A reseal always writes a new `sealed_at` (an RFC 3339 timestamp with nanoseconds, `overlay_seal.rs:509`), and a resealed edit changes `layer_digest`. So `(dev, ino, layer_digest, sealed_at)` being equal before spawn and after `Ready` proves that the child took the **same seal record** of the same directory. Replacing the directory changes `dev`/`ino`. For bundles, `(dev, ino, size, mtime_ns)` is compared. It does **not** prove the payload bytes are unchanged: a payload edited behind the seal (as in 3) keeps both fields. Only `overlay verify` (a rehash) catches that, and finalize does not rehash lowers (cost). Documented as a limit.

**Mechanics.** `new_attempts` snapshots the lowers (§6.2). After the readiness loop sees every ID `ready` (`daemon.rs:694`), and before `new` returns success, it makes two checks per attempt. Any difference returns `lower_changed`, naming the path, and the whole batch is rolled back through the existing `destroy` path (`:710-724`).
1. **The lowers themselves.** It re-reads every lower's identity once (`read_no_recovery`).
2. **What the child actually took** (sweep 8, Codex 1). Matching identities before and after cannot rule out a swap: a path could name layer A at validation, B while the child opened it, and A again at the re-check.
   - So the supervisor asks each child, through a new inspection command `lowers` behind a new `Mounter::lower_records(attempt)`, for the records it wrote into its top. The child serves them through the mount's own connection with `WriteOverlay::meta_value("lower_layers")` (`write_overlay.rs:3293-3298`), which works while mounted and opens no second connection.
   - Those records were built from what the child read when it opened each lower (`lower_stack.rs:196-208`). Each position's `layer_digest` and `sealed_at` must equal the snapshot's; at directory positions the canonical path must also match. A reseal of B writes a different `sealed_at` than A's, so B is caught.
   - The child's digests at bundle positions are stored in the attempt's spec, and they complete §6.2 item 5's stack check.
   - **Residual, documented:** the child reads a lower's metadata and builds its layer through two separate opens (`lower_stack.rs:176-215`, `overlay_layer.rs:45-47`). A same-user rename between exactly those two opens is not detected. Closing that would mean opening the layer once, by descriptor, inside the child, which is out of R1's scope; R1 guards against honest mistakes, not a same-user adversary.

Finalize repeats check 1 at step 2, before it unmounts anything. In finalize phase 2 (§6.3, after the stop, so the top's database is free), it also compares the snapshot with the `lower_layers` rows the child wrote into the **top** at creation (`OverlayMeta::lower_layers`; the records are built at `lower_stack.rs:196-208`). Those rows record what the mount actually took. The comparison is position by position, and the count must match:
- **Directory lower:** the row's path must equal the snapshot's canonical path, and its `layer_digest` and `sealed_at` must equal the snapshot's.
- **Bundle lower** (sweep 3, B3; completed in sweep 7):
  - The row's path is the cache directory the child resolved (`lower_stack.rs:150-172`), never the bundle path, so the path is **not** compared.
  - The bundle file's `(dev, ino, size, mtime_ns)` is re-checked against the snapshot.
  - The bundle is resolved again by `open_no_recovery` (§6.3, phase 2), and that record's `layer_digest` and `sealed_at` must equal the row's. A bundle whose contents were replaced in place with its stamp kept passes the stamp check but fails this one (Codex 2).
  - The row's `layer_digest` and `sealed_at` go into the attempt record and report as what the mount took.

A difference is `lower_changed`. Because this comparison runs after the unmount and possibly after fsck `--repair`, this variant leaves the attempt `stopped` (possibly repaired), not untouched (sweep 3, N9). Step 2's pre-unmount check of the lower directories themselves is the variant that touches nothing.

**Stated limit:** neither option protects a lower **after** `Ready`. The mount opens sealed lowers `Immutable` and holds no lock on them, and `unseal` needs only the root flock plus a database transaction that the mount does not hold (`overlay_seal.rs:676-711`). An operator who unseals a mounted lower changes what the attempt sees. Finalize's step-2 re-check refuses such an attempt (`lower_changed`) instead of sealing a top over a different stack. This existing limit is documented in `docs/sandbox.md` "Layered overlays".

Tests:
- U15 (`regression_lower_resealed_between_validate_and_ready_is_refused`): a Fake `spawn` hook unseals, edits and reseals the lower. Assert `lower_changed`, every attempt in the batch destroyed, and `attempts/` empty.
- U47 (`regression_post_ready_child_records_detect_a_b_a_swap`; sweep 8, Codex 1): an A→B→A swap. The Fake's `spawn` hook renames sealed layer B onto A's path, records B's `layer_digest`/`sealed_at` as what its child took (returned by `Mounter::lower_records`), then renames A back. Lower A's own identity is unchanged at the re-check, yet `new` returns `lower_changed` and the whole batch, including its other attempts, is rolled back.
  - A second case covers a bundle position: the child reports a resolved digest that differs from what the requested external layer recorded there. It is also `lower_changed` and rolled back (§6.2 item 5; Codex 7).
- U16 (`regression_finalize_refuses_changed_lower`), including:
  - a bundle lower whose top row carries the cache path: it is **not** `lower_changed`, and the report carries the row's `layer_digest`;
  - a bundle file replaced after `Ready`: it **is** `lower_changed` (sweep 3, B3);
  - **a bundle whose contents change while its identity does not** (sweep 7, Codex 2). The test injects a bundle resolver through the Fake's `Mounter::bundle_resolver` (§6.3; sweep 8, Claude N12), which feeds `LowerStackServices.resolve_bundle` (`lower_stack.rs:38-41`). It returns layer A for the bundle path at `new` and a different valid sealed layer B at finalize; the inode, size and mtime are unchanged. Finalize returns `lower_changed` before anything is sealed: the top has no `seal_rows`, and its status is `stopped`.
- U17 (`regression_lower_validation_refusals`): an unsealed lower, a relative path, a missing path, a path under `attempts/`, a symlink resolving into `attempts/`, a damaged retained lower, and 33 lowers. Each must be refused before any `tempdir_in`.

### #4: request-ID hashing does not depend on serde_json key order

- `op_hash = "sha256:" + hex(sha256(canonical_json(value)))`, where `value = serde_json::to_value(&OperationV2 with request_id = None)` plus `"version":2`.
- Hashing the **typed** operation means defaults are applied first, so `{"base":"b"}` and `{"base":"b","count":1}` are the same request.
- `canonical_json` is an explicit writer in `requests.rs`. It walks the `Value`, writes object members sorted by their UTF-8 key bytes at every depth and keeps array order (`lowers` order is meaningful). It writes no whitespace and uses serde_json's own string and number encoding for scalars.
- Because the writer sorts keys itself, the hash is correct whether or not some dependency later turns on serde_json's `preserve_order` feature. Today the feature is off: `Cargo.lock` lists serde_json 1.0.151 with dependencies `itoa, memchr, serde, serde_core, zmij` and no `indexmap` (`Cargo.lock:6321-6331`). There is no cfg a dependent crate can assert, so this is pinned by a test instead.
- Tests:
  - U5 (`regression_request_hash_ignores_key_order`): two raw request texts whose keys are permuted at the top level and inside `journal` hash equal. `request_id` does not change the hash. A different `count`, a reordered `lowers` array or a different `journal.reads` each change it. Explicit defaults equal omitted defaults.
  - U6 (`regression_serde_json_preserve_order_is_off`): asserts `serde_json::to_vec(&json!({"b":1,"a":2})) == br#"{"a":2,"b":1}"#`, with a comment saying the hash does not rely on this and that a failure means a dependency turned the feature on. That needs a review, not a change to the hash.
  - A golden digest constant for one fixed request, so the definition cannot drift unnoticed.

### #5: `requests.json` rewritten in full on every request. Choice: append log plus compaction

**Numbers.** The sizes come from the real shapes:
- An `Attempt` with a state-directory path is about 250 B, so a `new` result for count 8 is about 2 KB and one for count 64 about 16 KB.
- A finalize report with patch hash, manifest, journal summary and bundle paths is about 1-2 KB.
- Each record also holds an ID (≤128 B) and `op_hash` (71 B).

At 65,536 records of about 1 KB the file is about 64 MiB. `atomic_json` writes a temp file, calls `sync_all`, renames it and fsyncs the directory (`daemon.rs:282-298`). That happens **twice per request** (`running`, then `done`), so roughly 128 MiB is written and 4 fsyncs are issued per request.

Estimates for a typical NVMe/XFS host (to be measured in the PR):
- Writing and serializing 64 MiB costs about 0.2-0.6 s per rewrite.
- That blocks the single-threaded daemon, so every other client waits.
- An RL run of 10,000 attempts makes about 20,000 mutating requests (`new` plus `finalize`), or about 2.5 TiB of writes once the table is full.

That cannot be justified. Even with results stored only by reference (about 300 B per record, so about 19 MiB per rewrite), the same run would write about 750 GiB.

**Design (`ratarmount/src/sandbox/requests.rs`).**

- **`requests.jsonl`.** One JSON object per line:
  - `{"v":1,"seq":N,"id":R,"t":"running","op":"new"|"finalize","op_hash":H,"attempt":ID?}`
  - `{"v":1,"seq":N,"id":R,"t":"done","op":…,"op_hash":H,"attempt":ID?,"result":…}`
  - `{"v":1,"seq":N,"id":R,"t":"failed","op":…,"op_hash":H,"attempt":ID?,"error":{code,message}}`
  - `{"v":1,"seq":N,"id":R,"t":"retryable","op":…,"op_hash":H,"attempt":ID?}`

  A `new` record's `done` line (and a `failed` line from a partial rollback) also carries `"attempts":[ID…]` (sweep 6, N1, for the reserved set of §6.1a). A `finalize` record's lines also carry `"pack":bool` (sweep 6, N2, for K5).

  **Every line is self-contained** (sweep 4, B1; tightened in revision 7):
  - `op`, `op_hash` and `attempt` (when there is one) are repeated on every state, not only on `running`. So are `pack` (finalize) and `attempts` (a `new` record's `done` or partial-rollback `failed` line).
  - Compaction writes exactly one line per live record: that record's **last line, copied verbatim** except for the renumbered `seq`. No field is rebuilt or dropped, so the `attempts` lists §6.1a reserves and the `pack` flag K5 re-checks survive with everything else.
  - The lines appended at open to resolve a `running` record (K1-K5) copy `op`, `op_hash`, `attempt` and `pack` from that `running` line.
  - The `idempotency_conflict` check (§10 #4), §6.1a's reserved set, K5's retained lookup by attempt ID and K5's body check therefore work the same before and after a compaction and a reopen (U8).
  - A line without `op_hash` is a corrupt line (K6 rules).
  
  Each transition is one `write` of the whole line followed by `fdatasync`, through an `O_APPEND` descriptor held by the supervisor. The `running` line is durable before any directory is made or any child is spawned.
- **Log state: `Open(fd)` or `Broken{since, error}`** (sweep 4, N2; made a full state machine in sweep 7, Codex 4 and 5).
  - **`Broken` is in memory only.** While the log is `Broken`, a request-ID'd request that would append anything (a first run, or a re-run of a `retryable` record) is refused with `io`: "request log unavailable since …: …; restart the daemon".
  - Replays of `done`/`failed` records and `idempotency_conflict` answers are read-only, so they are still served. Requests without a `request_id` do not touch the log and are served as usual.
  - A restart reopens the log normally (K9).
- **A failed append before any side effect** (the `running` line):
  - The supervisor `ftruncate`s the file back to its length before the write and fdatasyncs it, so no torn line can end up in the middle of the file, where K6 would refuse the next start.
  - If that succeeds, the request fails with `io` and nothing was spawned or changed. The log stays `Open`, and a retry with the same ID runs as new.
  - If the truncation fails, the log goes `Broken`.
- **A failed terminal append after side effects** (`done`, `failed` or `retryable`; a write or `fdatasync` error after `new` spawned attempts, or after finalize changed the attempt) **always** makes the log `Broken` (Codex 5). Revision 7 left this undefined:
  - The line is truncated away if possible, so the file ends at the durable `running` line.
  - The in-memory record stays `running`, matching the file, so it is never replayed as done.
  - The response is `io`.
  - The effects stand until the restart, where K1-K5 resolve the record. A `new`'s attempts are discarded and the request reports `interrupted`. A retained finalize's `done` is replayed from `record.json` (K5).
  - Refusing further appends until then is what keeps "at most one `running` record" true, and stops a client from retrying into a second spawn.
- **Append cost** (estimate): 0.3-16 KB plus one `fdatasync`, about 0.05-2 ms on NVMe. Two appends per request.
- **Memory.** A `BTreeMap<id, Record>` plus a `VecDeque` of finished IDs in completion order. Results are stored inline, so a replay is byte-identical even after the attempt is destroyed.
- **Retention caps.** At most **65,536** records **and** at most **64 MiB** of live record bytes. The oldest `done`/`failed`/`retryable` records are evicted first. The `running` record is never evicted (at most one can exist, because requests are serial). At about 1 KB per record, the caps keep about 65,000 requests, which is more than 18 hours at 1 request per second. An evicted ID that is retried runs again; this is documented as the bounded retry window.
- **Compaction.** When the log is more than 2× the live bytes **and** more than 8 MiB, it rewrites the live set (finished records only) through `NamedTempFile` + `sync_all` + rename + directory fsync, and resets `seq`.
  - A compaction writes the live set `L` (at most 64 MiB). Each compaction needs at least `max(L, 8 MiB − L)` bytes of new appends since the last one. So the bytes compaction writes never exceed the bytes appended: at most about 2× write amplification overall.
  - Example: with a 1 MiB live set, compaction writes 1 MiB about every 7 MiB of appends.
  - It runs between requests, never while a `running` record exists.
  - **Publishing the compacted file** (sweep 3, B2; reordered in sweep 7, Codex 4). Once the rename succeeds, the held `O_APPEND` descriptor refers to the old, now unlinked inode. So the steps are:
    1. Write and `sync_all` the temp file, and rename it over `requests.jsonl`.
    2. **Immediately** set the log `Broken` and drop the old descriptor, before anything else can fail. Revision 7 did this only after the directory fsync, so a failed fsync would have left later appends going to the unlinked file.
    3. fsync the state directory.
    4. Reopen `requests.jsonl` through the same checked open used at start: `O_NOFOLLOW|O_APPEND|O_CLOEXEC`, then owner, regular-file type, mode `0600` and `nlink == 1` checked on the new descriptor, and the reopened `(dev, ino)` must be the temp file's.
    5. Only then set the log `Open` with the new descriptor.
    
    Any failure in steps 3-4 leaves it `Broken` until a restart. After a power loss, either the old or the compacted file is at the name, and both hold every live record, because nothing was appended in between.
- **Size of a stored record, preflighted before any side effect** (sweep 7, Codex 7).
  - **The problem.** A `new` result repeats the request's lowers in every attempt. `--max-attempts` allows 4,096 attempts (`mod.rs:43`), and a request may carry 32 lowers of about 1 KiB each. That is a 32,752-byte request with a 134,598,657-byte result, above both the 64 MiB response limit (`protocol.rs:9`) and the whole live-record cap.
  - **The fix.** One stored record may hold at most **4 MiB**. Before creating any directory or spawning anything, `new_attempts` computes the exact serialized size of its result: one `AttemptV2` with a maximal ID and the final paths, times `count`, plus separators.
    - With a `request_id`: a result over 4 MiB, or a record line over 4 MiB plus its fixed fields, is refused.
    - Without one: only the response limit applies, so a result over `MAX_RESPONSE` minus the envelope is refused.
    - The refusal is `capacity` ("result would be N bytes; lower count or the number or length of lowers"), with zero spawns (U38).
  - **Headroom.** 4 MiB holds over 100 attempts that each carry 32 one-kilobyte lowers, and thousands with typical lowers. The 64 MiB live cap still holds at least 16 such records.
- **Open.**
  - Parse every line; a torn final line is truncated (K6).
  - Any `running` record is resolved: for a finalize whose attempt is in `retained/`, append `done` with `record.report` (K5, including its damaged-layer and body-check cases). Otherwise append `failed` with code `interrupted` (K1-K3). Either line copies `op`, `op_hash`, `attempt` and `pack` from the `running` line.
  - An unknown `v` or a corrupt line that is not last refuses the start, naming the file.

### #6: `writers_active` leaves the attempt mounted, and the retry is idempotent under the same `request_id`

- `writers_active` is decided at finalize step 4 (unmount) **only**. At that point nothing has been written: no fsck, no seal, the mount and child untouched, status still `ready`. The request log gets `retryable` for that ID, which keeps its `op_hash`.
- **The same `request_id` with the same body re-executes.** Step 1 sees `ready` and step 4 tries the survivor test (§6.4.1) and the unmount again. After a `Detached` outcome, step 1 sees `detaching` and step 4 only waits for the child again. If the writers are gone, it runs to `done`. A third call with the same ID returns the stored `done` result byte for byte, without touching the attempt.
- **How often to retry** (sweep 8, Claude N11). Each retry repeats the survivor test over every process's `mountinfo` and the holder scan over every process's descriptors (§6.4.1), inside the single serve loop, so a tight retry loop would delay every other request. `docs/sandbox.md` tells callers to wait at least 1 s after `writers_active` before retrying, doubling the wait up to 30 s, and the error message says "retry after at least 1 s". The Python client does not retry by itself. Step 9 measures one scan on a host with about 1,000 processes, and the documented interval is raised if a scan costs more than a few percent of it. The daemon does not enforce the interval.
- **The same `request_id` with a different body** (for example `pack:true`) returns `idempotency_conflict`, even while the record is `retryable`.
- The other failures that leave nothing changed also become `retryable`: `in_use`, `lower_changed`, `timeout`/`mount_failed` with a complete rollback, `capacity`, `not_found`, and gate refusals. They differ in what a retry finds:
  - After an `in_use` at step 5 the attempt is `stopped` (unmounted, fsck may have repaired) or `sealed`, and a retry resumes at step 5.
  - After a failure at step 6, 7 or 8 the attempt is `sealed`, and the retry re-enters `finalize_top` through its sealed branch: `fsck(top, false)` instead of the refused `--repair` (`overlay_fsck.rs:164-170`), then `finish_if_sealed` returns the recorded digest (`overlay_seal.rs:349-356`), then the read-only hash. The bundle is rebuilt from scratch and `record.json` is written atomically.
  - Both paths are idempotent and both are tested (U19, U30).
  - Only a `new` whose rollback failed (some attempts kept; `daemon.rs:717-722`) and `interrupted` are `failed`, and those are replayed as errors.
- Finalize on an attempt that is already `finalized`/`retained`, under a new or missing `request_id`, returns its stored report only if the body agrees with how it was finalized. `pack:true` on an attempt finalized without a bundle is `invalid_request` ("already finalized without a bundle; run `ratarmount overlay pack` on its layer"), so a caller is never told it succeeded without the bundle it asked for (sweep 3, N10). `pack:false` on a packed attempt returns the stored report, bundle included.
- **Record transitions on a retry** (sweep 3, N9). The record starts as `retryable` (with `op_hash` H). A retry with the same ID and hash H appends a new `running` line (same `op` and `attempt`) before any side effect, and then `done`, `failed` or `retryable` again. At open, the **last** line for an ID decides its state. So a crash during a retry leaves `running`, which K1-K5 resolve exactly as for a first try (K5's retained lookup included). A `done` line is never followed by another line for that ID.
- Tests:
  - U18 (`regression_finalize_writers_active_retry_same_request_id`): the Fake `stop` returns `Busy` once. Assert `writers_active`, status `ready`, the mount still present and no seal row. Then the same ID succeeds, and a third call is byte-identical. Then the same ID with `pack:true` returns `idempotency_conflict`.
  - U19 (`regression_finalize_in_use_after_stop_resumes`).
  - FUSE F6 (§11).

### #7: a golden test proves v1 stays byte-for-byte strict

- **Fixture:** `ratarmount/src/sandbox/testdata/v1-golden.jsonl`. It is generated in step 0 from the **unchanged** baseline code through `respond()` (the exact `parse → handle → from_result → to_vec + '\n'` path of `daemon.rs:934-943`), using `Supervisor<Fake>`. Each entry is `{"request": <raw line>, "response": <raw bytes>}`.
- **Deterministic attempt IDs** (sweep 3, B1). In production, IDs come from `tempfile::Builder::new().prefix("attempt-").tempdir_in(..)` (`daemon.rs:651-655`) and are random. `new` returns them in creation order, but `list` returns them in `BTreeMap` order (`daemon.rs:493-497`). So numbering by first appearance would make a `new count 2` followed by `list` flip about half the time.
  - **Choice:** a `#[cfg(test)]` ID source on `Supervisor`. When set, `new_attempts` makes the attempt directory under the name it supplies (`attempt-000001`, `attempt-000002`, …, created `0700` exclusively in `attempts/`) instead of calling `tempdir_in`.
  - Sequential names sort in creation order, so both `new` and `list` bytes are stable.
  - Production code is unchanged: the seam is compiled only in tests.
  - Step 0 adds the seam (a test-only change) **before** generating the fixture, so the fixture still records the baseline's behaviour.
- **Normalization** is then limited to replacing the state root with `$STATE`. Every other byte is compared exactly, error messages and IDs included.
- **Coverage:**
  - `create_base`: success, `already_exists`, bad option key.
  - `new`: count 2, count 0 or over capacity (`capacity`), unknown base, an unknown field `lowers` (`invalid_request` with serde's exact message).
  - `list`: all, by base, unknown base.
  - `diff` and `stats` over a **real temporary directory base** registered under its own path placeholder `$BASE`, so the golden pins `diff`'s success path, not the factory's `base_open_failed` text for `/fake.tar` (sweep 6, N3). The base and the patch content are fixed bytes.
  - `destroy`: by id, by base, both selectors, neither selector, unknown id.
  - `shutdown`.
  - Envelope errors: `{}`, `{"version":3,…}`, `{"version":"1",…}`, malformed JSON, an over-1-MiB line. These stay byte-compared like everything else, which is why §4.1 keeps the `"version must be 1"` text unchanged. No entry is ever excluded or compared only by `code`.
- **Tests:**
  - U1 (`regression_v1_golden_transcript_byte_identical`) replays every request against a fresh supervisor and compares the bytes.
  - U2 (`regression_v1_request_reserialization_identical`) applies only to lines produced by the serializer itself (`serde_json::to_vec(&Request{version:1, …})`, which writes every `New` field including defaults). Parsing such a line and serializing it again reproduces it byte for byte. Hand-written golden lines that omit defaults, or that use the Python client's key order, are compared by parsed value and by their **response** bytes, never by re-serialization.
  - U3 (`regression_cli_v1_request_bytes_unchanged`) checks that the CLI's request bytes for every v1 subcommand without v2 flags are identical.
  - P1 (Python, `test_regression_v1_request_bytes_unchanged`) does the same for the Python client's raw request lines, with no v2 arguments.
  - U4 (`regression_v1_golden_with_retained_state`) replays the same transcript against a supervisor that already holds one retained attempt and one finalized, non-retained attempt, and the v1 bytes still match. The two pre-seeded attempts are named **outside** the deterministic sequence (`seed-retained`, `seed-finalized`, set directly instead of drawn from the ID source), and the ID source is reset to `attempt-000001` before the replay. The golden IDs therefore do not shift (sweep 4, N7).
    - The retained attempt does not count toward `--max-attempts` (§10, #1).
    - The finalized one holds a slot (§4.5), so U4 opens that supervisor with `max_attempts` = the golden value + 1. The golden `capacity` lines then fall at the same request.
    - The finalized attempt sits under a base name the transcript never uses, so `destroy {base}` lines are unaffected. The transcript's state-root placeholder covers the extra directories.
- The fixture is regenerated only on purpose, through an `#[ignore]`d generator test, and the commit must say why.
- **Changes to existing tests** (sweep 3, N7).
  - **Behaviour:** the only behaviour change asserted by an existing test is the version-2 line in `regression_protocol_rejects_unknown_fields_and_versions`, which becomes version 3.
  - **Signatures:** these change too, and the plan keeps the edits mechanical:
    - `Supervisor::handle` takes `impl Into<Op>` with `From<Operation> for Op`, so every `supervisor.handle(Operation::…)` call in `tests.rs` compiles unchanged.
    - The `Fake`'s `spawn` takes `SpawnSpec`, and it gains `stop` (and, in tests only, the `classify` seam of §6.3).
    - `supervisor.attempts[..]` keeps indexing a map of the wire `Attempt`. The extra fields live in a parallel `specs` map, so those uses are unchanged.
  - The source doc's "every existing v1 test passes unchanged" is accurate for assertions, not for these signatures.

---

## 11. Test plan

Unit tests live in `ratarmount/src/sandbox/tests.rs` and use the Fake `Mounter`. Wherever finalize needs a database, they use a real overlay built with `crate::base_identity::fixtures::overlay_over_with`, given the base directory's path (= `WriteOverlay::open` over a token that records the base place; never `new_overlay`, which records none, and never a re-added `WriteOverlay::new`). In the finalize tests, the base is a real directory classified by a test `classify` closure (§6.3) calling `fixtures::classify`. Tests marked FUSE live in `ratarmount/tests/sandbox.rs` and use the `prepared_fuse_check(required, …)` pattern (`tests/sandbox.rs:334-362`). A skip there is a failure **only when `RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE=1` is set** (`tests/sandbox.rs:365-366`); no workflow sets it today, and step 9 adds it to the `check` job.

Tests marked NS (F6b, F6c) need passwordless `sudo` and systemd, and live in their own integration-test binary, `ratarmount/tests/sandbox_namespaces.rs` (`#![cfg(target_os = "linux")]`, like `tests/sandbox.rs`):
- **Why a separate binary.** A private namespace pins every mount that exists when it is created. `cargo test` runs test threads of one binary in parallel but test binaries one after another, so a separate binary keeps the other FUSE tests' mounts out of these namespaces. Inside it the cases are serialized by a static mutex.
- **Opt-in.** The binary runs only with `RATARMOUNT_TEST_PRIVILEGED=1` (step 9 sets it in CI). With it set, a missing prerequisite fails; without it, the binary prints one `skip:` line and never calls `sudo`.
- **Cleanup.** Transient units get `--collect -p RuntimeMaxSec=300` and are stopped in a `Drop` guard. Persistent namespaces and their private bind directories under `/run` are unmounted and removed in a `Drop` guard.

**Tests that reopen a supervisor in-process take `ratarmount_index::test_process::exclusive()`** (sweep 7, Claude N4). Another test's child can hold a copy of `daemon.lock` between its fork and its `exec`, so a test that drops a `Supervisor` and opens another on the same state directory would fail at random with `in_use`. The existing restart test takes `exclusive()` for exactly this reason (`tests.rs:311-316`, #242).
- That covers U8, U11, U21, U23, U24, U29, U35 and U45, and any other test that reopens.
- The SIGKILL re-exec tests (U13, U14, U20, U22b, U34) hold `spawning()` while their child lives, and reopen in the parent only after the child is dead.

Every test name starts with `regression_` and has a `Regression:` doc line.

| ID | Test | Covers |
| --- | --- | --- |
| U1-U4, P1 | v1 golden (§10 #7) | Keystone #7 |
| U5, U6 | hashing (§10 #4) | Keystone #4 |
| U7 | `regression_request_log_torn_tail_and_corrupt_middle` | K6 |
| U8 | `regression_request_log_compaction_and_eviction_caps`:<br>**Setup:** a `requests.jsonl` of 70,000 records is written directly by the test (not through 70,000 fsync'd appends), plus a `#[cfg(test)]` no-sync switch for the appends the test does make (sweep 3, N11).<br>**Caps:** both caps are enforced.<br>**Replay:** replay after compaction is identical.<br>**`running`:** the `running` record is never evicted.<br>**Survives reopen** (sweep 3, B2): a record appended **after** a compaction is still there when the supervisor is reopened, and the descriptor in use after compaction has the inode now at `requests.jsonl`.<br>**Conflict after compaction** (sweep 4, B1): compact, reopen, then send a compacted `done` ID and a compacted `retryable` ID, each with a **different** body: both give `idempotency_conflict`. The same IDs with their original bodies replay (`done`) or re-run (`retryable`). A `running` finalize resolved at reopen still finds its attempt ID.<br>**Short append** (sweep 4, N2): a write cut short by an injected error leaves no torn line, and the next start succeeds.<br>**Verbatim compaction** (revision 7, re-verifying sweep 4 B1):<br>- every compacted line equals the record's last line byte for byte apart from `seq`, so `op`, `op_hash`, `attempt`, `attempts` and `pack` all survive;<br>- after compact and reopen, a compacted `done` `new` record's `attempts` are still in §6.1a's reserved set;<br>- a `running` finalize line appended after a compaction, then resolved at open, still gets K5's body check (`pack:true` against a report without a bundle resolves to `failed invalid_request`);<br>- the resolving lines appended at open copy `op`, `op_hash`, `attempt` and `pack` from the `running` line.<br>**Failure injection** (sweep 7, Codex 4 and 5; `#[cfg(test)]` seams):<br>- the directory fsync **after** the compaction rename fails: the log is `Broken` before that fsync, and the old descriptor has already been dropped, so no later line can land in the unlinked file;<br>- the checked reopen fails: the log stays `Broken`;<br>- a `running` write fails before any side effect: the file is truncated, the log stays `Open`, and a retry with the same ID runs as new;<br>- the `done` write, and separately its `fdatasync`, fails after a `new` spawned its attempts: the log is `Broken`, the file ends at the `running` line, and the next request-ID'd `new` is refused with `io` and spawns nothing. A replay of an older `done` record is still served. After a reopen, the record resolves `interrupted` and the attempts are gone;<br>- the same after a retained finalize renamed its attempt: after a reopen, K5 replays `done` from `record.json`. | Keystone #5 |
| U9 | `regression_request_id_same_body_one_spawn`: the same ID and body twice give one spawn and identical results; a different `count` gives `idempotency_conflict`, also after completion | source test 2 |
| U10 | `regression_sandbox_run_report_identical_after_finalize_top`: byte-identical, with `wall_time_s` passed as a fixed value (§6.3); plus the existing `run.rs` report tests. Its repair case is nonempty host content at a tombstoned path, which repair unlinks: usage after repair is smaller, and the report keeps the before-repair `bytes_written` (§6.3; sweep 8, Codex 5) | source test 10 |
| U11, U12 | capacity (§10 #1) | Keystone #1 |
| U13, U14 | crash seams K3 and K5 (§10 #2) | Keystone #2 |
| U15-U17, U47 | lower re-check and validation, and the post-`Ready` check of the child's records (§10 #3) | Keystone #3, source test 5 |
| U18, U19 | finalize retry (§10 #6) | Keystone #6 |
| U20 | `regression_restart_running_new_reports_interrupted` (K1 via SIGKILL re-exec) | source test 3 |
| U21 | `regression_destroy_shutdown_skip_retained_forget_removes`: `destroy --base`, `shutdown` and serve's final `destroy_all` keep retained attempts; `forget` removes one; forget refuses with `in_use` while a live attempt uses it | source test 8 |
| U22 | `regression_reconcile_removes_sealed_attempt_tree` | §6.7 |
| U23 | `regression_retained_damaged_listed_never_deleted`: an unsealed overlay, a digest mismatch and a missing `record.json` all show up as `retained_damaged` and survive a restart | §6.6 |
| U24 | `regression_retain_tmpfs_refused`, `regression_retained_dev_mismatch_refuses_start` | §6.6, §5 |
| U25 | `regression_layered_spawn_argv`: the order of `--lower`, the journal flags, no `--allow-unsealed-lower`, and the argv parses (extends `process.rs:395`). Also: a v1 `new`'s `mount_args` output (an empty `SpawnSpec` apart from quota and readonly) is byte-identical to a fixture captured in step 0 from the unchanged `mount_args`, because the golden goes through the Fake and does not pin child argv (sweep 6, N3) | §6.1 |
| U26 | `regression_diff_composes_attempt_lowers`, plus `diff` and `stats` on a `retained` attempt (offline, composed over its recorded lowers) and `invalid_request` on a `retained_damaged` one | §6.8, sweep 5 N6 |
| U27 | `regression_v2_error_envelopes_echo_version`, including a `response_too_large` reply to a v2 `diff`, which carries `version: 2` | §4.4, sweep 5 N2 |
| U35 | `regression_attempt_id_never_reuses_retained_or_logged` (§6.1a). The test ID source is forced to return, in turn:<br>- a retained ID;<br>- a destroyed attempt's ID that a `retryable` finalize record still names;<br>- an ID returned by a `done` `new` record;<br>- each of these again after a compaction and a reopen.<br>`new_attempts` redraws every time. Retrying the old `request_id` returns `not_found`, and the new attempt is untouched. Separately, a `retained/ID` directory created outside the supervisor before the commit rename makes the no-replace rename (`renameat_with(…, RenameFlags::NOREPLACE)`) fail with EEXIST: nothing is replaced, the status stays `sealed`, and the retry succeeds once the directory is removed (revision 7). | sweep 5 B1, revision 7 |
| U37 | `regression_survivor_test_classifies_by_parent_and_place` (in `process.rs`): a pure classifier test on `mountinfo` text, with no `/proc` and no FUSE. It covers §6.4.1's table, with the attempt under a `shared:185` `/tmp` (P = 185) unless a case says otherwise. Each case asserts its exact class and `Busy` or not.<br>**Ignored (propagation copies):**<br>- a systemd-resolved-style namespace, with the copy's parent `shared:189 master:185` under a PrivateTmp overmount and the copy `shared:K master:N` (lines taken from `/proc/508/mountinfo`);<br>- a ProtectHome namespace with a btrfs `/@home` root field (place formula with non-`/` roots);<br>- a peer copy (`unshare --propagation unchanged`);<br>- a slave copy;<br>- a nested slave whose `master:` names a visible intermediate group;<br>- a supervisor-namespace peer bind of the state directory at the corresponding place.<br>**Survivors:**<br>- a Docker container: a private root with no fields, as in `/proc/3859090/mountinfo`, and the attempt bound at `/repo` with root `/repo`;<br>- a private copy;<br>- an independent `shared:K` parent with no master;<br>- a parent whose master chain ends at a visible group with no master that is not P (a host overlay rootfs group);<br>- a `mount --bind` of the attempt elsewhere in the supervisor's own namespace, tagged `shared:N`, which sweep 6's rule wrongly ignored;<br>- a copy with another root;<br>- every copy when PA is private.<br>**Undecided:** a chain through a group with no visible member; a missing parent line; an escaped mount point (`\040`).<br>**Sweep 6's false positive:** a chained-slave namespace (snap per-user style) whose copy carries `master:<intermediate>`; it must be ignored.<br>**Real fixtures:** the step-0d captures (CI runner, Arch desktop; §9 step 0d) are replayed with their expected classes. | sweep 6 B1, revision 7 |
| U36 | `regression_finalize_crashed_attempt`: a `crashed` attempt with no recorded child finalizes without (a) or (c). A survivor reported by the Fake does **not** block it, because a dead FUSE server cannot be written through. If the Fake's (b) reports the host mount busy, the result is `writers_active` and the status stays `crashed`. A `crashed` attempt whose child is still recorded (a `poll` error) takes the normal (a)/(b)/(c) path. | sweep 5 N1, revised in revision 7 |
| U38 | `regression_new_result_size_preflight`, through the Fake. A v2 `new` whose result would exceed the 4 MiB stored-record cap (with a `request_id`), or the response limit (without one), is refused with `capacity` and makes **zero** spawns and no directories. The case is Codex's: `count` 4,096 with 32 lowers of 1,018 bytes, a 32,752-byte request and a 134,598,657-byte result. A request just under each limit succeeds. | sweep 7, Codex 7 |
| U39 | `regression_retain_durability_barrier_order`. A `#[cfg(test)]` seam records the calls of a retained finalize. The order is the barrier on `attempts/ID`, then `record.json` (`sync_all` and the parent fsync), then the no-replace rename, then the fsyncs of `retained/` and `attempts/`, then the `done` append. With the barrier forced to fail, the result is `io`, the status stays `sealed`, nothing is renamed and the request is `retryable`; the retry succeeds. First creation of `retained/` and `requests.jsonl` fsyncs the state directory. | sweep 7, Claude B1, Codex 6 |
| U40 | `regression_finalize_keeps_fetched_base_alive_through_pack`. A test `OpenBase` returns a path-backed source that reopens its file on every read, as CPIO's does, and a keep-alive that deletes that file when dropped, as `RemoteLocal::Fetched` does. Finalize with `pack` succeeds, and the file is deleted only after the report is built. Revision 7's shape, which returned only the view, fails with ENOENT in `finalize_pack`. | sweep 7, Codex 1 |
| U41 | `regression_supervisor_lower_reads_never_recover` (fixture corrected in sweep 8, Claude N2). After `new`, the operator **unseals** the lower (allowed by §10 #3's stated limit), and the lower's database gets a hot `-journal`: the test copies the database and its `-journal` while a write transaction is open, the effect `regression_hot_journal_unrecoverable` produces with a real SIGKILL. The lower must be unsealed and writable: on a **sealed** layer the recovering read refuses too and writes nothing (`recover_hot_journal`, `overlay_meta.rs:147-156`), so revision 7's sealed fixture passed with the regression present. `diff` returns `diff_failed` and finalize returns `lower_changed`, each naming the lower. Afterwards the lower's database and `-journal` are byte-identical: nothing was rolled back. A control case runs `OverlayMeta::read` on a copy of the same fixture and asserts that it **does** roll the journal back, which proves the fixture reaches the recovering path. | sweep 7, Codex 3; sweep 8 |
| U42 | `regression_removal_and_finalize_with_mode_000_directory`. An attempt leaves a directory `chmod 000` (applied to the host directory). `destroy`, `reconcile` after a re-exec, and `forget` of a retained attempt still remove the whole tree, which `host_stat::chmod_dir_at` restores to `u+rwx` before each open (§6.7). Finalize of such an attempt returns `io`, naming the directory, with status `stopped`. A `forget` killed after its rename back leaves an ordinary `attempts/ID`, which the next `reconcile` deletes.<br>**Plus a `host_stat` unit test in `ratarmount-compositing`** (sweep 8, Claude N3): `chmod_dir_at` restores a mode-000 directory, and refuses a name that was swapped for a symlink, a file or another directory after the walk's `statat`, changing nothing. On Linux it never calls a by-name `chmodat(.., SYMLINK_NOFOLLOW)`, which returns `EOPNOTSUPP` there. | sweep 7, Claude N6, N9; sweep 8 |
| U43 | `regression_create_base_caches_archive_digest`, in `ratarmount/tests/sandbox.rs` with the real daemon. It needs no FUSE, because preparation is `--no-mount`. It is an integration test because the caching lives in `ProcessMounter::prepare`, which the Fake replaces. After `create_base` of a local archive, the prepared index (the `sidecar_candidate` under `indexes/<name>`, §6.6) holds the archive's strong digest, read through `ratarmount_index` (a dev-dependency), and there is no `-wal` or `-journal` beside it.<br>**A second name** (corrected in sweep 8, Claude B1, Codex 3): registering the same archive under another name builds that name's own index under `indexes/<other>`, and that index holds the digest too. Each name hashes the archive once; there is no reuse across names. Revision 7's "does not hash it again" was false.<br>The real worker's `present` state is asserted by F4, on the live mount right after `new`. | sweep 7, Claude N7; sweep 8 |
| U44 | `regression_stop_decision_table` (in `process.rs`, pure). It covers step (c)'s decision for every combination of: `fusectl` connection present / gone / not mounted, and child exited / running past `exit_wait`. The outcomes are `Detached` at once, wait-then-`Stopped`, `timeout` with status `detaching`, and revision 7's child-only fallback. A non-zero child exit with a journal sets `journal_summary.complete: false`.<br>**Exit status kept wherever the child is reaped** (sweep 8, Codex 4, Claude N7), through the Fake: a worker that exited and was reaped by `poll` before finalize (status `crashed`) still reports its status from the `exited` map as `mount_exit`; a status reaped by `cleanup` or by `stop`'s own wait is reported the same way; with no recorded status, the report has `mount_exit: null` and `journal_summary.complete: false`. Only a known exit 0 gives `complete: true`. | sweep 7, Claude N8; sweep 8 |
| U45 | `regression_forget_resumes_after_fsync_or_delete_failure` (sweep 8, Codex 2). `#[cfg(test)]` seams fail, in turn, the fsync of `retained/`, the fsync of `attempts/`, and the deletion partway through the tree. Each time:<br>- `forget` returns `io`; the tree is at `attempts/ID`; the entry is `forgetting`, never `retained` (revision 7 kept `retained` naming a `retained/ID` that no longer existed);<br>- v2 `list` shows `forgetting` and v1 `list` hides it; `diff`, `stats`, finalize, `destroy {id}` and use as a lower return `invalid_request`; `destroy {base}` and `shutdown` leave it; a `new` with `retain` counts it against `--max-retained`;<br>- once the seam is cleared, the same `forget` succeeds **without a restart**, the tree is gone and a further `forget` returns `not_found`.<br>A last case reopens the supervisor while the entry is `forgetting`: `reconcile` deletes `attempts/ID` and the ID is unknown. A failed rename back (injected) returns `io` and leaves the entry `retained` and its tree untouched. | sweep 8, Codex 2 |
| U46 | `regression_create_base_digest_caching_skipped_not_failed` (in `process.rs`; sweep 8, Claude N8, Codex 6). It drives the caching helper that `ProcessMounter::prepare` calls, over a prepared index with a `files` table. The production `check` combines the extra `--timeout` window with `term_requested()`; the test passes its own `check`, because `term_requested()` is process-global. Cases:<br>- the digest lock is held by the test (a `flock` on the index's digest lock file through another open file description) and the window is 200 ms: the helper returns `Skipped` within about the window;<br>- `check` fails partway through the hash (the stand-in for SIGTERM): `Skipped`;<br>- the archive cannot be read: `Skipped`.<br>Each time no digest row is written, no `-wal` or `-journal` is left, and the helper's caller maps `Skipped` to a warning, not to a `create_base` error. A run with the lock free stores the digest. | sweep 8 |
| P6 | Python (sweep 7, Claude N10, Codex 9): after a retained `finalize`, the `Attempt`'s `path`/`overlay_dir` name `retained/ID`, taken from the report's `attempt` object and equal to a v2 `list` of the same ID (sweep 8, Claude N9). `Attempt.__exit__`, `Attempt.destroy()` and the client context's `close()` send **no** `destroy` for it. `forget()` removes it. `list(all=True)` with a `retained_damaged` item carrying only `{id}` returns an `Attempt` instead of raising `KeyError`. | §6.10 |
| U28 | `regression_seal_operation_acquire_until_times_out` (in `ratarmount-compositing`) | §6.4 |
| U29 | `regression_supervise_leaves_stopped_sealed_finalized_alone`: finalize without retain, then send any other request and wait more than one supervise tick. The status is still `finalized`, v1 `list` still hides it, and a second finalize returns the stored report. The same check is made for an attempt left `stopped` (injected `in_use`) and one left `sealed` (injected pack failure). A `starting` leftover from a failed rollback still appears in v1 `list`. | sweep 1 B1 |
| U30 | `regression_finalize_retry_after_seal_reaches_done`: (a) inject a `finalize_pack` failure after the seal, (b) inject a commit-rename failure, and (c) let the rename succeed but fail the `fsync(retained/)` (sweep 4, N1), all through `#[cfg(test)]` seams. In (c), the attempt is listed `retained` at once and the retry does no seal or rename work. Each time, retry with the same `request_id`. The retry goes through `fsck(top, false)` and `finish_if_sealed`, ends in `done` with the same `layer_digest` and `patch_hash`, reports the first try's `fsck_result` and `bytes_written` (on a top whose first fsck repaired something, so a retry's own `ok` would differ; sweep 8, Claude N6) and its `base_hashed_by_finalize` (in a variant whose base is a small local archive with no cached digest, so the top records `pending`: the first try reports `true`, and a retry's own reading would give `false`), leaves exactly one bundle, and a third call is byte-identical. A retry never calls `fsck(top, true)` on a sealed top (asserted through a test counter). | sweep 1 B2 |
| U22b | `regression_reconcile_and_destroy_remove_sealed_ram_overlay`: finalize a tmpfs attempt without retain, so `ram/ID` is sealed. `destroy` removes it. A second sealed `ram/ID` followed by a SIGKILL re-exec and reopen: `Supervisor::open` succeeds and the RAM root is empty (skip with `skip:` only where no tmpfs exists, as `regression_tmpfs_overlay_path_and_restart_cleanup` does) | sweep 2 B1 |
| U32 | `regression_finalize_stop_outcomes`: the Fake `stop` returns `Busy`, which gives `writers_active` with status `ready` and the mount kept; then `Detached`, which gives `writers_active` with status `detaching`, no seal, and **no kill** (the Fake records any kill request and the test asserts none); then a retry with the same `request_id` once the Fake reports the child exited, which reaches `done` | sweep 2 B2 |
| U33 | `regression_new_refuses_bad_journal_glob_and_stack_mismatch`:<br>**Refused** (`invalid_request` before any `tempdir_in`): a bad `journal.exclude` glob, and a retained lower whose `record.json` lowers do not match the requested lowers below it.<br>**Accepted** (sweep 3, B3): a retained layer finalized over a bundle lower, requested again over the same bundle path. It is accepted even though its top rows name the cache directory.<br>**External sealed layer over a bundle position:** `new` accepts it before the mount (only the count can be checked then), and after `Ready` the child's resolved digest at that position must equal the external layer's recorded one. The mismatch case is in U47 (sweep 8, Codex 7). | sweep 2 N7, N8; sweep 3 B3 |
| P5 | Python and CLI: a version-1 `unsupported_version` envelope answering a v2 request raises or prints the structured error, not a protocol error | sweep 2 N11 |
| U34 | `regression_k5_damaged_retained_resolves_failed`: SIGKILL re-exec after the rename. Before the reopen, delete `retained/ID/record.json`. The `running` finalize resolves to `failed interrupted`, naming the damaged ID, and the layer is listed `retained_damaged` and not deleted. | sweep 4 N8 |
| U31 | `regression_forget_refuses_retained_dependent`: retained B over `retained/A/overlay`; `forget A` returns `in_use`; `forget B` then `forget A` both succeed | sweep 1 N6 |
| P2-P4 | Python: v2 `new` and `finalize` bytes, response version check, the context manager skipping retained attempts | §6.10 |
| F4 | FUSE: `snapshot + sealed prepared layer` shows the prepared files; edit, finalize; `patch_hash` covers only the top and equals a manual `ratarmount diff --hash --json`.<br>**The base digest is cached, not hashed by finalize** (sweep 8, Claude N1): right after `new`, before anything can seal, the live mount root's `user.ratarmount.base_digest_state` xattr reads `present` (served for every `-w` mount, `ratarmount-fuse/src/lib.rs:916-922`, `:2637-2639`), and the finalize report has `base_hashed_by_finalize: false`. Revision 7 checked only the report's `base_digest_state`, which is `present` after seal either way. | source test 4 |
| F6 | FUSE: a process holding a file open makes finalize return `writers_active`, with nothing sealed and status `ready`; after the process exits, the same `request_id` succeeds | source test 6, Keystone #6 |
| F6b | NS, `regression_finalize_private_namespace_copies` (rewritten in revision 7). Survivors in another mount namespace. The test daemon keeps `Daemon::start`'s `--timeout 30` (`tests/sandbox.rs:31`; corrected in sweep 7, Claude N11, where revision 7 said 10). `--timeout` also bounds mount readiness (`daemon.rs:641`), so it is not shortened; `exit_wait` is `min(30, 10)` = 10 s. With `fusectl` present, the persistent-namespace case below is `Detached` about 500 ms after (b), without waiting that long (§6.4.1).<br>**Visible private copy:**<br>- After `new`, the helper runs `sudo -n unshare --mount --propagation private -- setpriv --reuid=$UID --regid=$GID --clear-groups -- sh -c 'exec 3< "$1"; : > "$2"; exec sleep 300' sh "$MNT/base.txt" "$READY"`.<br>- `setpriv` drops to the test user **after** the namespace is made. FUSE refuses root without `allow_other`, and supervisor bases default to no `allow_other`. Revision 6's root holder would fail its own `open`, exit, take its copy with it, and turn the expected `writers_active` into `done` (red CI).<br>- First finalize: `writers_active` from (a). The host mount is still present, the status is `ready`, and no seal row exists.<br>- After the test kills the holder (same uid): the same `request_id` reaches `done`.<br>**Invisible survivor, backstop (c):**<br>- Setup: a process-free persistent private namespace. `D=$(sudo -n mktemp -d /run/rrs-ns.XXXXXX)`; `sudo -n mount --bind D D`; `sudo -n mount --make-private D`; **`sudo -n touch D/mnt`**, because `unshare` bind-mounts onto an existing file and does not create it (`unshare(1)`, EXAMPLES; sweep 7, Codex 8); then `sudo -n unshare --mount=D/mnt --propagation private true`. Every command's exit status is checked, and a failure fails the test with that command named.<br>- (a) cannot see it (no process), (b) succeeds, `/sys/fs/fuse/connections/<minor>` stays, and finalize returns `writers_active` with status `detaching`. The child stays alive; the test asserts that no SIGKILL was sent and that the child still runs.<br>- `sudo -n umount D/mnt`: the same `request_id` reaches `done`.<br>- Cleanup in a `Drop` guard: `umount D/mnt` if it is still mounted, `umount D`, `rmdir D`.<br>- This replaces revision 6's "`#[cfg(test)]` seam" variant. That seam cannot reach the binary an integration test drives (`CARGO_BIN_EXE_ratarmount` is built without `cfg(test)`), and `ratarmount` has no `test-hooks` feature (`ratarmount/Cargo.toml:13-34`). The repository's integration-test seams live in dependency crates behind `test-hooks` (`:91`, `:98`).<br>**Opt-in Docker variant** (`RATARMOUNT_TEST_DOCKER=1`, the pattern of `regression_run_real_docker_opt_in`; not set in CI): `docker run -v "$MNT/repo":/repo`, the recipe's form. Result: a survivor, `writers_active` from (a). dockerd runs as root, so this variant's base is registered with `allow_other: true`, as the recipe's is (`swe-bench-sandboxes.md:68`), and it needs `user_allow_other`. Without that, it prints `skip:` (sweep 7, Claude N11). | sweep 2 B2, sweep 6 B2, Keystone #6 |
| F6c | NS, `regression_finalize_ignores_systemd_service_namespaces` (revision 7; sweep 6 B1's regression test on a real systemd host).<br>**Before `new`:** start transient unit U1 with `sudo -n systemd-run --unit=rrs-ns-$PID-1 --collect -p RuntimeMaxSec=300 -p PrivateMounts=yes -p PrivateTmp=yes sleep 300`. The attempt mount then propagates into U1's slave copy of the state directory's filesystem, beneath U1's PrivateTmp overmount. That is kernel propagation, the stock services' situation.<br>**After `new`:** start U2 with `-p PrivateMounts=yes` only. Its namespace is cloned with the attempt already mounted. U2 deliberately has no `PrivateTmp`: whether a clone keeps a copy beneath a PrivateTmp set up afterwards depends on systemd's namespace code, not on the kernel rule under test.<br>**Check the copies independently** of the supervisor's code, by reading `/proc/<MainPID>/mountinfo` (`systemctl show -p MainPID --value`). The test asserts that U1's and U2's namespaces each hold a copy of the attempt's `major:minor` with a `master:` field. The stock services' copies are only logged.<br>**No writer:** finalize returns `done`, not `writers_active`. Revision 6, and sweep 6's tag rule with a chain, returned `writers_active` here. Afterwards no copy of the device remains in U1's or U2's `mountinfo`, and the child exited. This observes umount propagation.<br>**Chain:** U3 (root) runs `sh -c 'unshare --mount --propagation slave sleep 300 & exec sleep 300'`. The nested copy's `master:` names U3's group, and finalize of a new attempt still returns `done`.<br>**Busy propagation copy:** U4 runs as the test user (`--uid=$UID --gid=$GID -p PrivateMounts=yes`, **no** `PrivateTmp`: `Daemon::start` keeps state under `$TMPDIR`, `tests/sandbox.rs:23`, which is `/tmp` in CI and `/var/tmp` in the before-merge commands, and PrivateTmp hides both) and runs `sh -c 'exec 3< "$1"; exec sleep 300' sh "$MNT/base.txt"`. Finalize returns `writers_active`: the host mount is still present and the status is `ready`.<br>**Proving the EBUSY came from (b)** (sweep 7, Codex 11). That outcome alone would look the same if (a) had wrongly reported a survivor, so the test shows (b) independently:<br>- before finalize, it runs `fusermount3 -u MNT` itself while U4 holds the file. That must fail with EBUSY and leave MNT mounted, which observes `propagate_mount_busy` directly;<br>- the `writers_active` message carries finalize's stage token, `stage=unmount` for (b) or `stage=survivor` for (a). It is documented as diagnostic text, not a stable API, and the test asserts `stage=unmount`.<br>After `systemctl stop U4`, the same `request_id` reaches `done`. | sweep 6 B1, revision 7 |
| F7 | FUSE: `retain`, finalize with `pack`, SIGKILL the daemon, restart: listed `retained` with the same `layer_digest`; the bundle mounts as `--lower`; the retained layer works as a supervisor lower for a new attempt (branching), also when the retained layer itself was finalized over a **bundle** lower (`lowers: [bundle, retained/ID/overlay]`; sweep 3, B3); unfinalized attempts are gone.<br>**`forget` against a grading mount** (sweep 8, Codex 8): with a grading mount `ratarmount --lower … --lower retained/ID/overlay` and a reader holding open a file that the retained layer itself wrote, `forget` returns `in_use`. The grading process holds that host file for as long as the reader keeps it open: the FUSE server keeps the reader `source.open` returned in its handle table for the life of the open (`ratarmount-fuse/src/lib.rs:1414-1441`), and a read-only layer's reader for a file it wrote is the host `File` from `open_host` (`overlay_layer.rs:548-551`). The test then closes the reader and unmounts the grading mount, as the docs require, and `forget` succeeds. An idle mount is not detected, so the test never calls `forget` while it is mounted. | source test 7 |
| F9 | FUSE: the journal is at `attempts/ID/journal.jsonl`; `ratarmount journal mark` on the attempt path works; the `journal_summary` counts match `journal summarize` | source test 9 |
| F10 | `ratarmount/tests/fuse_cow_agreement.rs` gains a case: a supervisor-finalized layer agrees on `diff --hash`, `fsck`, `seal`, `verify` and `pack`/`unpack` (the rule in `AGENTS.md` that every new overlay feature adds a case) | overlay agreement |

**Gate (every commit):**

```bash
CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo fmt --all
CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo clippy --workspace --all-targets -- -D warnings
CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test --workspace
python3 -I packaging/internal-read-clippy/test_policy.py
python3 -I packaging/internal-read-clippy/policy.py
```

**Plus, before merge:**

```bash
TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount --bin ratarmount sandbox
RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE=1 TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount --test sandbox   # FUSE host; no user_allow_other needed
RATARMOUNT_TEST_PRIVILEGED=1 TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount --test sandbox_namespaces   # F6b/F6c: systemd host, passwordless sudo (CI runs it)
TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount --test sandbox_run   # needs user_allow_other; skips without it, and CI does not enable it
TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount --test fuse_cow_agreement
TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount-compositing --lib regression_seal_operation_acquire_until
TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount-compositing --lib regression_chmod_dir_at
TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount-index --lib regression_checked_archive_digest
uv run --with pytest python -m pytest -q clients/python/tests/test_ratarmount_sandbox.py
cargo build --release -p ratarmount && ./packaging/test-no-test-hooks-in-release.sh target/release/ratarmount
./test-harness/test-cross-check-stub-cc.sh     # sandbox module is Unix-only; keep non-Linux builds compiling
```

Each Keystone fix also gets a row in `AGENTS.md`'s regression catalog, with the `cargo test` filters above: one row per fix (#1-#7), plus rows for the K-matrix, for `reconcile` of sealed trees, and for the step-4 survivor test. That last row lists `cargo test -p ratarmount --bin ratarmount regression_survivor_test` and `RATARMOUNT_TEST_PRIVILEGED=1 cargo test -p ratarmount --test sandbox_namespaces`. Sweep 7 adds rows for:
- the retained durability barrier (U39);
- the base keep-alive through pack (U40);
- non-recovering lower reads (U41);
- the request log's `Broken` state and compaction ordering (U8);
- the result-size preflight (U38);
- step (c)'s `fusectl` decision (U44).

Sweep 8 adds rows for:
- the post-`Ready` check of the child's records (U47);
- the resumable `forget` (U45);
- digest caching skipped, never failed (U46), and cached per base name (U43);
- the exit status kept wherever the child is reaped (U44);
- `chmod_dir_at` (U42's `host_stat` test, `cargo test -p ratarmount-compositing --lib regression_chmod_dir_at`).

Each row lands in the step that adds its test. U8's finalize cases land with step 6; U41's halves with steps 3 and 5; U42's `forget` case with step 6.

---

## 12. Documentation (R5 folded in, plus R1's living docs)

**`docs/sandbox.md`:**
- "Sandbox supervisor API": add a "Protocol version 2" subsection after "Protocol version 1" (`:2279-2353`). It covers:
  - the operation table for v2 `new`/`finalize`/`forget`/`list`
  - `AttemptV2`
  - the finalize report fields
  - the new error codes (§4.6)
  - the rule that the response version echoes the request's version
  - the statement that v1 is frozen and what v1 callers see once v2 state exists (§4.5)
  - a note that a v2-capable daemon still answers an unknown version with the message `"version must be 1"` (kept byte-identical for Keystone #7), so clients must go by the `unsupported_version` code, not the text (sweep 3, N11)
  - a note that a plain `ratarmount --lower …` mount does **not** check a middle lower's recorded stack. Only the supervisor's validation does (§6.2 item 5; sweep 3, N1). The R5 hidden-tests text must not suggest that a grading mount checks it.
- "Lifetime, concurrency and recovery":
  - Rewrite `:2406-2407` ("all abandoned attempts are unmounted and discarded"): unfinalized attempts are discarded, retained attempts survive, and `retained_damaged` is never auto-deleted.
  - Replace `:2415-2417` ("There is no request deduplication…") with the request-ID rules: scope, hashing, the retry window of 65,536 records / 64 MiB, `interrupted`, `writers_active` retry, and replays returning the original result rather than the current state. A replayed `new` may name attempts that a restart has since deleted; use `list`.
  - Add `--max-retained` next to `--max-attempts` (`:2369-2371`), and reword `:2370`. It says `--max-attempts` "caps total retained attempts across bases", using "retained" loosely for "kept until destroy". Next to R1's `retained` status that reads as the opposite of Keystone #1, so it becomes "caps the attempts that exist across bases, including crashed and finalized ones, until destroy; `retained` attempts do not count, `--max-retained` caps them" (sweep 8, Claude N10).
  - Add that a v1 `destroy {base}` and `shutdown` also destroy that base's v2 attempts whose finalize stopped partway (`detaching`, `stopped`, `sealed`), which v1 `list` does not show (§4.5). A later retry of that finalize returns `not_found` (sweep 8, Claude N13).
  - Add the same-filesystem requirement for `retained/`.
- "Layered overlays" (`:574`): replace "the sandbox supervisor API does not yet accept lower stacks" with the supervisor's lower rules. Add the stated limit: a lower unsealed while it is mounted changes what the attempt sees, and finalize refuses it as `lower_changed`.
- "Branching an episode" (`:1544-1560`): add the supervisor form (`finalize` with `retain`, then `new` with `lowers: [prepared, retained/ID/overlay]`).
- **R5, the "Journal" section** (`:984-1080`): add a paragraph saying the journal records what the filesystem served to **every** process in the container (the agent's `cat`, but also `make`, `perl` and the test harness). It is a hint about what the agent looked at, not a record of what the model saw. Model context comes from the harness's own tool-call log. `comm` helps separate agent tools from build tools, but only on a best-effort basis (Linux `/proc/PID/comm`, cache bounded to 1024 PIDs).
- "Python client" (`:2422-2449`): the new methods, and the version-2 rule.

**`docs/recipes/swe-bench-sandboxes.md` (R5):** a short "Hidden tests" section.
- Keep the task's new tests in a separate sealed layer. That layer is never in the agent's stack and is added above the finalized attempt only in the grading mount (cpanmine's tests layer).
- With the supervisor: `finalize` with `retain`, then grade with a plain `ratarmount --lower prepared --lower retained/ID/overlay --lower tests …`.
- `--overlay-readonly` (and `readonly_globs`, which this recipe already uses for `tests/**`, `:19`, `:101-106`) blocks edits but does not hide files, so it cannot be used to hide tests.
- The text must match cpanmine's tests-layer design (source doc §10).

**Also:**
- `CHANGELOG.md`: one entry for supervisor v2 (with the protocol-v1-frozen statement) and one for the R5 doc notes.
- `docs/tasks/beyond-parity-roadmap.md`: update the sandbox rows (`:297-298`).
- `README.md:260`: the subcommand table's supervisor row becomes `sandbox daemon\|create-base\|new\|list\|diff\|stats\|finalize\|forget\|destroy\|shutdown` (firm, sweep 8, Claude N10).
- `docs/local-ai/index.md:87-92`: the supervisor paragraph adds that an attempt can be finalized (sealed, hashed, optionally packed) and retained across restarts, and that attempts can stack sealed lowers, linking to `docs/sandbox.md` (sweep 8, Claude N10).
- `docs/getting-started.md`: the command tour (`:55`, `:176`) gains `sandbox finalize` and `sandbox forget` (`AGENTS.md` lists it for new user-visible commands).
- `docs/sandbox.md` limits (sweep 4, N12):
  - Neither v2 `new` nor finalize accepts a `base_digest`. A lower sealed against a strong digest over a base at another place is therefore refused by the child (`main.rs:1478-1540`) and reported as `mount_failed`.
  - A bundle lower overwritten in place, with its size and mtime restored, passes the `(dev, ino, size, mtime_ns)` check at `new`, and the attempt keeps seeing the layer the mount resolved. Finalize resolves the bundle again, finds a different `layer_digest` from the top's rows, and refuses with `lower_changed` (§6.3).
  - A downgrade after a crash needs `chmod -R u+w` on leftover attempt trees (§2).
- `docs/sandbox.md` gets these notes:
  - the finalize serialization note (step 9);
  - the step-4 rule behind `writers_active`/`detaching` (§6.4.1):
    - copies of an attempt in systemd service namespaces and other propagation copies never block finalize;
    - a container or namespace with the attempt bound in privately does block it, so stop every container that bind-mounted the attempt before finalizing;
    - keep the state directory on a shared mount (the systemd default);
    - the limits: survivors (a) cannot see (process-free namespaces, `hidepid`), propagation copies with mounts inside them, and one possible spurious `Busy` during a container's start-up;
  - the durability guarantee: a retained attempt is flushed to disk (`syncfs`) before it is published, so it survives a power loss intact (§6.4 step 6a);
  - finalize refuses an attempt that left a directory unreadable to its owner (§6.7);
  - a full v2 `list` can exceed 64 MiB with many retained attempts; use `list {base}` (§6.8);
  - the `forget`-after-unmounting-grading-mounts rule, stated as essential: an idle grading mount holds no descriptor under `retained/ID/` (`overlay_layer.rs:45-47`, `:177`), so `forget`'s holder scan cannot see it, and forgetting its layer pulls files out from under it (§6.7; sweep 8, Codex 8);
  - the `forgetting` status and how to finish it (retry `forget`, or restart) (§6.7);
  - the minimum retry interval after `writers_active` (§10 #6);
  - the "lower edited behind its seal" limit (§10, #3).
- `AGENTS.md`: the regression rows (§11).
- `clients/python/ratarmount_sandbox.py`: the module docstring.
- `mod.rs` help: `after_help` for the new subcommands.

A release tag after the merge is the orchestrator's job, following `release-tag-ci-watch`. cpanmine C9 pins it (it currently pins `v0.1.36`).

---

## 13. Risks and open items

1. **Supervisor base classification** (step 0c). If `classify_supervisor_base` cannot reproduce the recorded kind and place for `binds`/`recursive` bases, finalize returns `unsupported` for them in R1. A follow-up issue is filed; R1 is not widened.
2. **Where `erofs_denied` comes from** (§6.4 step 3). If the counter cannot be reached from the inspection socket's `Arc<WriteOverlay>`, the policy handle has to be passed into `inspection::start` too. If even that fails, the report says `null`. It is never guessed.
3. **`journal_path` metadata** in a retained overlay (the `meta` row set at `ratarmount-fuse/src/lib.rs:835-841`) still names the `attempts/` path. It is documented and not part of any digest.
4. **Busy detection** (step 0d). `ratarmount_fuse::unmount` matches busy on the end of `fusermount3`'s stderr under `LC_ALL=C` (`is_busy_diagnostic`, `ratarmount-fuse/src/lib.rs:4099-4102`). Finalize returns `writers_active` whenever `mountpoints()` still lists the mount after that non-lazy call, whatever the error text. The supervisor is Linux-only anyway (`daemon.rs:886-891`).
5. **Keystone sign-off on #2's record.** Keystone asked for "the state.json record". No `state.json` exists, and the plan records the retained attempt in `record.json` inside the directory, written before the rename, so the rename stays the only commit point (§10, #2). This changes the requested design, and Keystone must approve it explicitly before step 6 starts.
6. **Replays of `new` after a restart.** A `done` `new` record replays the original attempt array, including IDs that `reconcile` has since deleted. The response says nothing about that, because it is the stored original byte for byte. `docs/sandbox.md` states that a replay returns the original result, not the current state, and that callers use `list` to see what exists now.
7. **Keystone sign-off on scope and behaviour changes** (sweep 2, N3; extended in sweeps 3 and 7). cpanmine C9 will read the source doc, so each needs explicit approval:
   - (a) Attempt-level `allow_globs` are dropped from v2 `new` and from the Python signature (`source-plan-doc.md:87`, `:133`), because they would loosen the base policy (§1).
   - (b) A seal refusal because the database is in use maps to `in_use`, not the source doc's `writers_active` (`source-plan-doc.md:115`), because the child has already exited and the holder is foreign (§6.4 step 5).
   - (c) **The `Detached` case of Keystone #6** (sweep 3, N4; revision 7). When a survivor is invisible to step 4(a), the host unmount has already happened by the time step 4(c) finds the child still alive. Invisible or undecided survivors are a copy in a process-free namespace, one hidden by `hidepid`, or a propagation copy with mounts inside it (§6.4.1). Kernel-locked clones are not among them: the unmount unlocks and removes them (`propagate_mount_unlock`; corrected in sweep 7). With `fusectl`, this case is detected about 500 ms after the unmount instead of after 10 s. Finalize returns `writers_active` and sets `detaching`, but the attempt path is **no longer mounted on the host**, so "leaves the attempt mounted" holds only for `Busy`. Consequences for the harness:
     - Stop the container.
     - Retry with the same `request_id`. The retry only waits for the child to exit, and then seals.
     - Do not use `attempt.path` in between.
     
     Keystone must accept this or ask for a stricter rule, for example refusing finalize whenever any `mountinfo` was unreadable.

   - (d) **`create_base` hashes a local archive at registration** (sweep 7, Claude N7; cost corrected in sweep 8, Claude B1). This is a run-time change of the v1 operation for every caller, though its response bytes do not change.
     - **What it costs:** one full read and SHA-256 of the archive for **every registered base name**, including a second name for the same archive (each name has its own index, so nothing is shared), on top of that name's index build. It runs in the single serve loop and is capped at one extra `--timeout` window, after which the caching is skipped, never failed (§6.6).
     - **What it removes:** a whole-archive hash from every finalize of every attempt of that base.
     - **The alternative:** accept that per-finalize cost instead.

   **When each sign-off is needed** (sweep 5, N7): (a) before step 3 lands; (b), (c) and (d) before step 5 lands; §13.5 before step 6.
8. **Keystone's #240 rule** as relayed ("seal takes the exclusive archive lock first…; commit re-checks `layer_sealed` under the archive lock") does not match the code. Seal takes no archive lock (`overlay_seal.rs:276`), and commit re-checks `layer_sealed` under the overlay root flock before it takes the archive flock. Implementing the relayed order would make commits fail (the archive flock is non-blocking), or deadlock seal against commit through the index `HashGuard` (unbounded). The callout at the top of §2 gives the code's order, its citations, and how R1 honours it. Keystone should be told; no step is blocked on it.
9. **What the step-4 survivor test cannot see** (rewritten in revision 7).
   - **Visibility.** Step (a) (§6.4.1) reads `/proc/PID/mountinfo`. On the Arch host, an unprivileged user can read it for root-owned services and Docker containers (`/proc/508`, `/proc/3859090`); step 0d records the CI runner. With `/proc` mounted `hidepid=1`/`2`, other users' entries are hidden, and copies in process-free namespaces are never visible. A propagation copy with mounts inside it is left undecided. Kernel-locked propagation copies need no special case, because the unmount unlocks them first (`propagate_mount_unlock`).
   - **The rule is conservative by construction.** (a) reports only copies it can prove are survivors, so it has no false positives from systemd services, sandboxes or chains. Anything it cannot see or decide is left to (b) and (c):
     - (b)'s EBUSY catches busy propagation copies, wherever they are;
     - (c)'s `detaching` round trip still prevents a seal while any FUSE writer can exist. It only costs a round trip instead of a clean `Busy`.
   - **Kernel claims to observe.** The claims §6.4.1 marks as reasoned are observed by step 0d's shell commands before step 5, and the first three are automated in CI by F6b/F6c:
     - umount propagation;
     - `propagate_mount_busy`;
     - the child exiting at the last mount, with `fusectl`'s connection directory;
     - locked copies being unlocked and removed;
     - copies with mounts inside them staying.

---

## 14. Review log

### Sweep 1 (skeptic, 2026-10-31)

Each blocker was checked against the code at `2b96837` before the plan was revised.

| Finding | Verified | Resolution |
| --- | --- | --- |
| **B1** `supervise()` turns `stopped`/`finalized` into `crashed` | Yes. `daemon.rs:433-444` skips only `crashed` and maps every other poll result to `crashed`. `ProcessMounter::poll` returns `Crashed` when no child is recorded (`process.rs:201-208`). | §6.4 "Statuses and the supervise loop": `supervise()` polls only `starting`/`ready`. A new internal status `sealed` is added. §4.3 and §4.5 list the statuses. U29 is added. |
| **B2** a retry after the seal fails, because `fsck --repair` refuses a sealed overlay, and pack sat inside `finalize_top` | Yes. `overlay_fsck.rs:164-170` returns "overlay is sealed; fsck --repair is refused" when `repair && sealed`. | §6.3: `finalize_top` is resumable. On a sealed top it runs `fsck(top, false)` (must be clean), then `finish_if_sealed` (`overlay_seal.rs:349-356`), then the same `gate_base` that `overlay pack` applies to sealed layers (`overlay_cmd.rs:480-484`), then the read-only hash. Pack moved out into `finalize_pack`, a separately rerunnable step (§6.4 step 6). Steps 6-8 leave status `sealed`. §10 #6 is corrected. U30 is added (pack failure and rename failure, then a retry with the same `request_id`). |
| **B3** the crash tests build their overlay with the deleted `WriteOverlay::new` | Yes. `write_overlay.rs:1180-1215` has only `open` plus `#[cfg(test)] pub(crate)` helpers; `AGENTS.md` pins the deletion with `compile_fail` doctests. | §10 #2 and §11 use `crate::base_identity::fixtures::new_overlay` (`base_identity.rs:238-300`, which is `WriteOverlay::open` over a fixture token) and `fixtures::classify`. The plan says explicitly that `WriteOverlay::new` must not be re-added. |

**Non-blocking findings applied:**

- **N1, lock lifetime.** It follows the `overlay_cmd.rs:544-560` order: `acquire_until`, `finish_if_sealed`, classify and gate under the guard, `seal(self)`. The release point is stated in §7.
- **N2, detecting `in_use`.** The detection is `io::ErrorKind::WouldBlock`, which seal and fsck already produce for a locked database (`overlay_seal.rs:38-47`, `overlay_fsck.rs:149-157`).
- **N3, U2.** It is restricted to lines produced by the serializer.
- **N4, U4.** It runs with `max_attempts` = the golden value + 1, and the finalized attempt sits under a base name the transcript never uses.
- **N5, the v1 `list` filter.** v1 `list` hides only the new statuses, and a `starting` rollback leftover stays visible.
- **N6, forget and retained dependents.** `forget` also refuses while a retained record uses the layer as a lower (U31).
- **N7, internal-read sites.** The holder scan and the inspection `status` handler are added to §6.11.
- **N8, stale replays.** Documented in §12 and §13.6.
- **N9, smaller points.**
  - The spike also checks the view flags.
  - The `beyond-parity-roadmap.md:297-298` update is now firm.
  - The `journal_path` claim was **rebutted** with evidence: the key is written by `ratarmount-fuse/src/lib.rs:835-841` (`overlay.set_meta("journal_path", …)`), not in `overlay_meta.rs`. The citation is now in §5 and §13.3.
- **N10, the state.json wording.** Recorded as open item §13.5: Keystone must sign off before step 6.

### Sweep 2 (skeptic, 2026-10-31)

| Finding | Verified | Resolution |
| --- | --- | --- |
| **B1** a sealed tmpfs overlay makes `reconcile` fail, so the daemon cannot restart | Yes. The RAM loop calls `fs::remove_dir_all(entry.path())` on `ram/ID` (`daemon.rs:415-427`), which is the overlay root (`overlay_dir = ram/ID`, `:661-663`). Seal removes its write bits (`docs/sandbox.md:646-648`). `reconcile` returns with `?`. `destroy`'s `remove_dir_all(&attempt.overlay_dir)` (`:731-733`) has the same problem. | §6.6 and §6.7: every supervisor deletion (the `reconcile` `attempts/` and RAM loops, `destroy`'s root and `overlay_dir`, `forget`) goes through `remove_tree_restoring_write`. A non-retained tmpfs finalize stays allowed. Test U22b is added. |
| **B2** a writer inside a container is missed and the child gets SIGKILLed | The code behaviour is confirmed: revision 2's step 4 did unmount non-lazily, wait up to `--timeout`, then SIGKILL. The kernel behaviour (a bind copy in another mount namespace keeps the superblock and the FUSE server alive after the host unmount) is reasoned, not run; step 0d now runs it before anything builds on it. The source doc agrees: "or the child does not exit: return `writers_active`, change nothing" (`source-plan-doc.md:114`). | §6.4 step 4 is rewritten. (a) Before unmounting, scan `/proc/*/mountinfo` (deduplicated by mount namespace) for other mounts of the attempt's FUSE `major:minor`; if any exist, `Busy` → `writers_active`, nothing changed, the attempt stays mounted. (b) Non-lazy unmount. (c) Wait at most `min(--timeout, 10 s)` for the child; if it is still alive, `Detached` → `writers_active`, status `detaching`, **never SIGKILL**, no seal (seal needs the child gone, so no writer remains). A retry repeats only (c). Statuses, v1 hiding, §6.5 and §10 #6 are updated. U32 (Fake) and F6b (real `unshare -Urm` namespace copy, plus an opt-in Docker variant) are added. §13.9 covers namespaces the scan cannot read. |

**Non-blocking findings applied:**

- **N1, seal and the archive lock.** Confirmed: seal takes no archive lock (`overlay_seal.rs:276`, `overlay_meta.rs:1022-1036`, `docs/sandbox.md:612-616`). The §2 row is corrected, and level 3 is dropped from §7. Keystone's stated rule is also wrong; that is §13.8.
- **N2, phase order.** The composed view is built in phase 2 under the guard and reused in phase 4.
- **N3, scope changes.** The `allow_globs` drop and the `in_use` mapping are §13.7 (sign-off).
- **N4, test fixture.** The tests use `fixtures::overlay_over_with` with the base path, as the `finish` tests do (`run.rs:1791`, `:1864`). `new_overlay` records no place.
- **N5, forget and outside mounts.** `forget` adds a best-effort `/proc` holder scan, and the remaining risk is documented.
- **N6, `erofs_denied` transport.** The step-3 citation is corrected: `sandbox run` uses the control socket, the supervisor the inspection socket.
- **N7, journal globs.** Validated with `ReadOnlyGlobs::new` before `tempdir_in` (§6.2 item 6, U33).
- **N8, stack mismatch.** A lower stack mismatch is caught at validation from the recorded `lower_layers` (§6.2 item 5, U33).
- **N9, the #3 re-check claims.** Narrowed to "the same seal record", with the payload-behind-the-seal limit documented. Reason 3 is restated. Finalize also compares the snapshot with the `lower_layers` the child wrote into the top.
- **N10, serialization.** Documented and measured in step 9. A worker thread is out of scope.
- **N11, protocol gaps.**
  - `Op` is `#[serde(untagged)]`.
  - The CLI and Python accept a v1 error envelope answering a v2 request (P5).
  - Placeholder behaviour is specified for step 1.
- **N12, smaller points.**
  - The `retryable` definition in §6.5 now matches §10 #6.
  - `docs/getting-started.md` is added to §12.

### Sweep 3 (skeptic, 2026-10-31)

| Finding | Verified | Resolution |
| --- | --- | --- |
| **B1** the v1 golden is unstable because attempt IDs are random and `list` is in `BTreeMap` order | Yes. IDs come from `tempdir_in` with prefix `attempt-` (`daemon.rs:651-655`). `new` returns creation order; `list` iterates the `BTreeMap` (`daemon.rs:493-497`). | §10 #7: a `#[cfg(test)]` deterministic ID source on `Supervisor` (`attempt-000001`…, created `0700` exclusively), added in step 0 before the fixture is generated. Production code is unchanged. Normalization is now only `$STATE`; IDs are compared byte for byte. |
| **B2** after compaction the held `O_APPEND` descriptor points at the unlinked old file | Yes. A rename replaces the name and leaves the open descriptor on the old inode. | §10 #5: after the rename and directory fsync, drop the descriptor, reopen through the same checked open (`O_NOFOLLOW`, owner/type/mode/`nlink`) and check that `(dev, ino)` is the renamed temp file's. A failed reopen refuses request-ID'd requests until a restart. U8 asserts that a record appended after compaction survives a reopen. |
| **B3** lower-identity comparisons break for bundle lowers | Yes. For a bundle, `open_inner` replaces the path with the cache directory `resolve_bundle` returned, canonicalizes that, and records it (`lower_stack.rs:150-175`, `:196-208`). | §10 #3: the phase-2 comparison with the top's rows skips the path at bundle positions, re-checks the bundle file's `(dev, ino, size, mtime_ns)`, and takes `layer_digest`/`sealed_at` from the row. §6.2 item 5: a retained lower's stack is checked against its own `record.json` lowers, which hold bundle paths as the supervisor received them. An external layer at a bundle position is checked by count only, and that limit is documented. U16, U33 and F7 gain bundle cases. |
| **B4** the internal-read manifest was scheduled for step 8, but `policy.py` runs on every commit | Yes. `AGENTS.md` fails both an unmanifested expectation and an approval without a matching expectation, and §9 runs the gates before every commit. | §9: every step updates `manifest.json` and its `AGENTS.md` regression rows in the same commit, with a per-step inventory table (steps 2, 4, 5 and 6). Step 8 is only a cross-check. |

**Non-blocking findings applied:**

- **N1, the stack check's rationale.** The wrong rationale is removed: no child check covers a middle lower (`check_top`, `lower_stack.rs:266-299`, compares only the top). The docs and R5 text must not suggest that a grading mount checks it.
- **N2, the inventory list.** §6.11 now lists only calls that are actually disallowed. `read_link`, `read_dir`, `rename` and socket I/O are excluded. The `/proc/PID/mountinfo` and `comm` reads are added.
- **N3, namespace detection.** "Another namespace" is decided by mount ID. The `ns/mnt` de-duplication is only a speed-up, and an unreadable link never causes a process to be skipped.
- **N4, `Detached` and Keystone #6.** `Detached` vs Keystone #6 is added as §13.7(c) for sign-off, with the consequences for the harness.
- **N5, `diff`/`stats` on `detaching`.** They use the inspection socket, or return `in_use`.
- **N6, classification seam.** `Mounter::classify` is the seam.
- **N7, existing tests.** The plan states honestly which existing test signatures change. `handle(impl Into<Op>)` keeps call sites the same.
- **N8, `bytes_written`.** It is computed inside `finalize_top` with `OverlayQuota::new(&top, None, None)`, and U30 checks it on the retry.
- **N9, `lower_changed` and record transitions.** The phase-2 `lower_changed` leaves the attempt `stopped`. The record transitions on a retry are spelled out: the last line for an ID decides.
- **N10, finalize with a different body.** `pack:true` on an attempt already finalized without a bundle is `invalid_request`.
- **N11, smaller points.**
  - U8 builds its file directly and uses a no-sync test mode.
  - U10's "before" report is a fixture captured in step 0.
  - `check_offline_journal` is kept in `classify_supervisor_base`.
  - `docs/sandbox.md` tells clients to rely on the `unsupported_version` code, not its text.
- **Fork-N.** The scope section cites `fork-n-writable-tops.md:82-83`: there is no conflict.

### Sweep 4 (skeptic, 2026-10-31)

| Finding | Verified | Resolution |
| --- | --- | --- |
| **B1** compaction drops `op_hash`, so `idempotency_conflict` stops working after a compaction | Yes. Revision 4's §10 #5 schema put `op_hash` (and `attempt`) only on `running` lines, and compaction kept finished records in their last state. | §10 #5: every line (`running`, `done`, `failed`, `retryable`) now carries `op`, `op_hash` and `attempt`. Compaction writes one self-contained line per live record. A line missing `op_hash` is corrupt. U8 now compacts, reopens, and checks `idempotency_conflict` for both a compacted `done` ID and a compacted `retryable` ID with a different body, the original-body replay and re-run, and K5's attempt lookup after reopen. |

**Non-blocking findings applied:**

- **N1, rename succeeds but fsync fails.** The attempt moves to `retained` at once, only the fsyncs are retried, and the request is `retryable` (§6.4 step 8, U30 case c).
- **N2, failed or short append.** The file is `ftruncate`d back to its length before the write, and request-ID'd requests are refused until that succeeds (U8 short-append case).
- **N3, N4 target predicates.** All Linux-only code stays in the reviewed `sandbox/process.rs`. `finalize.rs` and `requests.rs` get no target predicates, otherwise a `policy.json` entry lands in the same commit (§6.11).
- **N4, `bytes_written`.** It is measured before fsck, as `sandbox run` does today (`run.rs:1064`), and stored for retries. U10 gains an fsck-repair case.
- **N5, lower reads.** Every supervisor-side lower read uses `OverlayMeta::read_no_recovery` (`overlay_meta.rs:274`), never the hot-journal-recovering `read` (`:267-269`).
- **N6, expensive finalizes.** The step 9 timing test includes a bundle lower and a `pending` archive digest. The PR reuses a cached digest as `base_key`, or documents the cost.
- **N7, seeded attempts in U4.** They are named outside the deterministic ID sequence, and the counter is reset before the replay.
- **N8, damaged retained layer at K5.** It resolves to `failed interrupted`, naming the damaged ID (U34).
- **N9, downgrade claim.** The §2 claim is corrected: a downgrade after a crash needs `chmod -R u+w` on leftover attempt trees, and this is documented.
- **N10, help-text test.** `sandbox finalize`/`forget` are added explicitly to `regression_help_states_exit_status` (`snapshot.rs:558`).
- **N11, classify callback type.** `FinalizeInputs.classify` is `&mut dyn FnMut`.
- **N12, two limits.** "No `base_digest` over a moved base" and "a bundle rewritten with size and mtime restored is seen only at finalize" are added to the `docs/sandbox.md` limits.

### Sweep 5 (skeptic, 2026-10-31)

| Finding | Verified | Resolution |
| --- | --- | --- |
| **B1** attempt IDs are not unique across `attempts/`, `retained/` and the request log | Yes. `new_attempts` uses `tempfile::Builder::new().prefix("attempt-").tempdir_in(attempts/)` (`daemon.rs:651-655`), which avoids only names that exist in `attempts/`. Nothing in revision 5 kept a new ID away from a retained ID or from a logged `attempt`. | New §6.1a. After `tempdir_in`, a name that is in the `retained` map (damaged included) or is the `attempt` of any live request-log record is removed and redrawn (at most 16 tries, then `io`), before it is recorded or spawned. The v1 ID shape is unchanged. A retry of a `retryable` finalize of a destroyed attempt returns `not_found` and never reaches a new attempt while its record lives; after eviction, the bounded retry window applies. U35 forces both collisions through the test ID seam. Scheduled in step 3. |

**Non-blocking findings applied:**

- **N1, finalize on `crashed`.** "No recorded child" counts as exited. A dead mount held by another namespace gives `writers_active` with status kept `crashed` (U36).
- **N2, oversize envelope.** `send` takes the version, so `response_too_large` answers a v2 request with a v2 envelope (U27).
- **N3, step order.** `SealOperation::acquire_until` and U28 move to step 4, and `sandbox run` passes no deadline. The supervisor's deadline is 5 s, after which the result is `in_use` and `retryable`.
- **N4, F6b on CI.** The CI path is named: the FUSE job sets `kernel.apparmor_restrict_unprivileged_userns=0` with `sudo sysctl`, with `sudo unshare --mount` as the fallback. A skip is allowed only off CI.
- **N5, retained-layer reads.** The retained load uses `read_no_recovery`; a hot journal or an unreadable database means `retained_damaged`.
- **N6, `diff`/`stats` on retained attempts.** They look in `attempts` and then `retained`, and work offline on a retained attempt (U26).
- **N7, smaller points.**
  - The `mod sandbox` gating claim is corrected: there is no cfg gate at `main.rs:56`, and the binary is Unix-only by imports.
  - `classify_supervisor_base` moves to `sandbox/finalize.rs`, using the already `pub` `FactoryOpener` (`base_identity.rs:20`).
  - A retained lower must have `record.base == new.base`.
  - Each §13.7 sign-off is tied to a step: (a) before step 3, (b) and (c) before step 5, and §13.5 before step 6.
  - `supervise()` reaps exited `detaching` children with `try_wait`, without changing their status.

### Sweep 6 (skeptic, final allowed sweep, 2026-10-31)

| Finding | Verified | Resolution |
| --- | --- | --- |
| **B1** on systemd hosts the step 4(a) scan reports `writers_active` on every finalize | Not run, but accepted from kernel semantics, since nothing in the plan contradicts it. On a systemd host `/` is `shared`, so a FUSE mount under it propagates into every `PrivateTmp`/`ProtectSystem` service namespace as a copy with a new mount ID and `master:N`. Revision 6's rule ("mount ID not in `/proc/self/mountinfo`" means writer) counted those copies. Step 0d and F6b used `--propagation private`, the one mode where this does not show. | §6.4 step 4(a): foreign lines tagged `shared:N`/`master:N` with the host mount's own peer group are ignored. umount propagation removes them, and if one is busy the host non-lazy unmount fails with EBUSY, which (b) already turns into `Busy`. Only untagged copies, or copies from another peer group, are writers. Step 0d adds a `--propagation slave`/`unchanged` probe asserting both halves, plus a no-writer run on stock systemd hosts. U37 is a parser test on synthetic `mountinfo`. §13.9 adds the `hidepid` blind spot. |
| **B2** "in CI a skip is a failure" is false, and F6b fails the `check` job as scheduled | Yes. `prepared_fuse_check` refuses to skip only when `RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE=1` (`ratarmount/tests/sandbox.rs:365-366`), and no workflow sets it. The FUSE tests run in the `check` job's `cargo test --workspace` (`ci.yml:102-105`), which installs `fuse3` (`ci.yml:20-24`) but never enables `user_allow_other`. The `fuse-harness` job (`ci.yml:300-341`) runs only shell allowlists. | §9 step 9 now edits `.github/workflows/ci.yml` in the same commit as the FUSE tests: it sets `RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE: "1"` next to `RATARMOUNT_REQUIRE_XORRISO`, adds `user_allow_other` to `/etc/fuse.conf`, adds the AppArmor userns sysctl (with the `sudo unshare --mount` fallback in F6b), and checks `test -c /dev/fuse`. A separate `sandbox-fuse` job is the named alternative. `ci.yml` is added to the header and to the per-step table. The §11 and F6b claims are corrected, and the plan states that until the wiring lands, the FUSE gate is met only by a recorded manual run on a FUSE host. |

**Non-blocking findings applied:**

- **N1, `new` records reserve no IDs.** `new` `done` lines (and partial-rollback `failed` lines) carry `attempts:[…]`, and those IDs join the §6.1a reserved set.
- **N2, K5 and the body check.** Finalize lines carry `pack`. K5 re-applies the body check, so `pack:true` against a report without a bundle resolves to `failed invalid_request`, never `done`.
- **N3, golden coverage.** The golden `diff`/`stats` use a real temporary directory base (`$BASE`), so the success path is pinned. U25 pins a v1 `new`'s child argv against a step-0 fixture.
- **N4, `list` and scope.** v2 `list` shows every status by default, matching the source doc (`source-plan-doc.md:120`). The proposed `all` protocol field is dropped; `--all`/`all=True` remain only in the CLI and Python client, where they choose to send v2. This removes the scope addition instead of asking for sign-off.
- **N5, report fields.** The finalize report carries `layer_digest`, `stack_digest` and `base_digest_state` at top level, as `source-plan-doc.md:118` lists them.
- **N6, scan cost.** The step 4(a) scan cost is part of the step 9 timing, with a fallback if it is slow.
- **N7, when `erofs_denied` is read.** It is read inside step 4, after (a) found no writer and before (b), and the remaining difference from `sandbox run` is documented.
- **N8, serialization shape.** Step 1 adds a serialization round-trip test for both versions, so the `#[serde(flatten)]`-over-`untagged` shape is pinned before step 7.

**Status after the final sweep.** The open Keystone decisions are unchanged:
- §13.5: `record.json` instead of `state.json`, before step 6;
- §13.7(a): dropping attempt-level `allow_globs`, before step 3;
- §13.7(b) and (c): the `in_use` mapping and the `Detached` case of Keystone #6, before step 5;
- §13.8: the correction to Keystone's #240 rule, for information.

Step 0d must confirm the two kernel behaviours this plan depends on (B2 of sweep 2 and B1 of sweep 6) before any code builds on them.

### Revision 7 (targeted, Matt's direction via Keystone, 2026-10-31)

Matt asked for four things after the last sweep:
- (a) fix the step-4 detection so it reports only real writers, and make step 0d exercise the systemd case that matters;
- (b) remove the false "in CI a skip is a failure" claim and make sure F6b does not fail CI as scheduled;
- (c) re-verify that sweep 4 B1 and sweep 5 B1 are closed;
- (d) keep a prominent statement for Keystone in §2 about seal's locks and the #240 order.

Every point was re-checked against the code and CI config at `2b96837`. Where possible, it was also checked against real `mountinfo` on Matt's Arch/omarchy host (read-only, unprivileged).

| Item | Re-verified against | Finding | Change |
| --- | --- | --- | --- |
| **(a) Sweep 6 B1**, detection | `/proc/self/mountinfo` (`/` `shared:1`, `/tmp` `shared:185`, `/home` `shared:197`); systemd-resolved's `/proc/508/mountinfo`; a Docker container's `/proc/3859090/mountinfo` | **Premise observed, not just reasoned:**<br>- every mount made after a service started appears in its namespace, including user FUSE mounts (gvfs `shared:620` → `shared:622 master:620`; portal `shared:636` → `shared:638 master:636`), so revision 6 would refuse every finalize;<br>- Docker container roots and binds carry no propagation fields.<br>**Sweep 6's resolution was incomplete.** Its tag rule (ignore `shared:N`/`master:N` with the attempt's group N) still reported chained slaves, whose `master:` names an intermediate group (nested sandboxes, snap per-user namespaces). It also ignored binds of the attempt elsewhere, tagged `shared:N`, which survive the unmount. | **New §6.4.1.** (a) decides from each copy's **parent** and **place**, the way umount propagation does:<br>- a propagation copy is ignored;<br>- only a provable survivor gives `Busy`;<br>- an undecided copy is left to (b)/(c).<br>Observed and reasoned claims are marked; btrfs roots are handled by the place formula. Locked clones (unprivileged namespaces created after the mount) and `hidepid` are documented limits ending in (c).<br>**Step 0d** is rebuilt around the stock services' slave namespaces, transient units started before and after `new`, a busy same-user unit, chains and private copies, and it captures real `mountinfo` as U37 fixtures.<br>**F6c** automates the systemd case in CI; **U37** is rewritten. This **supersedes** sweep 6 B1's resolution. |
| **(b) Sweep 6 B2**, CI | `ci.yml:13-110` (the `check` job), `ci.yml:300-341` (`fuse-harness`), `tests/sandbox.rs:255-267,334-375`, `tests/sandbox_run.rs:13-29`, `ratarmount/Cargo.toml:13-34,90-98` | The claim survived only in the header Gate line, which is now corrected; §11's intro was already qualified. **F6b as scheduled would have failed CI three ways:**<br>(1) the `sudo unshare` fallback ran the holder as root, which FUSE refuses without `allow_other`, so the copy vanished and the expected `writers_active` became `done`;<br>(2) its "`#[cfg(test)]` seam" variant cannot reach `CARGO_BIN_EXE_ratarmount`, and `ratarmount` has no `test-hooks` feature;<br>(3) adding `user_allow_other` to the shared job would switch on the never-in-CI `sandbox_run` suite.<br>Two further issues: private namespaces pin the mounts of tests running in parallel threads, and the sysctl edit is unnecessary with `sudo`. | **F6b rewritten:** `setpriv` drops to the test user after `unshare`, and a seam-free process-free persistent namespace exercises (c). F6b and F6c move to their own binary, `tests/sandbox_namespaces.rs` (binaries run sequentially; cases serialized).<br>**Opt-in variable:** `RATARMOUNT_TEST_PRIVILEGED=1`. When set, missing prerequisites fail; when unset, the binary never runs `sudo`.<br>**CI change shrinks** to two env vars on `cargo test`, with no `user_allow_other`, sysctl or device step. The `fuse-harness` job is cited as evidence that FUSE works on `ubuntu-latest`, and the first run must show no `skip:` lines. This **supersedes** sweep 6 B2's resolution and sweep 5 N4's sysctl path. |
| **(c) Sweep 4 B1**, `op_hash` across compaction | §10 #5 schema and U8 | Closed: every line carries `op`, `op_hash`, `attempt`. Two gaps in the wording: compaction did not say it keeps `attempts`/`pack`, and the resolving lines at open did not say they carry the fields. | Compaction copies each record's last line **verbatim** (only `seq` renumbered). The resolving lines copy `op`, `op_hash`, `attempt` and `pack` from the `running` line. U8 asserts byte-equal compacted lines, `attempts` still reserved after compact and reopen, and K5's body check after a compaction. |
| **(c) Sweep 5 B1**, unique attempt IDs | `daemon.rs:651-655`; tempfile 3.27.0 (`lib.rs:194-195`, `util.rs:15`); §6.1a | Closed: 62⁶ names confirmed, and the reserved set is rebuilt from `retained/` and the log (including `new` `attempts`). One fail-open edge: a plain `rename(2)` replaces an empty `retained/ID`. | The commit rename is `renameat2(…, RENAME_NOREPLACE)`, so a stray target fails with EEXIST and nothing is replaced. U35 covers every reserved source after compaction and reopen, plus the EEXIST case. Lengthening IDs was rejected as v1-visible (the `sun_path` budget, `docs/sandbox.md:2383-2388`). |
| **(d)** Keystone statement | `overlay_seal.rs:276,406-412,425-437,456,676-711`; `overlay_meta.rs:1022-1036`; `write_overlay.rs:3684-3696,7350,7357-7363,7418-7446`; `commit_journal.rs:707-717`; `docs/sandbox.md:601-616,2241-2243` | The correction already existed, but only as a table cell. | **A callout at the top of §2:** seal takes no archive lock (`overlay_seal.rs:276`); seal's order and commit's order, with citations; why the relayed order would deadlock (AB/BA with an unbounded spin); and how R1 honours the real order in four points. The §2 row and §13.8 point to it. |

**Also changed in revision 7:**
- **`crashed` attempts with no child** (revises sweep 5 N1): copies elsewhere no longer block finalize, because a dead FUSE server cannot be written through. (b) still must remove the host mount (§6.4.1, U36).
- **Recipe citation:** Docker's `-v` is `swe-bench-sandboxes.md:75`, not `:74`.
- **Step 9's scan-cost fallback** no longer skips reading files by comparing them; an unread namespace counts as undecided.
- **F6c's hard assertions rest only on kernel behaviour.** U1 (started before `new`) carries `PrivateTmp`. U2 (started after) has `PrivateMounts` only, because whether a clone keeps a copy beneath a later PrivateTmp is a systemd implementation detail. Step 0d records that case as a data point.
- **The namespace test daemon keeps `--timeout 10`.** `--timeout` also bounds mount readiness (`daemon.rs:641`), so a shorter value would add flakiness, not speed.
- **The commit rename names its binding:** `libc::renameat2`, a crate `daemon.rs` already uses.

**Status after revision 7.**
- The open Keystone decisions are unchanged: §13.5 before step 6; §13.7(a) before step 3; §13.7(b) and (c) before step 5; §13.8 for information.
- Step 0d must observe the reasoned kernel claims in §6.4.1 on the CI runner and Matt's desktop before step 5 lands, and record the results in the PR:
  - umount propagation removes propagation copies;
  - a busy propagation copy gives EBUSY;
  - the FUSE child exits only at the last mount;
  - locked clones survive the unmount.

### Sweep 7 (Claude skeptic and Codex skeptic, 2026-10-31)

Every blocking finding was checked against the code at `2b96837` before the plan was revised. All nine hold.

| Finding | Verified | Resolution |
| --- | --- | --- |
| **Claude B1**: a retained attempt is published without its contents synced | Yes. Seal commits its database and syncs only the sentinel (`overlay_seal.rs:546-551`, `:608`). Agent writes through FUSE are never synced; only COW staging copies are, at publication (`write_overlay.rs:6870-6916`). The manifest and summary are plain `File::create` (`run.rs:1163`, `:1179`), the journal is synced only with `--journal-sync` (`oplog.rs:580-583`), and only pack syncs its output (`overlay_pack.rs:522`). | §6.4 step 6a and §10 #2: a `syncfs` barrier on `attempts/ID` before `record.json` and the rename. It is Linux `rustix::fs::syncfs` (`#[cfg(linux_kernel)]` in rustix 1.1.5), with `rustix::fs::sync()` elsewhere, for tests only. A failure leaves the attempt `sealed`, unrenamed and `retryable`. K4 is corrected, K8 added (power loss), U39 pins the order, and step 9 times it. |
| **Codex 6**: the machine-crash durability is incomplete | Yes: the same file-content gap. First creation of `requests.jsonl` and `retained/` also left the state directory unsynced. | Covered by the barrier. The state directory is fsynced after first creating either (§6.6), and the fsync handles are added to §6.11. U39 includes a forced `syncfs` failure. |
| **Codex 1**: `finalize_top` drops the owner of fetched base files | Yes. `ClassifiedBase::source()` omits the `_keep_alive` (`overlay_identity.rs:1046-1058`), `RemoteLocal::Fetched` deletes its file on drop (`ratarmount-remote/src/lib.rs:698-703`), and CPIO's path backend reopens it per member (`ratarmount-formats-cpio/src/lib.rs:128-136`). | §6.3: `finalize_top` returns `Finalized { report, base: ClassifiedBase, stack, view }`, which the caller keeps through `finalize_pack` and report building. U40 uses a path-backed source whose keep-alive deletes its file. Lands in step 4. |
| **Codex 2**: finalize misses a bundle replaced in place with its identity kept | Yes. `compose` returns only the view and drops the records (`lower_stack.rs:61-69`). Revision 7 copied the top's digest into the report but never compared it with the bundle resolved again. | §6.3 phase 2 and §10 #3: the supervisor opens the stack with `open_no_recovery`, which returns the records, and compares each record's `layer_digest` and `sealed_at` (and paths at directory positions) with the top's recorded `lower_layers` before sealing. A mismatch is `lower_changed`. U16 injects a resolver that returns a different valid layer at finalize. |
| **Codex 3**: composing lowers still recovers hot journals | Yes. `open_inner` calls `OverlayMeta::read` (`lower_stack.rs:176-177`), which rolls a hot journal back (`overlay_meta.rs:267-269`, `347-353`), and `diff` had no validation step before it. | New `MountLowerStack::open_no_recovery` (an `open_inner` flag; every existing caller keeps the recovering read; `sandbox run` keeps `LowerReads::Recovering`). The supervisor's `diff` (step 3) and finalize (step 5) use it: a hot journal gives `diff_failed`/`lower_changed`, and nothing is written (U41). |
| **Codex 4**: compaction's directory fsync can fail after the rename, with appends going to the unlinked file | Yes. Revision 7 dropped the old descriptor only after the directory fsync. | §10 #5: right after the rename, the log is set `Broken` and the old descriptor dropped. Then the directory fsync and the checked reopen; only then `Open`. Any failure stays `Broken` until a restart. U8 injects the fsync failure after the rename. |
| **Codex 5**: a terminal append that fails after side effects has no defined next state | Yes. Finalize step 9 had an empty failure column, and the truncation rule let later requests run while the effects stood unrecorded. | §10 #5's state machine: such a failure always makes the log `Broken`. The line is truncated away and the in-memory record stays `running`; appends are refused until a restart, where K1-K5 resolve it, while read-only replays are still served. Finalize step 9's failure column is filled in. U8 injects `write` and `fdatasync` failures after a `new` spawned and after a retained rename. |
| **Codex 7**: an accepted `new` can exceed both result limits after spawning | Yes. 4,096 attempts (`mod.rs:43`) × 32 lowers of 1,018 bytes gives a 134,598,657-byte result, above `MAX_RESPONSE` (`protocol.rs:9`) and the whole live cap. | §10 #5: a 4 MiB cap on one stored record. `new` preflights the exact result size before any directory or spawn: over the record cap (with a `request_id`) or the response limit (without one) it returns `capacity`. U38 uses Codex's case and asserts zero spawns. §6.8 notes `list`'s existing `response_too_large`. |
| **Codex 8**: F6b's persistent namespace has no mount target | Yes. `unshare --mount=FILE` bind-mounts onto an existing file (`unshare(1)` EXAMPLES: `touch` first). | F6b and step 0d item 5 now run `sudo -n touch D/mnt` before `unshare`, check every command's status, and clean up `D/mnt`, `D` and the directory. |

**Non-blocking findings applied:**

- **Claude N1, the Keystone callout's deadlock reason.**
  - Confirmed: the archive flock is `LOCK_NB` with no retry (`commit_journal.rs:713`, `:917`, `:1239`, `:1354`), so the relayed order would make commits fail, not deadlock them. The unbounded lock is the index `HashGuard` (`digest_cache.rs:444-481`), taken by commit's refresh (`overlay_meta.rs:1541`) and by a seal resolving `pending` with a writable index (`overlay_meta.rs:997-1016`, `overlay_seal.rs:445-451`).
  - The §2 callout, its row and §13.8 are corrected, and §7 lists `HashGuard`.
  - R1's seals never take it: no writable index (`main.rs:2084`, `:2522`, `overlay_identity.rs:276-280`).
- **Claude N2, step order.** `remove_tree_restoring_write` moves into step 5, with the first finalize that can seal a tree.
- **Claude N3, step 0d.** It is now shell-only kernel observation with today's binary and records `mountinfo` captures for U37. Classifier and finalize assertions live in U37, F6b and F6c. Matt runs the desktop half, because it needs `sudo`.
- **Claude N4, in-process reopens.** These tests take `test_process::exclusive()` (`tests.rs:311-316`); the list is in §11.
- **Claude N5, the rename binding.** `rustix::fs::renameat_with(…, NOREPLACE)` as in `overlay_pack.rs:1069-1083`. `libc::renameat2` would break the macOS job (`ci.yml:441-481`).
- **Claude N6, mode-000 directories.** The removal restores `u+rwx` by name with `fchmodat` before opening (`write_overlay.rs:5224-5244` applies agent modes to the host). Finalize over an owner-unreadable directory returns `io`, naming it (`overlay_changes.rs:744-751`). Test U42.
- **Claude N7, base hashing per finalize.** Confirmed (`base_digest.rs:55-64`; `BaseOptions` has no digest field).
  - `create_base` caches a local archive's digest in the prepared index with the cached-or-compute call, then re-checkpoints the index (§6.6, spike 0c).
  - The work happens inside `ProcessMounter::prepare`, so the Fake (`/fake.tar`, `tests.rs:101`) and the v1 golden are unaffected. U43 is therefore an integration test with the real daemon.
  - The v1 run-time change goes to Keystone as §13.7(d), before step 5.
  - The step 9 fallback text is corrected.
- **Claude N8, step (c).** `/sys/fs/fuse/connections/<minor>` decides whether the superblock still lives: a survivor is `Detached` about 500 ms after (b), and a slow child is no longer mistaken for one. The child's exit status is reported, with `journal_summary.complete: false` on an unclean exit (`ratarmount-fuse/src/lib.rs:4015-4016`). Test U44.
- **Claude N9, `forget`.** It renames back to `attempts/ID` (fsynced) before deleting, so `reconcile` finishes any leftover.
- **Claude N10 and Codex 9, Python.** Retained attempts are never destroyed implicitly (`ratarmount_sandbox.py:55-57`). Paths are updated from the finalize report. `list` items with missing fields are tolerated (`:116`). Test P6.
- **Claude N11.**
  - The step-5 inventory row no longer lists the socket handler.
  - F6b's Docker variant needs `allow_other` and `user_allow_other` (`swe-bench-sandboxes.md:68`).
  - `Daemon::start` uses `--timeout 30` (`tests/sandbox.rs:31`).
  - Propagation copies with mounts inside them are undecided and listed as a limit.
- **Codex 10, locked clones.** The probe uses an explicit `--propagation slave`. The locked-clone claim is reversed: revision 7's "locked clones survive" was wrong, because `propagate_mount_unlock` unlocks them for the unmount. §6.4.1, §13.7(c), §13.9 and §12 are corrected; step 0d item 6 observes it.
- **Codex 11, F6c's busy case.** The test runs `fusermount3 -u` itself (expecting EBUSY) and asserts the `stage=unmount` token that the `writers_active` message now carries (§6.4.1).

**Also in this sweep:**
- The barrier's `attempts/ID` directory handle is a new inventory site, listed in §6.11 and in step 6's row. The `syncfs` call itself is not disallowed.
- The barrier row is numbered 6a, so the finalize table's rows follow the order of operations.

**Superseded by this sweep:**
- revision 7's locked-clone limit (in its review log above);
- `libc::renameat2`;
- the `--timeout 10` wording;
- the in-place `forget`;
- the "register bases with a known digest" advice.

**Status after sweep 7.** One Keystone decision is added: §13.7(d), `create_base`'s registration-time hash, before step 5. The others are unchanged: §13.5 before step 6; §13.7(a) before step 3; §13.7(b) and (c) before step 5; §13.8 for information. Step 0d's shell observations, run on the CI runner and by Matt on his desktop, must confirm the reasoned kernel claims in §6.4.1 before step 5 lands.

### Sweep 8 (Claude skeptic and Codex skeptic, 2026-10-31)

Every blocking finding was checked against the code at `2b96837` before the plan was revised. Claude B1 and Codex 3 are the same defect, so there are five distinct blockers, and all five hold.

| Finding | Verified | Resolution |
| --- | --- | --- |
| **Claude B1 and Codex 3**: U43 asserts that a second registration does not hash again, and §13.7(d) understates the cost; `served_without_indexing` does not return the prepared index | Yes. Each base name has its own index folder (`daemon.rs:384-386`), handed to the preparation child as `--index-folders` (`process.rs:41-52`, `:148-158`). The index is `<folder>/<escaped archive path>.index.sqlite` (`location.rs:645-660`). The digest is a row in that one file: `cached_for_stamp` consults only `cache_target(index)` (`digest_cache.rs:584-610`). `create_base` refuses an existing name (`daemon.rs:467-471`), so a second registration is a new name with a new index. `served_without_indexing` returns `index: None`, and the prepared file is its separate `sidecar_candidate` (`factory.rs:4633-4646`). | §6.6: the index is the `sidecar_candidate`; there is no reuse across names, and the cost is one full hash per registered base name on top of that name's index build. U43 now asserts that the second name's own index also holds the digest. §13.7(d) restates the cost for Keystone, capped at one extra `--timeout` window. |
| **Codex 1**: the post-`Ready` check cannot see an A→B→A swap | Yes. The child builds its records from what it read when it opened each lower (`lower_stack.rs:196-208`), and its layer snapshots rows at construction (`overlay_layer.rs:45-47`). Identities that match before spawn and after `Ready` do not prove the child took A. Revision 7 compared the child's records only at finalize, after `new` had reported success. | §10 #3 check 2: after `Ready`, before `new` returns, the supervisor asks each child for its records through a new inspection command `lowers` (`Mounter::lower_records`), served from the mount's own connection with `WriteOverlay::meta_value("lower_layers")` (`write_overlay.rs:3293-3298`). Every position's `layer_digest` and `sealed_at` must match the snapshot; a mismatch is `lower_changed` and the batch is rolled back. U47 is the A→B→A regression, including the rollback. The child's own two-open window is documented as a residual. Lands in step 3. |
| **Codex 2**: `forget` leaves memory and disk disagreeing when a parent fsync fails after its rename | Yes. Sweep 7's order removed the `retained` entry only after both fsyncs, so a failed fsync left memory naming a `retained/ID` that had already moved to `attempts/ID`. | §6.7: the entry moves to a new `forgetting` set immediately after a successful rename. A failed fsync or deletion returns `io`; a retry of `forget` resumes at the fsyncs without a restart; a restart's `reconcile` deletes the leftover (K10). `forgetting` is listed by v2, hidden from v1, refused by `diff`/`stats`/finalize/`destroy {id}`/use as a lower, skipped by `destroy {base}` and `shutdown`, and keeps its `--max-retained` slot (§4.3, §4.5, §6.4, §6.6, §10 #1). U45 injects each failure. |
| **Codex 4**: the interface cannot supply `mount_exit` for an attempt reaped earlier | Yes. `ProcessMounter::poll` reaps an exited child and discards its `ExitStatus` (`process.rs:205-207`), and sweep 7's `StopOutcome::Stopped` carried none. The child does return a journal writer's error as its exit status (`ratarmount-fuse/src/lib.rs:4015-4016`). | §6.4.1: an `exited: path → ExitStatus` map in `ProcessMounter`, filled by `poll`, `stop` and `cleanup`; `StopOutcome::Stopped { exit }` and a new `Mounter::exit_status(path)`. `journal_summary.complete` is `true` only for a known exit 0; unknown gives `mount_exit: null` and `complete: false`. U44 adds a worker reaped by `poll` before finalize. Lands in step 5. |
| **Codex 5**: U10's "orphan payload" fixture does not exercise repair | Yes. Host entries without a `files` row are normal COW content: fsck counts them as `unrowed` and never removes them (`overlay_fsck.rs:15-23`, `:347-350`). Usage before and after repair is the same, so U10 passed with the regression present. | §6.3 and U10: the repair case is nonempty host content at a tombstoned path, which repair unlinks (`overlay_fsck.rs:351-363`). U10 asserts that usage after repair is smaller and that the report keeps the before-repair value. Step 0(b) adds a golden for this case. |

**Non-blocking findings applied:**

- **Claude N1, proof that workers record `present`.**
  - F4 now reads the live mount root's `user.ratarmount.base_digest_state` right after `new`, before anything can seal (served for every `-w` mount, `ratarmount-fuse/src/lib.rs:916-922`, `:2637-2639`).
  - The finalize result gains `base_hashed_by_finalize` (§4.3). The report's `base_digest_state` is `present` after seal either way, so it proved nothing.
  - N1 also suggested `cached_archive_digest`. It canonicalizes and its reader is inventoried (`IR-B0419`), but it waits and hashes with `never_cancelled` (`digest_cache.rs:141-153`), which conflicts with N8's bound. The plan adds `cached_archive_digest_checked`, the same call with a `check` polled during the `HashGuard` wait and between chunks, and its own managed-read site in `ratarmount-index`, copying `PendingBase::hash` (`overlay_meta.rs:972-986`, `IR-B0154`). Sweep 7's `cached_archive_digest_cancellable_for_snapshot` was wrong: its contract needs a locked caller, a canonical path and a caller-supplied reader (`digest_cache.rs:235-248`).
- **Claude N2, U41 passed without the fix.** Confirmed: `recover_hot_journal` refuses a sealed or read-only overlay and writes nothing (`overlay_meta.rs:147-156`). U41's lower is now unsealed after `new`, with a hot journal; a control case shows the recovering read does roll it back.
- **Claude N3, the removal's chmod.** Confirmed: rustix's Linux backend returns `EOPNOTSUPP` for `chmodat(.., SYMLINK_NOFOLLOW)` (`rustix-1.1.5/src/backend/linux_raw/fs/syscalls.rs:123-137`), and `chmod_entry_at` refuses directories (`host_stat.rs:173-186`). New `host_stat::chmod_dir_at` in the reviewed `host_stat.rs` (`policy.json:116-120`): an `O_PATH | O_NOFOLLOW | O_DIRECTORY` pin, an identity check, and a chmod through `/proc/self/fd/N`, as `chmod_entry_at` does for files (`:198-233`). New inventory site (§6.11); test in U42.
- **Claude N4, where the barrier lives.** `sandbox/daemon.rs`, a reviewed N4 file, next to the commit rename (§6.4 step 6a, §6.11).
- **Claude N5, remote bases.** Remote, OCI, restic and torrent bases get `unsupported` for lowers, `retain` and finalize (§1). Classifying them in the daemon could download their bodies on every finalize and v2 `diff` (`ratarmount-remote/src/lib.rs:683-703`), and `served_without_indexing` gives none of them a local archive: it refuses remote URLs other than `file://` (`factory.rs:4610-4614`) and serves a torrent as a remote folder (`:4599-4608`).
- **Claude N6, a retry's `fsck_result`.** Kept with `bytes_written` from the first try (§6.3); U30 asserts both. The new `base_hashed_by_finalize` is kept the same way, because a retry over a sealed top would read the digest as `present`.
- **Claude N7.** Resolved with Codex 4.
- **Claude N8 and Codex 6, the registration hash's bound.**
  - It gets its own extra `--timeout` window. `check` fails past that window or once SIGTERM was requested (`overlay_commit::term_requested()`), during the `HashGuard` wait and the hash.
  - Cut short means skipped, never failed. Only the final checkpoint after a written row can fail `create_base` (§6.6).
  - Codex 6 proposed the preparation's remaining deadline. That would make registrations of large archives that succeed today fail, a v1 regression, so the plan does not share it.
  - U46 tests a held digest lock, a cancelled hash and an unreadable archive. Step 9 times registration.
  - The §2 callout (point 6) and §7 now say that `create_base` takes the index `HashGuard`, holding only `daemon.lock`, with a bounded wait.
- **Claude N9, Python paths.** The finalize result carries `attempt` (an `AttemptV2` with its final `path`, `overlay_dir` and `status`), and the client updates from it (§4.3, §6.10, P6).
- **Claude N10, docs.** `README.md:260` gains `finalize` and `forget`. `docs/local-ai/index.md:87-92` and `docs/sandbox.md:2370`'s "caps total retained attempts" are on §12's list, with the new wording.
- **Claude N11, retry pace.** `docs/sandbox.md` asks for at least 1 s between `writers_active` retries, doubling to 30 s; the message says so; step 9 measures one scan (§10 #6).
- **Claude N12, U16's resolver.** `Mounter::bundle_resolver(&self) -> Arc<BundleResolver>`. The handle is owned because the `classify` closure borrows the mounter mutably during the same finalize (§6.3).
- **Claude N13, consistency.** The header and crate list are fixed. Step 1 returns `invalid_request` for `retained_damaged` and `forgetting`. `unsupported` is decided at `new` for `lowers` and `retain`, so no retained slot is wasted. `docs/sandbox.md` notes that a v1 `destroy {base}` destroys mid-finalize v2 attempts. Step 0d item 6 notes Ubuntu's AppArmor user-namespace restriction; the throwaway workflow lifts it for that case only.
- **Claude N14, the estimate.** Re-estimated at 15-19 days (18.5 per step), with three items that can slip without breaking the gate: the digest caching, F6b's Docker variant and the timing test (§9).
- **Codex 7, bundle positions.** After `Ready`, the child's resolved digest at each bundle position must equal what the layer above recorded there: its `lower_layers` row for an external layer, or `record.json`'s new per-lower `layer_digest` for a retained one (§5, §6.2 item 5). U33 and U47 cover it.
- **Codex 8, the holder premise.** A grading layer closes its database after construction (`overlay_layer.rs:45-47`, `:177`) and opens host files only per reader, so an idle grading mount holds no descriptor. The claim is removed; unmounting before `forget` is stated as essential (§6.7, §12). F7 checks that an active reader makes `forget` return `in_use`. That rests on the FUSE server keeping each open's reader in its handle table (`ratarmount-fuse/src/lib.rs:1414-1441`), which for a file the layer wrote is the host `File` (`overlay_layer.rs:548-551`), so the descriptor lives as long as the reader's open.

**Also in this sweep:**
- The finalize table's step 8 and §6.11 still named `renameat2`; both now name `rustix::fs::renameat_with(…, RenameFlags::NOREPLACE)`, as §10 #2 already did.
- K10 is added for a crash inside `forget`.
- The before-merge commands gain `regression_chmod_dir_at` and `regression_checked_archive_digest`.
- §4.5 names `forgetting` next to retained attempts in what v1 `destroy {base}` and `shutdown` skip. §6.2 item 5 says which check answers `invalid_request` (before the mount) and which `lower_changed` (after `Ready`).

**Superseded by this sweep:**
- revision 7's "registering an already-hashed archive again costs nothing" and U43's "does not hash it again";
- sweep 7's choice of `cached_archive_digest_cancellable_for_snapshot`;
- sweep 7's by-name `fchmodat` restore (its Claude N6 line above);
- §6.7's claim that a grading mount keeps the layer's database open;
- the count-only check at bundle positions;
- U10's orphan-payload fixture and U41's sealed-lower fixture;
- sweep 7's `forget` order, which updated memory only after both fsyncs;
- the 9-11-day estimate.

**Status after sweep 8.** The Keystone decisions are unchanged: §13.5 before step 6; §13.7(a) before step 3; §13.7(b), (c) and (d) before step 5, with (d)'s cost now stated as one hash per registered base name, capped at one extra `--timeout` window and skipped rather than failed; §13.8 for information. Step 0d is unchanged apart from item 6's AppArmor note, and must still confirm §6.4.1's reasoned kernel claims before step 5 lands.
