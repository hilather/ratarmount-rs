# Local AI R1a: supervisor protocol v2 dispatch, request IDs and the v1 golden

**Status:** plan, not started (2026-10-31). Revised after sweeps 1–4 (§9). Baseline `main` at `2b96837739bd25bc41b1b5f6d5ad815ae9e8d20f` (v0.1.36 workspace). Branch `plan/localai-r1a-v2-dispatch`.
**Source:** `source-plan-doc.md` §4 (R1), only its "Protocol" and "Request IDs" parts and acceptance tests 1–3 (`source-plan-doc.md:77`, `:124-131`, `:141-143`). Matt approved Keystone's split of R1 into R1a/R1b/R1c on 2026-10-31, 5:06 PM ET, each with its own gate. This file is R1a.
**Scope rule** (Matt, 2026-10-31, 5:23 PM ET): "we only need to keep the scope limited to the sandbox features, not every feature ratarmount-rs supports". R1a supports and tests only the sandbox supervisor path; every other request field or operation is refused with `invalid_request`.
**Reference:** the blocked R1 plan (`ratarmount-rs-localai-r1`, `docs/tasks/plans/localai-r1-supervisor-v2.md` @943e0fce) and its last review (`rrs-localai-gate/skeptic-9.md`, `codex-9.md`).
**Gate:** every `AGENTS.md` CI command and both internal-read policy scripts before every commit; the before-merge commands in §7; an `AGENTS.md` regression-catalog row for every new test filter.
**Files touched:** `ratarmount/src/sandbox/{protocol,daemon,mod,tests}.rs`, new `ratarmount/src/sandbox/requests.rs` and `requests_tests.rs`, new fixtures `ratarmount/src/sandbox/testdata/{v1-golden,cli-v1-requests}.jsonl`, `ratarmount/tests/sandbox.rs`, `clients/python/ratarmount_sandbox.py` and its test, `packaging/internal-read-clippy/manifest.json`, `docs/sandbox.md`, `docs/recipes/swe-bench-sandboxes.md`, `docs/tasks/beyond-parity-roadmap.md`, `CHANGELOG.md`, `AGENTS.md`. No other crate changes.
**Effort:** about 5 days. The previous plan's per-step estimates for the same pieces (`localai-r1-supervisor-v2.md:750-762`) give protocol v2 1 day and the request log 2 days. R1a's share of the golden harness is about 1 day, and its shares of CLI/Python and of the docs about 0.5 day each.

---

## 1. Goal

Make the supervisor's `new` retry-safe without changing a byte of protocol version 1.

1. Version-2 requests are dispatched separately. Version 1 stays byte-for-byte strict, and a golden transcript generated from the baseline code proves it (Keystone #7).
2. A v2 `new` may carry a `request_id`. A retry with the same ID and the same body never starts a second batch. The same ID with another body is `idempotency_conflict`. Records survive restarts and compaction (Keystone #5, #6 at the request-ID layer; sweep 4 B1).
3. Every response carries its request's version. The integration-test helper `Daemon::envelope` sends the version it is given and asserts the answer's version, so v2 tests really send v2 (old blocker 6, `codex-9.md` #5).

## 2. Scope

- `protocol.rs`: `VERSION_2`, `OperationV2` (the v1 operations; `new` also accepts `request_id`), parse errors that carry the version to answer with, version-aware responses.
- `daemon.rs`: `respond()`, shared by `serve` and the tests; the request-ID layer for v2 `new`; attempt-ID reservation; restart resolution of an interrupted request.
- `requests.rs`: the `requests.jsonl` append log with compaction.
- CLI `sandbox new --request-id ID`; Python `RatarmountSandbox.new(..., request_id=...)`.
- Tests: the v1 golden, v1 request-byte fixtures for the CLI and Python client, unit tests with the Fake `Mounter`, one SIGKILL re-exec test, the version-aware `Daemon::envelope` and real-socket v2 tests.
- Docs, CHANGELOG, `AGENTS.md` rows and internal-read manifest entries for the above.

## 3. Out of scope

- **R1b:** layered spawn (`lowers`), per-attempt journal, lower validation, bundle stack checks, `SpawnSpec`.
- **R1c:** the `finalize_top` refactor, `finalize`, `forget`, `retain`, `retained/`, restart recovery of retained attempts, request IDs on `finalize` (including the `writers_active` retry), the R5 docs.
- **R2–R4:** tensor manifest, expert repack, Python `readinto`/`read_many`.
- **Digest caching** (`.digest-lock`, `overlay_base_digests`, hashing at `create_base`): cut entirely, not deferred.
- Everything in the source doc's §9.
- **Attempt-level `allow_globs`** (in the source doc's v2 `new`, `source-plan-doc.md:87`). Keystone's split names it in none of R1a, R1b or R1c. It would loosen the base's read-only policy, which the supervisor forbids ("Attempt policy can only tighten the base policy", `daemon.rs:621`; `docs/sandbox.md:2335`). It stays refused until Keystone assigns it to a slice.
- Request IDs on any operation other than `new`, and every v2 field not named in §5.1. R1a refuses them through `deny_unknown_fields` with `invalid_request` in a v2 envelope.
- Coverage outside the sandbox supervisor path: other archive formats, mount modes, the HTTP/WebDAV/NFS frontends, tensors, the `ratarmount_rs` Python bindings. A review request for such coverage is recorded here, not planned.
- CI wiring for the Python client tests. No workflow runs them today; the `AGENTS.md` catalog runs them by hand (`AGENTS.md:462`). The `check` job has no pytest installed, and its 45-minute budget is pinned (`packaging/internal-read-clippy/test_ci.py:22-24`). R1a keeps the hand run, and the PR records its output as a merge requirement (§7).
- **Whether R1c's log lines stay readable by an R1a daemon.** R1a refuses unknown `v`, `t` or `op` (§5.5), and Risk 5 documents the downgrade recovery. R1c may instead choose an encoding R1a can read as an opaque binding.
- The seal lock-order note ("seal takes only the overlay root flock, then its database transaction, no archive lock", `ratarmount-compositing/src/overlay_seal.rs:276`) is not carried. R1a seals nothing and takes no overlay or archive lock; its only lock is `daemon.lock`. The note belongs with R1c's finalize.

## 4. Code investigation (baseline `2b96837`)

| # | Evidence | Consequence for R1a |
| --- | --- | --- |
| 1 | `protocol.rs:7` `VERSION = 1`. `Request::parse` removes `version` and refuses anything except the integer 1 with `unsupported_version`, "version must be 1" (`:90-98`). It returns `Result<Self, ApiError>` (`:91`), so an error carries no version. | Parse must return the version to answer with (skeptic-9 N9). |
| 2 | `Operation` is `tag = "op"`, `deny_unknown_fields` (`protocol.rs:38-77`). A v1 `new` carrying `request_id` or `lowers` is `invalid_request` today. | `Operation` stays unchanged; the golden pins both refusals. |
| 3 | `Response::from_result` always writes `VERSION` (`protocol.rs:156-173`). `send` replaces an oversize reply with a v1 `response_too_large` (`daemon.rs:869-877`). | Responses take a version; the substitute keeps the reply's version. |
| 4 | `serve` handles one line as `Request::parse(..).and_then(\|r\| supervisor.handle(r.operation))`, then `send(.., Response::from_result(result))` (`daemon.rs:934-943`). Unterminated input over 1 MiB is answered at `:945-951`. Requests are serial; `daemon.lock` is held for the supervisor's whole life (`:319`). | One per-line function, `respond()`, for `serve` and the golden. No locking beyond `daemon.lock`. |
| 5 | `new_attempts` checks the base (`daemon.rs:614`), capacity (`:615-620`), merges policy and checks globs (`:622-634`), sets up the RAM root (`:635-638`), then per attempt draws an ID and spawns (`:643-673`), polls readiness (`:674-704`) and rolls back on error. A failed rollback keeps attempts and only names them in the message (`:710-724`). | Kept attempt IDs must be reported in structured form. `new_attempts` is otherwise not restructured (row 16). |
| 6 | IDs come from `tempfile::Builder::new().prefix("attempt-")…tempdir_in(attempts/)` (`daemon.rs:647-655`). tempfile 3.27.0 (`Cargo.lock:6787-6788`) draws 6 random characters (`tempfile-3.27.0/src/lib.rs:195`) and avoids only names that exist in `attempts/`. | IDs named by request records need their own reservation (§5.6). |
| 7 | `Supervisor::open` (`daemon.rs:313-382`) takes `daemon.lock` (`:319`). `reconcile` deletes every `attempts/*` and RAM attempt (`:398-431`). Attempts live only in memory (`:303`). | After a restart, every attempt a `new` record names is gone; replays still return the original answer (§5.3). |
| 8 | `atomic_json` writes a temp file, `sync_all`, renames it and fsyncs the directory, on every call (`daemon.rs:282-298`). | Cost basis for Keystone #5 (§5.5). |
| 9 | `lock` (`daemon.rs:80-125`): 0600, `O_NOFOLLOW\|O_CLOEXEC`, `truncate(false)`, then owner/type/mode/`nlink` checks on the descriptor, with four reviewed expectations. | Pattern for the log's checked open. |
| 10 | CLI `run` builds the operation (`mod.rs:107-139`); `call` sends `Request{version: VERSION, operation}` and rejects any response version other than 1 (`:163-192`, check at `:188-190`). `--max-attempts` is at most 4096 (`:43`). | `call` becomes version-aware. U3 drives `run` end to end against a recording listener. |
| 11 | Python: `_VERSION = 1` (`clients/python/ratarmount_sandbox.py:12`), `_call` rejects any other response version (`:94`), `new` at `:108-113`, the docstring says v1 (`:1-6`). The test's fake daemon always answers version 1 (`clients/python/tests/test_ratarmount_sandbox.py:64`), and the test asserts every request is v1 (`:95`). | Version-aware `_call`; the fake echoes the request's version. |
| 12 | `Daemon::envelope` sets `request["version"] = json!(1)` on every request (`ratarmount/tests/sandbox.rs:61-62`). A v2 request through `call`/`envelope` therefore goes out as v1 with an unknown field. | Old blocker 6 (§7, I1). |
| 13 | A corrupted prepared index makes `new` fail with `mount_failed` before any FUSE work, on every host (`tests/sandbox.rs:466-528`; the message never names `/dev/fuse`, `:518`). A crashed child is rolled back completely, because `cleanup` detaches only real mountpoints (`process.rs:224-246`). | A deterministic `retryable` outcome over a real socket without FUSE (I3). |
| 14 | `regression_protocol_rejects_unknown_fields_and_versions` asserts `{"version":2,"op":"list"}` is `unsupported_version` (`ratarmount/src/sandbox/tests.rs:124`) and calls `Response::from_result` (`:136`). `regression_base_allow_globs_optional_v1` destructures `parsed.operation` (`:484`). Every other test calls `supervisor.handle(Operation::…)` (for example `:103`, `:204`). `setup()` uses a 250 ms timeout (`:101`). | The version-2 line moves to version 3. Two tests adapt mechanically. `handle(impl Into<Op>)` keeps the other calls unchanged. The SIGKILL test needs its own long timeout. |
| 15 | `ratarmount_index::test_process::{spawning, exclusive}` (`ratarmount-index/src/test_process.rs:23`, `:30`). Reopen tests take `exclusive()` (`tests.rs:313`). The re-exec test takes `spawning()` and tells the child its role through `RATARMOUNT_SANDBOX_SOCKET_TEST`, read only in test code (`:360-375`). | Same guards and re-exec pattern for the SIGKILL test. |
| 16 | **Internal-read.**<br>- **Disallowed:** the `std::fs::OpenOptions` type, `OpenOptions::{new, create, open}`, `File::open`, `fs::read`, `NamedTempFile::new_in`, `tempfile::Builder::tempfile_in` (`packaging/internal-read-clippy/clippy.toml:87,129,135,143,145,152,158,229`).<br>- **Pinning:** every manifest entry is pinned by `item` and by `leaf_digest`, a SHA-256 of the covered statement's normalized tokens (`compiler/internal_read.rs:364-376`, `:466-476`), and any difference fails `policy.py` (`policy.py:393-399`). `new_attempts` holds two such sites: `IR-B0112-M01` (`tempdir_in`, `manifest.json:376-403`) and `IR-B0113-M01` (`File::open` of `mount.log`, `:404-432`).<br>- **Target predicates:** the only reviewed target-predicate files in the sandbox are `daemon.rs`, `process.rs` and `run.rs` (`policy.json:530-545`).<br>- **IDs:** the highest inventory ID is `IR-E0142` (`manifest.json:10562`). Append-log precedent: `IR-E0050`, `OpLog::open`, `append-or-create` (`manifest.json:4331`).<br>- **Root config:** the root `clippy.toml` (ordinary all-targets Clippy) disallows no filesystem call. | **New sites:** six new expectations, all in `requests.rs`, with no target predicate (§5.8).<br>**Existing sites:** both `new_attempts` statements must stay token-identical inside `new_attempts`. |
| 17 | The `check` job runs `cargo test --workspace` (`.github/workflows/ci.yml:102-105`). The macOS job does too (`ci.yml:481`). `tests/sandbox.rs` is Linux-only (`:2`). `Supervisor::open` canonicalizes the state root (`daemon.rs:315`), so `/tmp` becomes `/private/tmp` on macOS. | New unit tests must run on macOS as well; golden placeholders must use the canonical root. |
| 18 | A non-`git` diff prints raw file modes: `new file mode` and `old mode`/`new mode` use `entry.mode` unless `git` is set (`ratarmount/src/diff/patch.rs:354-359`, `:374-381`). `render_source` takes the `live::changes` branch when `deleted` is `Some` (`diff.rs:516-518`), the path `regression_live_diff_and_stats_do_not_reopen_locked_database` relies on (`tests.rs:588-658`). | The golden sets explicit fixture modes, and its `diff` succeeds through the Fake's deletion list without an overlay database. |
| 19 | `docs/sandbox.md`: protocol v1 at `:2279-2353`, error codes at `:2347-2351` ("Messages provide context and may change"), "There is no request deduplication" at `:2415-2420`, Python client at `:2422-2449`. The SWE-bench recipe says "Do not blindly repeat `new` after a client timeout" (`docs/recipes/swe-bench-sandboxes.md:124-125`). Roadmap row: `docs/tasks/beyond-parity-roadmap.md:297`. | Doc edits (§5.9). |
| 20 | serde_json 1.0.151 (`Cargo.lock:6321-6322`); `sha2` is already used by `daemon.rs:6`. `packaging/test-no-test-hooks-in-release.sh` scans the release binary for `RATARMOUNT_TEST_` strings (`:10-14`). | No new dependency. Test seams add no such string. |
| 21 | serde 1.0.229 (`Cargo.lock:6268-6269`) deserializes an internally tagged **unit** variant by draining and ignoring every remaining key (`serde-1.0.229/src/private/de.rs:2990-2996`). `deny_unknown_fields` therefore does not apply to v1's `Shutdown` (`protocol.rs:76`). `{"version":1,"op":"shutdown","x":1}` shuts the daemon down today. | v2's `shutdown` must be a struct variant (§5.1). v1 keeps the leniency, and the golden pins it. |

## 5. Design

### 5.1 Versions and dispatch (`protocol.rs`)

- `VERSION = 1`, `Operation`, `BaseOptions`, `Base`, `Attempt` and `ApiError` do not change.
- New `VERSION_2 = 2` and `OperationV2` (`tag = "op"`, `rename_all = "snake_case"`, `deny_unknown_fields`) with `create_base`, `new`, `list`, `diff`, `stats`, `destroy` and `shutdown`. Fields and defaults are the v1 ones.
- **`shutdown` is an empty struct variant** (`Shutdown {}`), not v1's unit variant. Serde ignores extra keys on an internally tagged unit variant (row 21), so a copied unit variant would execute `{"version":2,"op":"shutdown","request_id":"r"}` instead of refusing it (Codex sweep 4 B1). The struct variant gets `deny_unknown_fields` like every other operation and serializes to the same `{"op":"shutdown"}`. v1's `Operation::Shutdown` stays a unit variant, with its leniency. Step 2 adds an optional `request_id` to `new`, never serialized when absent. A present `request_id` must be a string. `"request_id": null` is `invalid_request`, not "no ID", so a hand-written client cannot believe it is protected when it is not. The mechanism is `#[serde(default, deserialize_with = …)]` with a function that deserializes a `String` and wraps it in `Some`. An absent key takes the default `None`; `null` fails as a non-string. (`quota`, by contrast, accepts `null` today, `protocol.rs:53-54`.)
- `Request` keeps `version` and flattens an `Op`, an untagged enum of `V1(Operation)` and `V2(OperationV2)`. Only serialization uses that derive; `parse` chooses the variant itself. `From<Operation> for Op` exists. U3 proves that the CLI's v1 bytes do not change.
- `Request::parse` returns either the request or a rejection that carries the version to answer with:

| Input | Answer version | Result |
| --- | --- | --- |
| Not valid JSON | 1 | `invalid_request` with serde's text (unchanged) |
| `version` missing, not an integer, or not 1 or 2 (including `"1"` and `1.0`) | 1 | `unsupported_version`, "version must be 1": the unchanged bytes, pinned by the golden. Clients key on the code, as `docs/sandbox.md:2350-2351` already says. |
| `version` 1 | 1 | Parsed as `Operation`; errors are `invalid_request` (unchanged) |
| `version` 2 | 2 | Parsed as `OperationV2`; an unknown field or operation, or a missing field, is `invalid_request` |

- `Supervisor::handle` takes `impl Into<Op>`. A `V1` operation runs today's code unchanged. A `V2` operation other than `new` is mapped to the same `Operation` and runs the same code, with an identical result. A v2 `new` without `request_id` is a v1 `new`. With one, it goes through §5.3.
- R1b and R1c add their fields and operations to version 2. Until then, R1a refuses them, which keeps an older daemon failing closed on a newer client.

### 5.2 Response versions and `respond()`

- `Response::from_result(version, result)`.
- New `respond(&mut Supervisor<M>, line) -> Vec<u8>`. A line over 1 MiB gets today's v1 `invalid_request`. Otherwise it parses, handles, builds the response with the version from the parse, and encodes it.
- `encode(response, limit)` is `send`'s current serialization: serialize; if the bytes plus newline exceed `limit`, substitute `response_too_large` **with the response's own version**; append `\n`. `send` only writes. `serve` calls `respond`. The unterminated-oversize path (`daemon.rs:945-951`) builds its v1 error through `encode` too.
- Net rule: a reply sent before a version 1 or 2 is known is version 1; every other reply carries the request's version.

### 5.3 The request-ID layer (v2 `new` with `request_id`)

Everything runs in the serial serve loop under `daemon.lock`. The rules are the source doc's (`source-plan-doc.md:124-131`) with Keystone #6's `retryable` state as the previous plan resolved it (its §6.5 and §10 #6).

1. Parse as in §5.1. `request_id` must follow the base-name rules (`daemon.rs:23-36`): 1–128 characters, an ASCII letter or digit first, then letters, digits, `.`, `_` or `-`. Otherwise `invalid_request`, and nothing is recorded.
2. Compute `op_hash` (§5.4).
3. Look up the ID among live records:
   - another `op_hash`, in any state: `idempotency_conflict` (also while the log is `Broken`);
   - `done`, same hash: the stored result, without doing anything (`source-plan-doc.md:127`). The response bytes equal those of the first response that was delivered. After an `io` answer (§5.5, `Broken`), the stored outcome can be one the client never saw;
   - `failed`, same hash: the stored error;
   - `running`, same hash: possible only while the log is `Broken` (§5.5): `io`;
   - `retryable` or no record: continue.
4. Append `running` with `fdatasync` before the request runs, so before any attempt directory or child exists (`source-plan-doc.md:126`).
5. Run `new_attempts` (today's validation, loop, readiness poll and rollback), with the stored-record preflight (§5.5) and the ID reservation (§5.6). It also returns, in structured form, the IDs a failed rollback kept; its v1 error text does not change.
6. Append the outcome, then answer:

| Outcome | Line appended | A retry with the same ID and body |
| --- | --- | --- |
| Success | `done`, with `attempts` and `result` | Gets the stored result |
| Refused before any attempt existed (unknown base, `capacity`, a bad glob, no tmpfs, the preflight) | `retryable` | Runs again |
| Error with nothing left (complete rollback after `spawn_failed`, `mount_failed`, `timeout`, or `io` in the loop) | `retryable` | Runs again |
| Error after a rollback that kept attempts (`daemon.rs:717-722`) | `failed`, with the kept `attempts` and the error | Gets the stored error |

7. Check for compaction (§5.5).

A `request_id` is bound to the body it first arrived with for as long as its record lives, refusals included. A client that changes the body uses a new ID.

**Restart.** In `Supervisor::open`, after `reconcile` has discarded every attempt:
- Every record whose last line is `running` was cut off. Its attempts, if any, were discarded by `reconcile`, so the supervisor appends `failed` with code `interrupted` (`source-plan-doc.md:129`): "request was cut off by a supervisor restart before it finished; any attempts it created were discarded; retry with a new request_id". Each such line copies `op` and `op_hash` and is its own append (write and sync). Requests are serial and appends stop once the log is `Broken`, so there is at most one such record, but the rule does not depend on that.
- A surviving `running` line can also come from a request that never ran: a failed `running` append whose truncation failed too (§5.5). The message holds for that case. The ID becomes terminal even if it was a re-run of a `retryable` record; that is conservative, because no second batch can start.
- `done`, `failed` and `retryable` records stay as they are. A replay after a restart returns the original answer byte for byte, even though `reconcile` has deleted the attempts it names. This is the source doc's rule and the previous plan's resolution (its §13.6): a replay reports the original result, not the current state, and callers use `list` for that. The docs say so.

**Keystone #6, at the request-ID layer.** A retry under the same `request_id` with the same body is idempotent: `done` and `failed` replay, and `retryable` re-runs until it reaches `done` or `failed`. A different body is a conflict in every state. R1c adds `finalize` to the same layer by adding an operation kind and its outcome classification; R1a defines no finalize behaviour.

### 5.4 `op_hash`

- `op_hash` is `"sha256:"` followed by the lowercase hex SHA-256 of `canonical(V)`.
- `V` is `serde_json::to_value` of the **typed** `OperationV2`, so serde defaults are already applied. `request_id` is removed, as is every **top-level** member equal to that field's typed default (for R1a's `new`: `count` 1, `overlay` `"disk"`, `quota` null, `readonly_globs` empty). `"version": 2` is added.
- **Nested values are hashed whole,** with their own defaults applied and nothing removed. So for R1b's `journal: Option<JournalSpec>`, `Some({})` (which serializes its defaults) never hashes like the default `None`.
- **Why omit defaults.** The previous plan hashed defaults in (its §10 #4). R1b and R1c add defaulted fields to v2 `new` (`lowers`, `journal`, `retain`). With defaults hashed in, a record written by R1a would conflict with its own same-body retry after an upgrade. With them omitted, a request shaped like R1a's hashes the same in every later release. U5's golden digest constant holds R1b and R1c to that.
- `canonical` writes object members sorted by their UTF-8 key bytes at every depth, keeps array order (reordered `readonly_globs` are a different request), writes no whitespace, and uses serde_json's own scalar encoding. Because the writer sorts keys itself, the hash does not depend on serde_json's `preserve_order` feature.

### 5.5 `requests.jsonl`: append log with compaction (Keystone #5)

**Why not `requests.json` with `atomic_json`.**
- An attempt object is about 250 B: a 14-byte ID, a base name of up to 128 bytes, two state paths and a status. A `new` with `count` 8 stores about 2.3 KB.
- `atomic_json` rewrites the whole file and syncs file and directory on every call (`daemon.rs:282-298`). One request needs two calls (`running`, then the outcome).
- With a table at the 64 MiB cap, that is about 128 MiB written and four syncs per request, inside the single-threaded serve loop. 10,000 such requests would rewrite about 1.3 TB.
- The append log writes two lines per request (about 0.2 KB, then the outcome) with two `fdatasync`s. Those 10,000 requests append about 25 MB. Compaction adds less than that again (below).

**Format.** One JSON object per line, schema version `v: 1`:

```text
{"v":1,"id":"r1","t":"running","op":"new","op_hash":"sha256:…"}
{"v":1,"id":"r1","t":"done","op":"new","op_hash":"sha256:…","attempts":["attempt-a1B2c3"],"result":[…]}
{"v":1,"id":"r2","t":"retryable","op":"new","op_hash":"sha256:…"}
{"v":1,"id":"r3","t":"failed","op":"new","op_hash":"sha256:…","attempts":[],"error":{"code":"interrupted","message":"…"}}
```

- **Every line is self-contained** (sweep 4 B1). `op` and `op_hash` are on every state, so a record's last line alone decides it, before and after compaction.
- No `seq` field. File order is the order, compaction keeps it, and nothing read the previous plan's `seq`.
- The parser is keyed on `t` (one variant per state). `attempts` and `result` are required on `done`, `attempts` and `error` on `failed`, and each is refused on any other state.
- A line that is valid JSON but has an unknown `v`, `t` or `op`, or a missing or extra field, is a schema error. A later change to the line schema bumps `v`.

**Open.** In `Supervisor::open`, after `daemon.lock` and the private directories (`daemon.rs:319-321`) and the state loads, before `reconcile` (`:380`):
1. **Checked open** of `state/requests.jsonl`, creating it if missing: read, append, `truncate(false)`, mode 0600, `O_NOFOLLOW|O_CLOEXEC`. Then check on the descriptor: a regular file, owned by the effective uid, `mode & 0o077 == 0`, `nlink == 1`, as `lock` does (`daemon.rs:107-117`). The file is created eagerly, so the log is always open.
   - An open error is `io`; a symlink fails with `ELOOP` under `O_NOFOLLOW`.
   - A descriptor that fails a check is `unsafe_path`: "requests.jsonl must be a private, owned regular file".
   - Either refusal comes before `reconcile`, so existing attempt data stays untouched (U16).
   - Open's own later writes to the log (the torn-tail truncation and the syncs) also come before `reconcile`. They are idempotent, so a start that `reconcile` then refuses leaves the log consistent.
2. **Sync before acting:** `sync_all` on the file, then fsync the state directory, before anything in the file is acted on. That makes durable whatever a killed daemon left visible but unsynced: a line whose `fdatasync` never ran, a compaction rename whose directory fsync never ran, or the file's first creation. This is the request-log half of codex-9 #2. If either sync fails, the start is refused with `io` naming the file, before `reconcile`.
3. **Read** through the same descriptor, one line at a time with a bounded line reader. Memory at open is the capped live set plus one line buffer, however much obsolete history the file holds. The file can outgrow the caps while compaction keeps failing before its rename.
   - **Line bound:** the per-record cap plus 512 KiB. That covers every line R1a writes:
     - a `done` line is at most the per-record cap (the preflight);
     - `running`, `retryable` and `interrupted` lines are a few hundred bytes;
     - the largest `failed` line is about 185 KB. It holds up to 4,096 kept IDs twice, once in `attempts` (about 70 KB) and once in the "retained attempts" message (`daemon.rs:717-722`, about 66 KB), plus an 8 KiB `mount.log` excerpt (`:678-691`) that JSON escaping can grow to 48 KiB.
   - **Torn tail:** every append is synced before the next starts, so only the last line can be physically damaged. A last line that lacks `\n`, is not valid JSON (a short write, or zero-filled pages after a crash) or exceeds the line bound is torn. It is truncated away (`set_len`, then `sync_data`). If the truncation fails, the start is refused with `io` naming the file, before `reconcile`.
   - **Refusal:** a damaged line before the last, or a schema error anywhere, refuses the start with `invalid_request`, naming the file and byte offset: "move it aside to start without request records". A crash cannot produce valid JSON with a wrong schema; that comes from corruption or a later release (Risk 5).
4. **Replay in file order** with the same rule appends use (below). Each line replaces its ID's record, or creates it, and makes it the newest. Then the oldest finished records, other than that one, are evicted until both caps hold. The live set and the reserved IDs (§5.6) come out of this replay; nothing else is kept.
5. Remove leftover compaction temp files: names `requests.jsonl.*.compact`, regular files only, checked with `symlink_metadata`. A removal that fails is logged and ignored, because a leftover is harmless. `atomic_json`'s own `.tmp*` leftovers stay untouched, as today (skeptic-9 N16).

Then `reconcile` runs unchanged. Then the restart resolution of §5.3 appends one line per `running` record, each with its own `sync_data`. If such a write or sync fails, the start is refused with `io` naming the file, and the line is truncated away when possible. Nothing has been served yet, and the next start resolves the same record.

Compaction is not attempted at open. A failure after its rename would leave a daemon that has served nothing in the `Broken` state. The first outcome append checks for compaction instead.

**Append.** One `write_all` of the whole line, then `sync_data`. **Memory changes only after `sync_data` returns.** The record map, the completion order and any eviction are applied after the line is durable, so memory equals a replay of the file whenever the log is open. Only `Broken` can leave the two apart, until the next start.

**`Broken` state** (in memory only; from sweep 7, Codex 4 and 5):
- **A `running` append fails:** `set_len` back to the previous length and `sync_data`. If that works, the log stays open, the request fails with `io`, and nothing ran. Memory is exactly as before: a new ID still has no record, and a re-run keeps its `retryable` record with the same `op_hash` and position, so another body still conflicts.
  - **The truncation fails too:** the log is `Broken`, and the request still answers `io` without running. A complete `running` line may survive. The next start syncs it and resolves it to `interrupted` (§5.3), although nothing ran.
- **An outcome append fails** (write or sync, after `running` is durable): the log is `Broken`, the in-memory record stays `running`, and the request answers `io`. The line is truncated back to the `running` line when possible. Any attempts the request created stay until `destroy` or a restart, where `reconcile` discards them. What the next start finds depends on the truncation:
  - **Truncation worked, or the write never completed:** the file ends at `running`, or at a torn tail that open truncates, so the record resolves to `interrupted`.
  - **The write completed, and both the sync and the truncation failed:** the complete outcome line can survive. Open syncs it, and it decides as written: `done` and `failed` replay, and `retryable` runs again. The client was answered `io`, so such a replay can be an outcome it never saw (§5.3).
  - **No branch starts a second batch.** While `Broken`, a retry is refused. After the restart, `reconcile` has discarded the batch and a replay starts nothing. Only a `retryable` record, whose batch left nothing, runs again.
- **While `Broken`:** a request that would append (an absent or `retryable` ID) is refused with `io`: "request log unavailable since …: …; restart the daemon". Replays, stored errors and conflicts are still answered. Requests without `request_id`, and all of v1, are unaffected. This keeps at most one `running` record and stops a retry from starting a second batch.

**Caps.** A `Limits` value is passed to the log's constructor.
- **Where `Limits` comes from:** `Supervisor::open` keeps its signature, and its body is extended, not split. It takes `Limits` from `requests::limits()`. That returns the defaults, or, in test builds, a thread-local override a test sets before calling `open`.
- **Existing sites:** `IR-B0110-M01` and `IR-B0111-M01`, the `fs::read`s of `bases.json` and `ram-root.json` (`daemon.rs:322-356`), stay token-identical inside `open`, so their item and digest are unchanged. A shared `open_with(…, limits)` would move them. Step 2's `policy.py` run is the check, as it is for `IR-B0112-M01` (§5.6).
- **Log-level tests** construct the log directly.
- **Defaults:** at most 65,536 live records, 64 MiB of live last-line bytes, 4 MiB per stored record, and a compaction floor of 8 MiB. `Limits` refuses a per-record cap above the live cap.
- **Eviction:** after each durable append, the oldest finished records go first, ordered by the position of their last line, until both caps hold. The record just appended is never evicted by its own append, and neither is a `running` record (at most one exists). So even a `failed` line larger than a small test cap stays, as the newest record.
- **Reopen:** the replay in open step 4 applies this same rule line by line, so a reopen reproduces the in-memory set exactly. That includes an evicted ID later reused with a smaller result (Codex sweep 1 #1).
- **Changed `Limits`:** a release with different `Limits` keeps or drops different records. Either way it starts no second live batch, because a restart discards every attempt.
- **Retry window:** an evicted ID that is retried runs as a new request. That is the documented bounded retry window.

**Stored-record preflight** (from sweep 7, Codex 7, scaled to R1a).
- With a `request_id`, `new_attempts` computes the exact size of the future `done` line after the RAM root is known, before the attempt loop. It uses `count`, the fixed ID length and the known state and RAM paths. Above 4 MiB it refuses with `capacity`, so the record becomes `retryable`.
- Ordinary paths cannot reach the cap: 4,096 attempts at about 300 B is about 1.2 MiB. Only a very long tmpfs root (a long `$XDG_RUNTIME_DIR`) can, so U13 forces it with small `Limits`.
- Requests without `request_id` keep today's behaviour: only the 64 MiB response limit applies.

**Compaction.**
- Runs when the file is larger than twice the live bytes **and** larger than the compaction floor. It is checked only after an outcome append (never at open) and never runs while a `running` record exists.
- **Steps:**
  1. Write each live record's last line, byte for byte and in file order, to a temp file `requests.jsonl.XXXXXX.compact` in the state directory. The temp file is created with tempfile's `Builder::append(true)` (`tempfile-3.27.0/src/lib.rs:384`, `:555-569`). `create_named` then adds read, write, `create_new` and mode 0600 (`file/imp/unix.rs:13-27`).
  2. `sync_all` the temp file and `persist` it over `requests.jsonl`. `persist` hands back the temp file's own `O_APPEND` descriptor of the published inode, so no reopen and no `(dev, ino)` check is needed.
  3. Immediately mark the log `Broken` and drop the old descriptor.
  4. fsync the state directory.
  5. Only then switch to the persisted descriptor and mark the log open again.
- **Why `append(true)`:** without `O_APPEND`, a failed append's `set_len` would leave the file offset past the end. The next write would then leave a zero-filled gap, which the next start refuses as a damaged line before the last (U14).
- **Replay after compaction:** replaying the compacted file evicts nothing, because every prefix of a set within the caps is also within them.
- **Failures:**
  - A failure before the rename drops the temp file (tempfile removes it) and leaves the log open on the old descriptor.
  - A failed directory fsync after the rename leaves the log `Broken` until a restart.
  - After a power loss, either file is at the name, and both hold every live record, because nothing is appended during compaction.
  - The request whose outcome append triggered the compaction answers that durable outcome whatever happens to the compaction. Only later appends can be refused.
- **Backoff after a failure before the rename** (Codex sweep 4 N2): the next attempt waits until at least as many bytes as the live set have been appended since. Without this, a temp-file sync that keeps failing would rewrite the whole live set after every request, blocking the serve loop each time.
- **Cost** (amortized; Codex sweep 1 #5 corrected a per-compaction bound):
  - A successful compaction runs only when the dead bytes exceed the live bytes (the file is more than twice the live bytes), so it writes fewer bytes than it discards.
  - A line is discarded at most once: compaction copies only live lines, and a superseded or evicted line never becomes live again.
  - So successful compactions write less than everything ever appended: at most 2× write amplification, whatever the record sizes. Shrinking live sets (evictions) only make the next compaction smaller.
  - **Failed attempts** come in streaks between two successful compactions:
    - The first attempt of a streak writes less than the dead bytes that triggered it. Those bytes are discarded only once, by the next success, so streak-first attempts together write less than everything appended.
    - Every later attempt waits, because of the backoff, until as many bytes as it writes have been appended since the previous attempt.
    - So even a sync that keeps failing keeps total writes below 4× the appended bytes. With no failures the bound is 2×.

**Memory.** The live last lines (at most 64 MiB) are kept in memory for byte-identical replays and verbatim compaction, along with a map from ID to record and the reserved-ID set (§5.6).

### 5.6 Attempt IDs named by the log stay unique (sweep 5 B1, the R1a part)

- The reserved set is the union of `attempts` over every live record's last line. The replay rebuilds it at every open, so it survives restarts and compaction.
- **Redraw:** after `tempdir_in` creates `attempts/X`, a reserved `X` is removed (it is still empty) and redrawn. The redraw applies to every `new`, v1 included; it is invisible on the wire.
- **Exhaustion** (Codex sweep 3 B1): after 16 reserved draws in a row, the request fails with `io`: "could not allocate a unique attempt ID".
  - It fails like any other error inside the attempt loop. Drawing and spawning interleave per attempt (`daemon.rs:643-673`), so earlier attempts of the batch may already be spawned.
  - Today's rollback (`:710-724`) destroys them, and §5.3's table classifies the result: `retryable` when nothing is left, or `failed` with the kept IDs when a rollback kept attempts.
  - The exhausted draw itself leaves nothing, since its directory is removed before the attempt is recorded.
- **Placement:** the reviewed statement (`IR-B0112-M01`) keeps its exact tokens and appears exactly once, inside `new_attempts`:
  - It stays `let dir = tempfile::Builder…tempdir_in(…)?.keep();`, with its `#[expect]`. It does not become `let mut`, and it is not duplicated before the loop. Either would change the leaf digest or `multiplicity: 1` (`manifest.json:376-403`).
  - It is the first statement of a `loop` whose value is the accepted directory.
  - After it, a separate `#[cfg(test)]` statement may shadow `dir` with the test ID source's renamed path.
  - Then an unreserved `dir` leaves the loop. A reserved one is removed and the loop continues, counting toward the 16 tries.
  - `IR-B0113-M01` (`File::open` of `mount.log`) is not touched.
  - Step 0 and step 2 each run `policy.py`, which is the real check that both entries are unchanged (row 16). If an implementer still has to reshape either statement, its manifest entry is re-reviewed in that commit.
- **Why R1a needs it.** A replayed `done` or `failed` names attempt IDs, and tempfile avoids only names present in `attempts/` (row 6). Without the check, a later batch could redraw an ID a client has destroyed, and a replay would hand that client another request's attempt.
- The ID shape (`attempt-` plus 6 characters) is unchanged; lengthening it would shrink the `sun_path` budget, which v1 callers can see. R1c extends the reserved set with `retained/` and finalize records.

### 5.7 CLI and Python client

- **CLI.** `sandbox new --request-id ID` sends a v2 `new` with `request_id`. Without the flag, it sends exactly today's v1 bytes (U3).
  - `call` accepts a response whose version equals the request's. For a v2 request it also accepts a v1 envelope with `ok: false`: that is how an older daemon answers (`unsupported_version`). It is printed as the server error, with exit 1. Any other mismatch stays "unsupported response version".
  - No new subcommand, so `regression_help_states_exit_status` (`ratarmount/src/snapshot.rs:558-599`, which checks only `sandbox run` among sandbox verbs) is unaffected.
- **Python.** `new(base, count=1, overlay="disk", quota=None, readonly_globs=None, *, request_id=None)`.
  - With `request_id`, it sends `version: 2` and the field. Without it, the bytes are unchanged and the key is absent, never `null` (skeptic-9 N8).
  - `_call(op, version=1, **fields)` requires the same response version, except that a v1 `ok: false` envelope answering a v2 request raises `SandboxError` with its code.
  - **Implicit cleanup after a stale replay** (Codex sweep 2 B1):
    - **The failure today:** a replay after a restart returns attempts that `reconcile` deleted. `new()` adds them to `_owned` (`:108-113`). Leaving the client context then calls `close()`, whose `destroy` answers `not_found`, and `close()` raises it (`:135-143`). `Attempt.__exit__` raises the same way (`:47-57`).
    - **The fix:** the two implicit paths, `Attempt.__exit__` and `RatarmountSandbox.close()`, treat a `not_found` answer to `destroy` as already destroyed. They mark the attempt destroyed, drop it from `_owned`, and raise nothing.
    - **Unchanged:** an explicit `Attempt.destroy()` or `destroy(id=…)` still raises `not_found`, as it does today.
    - **Visible to v1 users:** this also stops a context from failing when another client destroyed one of its attempts. The CHANGELOG says so (P4, P5).
  - The docstring (`:1-6`) describes v1, v2 for request IDs, the new retry advice, and stale replays.

### 5.8 Internal-read inventory and N4

- `ratarmount/src/sandbox/requests.rs` is a new production file with **no** `cfg(target_os …)`; it is not a reviewed target file (`policy.json:530-545`). Like `daemon.rs`, it is Unix-only through its imports.
- New narrow `#[expect]` sites take the next free IDs (from `IR-E0143` at baseline). Each has a literal `internal-read:v1` reason and creation metadata, plus a reviewed `manifest.json` entry from `policy.py --collect` in the same commit:
  1. **The checked log open:** the `std::fs::OpenOptions` type, `OpenOptions::new`, `.create(true)`, and `.open`.
     - The `.create(true)` site uses policy `append-or-create`, with this basis: read and append, `O_NOFOLLOW|O_CLOEXEC`, 0600, `truncate(false)`, and owner/type/mode/`nlink` checked on the descriptor.
     - The pattern follows `lock` (`daemon.rs:80-106`) and `IR-E0050`.
     - It runs only at open. Compaction keeps the persisted temp file's descriptor instead of reopening.
  2. **The compaction temp file:** `tempfile::Builder::tempfile_in` (`exclusive-new-file`: tempfile's `O_EXCL`, `append`, mode 0600, inside the 0700 state directory).
  3. **The directory handle for fsync:** `File::open` on the state directory (`directory-handle-or-durability`, as `IR-B0109`).
- **Existing sites:** `IR-B0112-M01` and `IR-B0113-M01` in `new_attempts` keep their item and their statement tokens (§5.6). `IR-B0110-M01` and `IR-B0111-M01` in `Supervisor::open` keep theirs (§5.5 Caps). `atomic_json` is not reused: it writes one JSON value, not raw lines, and reusing it would move its reviewed sites to a new item.
- **Not disallowed, so no expectation:** reads, writes, `set_len`, `sync_data` and `sync_all` on held descriptors, `persist` (the rename), `fs::rename`, `fs::remove_file`, `fs::read_dir` (coverage is #209), and `symlink_metadata`. The log is read through its checked descriptor, so there is no `fs::read` site.
- **Test placement:** every new unit test lives in a file that production builds never load: `tests.rs`, or a new `requests_tests.rs`. Both are declared under `#[cfg(test)]` in `mod.rs` (`mod.rs:9-10`), so the N3/N4 syntax audits do not read them; `tests.rs:661` already carries a `cfg(target_os …)` without a `policy.json` entry for that reason. `requests.rs` has no test module. Its `#[cfg(test)]` seams use no target predicate and put no `cfg` attribute inside a macro call.
- **Test seams** are `#[cfg(test)]` code with no `#[expect]`, since every expectation is checked regardless of cfg, and production compilations do not compile test code.
  - The seams are the ID source (a rename after the draw), the pause hook, the log's fault points, the `Limits` thread-local override and the Fake's spawn marker.
  - The SIGKILL test's child learns its role from an environment variable read only in `tests.rs`, as `RATARMOUNT_SANDBOX_SOCKET_TEST` does.
  - No new `RATARMOUNT_TEST_` string reaches the release binary, so `packaging/test-no-test-hooks-in-release.sh` stays clean.

### 5.9 Docs

- **`docs/sandbox.md`:**
  - The v1 section says v1 is frozen.
  - A new "Protocol version 2" subsection covers:
    - the dispatch and envelope-version rules;
    - `request_id`, the outcome table, and the binding of an ID to its first body;
    - the restart rule: an interrupted request answers `interrupted`, and a replay returns the original answer even after a restart (use `list` for the current state);
    - the bounded retry window and the `Broken` log;
    - `requests.jsonl` in the state directory, including that an older daemon ignores it and that a daemon refuses a log written by a later release;
    - later releases add v2 fields, which older daemons refuse.
  - `request_id` must be a string: `null` is refused, and a malformed ID writes nothing.
  - v2 refuses unknown fields on every operation, `shutdown` included. v1's `shutdown` keeps ignoring them (§5.1).
  - **Append cost:** each executed or re-executed request with an ID costs two synced appends, refusals included. Replays, stored errors, conflicts and refusals while `Broken` append nothing.
  - The error codes gain `idempotency_conflict` and `interrupted`.
  - `:2415-2420` changes: without `request_id` there is still no deduplication; with one, retry the same body under the same ID; after `interrupted`, use a new ID. The sentence on removing state files only with the daemon stopped names `requests.jsonl` too, because a running daemon keeps appending to a moved file through its open descriptor.
  - The CLI flag and the Python paragraph are added. The Python paragraph covers implicit cleanup after a stale replay (§5.7).
- **`docs/recipes/swe-bench-sandboxes.md:124-125`:** after a client timeout, retry `new` with the same `request_id`, or list and reconcile without one.
- **`docs/tasks/beyond-parity-roadmap.md:297`:** the supervisor row mentions retry-safe request IDs.
- **No change for the new CLI flag in `docs/formats.md`, `README.md` or `docs/getting-started.md`.** `AGENTS.md` sends CLI-flag changes there, but none of them lists `sandbox new`'s flags:
  - `docs/formats.md` only points to `sandbox.md` (`:293`);
  - the README row lists the sandbox verbs (`README.md:260`);
  - getting-started names `new --count N` and links the recipe (`docs/getting-started.md:174-177`).

  The flag is documented in `docs/sandbox.md` with the other `new` flags (`:2260-2261`).
- **Also:** the `CHANGELOG.md` Unreleased entry, the Python docstring, and the `AGENTS.md` rows (§7). The CHANGELOG also names the one new v1-visible error: `io` "could not allocate a unique attempt ID", after 16 reserved draws in a row (§5.6). It is possible only while request records name destroyed IDs, and extremely rare.

## 6. Steps

Each step is one commit. Before each, the `AGENTS.md` gates run: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `test_policy.py` and `policy.py`. Catalog rows land with the step that adds their test.

0. **Fixtures from the baseline (test-only).**
   - **ID source:** a `#[cfg(test)]` deterministic ID source on `Supervisor`. Right after the unchanged `tempdir_in` statement, it renames the drawn directory to `attempt-000001`, `attempt-000002`, …. The field and its branch live in `daemon.rs` under `#[cfg(test)]`, so the production compilation and the reviewed statement are unchanged.
   - **Golden:** the transcript (U1) and its fixture, `ratarmount/src/sandbox/testdata/v1-golden.jsonl`.
     - An `#[ignore]`d generator produces the fixture through a test-local copy of today's per-line path (`daemon.rs:934-943` plus `send`'s encoding, `:869-877`).
     - The copy carries a comment citing those two ranges and is reviewed line by line against them, so step 1's diff can be compared with `respond()`.
     - The generator's doc says that a serde_json upgrade, which changes the pinned parse-error texts, is an intentional regeneration.
     - In this step U1 replays through that same copy, so it proves nothing yet; its proof arrives in step 1.
     - **Real-daemon cross-check:** I5 ties the fixture to the real `serve`. It sends the golden's path-free envelope-error lines to the baseline daemon over its socket and byte-compares each reply with its fixture entry. It also sends an unterminated write over 1 MiB, the branch at `daemon.rs:945-951` that U1 cannot reach.
   - **CLI bytes:** a recording listener on a temporary socket stores the line it receives and replies `{"version":1,"ok":true,"result":null}`. The test drives the baseline `sandbox::run` in-process for each v1 subcommand argv. It stores the recorded lines in `testdata/cli-v1-requests.jsonl` (U3). The argvs cover `--readonly a,b`, `--quota 2G`, the `--options` JSON and the clap defaults.
   - **Python bytes:** the fake daemon records raw request lines. P1 asserts the baseline client's line for every method called without new arguments; the expected lines are inline literals in `test_ratarmount_sandbox.py`, captured from the baseline client in this step.
1. **Dispatch and envelope versions.**
   - §5.1 and §5.2 (`respond`, `encode`). `OperationV2::new` has no `request_id` yet; U2 asserts that a v2 `request_id` is refused as an unknown field.
   - U1 switches to the production `respond()`, and the test-local copy is deleted. From here on, `respond()` must reproduce the baseline bytes.
   - The existing tests adapt (`tests.rs:124` version 2 becomes 3; `:136`; `:484`). U2 and U4.
   - `Daemon::envelope` becomes version-aware (I1), and I2 is added.
   - Docs: the v2 dispatch rule.
2. **Request log and request IDs.**
   - `request_id` on v2 `new` (U2's refusal row becomes the accepted case), `requests.rs`, and §5.3–§5.6. `new_attempts` is not split.
   - The six inventory sites and their manifest entries; `IR-B0112-M01` and `IR-B0113-M01` unchanged.
   - U5–U16, I3 and I4.
   - Docs: request IDs, error codes, the roadmap row, CHANGELOG.
3. **CLI and Python.**
   - §5.7, including the Python client's implicit cleanup after a stale replay.
   - U3 re-run against the step-0 fixtures, plus its v2 and version-acceptance cases. P1 still passes; P2–P5 are added.
   - Docs: the CLI flag, the Python paragraph, the docstring, the SWE-bench recipe, and the CHANGELOG line for the cleanup change.

## 7. Tests

- Unit tests live in `ratarmount/src/sandbox/tests.rs` (with the Fake `Mounter`) or in the new `requests_tests.rs`, both loaded only under `#[cfg(test)]` (§5.8). Target-specific tests go only there.
- Every name starts with `regression_` and has a `Regression:` doc line.
- Tests that drop and reopen a supervisor in-process take `test_process::exclusive()`. The re-exec test holds `spawning()` while its child lives, then drops it and takes `exclusive()` before reopening.

| ID | Test | Asserts | Step |
| --- | --- | --- | --- |
| U1 | `regression_v1_golden_transcript_byte_identical` (Keystone #7) | **Setup:** replays the fixture against a fresh `Supervisor<Fake>` (small `--max-attempts`, deterministic IDs). Every response must match byte for byte after placeholder substitution:<br>- `$STATE` is `supervisor.root` (canonical, so `/private/tmp` on macOS);<br>- `$BASE` is the base path string as sent; the base sits outside the state directory.<br>Transcript entries are request lines, or file writes into an attempt's overlay. Every fixture file and directory gets an explicit mode, so the umask cannot leak into diff headers. The golden contains no symlinks: a non-`git` diff prints a symlink's raw mode (row 18), which Linux cannot chmod and macOS derives from the umask.<br>**`create_base`:** success, `already_exists`, an unknown option key.<br>**`new`:** `count` 2, `count` 0, over capacity, an unknown base, and a v1 `new` carrying `request_id` and one carrying `lowers` (serde's exact unknown-field text).<br>**`list`:** all, by base, an unknown base.<br>**`diff`:** one with `git: false` and one with `git: true`, over a real temporary directory base with fixed content. The Fake's deletion list takes `diff`'s success path (row 18).<br>**`stats`:** over the same attempt.<br>**`destroy`:** by id, by base, both, neither, an unknown id.<br>**`shutdown`:** last, once plain and once with an extra field, which v1 accepts and executes today (row 21).<br>**Envelope errors:** `{}`, version 3, version `"1"`, version `1.0`, malformed JSON, and an oversize line (generated, not stored).<br>No entry is skipped or compared only by `code`. No `version: 2` line appears, because version 2 is not v1. The fixture is regenerated only on purpose, through the generator, with the reason in the commit message. | 0, 1 |
| U2 | `regression_protocol_v2_dispatch_and_envelope_versions` | **Parse table** of §5.1, including:<br>- `{"version":2}` without `op`: v2 `invalid_request`;<br>- v2 `lowers`, and `op: "finalize"`: v2 `invalid_request`;<br>- v2 `request_id`: refused in step 1, accepted from step 2;<br>- `"request_id": null`: v2 `invalid_request`, from step 2;<br>- `{"version":2,"op":"shutdown","request_id":"r"}` and `{"version":2,"op":"shutdown","extra":1}`: v2 `invalid_request` through `respond()`. Existing attempts stay and `stopping` stays false (Codex sweep 4 B1).<br>**`respond`:** v1 success and error carry version 1; v2 success and error carry 2.<br>**`encode` with a small limit:** an oversize v2 reply becomes `response_too_large` with version 2, a v1 reply with version 1.<br>**Shared operations:** v2 `list`, `diff`, `stats` and `destroy` return the same results as v1 on the same state. | 1, 2 |
| U3 | `regression_cli_v1_request_bytes_unchanged` | **v1 bytes:** every v1 subcommand argv, driven through `sandbox::run` against the recording listener, sends the fixture bytes. This holds after step 1's `Op` wrapper and after step 3.<br>**Step 3:** `new --request-id r` sends a v2 line with the field.<br>**`call`'s version rule** (the listener's reply varies): the same version is accepted, a v1 `ok: false` answering v2 is the server error, anything else is an error.<br>**Mechanics:** `run` prints through `stdout().lock()` (`mod.rs:143-147`), which libtest does not capture. So assertions use `run`'s return value: `"request failed (see JSON error)"` for an accepted error envelope, and `"unsupported response version"` for a rejected one. They also call `call()`, which is visible to the child test module. The test log shows one JSON line per argv.<br>**No hang:** `call` waits up to 3600 s (`mod.rs:167`). So the recording listener is owned by its thread: a panic there drops it, and `call` sees EOF at once. The test joins that thread with a bounded wait. | 0, 3 |
| U4 | `regression_protocol_rejects_unknown_fields_and_versions`, `regression_base_allow_globs_optional_v1` (existing) | The version-2 line becomes version 3, and the types adapt. No other existing assertion changes. | 1 |
| U5 | `regression_request_hash_canonical_and_default_free` | **Equal hashes:**<br>- texts with permuted keys;<br>- explicit defaults and omitted defaults;<br>- with and without `request_id`.<br>**Different hashes:** `count`, `overlay`, `quota`, or the order of `readonly_globs`.<br>**Golden constant:** a fixed digest for `{"version":2,"op":"new","base":"task","request_id":"r"}`, which R1b and R1c must keep.<br>Only top-level defaults are dropped. R1b adds the case `journal: Some({})` ≠ `None` when it adds the field. | 2 |
| U6 | `regression_request_id_same_body_one_spawn` (source test 2) | **Same ID and body twice:** the Fake records one spawn batch, the second response's bytes equal the first's, and the attempt count is unchanged.<br>**After `done`:** another `count` is `idempotency_conflict`.<br>**Without an ID:** a v2 `new` spawns every time and writes no line. | 2 |
| U7 | `regression_request_id_retryable_reruns_and_failed_replays` | **Retryable:** Fake `fail_spawn` gives `spawn_failed` and a `retryable` record. A retry with the same body spawns again and reaches `done`, and a third call replays it. A different body conflicts while the record is still `retryable`.<br>**Failed:** `fail_spawn` plus `refuse_cleanup` gives `failed` with the kept attempt. Its replay is byte-identical, and the kept ID is reserved. | 2 |
| U8 | `regression_request_id_refusal_is_retryable` | **Refusals:** `capacity` and an unknown base each append `running`, then `retryable`, and make no spawn. A bad `request_id` is `invalid_request` and writes no line.<br>**Re-run:** after capacity frees, the same ID and body runs and reaches `done`.<br>**Binding:** the same ID with another body is `idempotency_conflict`. | 2 |
| U9 | `regression_restart_running_new_reports_interrupted` (source test 3) | **Setup:** a SIGKILL re-exec of the test binary, in the pattern of `tests.rs:360-375`. The child opens its supervisor with a 60 s timeout, so readiness never times out first.<br>**K1:** the Fake is `stuck` and writes a `spawned` marker into each attempt directory. The parent waits for `count` markers, so the attempts exist and spawning has begun, then kills the child.<br>**K2:** a `#[cfg(test)]` hook pauses the child before the outcome append and writes a marker. The parent kills it at the marker.<br>**Bounded waits:** the parent waits at most 30 s for markers and polls `child.try_wait()` between checks, so an early child exit or panic fails the test at once.<br>**After either kill, the parent reopens:**<br>- the attempt directories are gone and the record is `failed interrupted`;<br>- a same-body request through `respond()` answers `interrupted` in a v2 envelope;<br>- another body answers `idempotency_conflict`. | 2 |
| U10 | `regression_restart_keeps_finished_request_records` | **In-process reopen:**<br>- a `done` record replays the original response bytes, although its attempts are gone;<br>- a `failed` record replays its error;<br>- a `retryable` record re-runs;<br>- the reserved IDs survive. | 2 |
| U11 | `regression_request_log_torn_tail_and_corrupt_middle` | **Torn tail:** a last line without `\n`, and separately a newline-terminated last line containing zero bytes, are both truncated, and the start succeeds.<br>**Refusals:** each of these refuses the start, naming the byte offset:<br>- a damaged line before the last;<br>- an unknown `v`, `t` or `op`;<br>- a missing `op_hash`.<br>**Sync order:** a `#[cfg(test)]` call log shows the file `sync_all` and the directory fsync before any lookup or append.<br>**Open failures** (fault points): a failed file sync, a failed directory fsync, and a failed torn-tail truncation each refuse the start with `io` before `reconcile`. A stale attempt's file stays byte-identical, and the Fake records no cleanup. A failed removal of a `.compact` leftover is ignored and the start succeeds. | 2 |
| U12 | `regression_request_log_compaction_keeps_op_hash` (sweep 4 B1) | **Setup:** small `Limits`, including the compaction floor.<br>**Verbatim:** compaction writes every live last line byte-identical and in order.<br>**After compaction, and again after a reopen:**<br>- a compacted `done` ID with another body conflicts, and with its body replays;<br>- a compacted `retryable` ID conflicts or re-runs the same way;<br>- reserved IDs remain.<br>**Descriptor:** after compaction the log's descriptor is the inode now at `requests.jsonl`, and a line appended afterwards survives a reopen.<br>**Temp leftovers:** a leftover `.compact` file is removed at open. | 2 |
| U13 | `regression_request_log_caps_and_record_preflight` | **Caps:** both caps evict the oldest finished records, and `running` is never evicted.<br>**Reuse of an evicted ID** (Codex sweep 1 #1): complete `a` (`count` 1), `b` (`count` 8), `c` (`count` 4) under a byte cap that evicts `a` and `b`, then reuse `b` with `count` 1. The live set is `{c, b}` in memory, after a reopen, and after compaction plus a reopen; `a` stays unbound.<br>**Preflight:** over the record cap, the result is `capacity` with no spawn, and the record is `retryable`; just under it, the request succeeds.<br>**Newest record:** a `failed` line larger than the small live cap is kept as the newest record and evicts every older one. `Limits` refuses a record cap above the live cap.<br>**Streaming open:** a log whose obsolete history is many times the live cap reopens to the same live set. A `#[cfg(test)]` high-water mark of the line buffer stays within the line bound.<br>**Small `Limits` reach `open`** through the `#[cfg(test)]` thread-local override (§5.5 Caps).<br>**Maximal `failed` line:** a synthetic `failed` line with 4,096 kept IDs and an 8 KiB `mount.log` excerpt made of control characters stays within the line bound and reopens intact (§5.5 Open, step 3). | 2 |
| U14 | `regression_request_log_append_failures_and_broken_state` | **A failed `running` write or sync:**<br>- for a new ID, the log is truncated, stays open, the request gets `io`, and a retry runs as new;<br>- starting from a `retryable` record, write and sync failures each keep that record, so another body still conflicts before and after a reopen (Codex sweep 1 #2);<br>- a written line whose sync and truncation both fail makes the log `Broken`, and the request answers `io` without spawning. After a reopen, the record is `interrupted` with the "before it finished" message.<br>**While a record is `running` under `Broken`:** the same body is refused with `io`, and another body is `idempotency_conflict`.<br>**A failed outcome write or sync after spawning:**<br>- the log is `Broken` and the file ends at the `running` line;<br>- the request answers `io`, and the next request-ID'd `new` is refused with `io` and no spawn;<br>- an older `done` still replays, and a request without an ID is still served;<br>- after a reopen, the record is `interrupted`.<br>**Outcome written, then the sync and the truncation both fail:**<br>- with a `done` outcome, a same-ID retry is refused while `Broken`. After a reopen it replays the surviving `done` line, and the Fake records no further spawn;<br>- with a `retryable` outcome, after a reopen the same body runs again.<br>**Compaction failures:**<br>- a failed directory fsync after the rename leaves it `Broken`, and the unlinked old inode gains no bytes; the triggering request still answers its outcome;<br>- a failure before the rename leaves it open on the old descriptor with no temp file;<br>- after that failure, the next outcome appends do not retry until as many bytes as the live set have been appended, and then the retry runs.<br>**After a compaction:** an injected failed append is truncated, and the next append lands at the end with no zero-filled gap, because the persisted descriptor is `O_APPEND`. The next start succeeds.<br>**Restart resolution:** a failed resolution write refuses the start with `io`, and the next start resolves the same record. | 2 |
| U15 | `regression_attempt_id_never_reuses_logged_ids` (sweep 5 B1) | **Redraw:** the ID source returns a reserved ID taken from:<br>- a `done` record;<br>- a `failed` record with attempts;<br>- either kind after compaction and a reopen.<br>Each time the ID is redrawn.<br>**v1 sees nothing:** a v1 `new` whose first draw is reserved returns an ordinary v1 envelope naming the redrawn ID, through `respond()`.<br>**Exhaustion** (Codex sweep 3 B1):<br>- on the first attempt, 16 reserved draws in a row give `io`, and the record is `retryable`;<br>- with `count` 2, the first attempt spawns and the second exhausts. If the rollback destroys the first, the record is `retryable`. If cleanup fails (Fake `refuse_cleanup`), the record is `failed` with the kept ID, and its replay spawns nothing. | 2 |
| U16 | `regression_request_log_refuses_unsafe_file` | **Setup:** a state directory with a stale attempt directory holding an overlay file.<br>**Refusals:** `Supervisor::open` refuses when `requests.jsonl` is:<br>- a symlink to a regular file (`io`, `ELOOP`);<br>- a regular file with a second hard link (`unsafe_path`);<br>- a regular file with mode 0640 (`unsafe_path`).<br>**Before reconcile:** each of these checked-open refusals happens before `reconcile`. The stale attempt's file is byte-identical, and the Fake records no cleanup. | 2 |
| I1 | `Daemon::envelope` (`ratarmount/tests/sandbox.rs`; old blocker 6) | **Version:** it keeps an explicit integer `version` of 1 or 2 and inserts 1 when the field is absent. Any other value panics; invalid versions are written raw, as `:147` does.<br>**Response check:** it asserts `response["version"]` equals the version sent. Every existing `call`/`envelope` use now checks for version 1. | 1 |
| I2 | `regression_sandbox_v2_envelopes_over_socket` | A v2 `list` returns `[]` in a v2 envelope. A v2 `new` with `lowers` returns `invalid_request` in a v2 envelope. | 1 |
| I3 | `regression_sandbox_v2_request_id_over_socket` (no FUSE needed) | **Setup:** a corrupted prepared index (row 13).<br>**v1:** a v1 `new` with `request_id` gets `invalid_request` in a v1 envelope.<br>**Retryable path:**<br>- v2 `new` `r1` answers `mount_failed` (v2), naming attempt A;<br>- the same body answers `mount_failed` naming another attempt, so it ran again;<br>- `count` 2 under `r1` is `idempotency_conflict`.<br>**After a daemon restart:** the conflict persists, and the same body runs again.<br>**File:** `requests.jsonl` is a regular file with mode 0600.<br>Everything goes through `call`/`envelope`, so the v2-only field proves the helper sends v2. | 2 |
| I4 | `regression_sandbox_v2_request_id_replay_fuse` | **FUSE gate:** uses the `prepared_fuse_check` pattern; under `RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE=1` a missing prerequisite fails the test instead of skipping it.<br>**Replay:** v2 `new` `r2` succeeds, the same request returns an identical result, and `list` shows `count` attempts.<br>**After a restart:** the same body returns the original result, and `list` is empty. | 2 |
| I5 | `regression_sandbox_envelope_errors_match_golden_over_socket` (Claude sweep 4 N1) | **Setup:** the real daemon, no base needed.<br>**Envelope errors:** each of U1's path-free envelope-error lines (`{}`, version 3, `"1"`, `1.0`, malformed JSON, and a terminated line over 1 MiB) is sent over the socket. Each reply line equals that line's fixture entry byte for byte. This ties the fixture to the real `serve`, not only to step 0's copy.<br>**Unterminated input:** an unterminated write over 1 MiB gets `{"version":1,"ok":false,"error":{"code":"invalid_request","message":"request exceeds 1 MiB"}}` and then EOF (`daemon.rs:945-951`).<br>Lands in step 0 against the baseline daemon and must keep passing. | 0 |
| P1 | `test_regression_v1_request_bytes_unchanged` | The raw lines for every method called without `request_id` equal the step-0 fixtures. | 0, 3 |
| P2 | `test_regression_request_id_sends_v2` | `new(..., request_id="r")` sends version 2 with the field and accepts a v2 answer. Without it, there is no `request_id` key. | 3 |
| P3 | `test_regression_v1_error_envelope_answering_v2` | A v1 `unsupported_version` envelope answering v2 raises `SandboxError("unsupported_version")`. A v1 `ok: true` envelope answering v2 is a `protocol` error. | 3 |
| P4 | `test_regression_stale_replay_client_context_cleanup` (Codex sweep 2 B1) | **Setup:** the fake daemon gains a stale-replay mode. A `new` with `request_id` returns attempts the fake does not hold, and `destroy` of an unknown ID answers `not_found`.<br>**Client context:** inside `with client:`, `new(..., request_id="r")` is followed by `list()`, which returns `[]`. Leaving the context raises nothing, `_owned` is empty, and a `destroy` was sent for each replayed ID. | 3 |
| P5 | `test_regression_stale_replay_attempt_context_cleanup` | **Context:** with the same fake, `with attempt:` on a replayed attempt exits without raising, and the attempt counts as destroyed.<br>**Explicit call:** `attempt.destroy()` on another replayed attempt still raises `SandboxError("not_found")`. | 3 |

**Before merge,** in addition to the per-commit gates:

```bash
TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount --bin ratarmount sandbox
TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount --test sandbox
RATARMOUNT_REQUIRE_PREPARED_INDEX_FUSE=1 TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount --test sandbox regression_sandbox_v2_request_id_replay_fuse   # FUSE host
uv run --with pytest python -m pytest -q clients/python/tests/test_ratarmount_sandbox.py   # output recorded in the PR (not in CI, §3)
CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo build --release -p ratarmount && ./packaging/test-no-test-hooks-in-release.sh target/release/ratarmount
```

**`AGENTS.md` catalog rows** (filters run separately):
- (a) v1 golden, dispatch and envelope versions: `regression_v1_golden`, `regression_protocol_v2_dispatch`, `regression_protocol_rejects_unknown_fields_and_versions`.
- (b) request IDs: `regression_request_hash`, `regression_request_id_`, `regression_restart_running_new`, `regression_restart_keeps_finished`, `regression_attempt_id_never_reuses`.
- (c) the request log: `regression_request_log_`.
- (d) the envelope helper, v2 over a socket and the real-daemon envelope check: `cargo test -p ratarmount --test sandbox regression_sandbox_v2_`, `cargo test -p ratarmount --test sandbox regression_sandbox_envelope_errors`.
- (e) CLI and Python bytes: `regression_cli_v1_request_bytes`, plus the pytest command above.

## 8. Risks

1. **Stale replays.** A replay returns the original answer, also after a restart that discarded its attempts, or after the client destroyed them. That is the source doc's contract (`source-plan-doc.md:127`) and the previous plan's resolution (its §13.6). The docs tell callers to use `list` for the current state and a new ID after `interrupted`. The Python client's implicit cleanup tolerates such attempts (§5.7; P4, P5).
2. **`retryable` versus the source doc's wording.** The source doc stores errors as `failed` (`:126`). R1a records outcomes that changed nothing as `retryable`, which re-runs under the same ID. That is the Keystone #6 resolution the request carries over (previous plan §6.5, §10 #6), not a new departure.
3. **Compaction blocks the serve loop** while it writes and syncs up to 64 MiB: an estimated 0.1–0.6 s on NVMe. The PR records one measurement on the author's host. Up to 64 MiB of request records stay in memory.
4. **Bounded retry window.** After about 65,536 requests or 64 MiB of records, an evicted ID that is retried runs as new. A refused request with an ID, like any executed or re-executed one, costs two synced appends and occupies a record until evicted. Replays, stored errors, conflicts, refusals while `Broken`, and a malformed `request_id` append nothing.
5. **Version skew of the log.**
   - **Older daemon:** a daemon from before R1a ignores `requests.jsonl` and refuses v2 with `unsupported_version`.
   - **R1a on a later log:** an R1a daemon started on a state directory whose log holds lines from R1b or R1c (an unknown `v`, `t` or `op`) refuses to start. The same holds for a corrupt log.
   - **Recovery, documented in `docs/sandbox.md`:** stop the daemon, move `requests.jsonl` aside, and start the older daemon. Every request record is then lost: reservations, replays and conflicts. A retry of an old ID runs as new, which cannot duplicate live attempts, because the restart discarded them all. R1c decides whether its lines can stay readable instead (§3).
6. **Version 2 grows** in R1b and R1c. An R1a daemon refuses their fields with `invalid_request` (fail closed). R1b and R1c must keep U5's golden digest.
   - **For Keystone:** dropping top-level defaults from `op_hash` (§5.4) goes beyond the source doc's "serde_json with sorted keys is enough" (`source-plan-doc.md:124`). It also differs from the previous plan, which hashed defaults in (`localai-r1-supervisor-v2.md:857-858`).
   - **What it buys:** a `retryable` record written by R1a can still re-run after an upgrade to R1b or R1c, and a `done` one still replays, instead of conflicting.
   - **Cost of reversing it:** hashing defaults in is a one-line change before R1a ships. Afterwards, records written by R1a would conflict with same-body retries across each upgrade that adds a field.
7. **The `respond()` refactor** could change `serve`'s bytes. U1 catches that for the whole transcript from step 1 on. The proof rests on the step-0 copy matching `daemon.rs:934-943` and `:869-877`, which is checked by line-by-line review.
   - **Framing:** request framing, pipelining and malformed lines stay covered by `regression_sandbox_socket_protocol_and_restart` (`tests/sandbox.rs:137`).
   - **Write timeout:** `send`'s write path (blocking mode and the 5-second write timeout, `daemon.rs:878-882`) is moved, not changed. No test exercises a stalled reader today, and R1a adds none, so that property stays untested, as it is at baseline.
8. **`unsupported_version` keeps saying "version must be 1"** although version 2 exists, so the v1 bytes stay identical.
9. **The Python tests run by hand only,** as today. This matters most for the one v1-visible client change, implicit cleanup ignoring `not_found` (§5.7). So the PR records the before-merge pytest output as a merge requirement (§7).

## 9. Review log

The author seeded the first table before any sweep. The gate driver runs each sweep (a Claude skeptic and a Codex skeptic).

**Carried into R1a**

| Item | From | Where in this plan |
| --- | --- | --- |
| Keystone #5: justify the `requests.json` rewrite cost, or use an append log with compaction | request; previous plan §10 #5 | §5.5 (cost, then append log) |
| Keystone #6: a retry under the same `request_id` is idempotent, at the request-ID layer, with `retryable` for outcomes that changed nothing | request; previous plan §6.5, §10 #6 | §5.3; U6–U10 |
| Keystone #7: v1 golden replay | request; previous plan §10 #7 | §6 steps 0–1; U1, U3, P1 |
| Old blocker 6: `Daemon::envelope` forces version 1 | `codex-9.md` #5 | I1, I3 |
| Sweep 4 B1: `op_hash` survives compaction, so `idempotency_conflict` still works | previous plan, sweep 4 and revision 7 | §5.5 (self-contained lines, verbatim compaction); U12 |
| Sweep 5 B1: attempt IDs named by the request log stay unique (R1a part: `new` records only) | previous plan, sweep 5 and sweep 6 N1 | §5.6; U15 |
| Sweep 3 B2: reopen and inode check after compaction | previous plan | §5.5; U12 |
| Sweep 7 Codex 4 and 5: the `Broken` state machine | previous plan | §5.5; U14 |
| Sweep 7 Codex 7: stored-record cap checked before any attempt exists | previous plan | §5.5; U13 |
| Previous plan §13.6: replays return the original result after a restart | previous plan | §5.3; U10, I4; Risk 1 |
| Skeptic-9 N9: parse errors carry the version to answer with | `skeptic-9.md` | §5.1; U2 |
| Skeptic-9 N16: which temp leftovers are removed, and under which lock | `skeptic-9.md` | §5.5 open, step 5 |
| Skeptic-9 N8: never send `null` for an absent field | `skeptic-9.md` | §5.7; P2 |
| Codex-9 #2, request-log half: make everything restart sees durable before acting on it | `codex-9.md` | §5.5 open, step 2; U11 |

**Remaining departures from the previous plan** (author decisions):
- `op_hash` omits members equal to their default, for compatibility with R1b and R1c fields. The previous plan hashed defaults in (§5.4).
- No `seq` field (§5.5).
- The log is read through its checked descriptor, so there is no separate `fs::read` inventory site (§5.8).
- Version 2 in R1a is the v1 operations plus `request_id`; later fields are refused until their slice lands (§5.1).

**Not carried:** skeptic-9 B1 (digest caching, now cut), N1–N7 and N10–N15, N17; codex-9 #1 (bundle prefix, R1b), #3 and #4 (finalize, R1c), #6–#9 (R1b/R1c); the previous plan's §2 lock-order callout (§3).

### Sweep 1 (Claude skeptic: no blocking findings; Codex skeptic: three blocking)

Every finding was checked against the code at `2b96837` before the plan was revised.

| Finding | Verified | Resolution |
| --- | --- | --- |
| **Codex B1:** an evicted request ID can come back after a reopen | Yes. "Last line per ID, then caps" drops a superseded record from the sequence: `a`, `b` (`count` 8), `c`, then `b` reused with `count` 1 reloads `a`, which memory had evicted. | §5.5: open replays the log in file order with the append-time eviction rule, so a reopen reproduces memory exactly. Memory changes only after an append is durable. U13 adds Codex's case, before and after reopen and compaction. |
| **Codex B2:** a failed `running` append discarded a `retryable` binding | Yes. The plan said a truncated `running` append leaves "no record", which is wrong for a re-run of a `retryable` record (also Claude N8). | §5.5: memory is exactly as before a failed append; a re-run keeps its `retryable` record and position. U14 covers write and sync failures from `retryable`, and the conflict before and after reopen. |
| **Codex B3:** turning `done` into `interrupted` at restart replaced the approved replay contract | Yes. `source-plan-doc.md:127` replays the stored result; the previous plan's §13.6 kept it after a restart. The split did not authorize a change (also Claude N3). | §5.3: reverted. Only `running` resolves to `interrupted`; `done`, `failed` and `retryable` stay as they are, and replays return the original answer (Risk 1). U10 and I4 are rewritten. Also reverted: the other source-doc departure (Claude N3), a validation refusal leaving no record. `running` is again appended before the request runs, and refusals record `retryable`, as the previous plan resolved under Keystone #6 (Risk 2). That removes the split of `new_attempts`. |

**Non-blocking findings applied:**
- **Claude N1, reviewed sites in `new_attempts`.** Confirmed: entries are pinned by `item` and statement-token digest (`compiler/internal_read.rs:364-376`, `policy.py:393-399`). `new_attempts` is no longer split. The `tempdir_in` statement (`IR-B0112-M01`) and the `mount.log` open (`IR-B0113-M01`) stay token-identical, with the redraw loop around the first and the test ID source after it (§5.6, §5.8). The `#[cfg(test)]` seams carry no `#[expect]`.
- **Claude N2, a host-dependent golden.** Confirmed: non-`git` diffs print raw modes (`patch.rs:354-359`, `:374-381`), and macOS canonicalizes `/tmp` (`daemon.rs:315`). U1 sets explicit modes, has `git: false` and `git: true` diffs, and defines `$STATE` as `supervisor.root` and `$BASE` as the path sent. Step 0's copy is reviewed line by line, and U1 is said to prove nothing until step 1 (Risk 7).
- **Claude N4 and Codex N4, a vacuous K1.** U9's child gets a 60 s timeout, and K1 waits for `count` spawn markers before the kill. §5.8 now allows an environment variable read only in test code, as `RATARMOUNT_SANDBOX_SOCKET_TEST` does (the release scan looks only for `RATARMOUNT_TEST_`).
- **Claude N5, U3's fixtures.** U3 records what the baseline `sandbox::run` actually sends to a recording listener, for argvs with delimiters, sizes, options JSON and defaults.
- **Claude N6, the torn-tail rule.** A last line that lacks `\n` or is not valid JSON is torn and truncated. Only a damaged line before the last, or a schema error, refuses the start (U11).
- **Claude N7, downgrade from a later slice.** Risk 5 and the docs cover an R1a daemon refusing a log written by R1b or R1c.
- **Claude N8, spec gaps.** The checked open sets `read`. The post-compaction reopen does not create. The `running`-failure sentence is fixed (Codex B2). The compaction floor is in `Limits`. Cap order is fixed by the chronological replay.
- **Claude N9, `request_id` before its layer.** The field lands in step 2. In step 1, U2 asserts a v2 `request_id` is refused.
- **Claude N10, bookkeeping.** Attempt-level `allow_globs` is recorded as out of scope until Keystone assigns it (§3). The SWE-bench recipe's timeout advice mentions `request_id` (§5.9). The release-build command uses `CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock`.
- **Codex N5, the compaction cost.** The per-compaction bound was wrong when live bytes shrink. §5.5 now gives the amortized bound: each compaction writes less than it discards, and each line is discarded at most once.

### Sweep 2 (Claude skeptic: no blocking findings; Codex skeptic: one blocking)

Every finding was checked against the code at `2b96837` before the plan was revised.

| Finding | Verified | Resolution |
| --- | --- | --- |
| **Codex B1:** after a stale replay, the Python client's context exit raises `not_found` | Yes. `new()` adds every returned attempt to `_owned` (`ratarmount_sandbox.py:108-113`). `Attempt.__exit__` → `destroy()` → `client.destroy(id=…)` raises `not_found` for an attempt `reconcile` deleted (`:47-57`), and `close()` re-raises it (`:135-143`). `list()` does not clear `_owned`. Also Claude N6. | §5.7: `Attempt.__exit__` and `close()` treat `not_found` from `destroy` as already destroyed: they mark the attempt destroyed, drop it from `_owned`, and raise nothing. An explicit `destroy()` still raises. P4 (client context) and P5 (attempt context, explicit call) are added. The server's replay contract is unchanged; the CHANGELOG notes the client change. |

**Non-blocking findings applied:**
- **Codex N2 and Claude N3, outcome sync and truncation both failing.**
  - §5.5 now gives each branch: a completed outcome line that survives decides at the next start (`done` and `failed` replay, `retryable` re-runs), and no branch starts a second batch.
  - §5.3 qualifies the byte-equal replay to responses that were delivered.
  - U14 covers both the `done` and the `retryable` case.
  - The restart rule resolves every `running` record, one append each, rather than assuming at most one.
- **Codex N3, refusal paths of the checked open.** U16 opens over a symlink, a second hard link and mode 0640: each refuses before `reconcile` and leaves stale attempt data untouched. §5.5 names the error codes (`io`, `unsafe_path`).
- **Claude N1, the statement shape that keeps `IR-B0112-M01` unchanged.** §5.6 spells it out: one unchanged `let dir = …;`, never `let mut` and never duplicated, as the first statement of the redraw `loop`, with the test rename shadowing it afterwards. The `policy.py` runs in steps 0 and 2 are the check.
- **Claude N2, test placement.** All new unit tests live in `tests.rs` or a new `requests_tests.rs`, both declared under `#[cfg(test)]` (`mod.rs:9-10`), so N3/N4 do not read them. `requests.rs` has no test module (§5.8).
- **Claude N4, compaction at open.** Not attempted at open, so a failure there cannot leave a fresh daemon `Broken`; the first outcome append checks it (§5.5).
- **Claude N5, `"request_id": null`.** Refused with `invalid_request` (§5.1, U2).
- **Claude N7, docs.** `docs/sandbox.md` names `requests.jsonl` in the stopped-daemon sentence and states the two appends per ID'd request; Risk 4 does too.
- **Claude N8, test mechanics.** U3 asserts through `run`'s return value and `call()`, since `run`'s stdout is not captured. P1's expected lines are inline literals in its test file. The CLI fixtures live in `testdata/cli-v1-requests.jsonl`.
- **Claude N9, effort.** Re-estimated at about 5 days from the previous plan's per-step table (header).
- **Claude N10, golden maintenance.** The step-0 copy cites `daemon.rs:934-943` and `:869-877` in a comment. The generator notes that a serde_json upgrade is an intentional regeneration.

### Sweep 3 (Claude skeptic: no blocking findings; Codex skeptic: one blocking)

Every finding was checked against the code at `2b96837` before the plan was revised.

| Finding | Verified | Resolution |
| --- | --- | --- |
| **Codex B1:** ID exhaustion was declared `retryable` unconditionally | Yes. Drawing and spawning interleave per attempt (`daemon.rs:643-673`). With `count` 2, the first attempt spawns before the second draw can exhaust, and a rollback whose cleanup fails keeps it (`:710-724`). An unconditional `retryable` would let the same ID start another batch beside the kept attempt. | §5.6: exhaustion is an ordinary error in the loop. It goes through today's rollback and §5.3's classification: `retryable` when nothing is left, `failed` with the kept IDs otherwise. U15 adds exhaustion after a spawned first attempt, with cleanup succeeding (`retryable`) and failing (`failed`; its replay spawns nothing). |

**Non-blocking findings applied:**
- **Claude N1, the `Limits` seam in `open`.** Confirmed: `IR-B0110-M01` and `IR-B0111-M01` are pinned to the item `Supervisor::open` (`daemon.rs:322-356`). `open` keeps its body; `Limits` come from `requests::limits()`, with a `#[cfg(test)]` thread-local override, so the replay at open already sees small test caps (§5.5 Caps, §5.8).
- **Claude N2, the `null` mechanism.** `#[serde(default, deserialize_with = …)]` with a function that deserializes a `String` (§5.1).
- **Claude N3, a failed `running` append whose truncation also fails.**
  - §5.5 states the outcome: `Broken`, `io`, nothing ran, and the next start resolves the surviving line to `interrupted`.
  - The `interrupted` message no longer claims attempts existed (§5.3).
  - U14 adds the reopen assertion, and the same-body refusal and other-body conflict while `running` under `Broken`.
- **Claude N4, compaction.**
  - The triggering request answers its durable outcome even if compaction fails afterwards.
  - The temp file is created with tempfile's `append(true)` (confirmed at `tempfile-3.27.0/src/lib.rs:384`, `:555-569`, `file/imp/unix.rs:13-27`), so `persist` hands back an `O_APPEND` descriptor of the published inode.
  - That removes the reopen, the `(dev, ino)` check and the checked open's `create` parameter.
  - U14 checks that an append after compaction leaves no zero-filled gap.
- **Claude N5, self-eviction.** Eviction never removes the record just appended, and `Limits` refuses a record cap above the live cap (§5.5, U13).
- **Claude N6, the AGENTS.md docs rule for a new flag.** §5.9 records why `docs/formats.md`, `README.md` and `docs/getting-started.md` need no change: none lists `sandbox new`'s flags.
- **Claude N7, wording.** "Attempt data stays untouched" is limited to the checked-open refusals. Open's own idempotent log writes before `reconcile` are stated (§5.5, U16).
- **Codex N2, write-timeout coverage.** The claim is withdrawn. `send`'s write path is moved unchanged, and a stalled reader stays untested, as at baseline (Risk 7).
- **Codex N3, memory at open.** The log is read one line at a time with a bounded line reader, keeping only the capped live set. U13 reopens a log with heavy obsolete history and checks the line buffer's high-water mark.
- **Codex N4, append-cost wording.** Two appends per executed or re-executed request, refusals included; replays, stored errors, conflicts and `Broken` refusals append nothing (§5.9, Risk 4).

### Sweep 4 (Claude skeptic: no blocking findings; Codex skeptic: one blocking)

Every finding was checked against the code at `2b96837` and the pinned dependencies before the plan was revised.

| Finding | Verified | Resolution |
| --- | --- | --- |
| **Codex B1:** a v2 `shutdown` copied from v1's unit variant would accept forbidden fields | Yes. serde 1.0.229 (`Cargo.lock:6268-6269`) deserializes an internally tagged unit variant by draining and ignoring every remaining key (`serde-1.0.229/src/private/de.rs:2990-2996`). `deny_unknown_fields` never sees them. So `{"version":2,"op":"shutdown","request_id":"r"}` would destroy every attempt and set `stopping` (`daemon.rs:560-563`). v1 behaves this way today (`protocol.rs:76`). | §5.1: `OperationV2`'s `shutdown` is an empty struct variant, which gets `deny_unknown_fields` and serializes to the same `{"op":"shutdown"}`. v1 keeps its unit variant and leniency. U2 asserts the v2 refusal, with attempts kept and `stopping` false. U1 pins v1's leniency. New row 21 in §4. |

**Non-blocking findings applied:**
- **Codex N2, repeated compaction failures.** The 2× bound now covers successful compactions only. After a failure before the rename, the next attempt waits until as many bytes as the live set have been appended. With that backoff, total writes stay under 4× even if the sync keeps failing. U14 checks the backoff.
- **Claude N1, the golden tied to a copy.** New I5, in step 0, byte-compares the real baseline daemon's replies to the golden's path-free envelope-error lines. It also covers the unterminated-oversize branch (`daemon.rs:945-951`), which U1 cannot reach.
- **Claude N2, failure outcomes at open.** A failed sync or torn-tail truncation refuses the start with `io` before `reconcile`; a failed leftover removal is logged and ignored (§5.5). U11 has an injected-failure row that checks a stale attempt stays untouched.
- **Claude N3, "keeps its body".** Restated as the real invariant: `IR-B0110-M01` and `IR-B0111-M01` stay token-identical inside `open`, checked by step 2's `policy.py` run.
- **Claude N4, `op_hash` defaults.** The rule is pinned to top-level members compared with the typed default; nested values are hashed whole, so R1b's `journal: Some({})` never equals `None` (§5.4, U5). The departure from the source doc and the previous plan is listed for Keystone, with what it buys and what reversing it costs (Risk 6).
- **Claude N5, the Python change without CI.** The before-merge pytest output is recorded in the PR as a merge requirement. CI wiring stays out of scope: the `check` job has no pytest, and its budget is pinned (`test_ci.py:22-24`; §3, Risk 9).
- **Claude N6, the line bound.** The bound is now the per-record cap plus 512 KiB. The largest `failed` line is derived at about 185 KB (4,096 kept IDs twice, plus an escaped 8 KiB `mount.log` excerpt). U13 reopens a synthetic maximal `failed` line.
- **Claude N7, the v1 redraw.** U15 adds a v1 `new` whose first draw is reserved and checks its ordinary v1 envelope. The CHANGELOG names the rare new v1 `io` after 16 reserved draws (§5.9).
- **Claude N8, downgrade after R1c.** Risk 5 gives the exact recovery and what it loses. §3 records that R1c decides whether its lines can stay readable by R1a.
- **Claude N9, symlinks in the golden.** The golden contains none (U1).
- **Claude N10, test hangs.** U3's listener is owned by its thread, so a fault gives `call` an immediate EOF instead of its 3600 s timeout (`mod.rs:167`). U9's parent waits at most 30 s and polls `child.try_wait()`.
