# #235 part 2 — revised delivery plan

## Summary

Plan only, 2026-11-07, at 4f54c6b932370d23a5a5cd1613f3653c40b7daaf (HEAD). The accepted plans/rrs-235-part2/PLAN.md remains binding, with delivery sequencing revised by Keystone's **06:53 ET ruling**. Deliver **A: native filesystem/open/publication primitives → B: alias-safe coordination/cleanup → C: caller migration**, with native/child-process gates before advancing. C0 is preparatory API → bounded migration waves → bounded final cutover; the former 144-file exception is withdrawn. No implementation, Cargo, commit, push or PR here. Preserve supported Linux/macOS/Windows behavior; UnsupportedPlatform/AcquisitionUnavailable stubs are not implementations. Each future PR records base, diff counts, exact tests/engine/native outcomes and gaps; actual architecture conflicts go to Keystone/Matt.

## Attempt-1 post-mortem (why 214 files/~54k lines; root process mistake)

Basis: the accepted plan, all six code{1,2,3}.{review,skeptic}.out inputs in /home/brewerm/git/muse-worktrees/plans/rrs-235-part2-impl/gate-attempt1/, snapshot 7fd8f966's read-only diff statistics, and current-main code checks. Review line numbers describe earlier attempt-1 trees, not main. Attempt 1 was blocked at code-gate cap 3; its local WIP is evidence, not a migration base.

The final skeptic reports a **53,933-line tracked review diff**. Snapshot git show --stat reports **214 files, 27,395 insertions + 8,860 deletions = 36,255 changed lines**. Direct main-base comparison additionally deletes the accepted plan/PARKED reference (607 lines): 216 paths/36,862 changed lines. Preserve those inputs; rendered review surface and added/deleted lines are different metrics.

The snapshot touches 45 crates, including 30 format crates. Eight index_access modules add 6,346 lines; compositing contributes 7,209 changed lines/28 files, session 2,966/15, policy/manifest 1,726. Infallible discovery creates necessary fan-out (ratarmount-core/src/lib.rs:712), but combining signature changes, native adapters, coordination, recovery, cleanup and protocols made semantic review unmanageable.

**Process failure:** migration preceded foundational proof. Ordinary native admission, retained-lock replacement, equivalent absent-name admission and coordination-child alias/cleanup experiments should have run first. Refusal stubs and generation/suffix-only test groups were mistaken for supported behavior; repairs then spread across the large diff. Reverse the old discovery-first order, retain architecture.

Besides the five final blockers, preserve earlier gate obligations: post-mutation discovery, SQLAR absence, CAB strings, remote-folder fallback, ancestor MKDIR chmod, HTTP late len/hints, swallowed digest/maintenance errors, successful denied unlink, lost local committed outcome and inode-only recovery. A2/B3–B5/C0*–C5 allocate these explicitly below.

## Locked architecture recap (what is NOT changing)

**One shared ratarmount-index boundary built on #239 checked_open::open_checked**, for selected SQLite connections/bytes/install/publish/remove. Parent-only resolution; untouched final spelling/literal companions; reads and writes refuse existing/dangling final links while parent symlinks work. No raw/alternate/memory/spool fallback after refusal. Diagnostic:

```text
refusing to rewrite symlinked index '<path>'; pass the real path via --index-file
```

Inherit the full accepted contract: lifetime ownership/poisoning/latched cleanup through cross-thread teardown; #239 rejected-descriptor retention; managed-reader lock safety; macOS ordinary automatic unix versus existing snapshot/overlay/managed unix-posix policy; Windows path-type-only proof plus native publication. Keep stable absolute coordination, directory-identity keys, ordered lifetime/publication leases, complete durable roles including absent names, equivalent-family logical IDs/digest locks, and no PID/absence-based release.

Mutable sources require checked snapshots even without companions; staging is exclusively owned. Freeze/finalize before immutable IDs; exact bytes/intent survive teardown/recovery, without mutable pin aliases. Publication retains locks through move-map/retirement/rename/durability/InstalledPending, verifies by intent, then owns cleanup and syncs Done; prior Done survives and old WAL never joins a new main. Alias-safe disjointness and reserved-state hiding/mutation/ancestor/reset/seal guards remain required. Fallible discovery preserves nested historical row dispatch and typed index plus archive outcomes. Existing identity/journal/restamp/hash/seal/prepared/retention authority is unchanged; installation records have no overlay replay authority.

Current-main grounding (all at the base above; proposed symbols are future work):

| File:line | Fact |
| --- | --- |
| ratarmount-index/src/checked_open/acquire.rs:419, :479, :507, :519, :544; ratarmount-index/src/checked_open/install.rs:1761 | Checked foundation, final/companion checks, independent Windows type-only path; Unix availability must not gate Windows. |
| ratarmount-index/src/checked_open/acquire.rs:730; ratarmount-index/src/internal_reads_tests.rs:780, :841, :856; ratarmount-formats-sqlar/src/lib.rs:1454 | Checked macOS POSIX default versus ordinary automatic-locking pins. |
| ratarmount-index/src/lib.rs:744, :1048, :806, :1998, :2004, :2013; ratarmount-index/src/managed_read.rs:16–22, :689–691 | Following lookup/prepared paths; checked snapshot; separate rename/companion/WAL actions; managed bytes lack transactional snapshot and canonicalize. |
| ratarmount-index/src/location.rs:383; ratarmount-index/src/local_cache.rs:421–423, :93, :364; ratarmount-index/src/digest_cache.rs:270, :414, :511–515 | Hash/pin publication, relative cache fallback, swallowed budget maintenance, sibling probe/non-Unix lock gap. |
| ratarmount-core/src/lib.rs:712, :764, :843–844 | MountSource's infallible lookup/exists fan-out; **index_state.rs is absent on main**. paths_overlap/preflight_namespace_free_cleanup are attempt-1 reference symbols, not existing main helpers. |
| ratarmount-compositing/src/overlay_meta.rs:726, :831; ratarmount-compositing/src/overlay_seal.rs:124, :159 | Directory descent/recording and independent permission/rollback walker. |
| ratarmount-compositing/src/write_overlay.rs:78, :2545, :9722; ratarmount-csi/src/process.rs:221; ratarmount/src/overlay_import.rs:340; ratarmount/src/overlay_upperdir.rs:105 | Existing reservation, MKDIR chmod, recursive reset/CSI cleanup and failure unseal/wipe. |
| ratarmount-compositing/src/overlay_seal.rs:684; ratarmount-compositing/src/write_overlay.rs:7431, :7463 | unseal reacquires SealCommitGuard; its separate Unix directory flock can wait on the caller's guard, while the non-Unix branch supplies no exclusion. B3/B4 must share a held guard. |
| ratarmount-compositing/src/write_overlay.rs:1750, :2599, :2601, :2834, :2836, :4435; ratarmount-compositing/src/rolling.rs:433 | Discovery after mutation, stringified late failure, creation before opening. |
| ratarmount-formats-sqlar/src/lib.rs:746, :821, :830; ratarmount-session/src/factory.rs:458, :462, :1342, :1352; ratarmount-session/src/remote_open.rs:1631; ratarmount-http/src/handler.rs:1479; ratarmount-compositing/src/automount.rs:947 | CAB UnsupportedCompression/libarchive escape (:458) and string erasure (:462), SQLAR/error-to-absence traps, separate HTTP len seam, infallible lazy discovery. |

## Staged PR sequence with per-PR diff budgets

**Hard caps:** touched files and additions + deletions against each PR's declared base, including tests, generated data/manifests, lockfile, CI, docs and deletions. Freeze a path allowlist. No formatting churn, hidden payloads, blanket approvals or test-line exemption. Each PR builds/tests against its predecessor and receives normal plus independent skeptical review. Repeated waves have separate caps, never pooled. Breach stops for decomposition/review. Do not resume paused agent-skills or run codex-workflows; no gate waiver/extra sweep is created here.

Crate names below abbreviate ratarmount-*.

| PR | Max files | Max changed lines incl. tests | Product scope (CI/docs counted below) | Entry → required exit |
| --- | ---: | ---: | --- | --- |
| A1 native filesystem/name rules | 12 | 2,200 | core, index | Inventory/provider decision → native identities, existing/absent family comparison/private-directory capabilities on all three OSes. |
| A2 Unix open/lifetime | 12 | 2,400 | core, index, checked-open-fixture | A1 → auto/POSIX proof, reuse/cross-thread close; denied unlink returns failure, connection-lifetime latch, missing scope denies; native Linux/macOS tests/child locks, both engines. |
| A3 Windows handles/lifetime | 14 | 2,600 | core, index, formats-sqlar | A2 (serialized shared files) → actual handles, private staging/managed bytes/lock-only objects, creation/cleanup mediation; observed flags/child exclusion, both engines. |
| A4 native publication I/O | 12 | 2,200 | core, index | A2+A3/durability decision → retained-lock rename/sync on owned fixtures: first/replacement/repeated native success. No caller cutover. |
| B1 alias-safe layout | 12 | 2,200 | core, index | All A accepted → prospective/per-descendant physical disjointness including coordination-child binds; no effects before refusal. |
| B2 durable coordinator | 14 | 2,600 | core, index | B1 → stable storage/ordered leases/complete roles/logical-ID digest locks; first-vs-lost ledger and native child/restart/equivalence proofs. |
| B3 recursive cleanup | 14 | 2,200 | core, compositing, csi, ratarmount | B1+B2 → full-tree preflight/shared filesystem guard and held-guard unseal; actual CSI/import/upperdir preservation before effects, namespace-free native success and Windows exclusion. |
| B4 content/ancestor/seal guards | 14 | 2,400 | core, compositing, ratarmount | B3 → reuse held guard through seal/unseal/rollback, collision-before-digest, common hiding/mutations/selective reset; native/race tests. |
| B5 installation/recovery | 14 | 3,000 | core, index | B1–B4 → compose A with coordinator permits through a **test-only entry**; snapshots/intents/move maps/phases/Done/owned cleanup and native crash/restart. |
| C0a preparatory fallible API | 10 | 1,800 | core, focused fixtures | All A+B exits → additive fallible surface alongside existing boundary, typed cause, dependency/retirement inventory; unchanged production acquisition and legacy behavior. |
| C0b* mechanical migration waves | 16 each | 3,000 each | frozen dependency-closed subset of inventoried implementers/consumers | C0a → migrate leaves/defaults, wrappers, session/compositing and adapters in separate waves; retire legacy edges as they close, preserve pre-mutation decisions/errors; no open/publication activation. |
| C0z bounded discovery cutover | 12 | 1,800 | core + final inventoried adapters | All C0b waves → remove remaining compatibility surface/exports, canonical fallible discovery only; no workspace-wide rename/signature sweep left for this PR. |
| C1 central API preparation | 16 | 2,800 | index, core, formats-sqlar | C0z → shared owners integrated with actual install_selected AND publish_tmp in test-only complete-path execution; native first/replacement/second success, both engines. Production activation waits for C1-cutover. |
| C2 factory/format waves | 14 | 2,000 each | session, compress, ≤6 format crates/wave | C1 preparation → inventoried warm/prepared/nested/compression paths, CAB/SQLAR real errors; no rebuild/spool escape. Repeat to exhaustion. |
| C3 bytes/cache/remote waves | 12 | 2,200 each | index, remote, session, ratarmount | C1 preparation → admitted copy/hash/cache/pin/pointer/upload paths, exact IDs/fallible maintenance; no fetched-path escape. |
| C4 commit/rolling | 12 | 2,400 | compositing, compress, session, ratarmount | C2+C3 → index before recovery/mutation/creation; typed late outcomes/failed source/no replay; identity/seal/retention preserved. |
| C5 frontend waves | 10 | 1,800 each | core/export-core + ≤2 of http/fuse/sftp/nfs/smb/9p | C2+C4 → all six handler mappings/lazy/history; HTTP + another wire exchange, feature v4/russh and mounted FUSE proofs. |
| C1-cutover production activation | 10 | 1,800 | core, index + final wiring sites | C2–C5 complete → switch the already-prepared closed graph to the shared boundary; remove staging plumbing, prove no reachable old index route, rerun native actual-caller and refusal controls. |
| C6 audit/docs | 12 | 1,200 | docs/packaging; no product mechanism | All C → no bypass/unknown inventory row, required evidence green, docs/catalog accurate. Fixes return to bounded owning wave. |

**No size exception:** every PR, including each C0b wave, stays ≤16 files/3,000 changed lines and within its tighter row cap. If a row will not fit, decompose within that stage before advancing; do not pool caps or move tests/docs into a later PR. A2 and A3 are serial, including shared core/index, workflow and manifest edits.

**CI ownership:** A1 includes `.github/workflows/ci.yml`, the packaging runner/contract checker and per-platform expected-test manifests for native L/M/W exits. A2 extends Unix lifetime/engines; A3 Windows flags/lifetime; A4 primitive publication. B1 owns privileged L/M mount runner setup and W junction fixtures; B3/B4 cleanup/guards; C1 actual-caller publication. Each extension lands before its owning exit, within that PR's caps. Stage manifests expand with implemented success groups; C6 cannot supply missing earlier infrastructure.

**Living docs ownership:** B3: `docs/csi.md`, `docs/write-overlay.md` cleanup/refusal/recovery. B4: `docs/write-overlay.md`, affected `docs/sandbox.md` ancestor/reset/seal rules. C0*: applicable `docs/session-api.md`/API migration notes in each wave, temporary notes closed by C0z. C1/C1-cutover: acquisition/platform/embedding compatibility in those API/overlay docs and CHANGELOG.md; a focused acquisition doc may be added. Each behavior-changing PR includes applicable README/matrix/catalog deltas per AGENTS.md:668, within caps. C6 audits already-shipped docs.

### C0 intermediate invariants and bounded cutover

The ruling authorizes a **temporary preparatory fallible API alongside the existing boundary**. C0a inventories method/call edges through defaults, implementers, wrappers, fixtures, public exports, mutations and feature/native adapters, with file/churn estimates per wave and final residue. Demonstrate a buildable transition with C0z inside its cap; deferring a 144-file sweep fails this exit.

| State | Protection invariant | Required evidence before merge |
| --- | --- | --- |
| C0a: additive preparation | Production acquisition preserves its existing #239 boundary and legacy behavior. Forward-only legacy-to-fallible wrapping is limited to genuinely infallible results; no error-capable producer is exposed behind legacy discovery. | Compile real implementers/defaults; success/absence parity and injected typed-error identity on the preparatory API; existing native checked-open/link/lock/lifetime regressions. |
| Each C0b wave | Closed caller/implementer group preserves acquisition; Err survives end-to-end, only absence selects fallback. Decisions precede mutation. Retire old entries as incoming edges close; no error producer reaches an infallible caller. No coordinator/publication activation. | Compile affected targets/features; audit remaining edges. Inject refusal through migrated defaults/wrappers and a mixed legacy/migrated fixture: no erasure/alternate open, unchanged bytes/rows/tombstones/queues/accounting. Run relevant native and healthy/history controls. |
| C0z: final discovery cutover | Canonical fallible public/default/wrapper paths only; existing open_checked protection stays. Bounded remaining declarations/exports/wiring only. | Zero unexplained legacy calls/entries across cfg/features; public lazy/history/refusal transport, pre-mutation/native controls, breaking-API docs. |

C0b follows dependency closure: source/defaults → wrappers/compositing → session/mutations → protocol/embedding; repeat groups as separately capped PRs. Retire compatibility incrementally; no global rename remains at C0z. Names/visibility are implementation details subject to the proof above. No `.ok()`, error-to-None/false/zero/string, panic substitute, raw fallback or bypass feature to make a wave compile.

If the real Rust call graph prevents this split, **stop with a concrete dependency/invariant proof**, not a size exception: identify caller → wrapper/default → trait slot → implementer edges (file/symbol/feature), why each cannot coexist or retire safely, and the smallest forced atomic set with counts. Take only that demonstrated conflict to ADR-3/Keystone/Matt; this plan does not assert impossibility or approve a larger PR.

**Acquisition activation invariant:** A/B producers/publication are test-only; B3/B4 may strengthen cleanup without enabling new index admission. C0* preserves existing acquisition. B5 leaves production `install_selected`/`publish_tmp` unwired until C1. C1 preparation/C2–C5 test the new complete path, selected before acquisition; production preparation preserves the existing boundary. Before **C1-cutover**, prove every reachable SQL/byte/copy/remove/cleanup and outward failure edge participates. No old-route fallback after new refusal, active coordination hybrid or optional checks. Bounded final activation/compatibility removal needs the same ADR-3 graph proof if closure fails.

### Caller-wave acceptance

Trace every accepted-inventory route: selection → owner → SQL/bytes → cleanup/publication → outward outcome. Audit following checks, Option/bool/string reductions and fallbacks.

C0* hoists fallible base decisions before unlink/rename/copy-up/accounting; injected refusal preserves payload/targets/rows/tombstones/queue/accounting. SQLAR checked failures and stored failed-source errors must survive wrappers/discovery/history. C1–C3 cover all index/cache/format/byte routes, especially CAB and remote-folder catches; preserve admitted stale/corrupt recovery separately. C2's CAB exit names both `factory.rs:458` UnsupportedCompression/libarchive fallback and `:462` string conversion: terminal checked failure must survive either branch without rebuild/spool retry.

C4 admits before journal recovery, missing archive/rolling creation and mutation; Auto cannot evade refusal. Local Copy/in-place/offline/remote late tests preserve typed cause + committed/unknown outcome, correct baseline/journal, failed live source, retention and no archive replay. Proven late commit exits 1: “archive committed; index maintenance failed”.

C5 swaps the actual outer durable index before first lazy/historical access; prove reacquisition and healthy oldest/newest bytes. GET/HEAD includes the len seam; DAV completes discovery before headers, no 404/partial 207/socket drop. Inherit every accepted protocol mapping, structured pending/unknown ID/state/cause and reason-specific headers; HEAD has no body.

## Blocker-by-blocker resolution

### (i) macOS/non-Linux availability and name equivalence

**A1–A3/B2 mechanism:** implement a parent capability adapter: directory identity, filesystem/configuration-specific comparison including absent names, native locks/durability. Ordinary supported configurations must succeed. Windows uses its own adapter, not Unix installed()'s UnsupportedPlatform result.

- Linux: fstatfs selects a reviewed rule; ext4 additionally verifies FS_IOC_GETFLAGS/FS_CASEFOLD_FL. Prove normal tmpfs/ext4 and reviewed btrfs success; reject unknown rules and classify unsupported ABI before its ioctl.
- macOS: getattrlist/fstatfs metadata supplies volume/directory identity and case capabilities; a reviewed versioned filesystem comparator handles existing **and absent** components, corroborated for existing names by native nofollow metadata lookup without SQLite alias descriptors. APFS normalization equivalence is separate from spelling preservation ([Apple](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/FAQ/FAQ.html)). Choose the exact API/table provider at ADR-1; generic lowercase/current-Unicode NFC is insufficient. Default APFS and existing supported configurations cannot be dropped. Preserve automatic locking with descriptor/reuse/cleanup proof.
- Windows: directory handles provide volume/directory identity and FileCaseSensitiveInfo; native directory/name metadata enumerates long/short aliases. Apply a verified NTFS UTF-16 comparison rule to absent names too, without assuming APFS normalization or generic lowercase/CompareStringOrdinal is volume collation. Reject unrepresentable stream/device/path spellings. Main equivalence does not prove literal companion-family equivalence: refuse an unprovable short-name family before a second claim/lock, not every NTFS admission.

**Native/process proof:** existing/absent success, parent-link success (/var included), final/companion-link refusal. Children select Index.sqlite/index.sqlite in both orders/absent races: one logical role/state/digest lock and serialized publication, retained after exit/restart. Test APFS NFC/NFD, NTFS non-ASCII case/normalization-distinct controls, and genuinely distinct case-sensitive names. Real NTFS 8.3 fixtures prove main identity then full-family equivalence or early refusal without duplicate claims. Vectors/unavailable controls cannot substitute.

**A2 Unix cleanup exit:** denied unlink must return syscall failure (and xDelete an error), retain the connection-lifetime typed latch, and treat a missing callback/thread scope as denial for protected names. No success return or TLS absence grants authority. Native Linux/macOS tests force denied unlink, absent scope, cross-thread close and complete drop; even if SQLite ignores the return, finish reports the latch and links/targets/bytes remain intact. A3 requires the equivalent Windows guarantee.

### (ii) Windows publication: FILE_SHARE_DELETE + retained SetFileInformationByHandle(FileRenameInfoEx)

**A3–A4/B5/C1 mechanism:** actual Windows VFS/I/O, staging and managed-byte adapters, with these mandatory steps:

1. Before concurrent SQLite use, install/verify each engine's enabled CreateFileW/CreateFileA paths, including internal winOpen from shared-memory methods. Unknown/replaced creation paths refuse before exposure. No slot patching around opens; registration survives callbacks and cross-thread close.
2. Forward admitted selected/owned handles with **FILE_SHARE_DELETE**, and request **DELETE access at creation** for the candidate's retained lock-only VFS object. Observe actual forwarded flags; sharing cannot be retrofitted ([CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)).
3. Drain participating readers/connections/maps under admission gate + exclusive parent lease (eligible readers may use accepted private snapshots); undrainable owners are Busy. Retain old nonempty-destination and candidate SQLite VFS lock-only objects. Never close their locks for rename, duplicate ownership or substitute raw alias locks. Revoke old pathname cleanup authority separately.
4. Borrow the existing candidate HANDLE through **SQLITE_FCNTL_WIN32_GET_HANDLE**. Call **SetFileInformationByHandle(FileRenameInfoEx)**, same volume, replace-if-exists + POSIX replacement flags for admitted existing destination, no replacement permission for expected absence ([structure](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info), [semantics](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4217551b-d2c0-42cb-9dc1-69a716cf6d0c)). Old/candidate VFS locks and namespace exclusion survive rename, durability and synced InstalledPending.
5. Implement actual NTFS file/record/namespace durability. Preflight before retirement; do not assume Unix sync_dir or directory FlushFileBuffers works. ADR-2 resolves the exact barrier before stage exit. Only durable evidence permits lock transfer for checked reopen, retirement cleanup and Done.
6. Mediate xDelete/delete-on-close/xShmUnmap through final teardown; deny and latch unauthorized cleanup, returning failure even if SQLite ignores it. Incompatible sharing/external locks are Busy; unsupported-adapter controls refuse before retirement. Neither replaces native NTFS success.

**Native/process proof:** both actual **install_selected and SqliteIndex::publish_tmp**, bundled/SQLCipher: absent first publication, old-WAL regular replacement, second after Done; candidate-only rows/integrity, prior Done unchanged, fresh-process reopen. Section (v) proves flags/HANDLE continuity, child locks and crashes. Add incompatible non-delete-sharing handle Busy then successful retry, shm/companion creation, denied delete/unwind and hook replacement. Generations/compilation alone are insufficient.

### (iii) bind aliases of coordination descendants: paths_overlap

**B1 mechanism:** a fallible filesystem-location proof compares physical containment both ways, shared by layout and each descendant traversal. Prospective paths use nearest existing ancestor + verified remaining components without mkdir.

On Linux combine directory/statx mount evidence with decoded /proc/self/mountinfo. Translate relevant mounts using filesystem device + **mount root and relative suffix**; distinct mount IDs do not imply disjointness. A bind of `coordination-v1/index-namespaces/<id>` under base/alias is still inside coordination despite disjoint exposed ancestor chains. Inspect descendant/nested/file mounts, corroborate identities, and refuse ambiguous mappings without reading protected ledgers. macOS/Windows use native volume/directory identity and resolved ancestry; inspect supported mounts/junction/reparse targets before descent. Opaque user symlinks remain nofollow; explicit aliases into coordination refuse.

Validate before digest recording, enumeration, serving/open, payload/bundle or cleanup effects; revalidate topology under guards. Arbitrary out-of-band topology mutation retains the accepted limit. Ordinary disjoint native layouts succeed.

**Native/process proof:** real Linux binds, **macOS mounts and Windows junctions targeting coordination descendants**: `index-namespaces/<id>`, digest-locks and deeper directories/contained files beneath ordinary content children. Also test parent/root, reverse containment, absent children, nested aliases and disjoint siblings. Parent-only aliases do not satisfy any platform's exit. Drive digest/payload/direct access and B3 cleanup; assert no protected read/digest change, unchanged bytes/identities/modes and held child locks. Unsupported or unproven mount mappings refuse; required native fixtures must actually execute.

### (iv) recursive preflight_namespace_free_cleanup and CSI remove_dir_all

**B3–B4 mechanism:** full read-only preflight under retained root/operation serialization precedes any unseal/chmod/deletion/row/queue/accounting effect. **Every entry** receives B1's physical coordination check and reserved-state/ownership classification before enumeration/descent. Root-only placement + suffix-only recursion is prohibited. Inspection errors refuse, without flatten()/best-effort continuation.

Coordinator creation, reset, cleanup, mutation and permission transitions share containing-root serialization and explicit lock order. Private/driver-created roots may gain state later. CSI restart/teardown uses the child's resolved coordination configuration across env-clearing paths; the filesystem helper needs no SQLite dependency.

**B3 introduces, B4 reuses a shared held-guard unseal entry point.** The public unseal wrapper acquires once; cleanup passes its validated filesystem guard through preflight → unseal → guarded delete/rollback. Do not call today's self-acquiring unseal under SealCommitGuard (`overlay_seal.rs:684`, `write_overlay.rs:7431`): a second descriptor can deadlock. Replace the non-Unix no-op with real exclusion for supported cleanup; native Windows child contention must prove it. Test one acquisition, wrong-root guard rejection, no nested wait, competing coordinator/cleanup exclusion and release after success/error. Preserve seal/commit-before-archive lock order.

Replace CSI's unrestricted remove_dir_all with shared guarded deletion consuming/revalidating the classified tree; never recursively wipe an unclassified subtree. Import/upperdir acquire the guard and preflight **before unseal**, retaining it through permitted unseal/deletion and returning original failure + recovery condition. Namespace-free owned trees can be removed; pending/unsafe state blocks reset before effects; terminal state permits selective payload removal preserving records/locks/ancestors/access. Global overlap refuses rather than becoming an exclusion.

Protect existing ancestor effects, including MKDIR/create_dir_all followed by chmod, rename-over, tombstones, metadata/xattrs and aliases. Include row-only collisions and independent seal walker/rollback. Terminal-state seal/reseal/unseal preserves exact protected modes and ordinary payload sealing; incompatible access refuses before modes/rows/sentinel, without weakening sealing.

**Native/process proof:** whole coordination and **individual descendant** aliases through actual CSI unmount/restart, reset and import/upperdir failures. Refusal preserves payload, rows, queues, accounting, modes, records and child lock before unseal/partial deletion. Add unreadable/partial/foreign/link/row-only collisions; namespace-free, sibling/look-alike and selective-terminal success. Barrier-controlled coordinator creation versus reset/ancestor rename/permission transition must serialize; test shared MKDIR/chmod protection through a writable frontend. Core helpers do not replace CSI/permission-walk execution.

### (v) native plus cross-process evidence

Use a small re-exec harness with exact child roles, pipe/socket barriers, timeouts, exit/backend capture and isolated roots/umasks. No sleep-only races or thread-only Windows locks. Required observations:

- Child namespace contenders and independent old/candidate SQLite VFS lock-only probes remain excluded at rename/durability, then succeed after deliberate release. Probes retain the intended objects across rename and use compatible Windows sharing; NotFound is not exclusion. A negative control releasing a required lock early must be detected. Observe flags/HANDLE continuity and macOS descriptor/reuse + automatic-locking exclusion.
- Kill after preparation, each companion move, rename, durability, phase sync, reopen, cleanup and Done sync; fresh-process recovery proves exact old rollback or installed/pending/unknown, never old-WAL replay. Same-inode candidate-byte changes **before durable publication evidence** fail the recorded digest; mutable drift is allowed only after proven InstalledPending, immutable bytes never drift.
- Case/Unicode/absent/8.3 tests establish durable shared roles/state/digest identity through exit/restart/second install; lost/corrupt/partial ledger is not new initialization.
- B5/C3 also run accepted mutable-writer-after-classification cutoff/checksum/integrity tests and immutable DELETE/live-WAL exact-hash/fresh-ID tests; failed pins cannot advance pointers.
- Digest availability/peek/hash/refresh/error/drop leave legacy siblings untouched. With a sibling alias to a held database, child writers stay excluded across support close, then succeed on release. Native hash exclusion/restart/cancellation and planted support-alias controls remain required.

Exact-name/count manifests prove selection, not correctness. Review assertions/negative controls. Required native groups need nonzero executed **supported-success** tests; all-unavailable, ignored or runtime-skipped suites fail their lane.

## Platform test matrix

All rows are **future required evidence**, not runs in this session. New tests use regression_235_part2_ and Regression: symptom docs; assign exact names in each PR. L = Linux brewtop + Linux CI; M = native macOS CI; W = native Windows CI. Both SQLite engines run separately as below.

| Test/group | Where | Proves |
| --- | --- | --- |
| Existing/absent admission, parent/final/companion links, typed errors | L x86_64 + native Linux CI aarch64; M; W | Supported native success and refusal, not Unix simulation of Windows. |
| Complete roles, equivalent/absent names, both orders/restart; native flags/locks | L ext4/tmpfs/reviewed rules; M APFS sensitive/insensitive; W NTFS case/8.3; both engines | Case/Unicode/full-family identity, shared state/leases/digest lock and real interprocess exclusion. Disposable fixtures only. |
| macOS auto locking/reuse/teardown and existing VFS pins | M both engines, deployment-target 14.0 checked-open/DSO retained | Descriptor proof and child exclusion; ordinary versus snapshot/managed policy. |
| install_selected AND publish_tmp first/replacement/second/old-WAL/crash; mutable writer/immutable exact IDs | **Linux ext4, macOS APFS, Windows NTFS; both engines on each**; C1/C3 actual callers | Retained locks/handle flags, retirement/Done, rollback/pending/unknown/restart, snapshots/exact pins/pointers. |
| Coordination root/parent/**descendant** aliases and traversal/cleanup | brewtop if permitted; required isolated Linux bind CI, macOS descendant-mount CI, Windows descendant junctions | Physical disjointness before reads/creation/deletion. Parent-only controls/local skips do not satisfy exit. |
| Recursive cleanup/races, CSI unmount/restart, import-before-unseal; reserved ancestor/reset/seal | L/M/W shared helper; actual CSI L; full L/M compositing/CLI and supported W paths | No descendant deletion/partial refusal; namespace-free success; protected state/access preserved. W helpers do not prove Unix modes. |
| SQLAR/CAB/folder transport, wrappers/history outer-index reopen | L/M workspace, W supported library targets | Actual failures survive without absence/rebuild/spool/fetched fallback. |
| Commit/rolling ordering, late outcomes, identity/raw/retention | L, M applicable tests, Linux mounted live/idle/on-exit | No destructive discovery, replay or baseline downgrade. |
| HTTP GET/HEAD/len, DAV Depth 0/1 lazy/history/pending/unknown | Loopback L + supported M | Complete statuses/body/HEAD headers; no partial 207/socket drop/leak. |
| FUSE discovery/history errno and protected ancestor writes | brewtop with FUSE; required mounted Linux CI + phase/seccomp allowlists | Kernel-facing errors/common mutations; no skipped-mount inference. |
| SFTP russh/NFSv3+v4/SMB2/9P handlers | Linux feature jobs; HTTP + SFTP or NFS real wire | All accepted statuses/messages; other clients unverified unless run. |
| #239 hooks/private embedding/DSO/prepared/readers/modes/policy | Existing Linux x86_64/aarch64, M deployment/DSO, Python embedding/wheels; retain W compile | Foundation/initialization/approval compatibility; compilation does not prove publication. |

Main CI: .github/workflows/ci.yml:40 fmt first; :105 clippy, **:108 cargo test**; :306 FUSE needs check; :123 native aarch64; :355/:480/:510 macOS workspace/deployment; :529 best-effort macOS FUSE; :542/:558/:561 Windows compile-only/session-skippable; :180 v4_ selection. Separate Python embedding: .github/workflows/python.yml:97. Existing checks do not establish native publication.

Add Linux/macOS native backend rows and non-optional **windows-index-publication**, windows-2022/stable MSVC/local NTFS, backend [bundled, sqlcipher], fail-fast false, no continue-on-error. Preserve windows-lib. Provision MSVC/Perl/NASM/vendored-OpenSSL tools and fixture privileges; missing requirements fail rather than skip. Record OS/build/architecture/filesystem/case/8.3/tools and isolate target directories.

A1 provisions native rows on ubuntu-24.04, macos-15 and windows-2022. B1 owns required `coordination-aliases-linux` on ubuntu-24.04 with sudo/private disposable mount namespaces, and `coordination-aliases-macos` on `[self-hosted, macOS, rrs235-alias-mount]` with a proved native descendant-mount facility; that runner is a provisioning requirement, not existing evidence. Windows junctions run in its native row. No continue-on-error/skip; unavailable privilege or runner blocks B1. Setup/checker/manifests count within B1's cap.

For the core/index/SQLAR backend matrix, run only **ratarmount-core + ratarmount-index + ratarmount-formats-sqlar** together per engine: stock without cipher; cipher with **--features ratarmount-formats-sqlar/sqlcipher**. Index has no cipher feature (ratarmount-index/Cargo.toml:10); SQLAR enables the shared engine (ratarmount-formats-sqlar/Cargo.toml:18). Later commands use cargo test --locked with those -p selections and --lib regression_235_part2_, then `-- --list` and `-- --nocapture --test-threads=1`; capture matching cargo tree -e features -i libsqlite3-sys. Other matrix rows run their affected packages/targets separately.

Set RATARMOUNT_TEST_SQLITE_BACKEND per row; every index process/child verifies version/source ID and PRAGMA cipher_version (absent stock/nonempty cipher); SQLAR tests encrypted create/reopen. Reviewed per-executable/platform manifests require exact nonzero executed success groups, no ignored/runtime-skipped requirements. Packaging regressions in Linux check enforce matrix/packages/features/backend/count/non-optional execution; counts do not prove behavior.

Retain AGENTS.md:9 gates: fmt/fmt-check, workspace clippy/test under CARGO_BUILD_JOBS=2/flock, Python policy tests and affected compiler/syntax/manifest controls; no weakened/automatic approvals. Run explicit sftp-russh/nfsv4 checks; regression_235_part2_v4_ must be a nonzero subset of executed v4_. Preserve every accepted-plan baseline regression, especially locks/modes/prepared/readers, directory reopen, #235/#254/#259/#261/#263 and identity/journal/seal/retention; verify separate filter selection.

### UNVERIFIED

- **All proposed runtime behavior:** this session only reads/writes plan evidence; no Cargo/native/FUSE/wire execution. Attempt-1 results are not inherited acceptance.
- Comparator providers/absent-name rules, macOS auto-locking proof and Windows flags/rename/durability, both engines, case/Unicode/8.3/child/restart: outstanding and block their stage exits.
- Linux binds/macOS descendant mounts/Windows junctions, CSI/import preservation, guard exclusion, runner/privilege provisioning and races: outstanding; brewtop namespace/FUSE availability is not assumed.
- Untested architectures/configurations remain unverified, never relabeled as removed support; x86_64 does not prove aarch64.
- macOS best-effort FUSE does not prove mounting; W library/publication does not establish WinFsp/full overlay/Unix permissions. Handler tests do not prove all clients; required HTTP + second wire and Linux FUSE must actually run.
- Cloud concurrency/conditional writes and hardware power-loss durability are not established by mocks/process kills. Unsupported/ambiguous refusals are negative controls, never supported-native success.

## Out of scope

**#274, RetainOffline redesign, receipt supersession and PARKED 5b517d2c stay OUT.** No revival/rebase/cherry-pick/reconstruction. No latest-receipt replacement, edit revisions, frozen deltas, commit-state namespaces, rolling completion receipts, remote replay spools or exactly-once claims. The separate RetainOffline replay hole is neither fixed nor a dependency. Index Done records concern companion installation only; they cannot authorize replay/consumption or clear earlier identity evidence.

No archive-permission/#239 proof redesign, terminal-record compaction, unrelated refactors, arbitrary remote guarantees or WinFsp work. Older sibling-locking binaries are not interoperable: stop them before activation; never dual-lock/adopt legacy siblings. Preserve genuine raw semantics and every protected identity/journal/hash/seal/retention rule. Do not close #235 or change tracking here.

## Architecture-decision flags (Keystone/Matt)

Flags are not approvals. Routine adapters/decomposition within the contract need ordinary review; support narrowing/refusal stubs are forbidden. **ADR-1/ADR-2 detail belongs in the separate ADR-PACKET.md review artifact**; this revision edits neither that packet nor other files. The obligations/deadlines below remain here.

| Flag / deadline | Options and recommendation |
| --- | --- |
| **ADR-NEEDED-1: comparator provider**, before A1 exit | Packet: exact API/rule provider, provenance/size and native absent-name evidence. Undocumented APIs, raw-volume reads, large tables or production probes need Keystone/Matt; no guessed comparator or dropped platform. |
| **ADR-NEEDED-2: Windows durability**, before A4 exit | Packet: retained-lock NTFS barrier/API/access/error/crash proof. Any changed durable-evidence/recovery model needs Keystone/Matt; no assumed directory flush, close-before-rename or supported-NTFS refusal substitute. |
| **ADR-3: staged API/activation**, proof at C0a; conflict before cutover | Binding direction is C0a → C0b* (each ≤16 files/3k lines) → bounded C0z, then closed-graph C1 activation. Temporary preparation is authorized. Review real edge inventory/churn/retirement proof. If impossible, provide the concrete forcing call graph/invariant to Keystone/Matt; no cap exception, broad final sweep, error erasure or active hybrid. |
| **ADR-4: demonstrated contract conflict only**, if encountered | Escalate an actual proof/automatic-locking/seal/rolling-order conflict. Routine adapters, decomposition and missing runtime/runner evidence are not ADR-4 decisions. No POSIX-only substitute, #239 descriptor redesign, weakened sealing or replay authority. Already-permitted external state placement needs no new decision. |

No flag authorizes #274/receipt supersession. Present any claimed dependency without implementing it.

## Rollback/abort criteria per stage

Every PR stops on cap breach, unreviewed policy expansion, zero/skipped required evidence, lost cause/outcome or excluded dependency. Freeze/report the failing invariant; do not extend review caps through broad repair sweeps.

| Stage | Abort → safe response |
| --- | --- |
| A1 | Ordinary native admission refuses/equivalence splits → no migration; resolve provider/rule (ADR-1). |
| A2 | Auto/reuse proof, child locks or teardown regresses → withhold activation, repair isolated lifetime proof/ADR-4; preserve rejected descriptors. |
| A3–A4 | Missing Windows protocol, wrong flags, early close or unproved durability → stop before retirement; ADR-2, no raw/close-rename fallback or Linux-only acceptance. |
| B1 | Descendant alias admitted/ambiguous, overlap reads/creates state → refuse before effects and repair proof with native disjoint controls. |
| B2 | Child escapes lock/claims split/lost ledger reinitialized → stop admissions; retain stable locks/ledger, no PID expiry/reconstruction. |
| B3–B4 | Partial cleanup/unseal, ancestor access loss, changed protected identity/modes → retain tree/original failure; no record deletion/sealing downgrade. |
| B5 | Old WAL/new main, bad digest/immutable drift/lost Done/uncertain publication → restore only exactly proven old set before publish and sync rollback; after publish retain installed/pending or unknown, never old companions beside candidate. |
| C0*–C3/C1-cutover | Absence/fallback, post-mutation discovery, unsafe compatibility edge or reachable bypass/hybrid → stop cutover; fix bounded owning wave; actual forced atomicity needs ADR-3's dependency proof, not a larger cap. |
| C4 | Mutation on refusal, lost committed outcome, downgrade/replay → preserve committed baseline/journal/delta; stop unsafe retry/failed source; return architecture conflict. |
| C5–C6 | Missing native/FUSE/wire, partial/wrong response/history or unproved claim → no completion/release; repair owning wave, retain UNVERIFIED gaps. |

Code rollback never authorizes deleting durable roles/installation/overlay evidence or mixing incompatible binaries. Recovery follows the last durable installation phase. Unresolved conflicts return to Keystone/Matt.

— Muse
