# Design: Fork-N writable CoW tops

Status: **design of record for Keystone’s Option A BUILD lock (2026-10-23)**.
This document is that contract, published as docs only. Matt approved this
publication. It does not claim a planning-gate ACCEPT, and it is not Keystone
code LGTM of an implementation. PR1 and PR2 are later work. The v3 planning
packet is capped at six skeptic sweeps; this text is the contract those sweeps
produced, plus the [BUILD-lock v1 limits](#v1-limits-keystone-build-lock).
Base: `main` at `42f4fb66c8f09fd26fd743dfd3f8fbb5240267f2`.

## Problem and decision

cpanmine needs one sealed prepared tree with parallel writable phase layers. The
[N-process recipe](https://github.com/hilather/ratarmount-rs/blob/42f4fb66c8f09fd26fd743dfd3f8fbb5240267f2/docs/sandbox.md#branching-an-episode) and
[§3.4](https://github.com/hilather/ratarmount-rs/blob/42f4fb66c8f09fd26fd743dfd3f8fbb5240267f2/docs/tasks/plans/sandbox-features.md#34-branching-an-episode-recipe-no-new-code)
already permit sharing a sealed lower; each process opens its own factory stack.
Fork-N shares that work while keeping every phase a normal host mount root for
`make` and container bind mounts. Incremental make orchestration stays with the
consumer; there is no timing claim or benchmark result in this design.

Keystone's 2026-10-23 BUILD lock is **Option A**: one serving process, N FUSE
sessions on N threads, N host mountpoints, one composed
`Arc<dyn MountSource>`, and N separate `Arc<WriteOverlay>` tops. Each overlay
stores a clone of the shared composed Arc in `WriteOverlay.base`. Each session
receives **its own top's overlay as both `source` and `overlay`**. The outer
composed handle can be dropped after the overlays retain their clones.

Options B (one path-namespaced mount), C (N processes), and D (kernel overlayfs
uppers) are rejected for v1. N `/dev/fuse` descriptors are accepted until measured.
A single `fuser::Session` does not serve N mountpoints.

## Existing code at the base SHA

All file:line references below were checked against
`42f4fb66c8f09fd26fd743dfd3f8fbb5240267f2`; they identify that immutable baseline,
not the future positions after PR1/PR2. New APIs below are **proposed**, absent at
this SHA. Workspace members are in `Cargo.toml:4`; the binary is
`ratarmount/src/main.rs` (`ratarmount/Cargo.toml:11`).

| Building block | Verified location and behavior |
|---|---|
| CLI | `ratarmount/src/main.rs:519` has one `write_overlay`; `:523` has repeatable lowers; `:527` permits unsealed lowers. `:90`–`:96` is foreground (the doc comment through the field). Mount CLI has no `--top` or `--mount`; `sandbox/run.rs:31` has an unrelated one-directory `--top`. |
| Stack opener | Binary-private `MountLowerStack`, `main.rs:1412`; `compose` at `:1487`, `open` at `:1503`, `open_in` at `:1513`, `open_with` at `:1531`, full `check_top` at `:1671`. |
| Composition | `ratarmount-compositing/src/overlay_layer.rs:577` composes bottom-up; `ratarmount-core/src/lib.rs:706` requires `MountSource: Send + Sync`. |
| Lower snapshots | `Immutability::Immutable`/`Shared`, `overlay_layer.rs:20`; rows are a construction-time snapshot, transaction committed at `:177`; host bytes remain independently opened (`:45`–`:47`). |
| Writable source | `ratarmount-compositing/src/write_overlay.rs:719` declares `base`; `open` at `:1062` forwards composed source; initializer `:1301` stores it. `current_base`/`replace_base` at `:1473`/`:1482` retarget only that instance. |
| Creation | `CreateOptions`, `overlay_identity.rs:1190`, includes `lower_layers`; `LowerLayerRecord`, `overlay_meta.rs:49`, records path/digest/seal time. Mount builds options at `main.rs:2600`, invokes `overlay_create::create_overlay` at `:2615`, which calls `WriteOverlay::open` (`overlay_create.rs:46`). |
| Identity | `MountedBase`, `main.rs:1386`, and `BaseIdentity`, `:1407`; `mounted_base_identity`, `:1425`; the lower marker key at `:1331` (`lower_key_for`), the view key at `:1347` (`mounted_view_key`), and the default-view predicate at `:1366` (`mounted_view_is_default`). These are binary dependencies, not library APIs today. |
| Mount safety | `ratarmount/src/mount_guard.rs:570` implements lexical, mountinfo-view and same-view inode comparisons. Read-only resolution never creates mountpoints (`:6`–`:7`). |
| FUSE | `ratarmount-fuse/src/lib.rs:3932` serves one blocking session; `:3981` constructs it, `:3988` runs it, `:3989` clears notification state, and `:3990` joins its notifier. |
| Offline verbs | `overlay_seal.rs:202`/`:446` seal/verify; `ratarmount/src/overlay_import.rs:23` owns binary `ImportArgs`. |

An allowed unsealed lower is constructed once using `Immutability::Shared` and
shared by all tops. Its database rows do not refresh during this run; later host
file edits can be visible through both tops. This does not claim immutable host
bytes or a per-top lower snapshot.

## Proposed CLI and ownership

```text
ratarmount [--lower PREPARED ...] [--allow-unsealed-lower] \
  --top A=OVERLAY_A --mount A=MOUNT_A \
  --top B=OVERLAY_B --mount B=MOUNT_B BASE...
```

`--lower` is optional. Split each assignment on the first `=`; require a
nonempty name and path, unique names on each flag, exactly matching name sets,
and N ≥ 1. Match by name, not argument order. In Fork-N mode all positional
paths are sources: bypass the positional-mountpoint heuristic at
`main.rs:5034`/`:5050`. There is no extra positional mountpoint. Neither flag
means the existing CLI and its single `-w` path remain unchanged.

The early `corpus` verb keeps its existing `LIST-FILE MOUNTPOINT` grammar and
**rejects either Fork-N flag with exit 2 / `ArgumentConflict`** inside that
branch, before setting `corpus_list` or returning (`main.rs:858`–`:880`). It
returns before generic validation (`:897`), so a later Fork-N conflict check
alone is insufficient. No Fork-N corpus adaptation is part of v1.

Fork-N is FUSE-only. Either flag refuses, with exit 2, `-w`/`--write-overlay`,
`--overlay-tmpfs`, `--sandbox` shorthand, `--no-mount`, export modes (`--nfs`,
`--http`, `--webdav`, `--smb`, `--ninep`, `--sftp`, `--sftp-subsystem`), and
non-serving actions such as find, unmount, repack and publish. The sandbox
supervisor and `sandbox run --top` are not changed. Refuse `--control-interface`
(including socket-only mode) and `--journal`: both currently represent one
mount's state. No multi-mount control or journal protocol is introduced.

Daemon Fork-N additionally refuses torrent sources with exit 2 and guidance to
use `--foreground`. Before factory construction or invocation-created
directories, check **every positional and `--bind` source**, including mixed
source lists, using the same `ratarmount_remote::is_torrent_input` dispatch as
the factory (`ratarmount-remote/src/lib.rs:508`;
`ratarmount-session/src/remote_open.rs:1211`). This covers magnets and, with
`bittorrent` enabled, existing local metainfo, HTTP(S) `.torrent` URLs and
`file://` metainfo. There is no exception for `--torrent-swarm never` or seed
settings. Carry a proposed daemon Fork-N source-policy flag through factory
and nested-opener options and recheck immediately before
`TorrentMountSource::open` (`ratarmount-session/src/remote_open.rs:1214`), so an input that changes after preflight cannot
start workers before the fork. A lazy nested opener discovering a torrent
after startup returns `Unsupported` without constructing it, rather than
exiting the serving process. Foreground Fork-N remains eligible subject to
transitive storage admission; legacy single-mount behavior is unchanged. The daemon worker-preparation contract
below also governs local zstd, HTTP and every selected constructor's complete
dependency subtree. Torrent refusal alone does not make daemonization safe.

For **any** `--top`/`--mount` invocation, with or without `--lower`, refuse
`--commit-overlay`, `--commit-overlay-on-exit`, a nonzero
`--commit-overlay-interval`, and `--roll-every`. Preserve the diagnostic
`commit of a layered stack is not supported; flatten first` for commit
refusals. Do this before rolling implies on-exit at `main.rs:921`; do not copy
only the lower-gated test at `:923`. One top's `replace_base` does not update
its siblings, and rewriting a shared archive invalidates their readers.

Proposed `ForkedTops` owns the shared classified-base keepalive, composed stack,
and N `TopHandle { name, overlay_dir, mountpoint, overlay }` values. `overlay`
is `Arc<WriteOverlay>`; each worker gets that same Arc coerced to
`Arc<dyn MountSource>` as `source`, and `Some(overlay.clone())` as `overlay`.
A top never becomes another top's base. Proposed coordinator state owns worker
handles and startup/shutdown state, without changing the sandbox supervisor.

Include Fork-N in `wants_identity` (`main.rs:2331`), in `overlay_target`
(`:81`) and `base_flag_needs_target_or_lower` (`:746`), so no-lower forks can
use identity, force and policy options. Apply the process-wide encoding,
read-only/allow policy, quota, commit-mode/manifest settings to each individual
overlay as today's setup does at `main.rs:2627`–`:2685`. Each quota has its own
counters. Parent policies are preflight state; daemon serving policies and
host-derived counters are rebuilt under all child locks as specified below.
Shared process FUSE options, readahead, direct I/O and
`PassthroughOptions` (`main.rs:2923`, default `auto` at `:404`) apply to every
session. There are no per-top forms of those flags.

## Identity: mountpoints are subjects, tops are exclusion bases

For each mountpoint, compare it against every served directory, bind-source
directory, every top directory and every *other* mountpoint. Use the same
three checks as `mount_guard::relation`: lexical (`mount_guard.rs:572`),
`/proc/self/mountinfo` views (`:577`) and same-view inode identity (`:595`).
These catch bind aliases, hidden binds, and existing case/Unicode aliases;
`canonicalize` or prefix checks alone do not implement the contract.

**Only mountpoints are hang-refusal subjects.** A top inside the directory
base is allowed and excluded from the weak digest, not exit 2. Today's overlay
is a comparison base in `bases_now` (`mount_guard.rs:805`), while
`check_mount_point` (`:869`) supplies the mountpoint subject. Do not make a top
a subject against the served directory: `compare_rel` at `:489` would reject
the required inside-base case. A mount equal to, inside, or an ancestor of any
top is still refused, as are unsafe mount-to-mount relations.

**Inside-base visibility is path-relative, not a hidden subtree.** Digest
exclusions affect identity hashing only. With base `/repo`, top A
`/repo/runs/a` and top B `/repo/runs/b`, writing A's `/x` leaves B's `/x`
independent, but B can list and read A's host file as `/runs/a/x` through the
live folder base. The reverse path `/runs/b/x` behaves symmetrically. The
folder source directly joins virtual paths onto its host root
(`folder.rs:31`–`:37`, `:189`, `:236`); overlay lookup/open fall through to it
(`write_overlay.rs:5451`, `:5486`). This includes other host entries in those
top directories, subject to existing source visibility rules. V1 adds no
source filtering or security boundary for inside-base tops. Consumers needing
namespace separation must place tops outside the served directory base.
The same-virtual-path isolation and symmetric live-listing requirements below
still apply.

Retain an early read-only check, and generalize `decisive_check`
(`mount_guard.rs:956`) in its **post-factory slot** at `main.rs:2420`–`:2441`.
Preserve exclusion observations before factory construction; bind them to the
actual classified base, then create all missing top **and mountpoint**
directories outside read-only guard resolution. Rebuild every target and the
entire comparison matrix after all those mkdirs. Require each prepared top
and mountpoint leaf to be an existing directory; report missing/unavailable
required directory identity before metadata instead of skipping the entry.
Preserve the existing device fallback when mount IDs are unavailable
(`mount_guard.rs:443`). Do not filter missing peers out through
`Target::exact()` as served-folder discovery does (`:813`, inside the `resolve` match at `:812`), or reuse cached
early targets. This pass precedes every writable top DB, marker, forced stack
transaction, fork and mount. It catches factory-created paths and aliases
revealed by either top or mountpoint mkdir; the existing late-alias regression
is `mount_guard/tests.rs:1390`.

Two absent mountpoint spellings such as `/mnt/PhaseA` and `/mnt/phasea` may
pass the early read-only check. Once directory creation makes them the same
inode on a case-insensitive filesystem, the rebuilt final matrix must refuse
with exit 2. Apply the same rule to Unicode aliases and top-storage aliases.
Always-on fake-filesystem tests model that absent-to-existing transition;
real alias-filesystem tests may skip with a reason. Empty created top,
mountpoint and parent directories can remain on failure.

The **separate writable-storage gate** has two rules:

1. Distinct tops must be disjoint: reject duplicate/equivalent or nested top
   roots and top roots overlapping a lower layer in either direction.
2. For every top T and every local shared-source dependency S, reject **T
   equal to S or T containing S**. Include directory bases, archive/image
   files, local Git backing paths, every composite member and bind input,
   **and the complete transitive set of backend backing files and active
   index/cache artifacts**, rather than only factory input paths. Bind inputs
   enter the factory at `ratarmount-session/src/factory.rs:4857`–`:4866`.
   A top strictly *inside* its directory base remains permitted, with its
   frozen exclusion; equality or reverse containment is refused even with
   force flags. Lower-layer disjointness still takes precedence.

PR2 adds a proposed `ForkNStorageContext` before any source construction in
**both foreground and daemon Fork-N**. It carries all top roots, kind-aware
dependency records and a closed constructor-coverage policy through factory,
backend overrides/fallbacks, binds, lower/bundle callbacks, index/cache helpers
and nested option clones. A successful factory-open result alone cannot
certify completeness. Each admitted constructor must guard/report every
transitive shared-source dependency at its actual path-open boundary; an
unaudited constructor or opaque already-open source refuses Fork-N before
construction/adoption, with a diagnostic naming the missing storage coverage.
This policy is independent of daemon worker admission: `-f` does not bypass
storage coverage. An implementation coverage table must identify the actual
open/create sites and regression coverage for each admitted dependency subtree;
there is no blanket approval for local files or a format name.

At minimum the records and guards cover:

- Every split volume (`factory.rs:2353`–`:2356`), every QCOW2 backing-chain
  member opened recursively (`ratarmount-formats-qcow2/src/disk.rs:204`,
  `:579`, `:583`), and VMDK descriptor/sparse/flat extents opened internally
  (`ratarmount-formats-vmdk/src/lib.rs:222`, `:250`, `:265`, `:275`).
- Effective index destinations after option/fallback selection
  (`factory.rs:2361`–`:2373`), including explicit `--index-file` and
  `--index-folders`, active SQLite DBs and any journal/WAL/SHM companions,
  temporary build/publication paths, materialized content bodies, seek-index
  sidecars, bundle caches, and enabled local remote/range-cache artifacts.
  TAR retains its index (`ratarmount-formats-tar/src/lib.rs:341`); xattrs still
  query it (`:985`, `:991`; `ratarmount-index/src/lib.rs:2863`, `:2877`) even
  when MemIndex serves file lookup. Cache reads/writes also open host paths
  (`ratarmount-index/src/range_cache.rs:403`, `:441`).
- Lazy nested source/index/cache opens, including durable outer-index reads
  and writes (`factory.rs:1328`, `:1368`). Keep the same context attached after
  startup and after daemon handoff; neither a fallback nor an optional-cache
  error handler may swallow a storage refusal and proceed through an
  unchecked open. Each top's own private overlay DB is top state, not a
  shared-source index; it retains its separate top-lock protocol. A source,
  backing file, index, sidecar, or database file that canonicalizes under a
  mountpoint, or a database file that canonicalizes under a different top, is
  the [self-reopen limit](#self-reopen).

Check/register a dependency **before opening or using it**, and a destination
before mkdir, creation, truncation, recovery, rename/publication or SQLite
open that could modify it. Reserve known absent destinations and companions
using their resolved existing ancestors; acquire and verify the opened file's
identity before adoption. Revalidate records after materialization or path
replacement. Known CLI and configured paths get a read-only preflight before
factory work; backend discoveries must pass the same guard before their first
open, so discovery itself cannot truncate a conflicting index/cache file.

After all top/mountpoint mkdirs, rebuild the complete manifest's targets and
run the decisive storage gate alongside the mount safety matrix, before any
writable top metadata, forced stamp or archive-journal recovery. Preparation
must finish enumerating the currently retained source graph, predeclare known
lazy artifact destinations, and verify constructor coverage before this gate.
Lower/bundle dependencies must be covered by the read-only preflight too;
callbacks used after the gate cannot introduce unguarded dependencies. Unknown
lazy paths are checked when discovered, **before** opening/adoption/use; an
unsafe late path returns a typed storage refusal (`Unsupported` at a library
boundary), with no constructor, dependency mutation or process exit. Startup
refusals give exit 2 and no sessions. A serving-time refusal fails that lazy
operation and leaves existing safe sessions available. If a constructor cannot
uphold these rules, v1 refuses it instead of deferring an unsafe check.

Resolve symlinks and apply lexical, mount-view and inode/ancestor alias checks,
including bind views and case/Unicode aliases. Files need a **file-aware**
endpoint: resolve the parent and final symlink/file identity, preserve mount
views and compare ancestor-directory identities against each top. Do not pass
regular files to the directory-only resolver and skip its errors:
`mount_guard::walk` rejects them (`mount_guard.rs:265`), `dir_id` filters them
(`:97`), and `bases_now` drops them (`:829`). Required dependency/ancestor
identity failures refuse before metadata or dependency mutation. The new
registry and file-aware endpoint are PR2 work; existing `relation` is not
claimed to implement them.

For example, an external `/images/root.qcow2` whose raw or recursive backing
is `/work/A/base.raw`, or an external TAR whose active index is
`/work/A/catalog.sqlite`, must refuse top A `/work/A` before serving, in both
`-f` and daemon mode; a disjoint primary pathname is insufficient. The same
rule refuses base `/work/A/base` with top A `/work/A`. A's `/base/file` maps
to that host file (`write_overlay.rs:1486`); existing host entries skip CoW
(`:1658`–`:1663`) and write-open uses the host path (`:2226`, `:2268`). Exclusions
cannot repair this (`overlay_meta.rs:447`–`:449`).

This is dependency admission, not namespace filtering: register a live folder's
root once, rather than reclassifying every ordinary folder member read as an
independent backing file. The documented inside-base `/runs/a/x` visibility
remains. Promoting a member into an independently opened nested archive/image
or index/cache dependency must pass the gate. Tops remain exclusion bases,
not mount-hang-refusal subjects.

## One pre-factory exclusion snapshot, consumed by both identity paths

Ordinary `WriteOverlay::open_with_create_info` calls `plan_excludes` before
mkdir (`write_overlay.rs:1090`–`:1103`). That planner resolves one overlay plus
`info.weak_exclude` (`overlay_meta.rs:91`–`:114`). Resolving separately for N
tops is incorrect: `/repo/runs/a` and `/repo/runs/b`, with `runs` absent,
resolve to `runs` initially and to `runs/a`,`runs/b` after mkdir. The topmost-new
rule is `resolve_base_excludes`, `overlay_meta.rs:425`–`:462`.

Factory construction also mutates path existence: recursive compositing calls
`resolved_index` (`ratarmount-session/src/factory.rs:4304`), and index location
selection reaches `path_can_create_index` from `pick_index_path`
(`ratarmount-index/src/location.rs:1213`). That function creates missing
parents (`:1410`, definition at `:1398`). With absent `/repo/runs`, allowed flags
`--recursive --index-folders /repo/runs/indexes` create `runs` before a
post-factory snapshot. Capturing then would incorrectly retain only
`runs/a`,`runs/b`, causing a sealed lower recorded before `runs` existed to
refuse. "Before top mkdir" alone is insufficient.

PR2 proposes a two-phase opaque compositing API:

1. `ObservedBaseExcludes::capture(inputs)` runs **before factory construction
   or any invocation-created directory**. Inputs retain their roles:
   `Top`, `CallerJournal` or `LowerArtifact` (proposed variants). Resolve the
   complete path list once without assuming a base kind. Store each input's
   canonical longest existing ancestor, that anchor's identity, remaining
   lexical suffix and first missing component (or complete existing path),
   preserving per-input correspondence, top DB presence and each journal's
   `missing_at_capture` eligibility. The list contains **every top**, library
   caller journal paths and all `--lower` paths carried by today's
   `weak_exclude` (`main.rs:2607`), including planned effective bundle-cache/
   verification destinations. No directory content walk occurs.
   A newly supplied journal contributes an exclusion only if its entry was
   missing at capture; an existing unrecorded journal remains base content.
   Use lstat so an existing dangling symlink is not called missing; refuse
   indeterminate observation errors. Freeze this eligibility before factory
   side effects, alongside the first-missing prefix. Do not apply the journal
   existence filter to tops or lower/cache artifacts. Existing recorded
   exclusions are retained separately below, even after the journal exists.
   This preserves `lower_extra_excludes`'s missing-versus-recorded journal
   rule (`main.rs:5066`–`:5070`, `:5082`, `:5094`) before the comparator unions
   inputs (`overlay_meta.rs:1515`).
2. `observed.bind(classified, digest_request)` runs after the factory returns
   its actual `ClassifiedBase` and produces `FrozenBaseExcludes`: the canonical
   eligible directory base, one aggregate `BaseExcludes`, and each top's own
   saved entry and explicit planning eligibility. Only eligible role-tagged
   observations enter the aggregate and per-top plans; binding never promotes
   an existing unrecorded journal into an exclusion. Derive base eligibility
   from the actual token and its create-info semantics (`overlay_identity.rs:252`–`:260`),
   never from a typed positional spelling. Git, archive, remote and composite
   identities that lack an eligible local directory retain explicit `None`.
   Revalidate saved existing anchors and their resolution against the actual
   base, and verify any now-existing part of the saved missing suffix follows
   ordinary directory creation. Refuse changed anchors, symlink retargeting or
   an observation that cannot be safely bound before writable top metadata.
   Factory-created ordinary ancestors are allowed, but **never recompute or
   narrow the saved first-missing entry**. Thus both tops still contribute
   `runs` even after the factory creates `runs/indexes`. Keep per-top DB-state
   checks and the explicit None semantics below. Private fields prevent
   forging or rebinding a plan for another base/top.

Before observation, read existing tops' `base_weak_excludes` with
`OverlayMeta::read_no_recovery` (`overlay_meta.rs:200`), and union those already
base-relative entries into the aggregate at binding without re-resolving them.
Ordinary `read` can recover a hot SQLite journal (`:222`), so it is unsuitable
before the decisive check. A corrupt, hot or unreadable existing top that prevents a safe
snapshot fails in the parent; it is not silently treated as new. A truly
absent database uses `overlay_db_absent` and its lstat semantics. Existing
recorded sets are essential on a second invocation: retain recorded `runs`
when current path resolution yields `runs/a`,`runs/b`. `BaseExcludes::new`
(`:383`) sorts and deduplicates; it does not remove descendant entries.

There is a bundle dependency to resolve before observation. Today's effective
lower directory is obtained inside `open_with` (`main.rs:1549`–`:1575`) and
later put into `weak_exclude` via records. PR2 proposes binary
`PreparedLowerBundle` / `prepare_lower_bundles`: hold each bundle's opened
file, hash its bytes read-only (the descriptor pins an inode, not immutable bytes),
and plan its exact cache destination using the
existing byte-hash layout (`overlay_pack.rs:1511`–`:1535`, `:1604`). No cache
directory, extraction or publication occurs in preflight. Include the planned
effective destinations (and any planned persistent verification-marker paths)
in the pre-factory observation. The promoted opener's resolver later copies
from that descriptor into the normal immutable private copy, rechecks the
expected byte hash and
refuses a changed file before publishing. It then performs the existing
bottom-up view verification and cache publication exactly once. Do not call
`cached_lower` early: its verification requires the preceding composed view
(`overlay_pack.rs:1539`, `:1615`, `:1639`). Do not exclude an entire existing
cache root to avoid planning exact paths. Directory bases do not generate the
strong archive marker key (`main.rs:1298`–`:1320`). Transient copy/staging files
must be cleaned before the bottom identity walk; persistent artifacts must be
represented by the frozen plan. This extra adapter belongs to PR2, not PR1.

The exact snapshot carriers are:

1. **Lower gate:** before `MountLowerStack::open_with`, set
   `MountedBase.extra_excludes = frozen.excludes().paths().to_vec()` (proposed
   accessor). `open_with`'s bottom-layer call (`main.rs:1597`) reaches
   `mounted_base_identity`, which supplies that vector to
   `overlay_gate::BaseProbe.extra_excludes` (`main.rs:1434`–`:1439`).
   `overlay_gate::content_probe` (`:187`–`:201`) forwards it into
   `overlay_meta::compare_content`'s directory walk (`:1515`–`:1523`), unioned
   with the bottom lower's recorded exclusions. This is how the **same
   pre-factory set reaches the hasher after factory/top/mountpoint mkdirs**.
   Binding does not recapture it. Do not substitute
   `lower_extra_excludes`: it takes one top and returns empty without lowers
   (`main.rs:5071`–`:5080`).
2. **Each top's creation and reopen:** propose
   `WriteOverlay::open_with_frozen_excludes(base, composed, dir, options, frozen)`
   and a matching binary `overlay_create::create_overlay_with_frozen_excludes`
   wrapper preserving existing warning/remote-token setup. Extend private
   `open_with_create_info` with explicit `ExcludeMode::ResolveSingle` versus
   `ExcludeMode::Frozen(Option<&ExcludePlan>)`. `Frozen` selects that top's
   already-built plan; even explicit `None` never falls back to `plan_excludes`.
   Existing `WriteOverlay::open` selects `ResolveSingle`, unchanged.
3. Feed the selected `exclude_plan.as_ref()` to the existing
   `overlay_meta::initialize` call (`write_overlay.rs:1215`–`:1220`). It writes
   new `base_weak_digest` and `base_weak_excludes` at `overlay_meta.rs:1139`–`:1140`.
   On reopen it carries the plan through `initialize` → `reopen_classified` →
   `verify` (`:1069`–`:1076`, `:1655`, `:1700`, `:1741`). `verify` continues
   hashing the **recorded** set and checking additions (`:1786`–`:1805`);
   it does not silently skip the walk or replace the old baseline with a hash
   using newly narrower excludes. Preserve each top's own `ExcludePlan.overlay`
   fallback for old metadata lacking `base_weak_excludes` (`:1791`).

Keep all three per-top `plan_excludes` **None** cases: Git tree (`:95`),
`--base-digest none` with an absent database (`:100`), and non-directory base
(`:103`). The `none` creation exemption does not apply on reopen. The global
directory snapshot remains available to the lower comparison even when a new
top has opted out of its own digest; observation/binding is metadata resolution,
not a directory content walk. Git skips the directory walk. No archive is
turned into a directory base based on spelling alone.

New digest-bearing tops in one invocation persist the same aggregate excludes
and hash the same filtered directory base. Reopening an unchanged cohort keeps
its stored weak digests and stored exclusions, even when the new aggregate also
contains narrower covered entries. Real base edits still fail. Existing tops
with incompatible recorded sets are not silently reconciled: preserve today's
refusal of newly excluding existing base content (`overlay_meta.rs:1798`).
Adding a peer outside the old recorded excluded subtree can therefore fail
after its empty directory was created. Dynamic cohort expansion is not
promised in v1; use a common excluded subtree from the initial run. No relaxed
append rule or forced digest rebaseline is introduced.

## Archive-journal recovery: classify early, write after final identity

Fork-N must not call the existing early `recover_mount_journals` unchanged.
Its `Own` branch currently calls recovery before factory construction
(`main.rs:2095`, `:5170`–`:5175`), with one top DB (`:5159`), and recovery can
execute a writable restamp transaction (`journal_recovery.rs:287`). That would
violate the final identity gate even when the archive bytes need no repair.

PR2 splits Fork-N journal handling into read-only classification and two
post-identity recovery phases. Generalize `MountRecords.top` into the cohort
of top voters and retain all lower/bundle votes (`journal_recovery.rs:448`,
`:516`). Read journal completeness separately; `MountJournal::Own` by itself
does not expose that bit. Early classification never runs recovery, restamps
rows or clears stale locators, including the `None` and `Own` branches.

For v1, Fork-N **refuses every incomplete/torn journal, including an owned
one**, unchanged and before factory opening, with exit 2 and guidance to
recover the archive alone using the existing single-mount/`--no-mount` path,
then retry Fork-N. This is an explicit scoped restriction compared with the
legacy `Own` branch, which may repair a torn archive early; legacy behavior
stays unchanged. It avoids parsing a half-written archive before the required
post-factory decisive identity check. Complete owned journals can wait: the
complete path skips archive rollback writes (`commit_journal.rs:1422`–`:1444`).
Keep factory `recover_journals: false` (`main.rs:2238`); otherwise the factory
can recover with only `Owner::Inode` (`factory.rs:2323`–`:2329`) and bypass
cohort voting and the metadata-order guarantee.

After the final mkdir/identity matrix, revisit **every original local member**,
including early None, before lower/top content gates. Reclassify read-only;
recover complete Own once each, and rebuild a deduplicated late queue for
complete Deferred members. For None, preserve the existing under-lock missing-
journal/locator behavior: clear stale P, preserve and warn for D, refuse
missing C (`commit_journal.rs:1094`, `:1106`, `:1117`). `pending()` alone is
insufficient because a missing located journal returns None (`:1176`). If a
real journal appears during this pass, the same still-complete/cohort
under-lock authorization below must apply before any recovery write; never
fall back to an unguarded inode-only call.

Propose a compositing cohort recovery entry point: acquire never-create writable
connections and retained EXCLUSIVE locks for every existing top DB before
applying recovery; an absent DB contributes no rows and is not created here.
Use these owned connections to reread top votes, never a second path-open on
an already locked top DB. Reauthorize all top/lower votes and require the
journal still be complete under the archive lock before any recovery mutation.
A foreign/now-incomplete journal refuses without applying it. If an Own
selected for early recovery becomes Deferred during the under-lock recheck,
abort with retry guidance and no recovery write; do not silently drop the
member or bypass its later gates. A retry reclassifies it and queues it for
post-gate recovery if still Deferred.

The proposed cohort `before_unlink` hook applies existing `restamp_rows`
semantics to **every affected top**, using the same locked descriptor's
`Applied` result, including strong-digest pending updates. Non-target and
kind-only records keep the existing no-op rules (`journal_recovery.rs:297`).
The hook returns success only after every required per-top transaction commits;
then, and only then, may the journal be removed (`commit_journal.rs:1450`–`:1455`).
Failure retains the journal and serves nothing. Earlier successful top restamps
may remain; retry accepts both pre-commit and already-final stamps
(`journal_recovery.rs:171`–`:179`) and must finish all tops before unlink.
There is no transaction or rollback across independent DBs. Close every
temporary recovery connection before normal `check_top`/`WriteOverlay`
construction; no temporary descriptor may close over a live overlay lock.

Complete **Deferred** members still wait until all normal identity/stack/top
gates accept. Recover each once using all live overlays' owned connections and
the same cohort hook, retaining existing authorization rules for accepted
replacements and rechecking them under the archive lock. Recheck unresolved
bundle votes after unpacking. Neither phase may select only top A's vote or
restamp carrier. Stale-locator cleanup is also post-identity. Before serving,
verify the common factory source still names the recovered inode and content
stamp; refresh/reopen as required or refuse, never expose stale readers.
Lower records remain immutable: their subsequent gates may honestly refuse;
recovery does not rewrite lower baselines to manufacture acceptance.

## Parent construction order and failure effects

1. Validate CLI and all Fork-N conflicts. For daemon mode, install the
   proposed `ForkNWorkerPhase::Preparing` guard before any source/backend
   initialization, then enforce source capability admission and the torrent
   restriction below. No background source runtime may already exist. In both
   foreground and daemon mode install `ForkNStorageContext`, enforce closed
   transitive storage-constructor coverage and perform early read-only mount
   and storage identity checks for known inputs and artifact destinations.
   Classify journals across every top and lower without recovery or
   locator cleanup. Retain the existing ownership and Deferred vote outcomes;
   refuse every incomplete journal, including `Own`, as specified above.
   Retain all original local members, including None, for the post-identity
   pass. No recovery write may bypass any readable record's vote or the final
   identity matrix.
2. Before calling the factory or creating any directories, preflight bundle
   destinations read-only, read existing tops' metadata without recovery, and
   capture `ObservedBaseExcludes` for the complete path list, preserving each
   first-missing ancestor and role-specific journal eligibility. Include
   library journals without newly excluding existing unrecorded files, even
   though Fork-N CLI refuses `--journal`. Open/classify the factory base once
   with all transitive source work subject to the Preparing guard,
   retain its keepalive, then validate and bind the saved observations to that
   actual token to obtain `FrozenBaseExcludes`. Guard and retain the complete
   transitive dependency manifest, including backend-opened backing chains,
   split/extents, active indexes/caches and their destinations/companions;
   checks precede dependency opens and artifact writes. Predeclare lower/bundle
   dependencies and known lazy destinations before the decisive gate, and
   keep guards attached to later callbacks and lazy opens. Do not discover
   dependencies with directory-only `bases_now`. Do not recapture excludes
   after factory index/cache side effects; no unvalidated typed base guesses
   are accepted.
3. Create all missing top and host mountpoint directories in the parent,
   outside read-only guard resolution (move mountpoint preparation forward
   from `main.rs:2866`–`:2868`). Report creation failures directly (exit 1) and
   start no sessions. Require existing directory leaves, rebuild every target,
   then run the decisive N-way mount safety matrix and the separate storage
   gate: top/top and top/lower disjointness, plus no top equal to or containing
   any transitive shared-source dependency, including backend-opened backing
   files and active index/cache files with aliases. Require complete current
   graph coverage; unknown constructors refuse. Strictly inside-directory-base
   tops remain allowed. In the same pre-fork window, apply the
   [BUILD-lock v1 limits](#v1-limits-keystone-build-lock): refuse a mount
   target that is already a mountpoint or is not an empty directory (a
   directory this process just created is empty); refuse when any regular
   file in any top has `nlink > 1`, naming that path; refuse self-reopen
   when a source, dependency, or post-mount file dependency canonicalizes
   under any of this process's mountpoints or top directories, with the
   owning-top database exception in that section. An unresolvable
   path before mount is a refusal. These checks run in
   the post-factory slot. Identity conflicts and these limits exit 2 before any top
   database/marker/forced transaction/fork/mount. Empty created top, mountpoint
   and parent directories, and factory index artifacts, may remain on failure.
   Do not promise transactional filesystem rollback. Failed startup unmounts
   only targets this process mounted, verified by the recorded `(st_dev, st_ino)`
   and this process's owned FUSE session.
4. After step 3 succeeds, run the member pass above, including initial None
   locator handling, complete Own recovery and the complete Deferred late
   queue. Use the cohort hook and close all temporary recovery connections.
   Only then open the common lower stack using the frozen `MountedBase` input.
   Compose each lower once, retaining each caller's unsealed policy. Run
   **full `check_top` for every top** in the parent before opening writable
   tops or forking (`main.rs:1671`–`:1734`). Its absent DB path returns early;
   sealed, recorded `lower_layers` mismatch, forced EXCLUSIVE transaction,
   in-transaction sealed recheck and `stack_mismatch_forced_at` commit all
   remain. The force path records an override timestamp; do not claim that
   this function itself rewrites `lower_layers`.
5. Construct each overlay with its frozen plan and its own preflight
   policy/quota. Sealed, unsealed-lower, stack, DB or policy failure returns
   directly in the parent (exit 1), never as a 30-second mount timeout. An earlier
   recovery restamp, forced metadata commit or successful initialization is not
   rolled back when a later top fails; drop acquired handles and serve no sessions.
6. Finish complete Deferred archive-journal recovery **once per member in the
   parent**, after all gates accept, not once per top (current single-top loop
   is `main.rs:2698`–`:2716`). Use all live overlays' owned connections and the
   cohort hook above; reauthorize under the archive lock, restamp every affected
   top before journal removal, and verify/refresh the common source before
   exposing sessions. Do not open/close a second descriptor over an owned top
   DB. No phase chooses top A's vote or row carrier and ignores top B.
7. Enter the one serving-process transition using mountpoints already
   prepared and checked in step 3; do not defer their first creation until
   here. Keep Preparing while finishing source-SQLite handoff preparation and
   flushing/closing all parent source and writable-top SQLite connections;
   immediately before fork, require the worker-free/connection-closed permit
   below, with all scoped tasks joined and no source worker/pool initialized.
   No session or deferred source runtime starts until all source connections
   are reopened/validated, serving-process top locks acquired and rebuilt
   policies installed. Foreground retains its validated connections and the
   storage guards without a fork handoff.

Two sealed messages are deliberately retained. `check_top` gives
`` overlay {path} is sealed; mount it with --lower, or `overlay unseal` ``
(`main.rs:1684`). Its force transaction (`:1723`) and `WriteOverlay`'s own
transaction (`write_overlay.rs:1212`) give
`` overlay is sealed; mount it with --lower, or `overlay unseal` ``.
Unsealed lower refusal is
`lower PATH is unsealed; pass --allow-unsealed-lower to use it`
(`main.rs:1586`).

## Daemonization, ownership and teardown

On this SHA, parent overlay construction opens SQLite (`write_overlay.rs:1129`),
sets `LOCKING_MODE=EXCLUSIVE` (`:1204`) and executes
`BEGIN EXCLUSIVE; COMMIT;` (`:1287`) **before fork**. Existing serve forks are
`main.rs:3860` (exports), `:4096` (FUSE+NFS) and `:4232` (plain FUSE); parents
wait on one mount then `process::exit`. These cannot be looped once per top.
POSIX `fcntl` locks are not inherited: parent exit loses the protection.
Packet #183/#203 discussion is background, not a helper present on this SHA;
#203's reported branch/merge state is packet provenance, not newly queried
remote state. PR2 implements the outcome on this base without depending on it.

Factory-created source workers are a separate fork hazard from SQLite locks
and quota counters. Factory opening precedes the fork (`main.rs:2385`,
`:4232`). The zstd opener passes thread and readahead settings into the
seekable body (`factory.rs:3349`–`:3355`);
reader Drop merely cancels (`zstd_seek.rs:1504`). An already-running job can
still drop its reservation while holding the global budget mutex
(`ratarmount-core/src/budget.rs:259`–`:264`), which later pool registration
needs (`:68`). The executor's PID check (`zstd_decode_ahead.rs:15`–`:20`)
rebuilds its queue, not that mutex. HTTP prefetch Drop explicitly detaches
workers (`http_pool.rs:1151`–`:1156`); signed-URL refresh holds its transport
mutex across resolution/network work (`:562`–`:567`). Forking in either window
can leave the child waiting for a thread that no longer exists. Selected
local fixtures and fresh top SQLite connections do not address this.

**PR2 must prevent background source work before fork**, while preserving all
parent construction/refusals and the single shared stack. Proposed
`ForkNWorkerPhase` is process-wide, with `Preparing` and `Serving` states;
install it before the first constructor and retain original requested
parallelism/readahead settings separately. Carry the same context through
factory, lower/bundle callbacks, bind inputs, backend overrides/fallbacks and
nested option clones. Legacy single-mount paths are unchanged; foreground
Fork-N starts in Serving because it has no handoff.

1. During Preparing, zstd prefetch returns **before** `reserve_frame`
   (`zstd_seek.rs:1341`) or any queue submission. Add a second gate at
   `zstd_decode_ahead::submit` **before** its static pool initialization/lock
   (`zstd_decode_ahead.rs:15`–`:17`), so no idle executor threads exist either.
   Demand reads use the existing synchronous decode path
   (`zstd_seek.rs:1478`–`:1492`). This remains true with `--memory-budget`,
   parallel codec settings and eager nested indexing.
2. HTTP range readers do not create speculative Prefetch while Preparing;
   `Prefetch::fill` independently returns before budget registration, permit
   acquisition, source cloning or spawn (`http_pool.rs:1056`–`:1088`). Demand
   reads use the synchronous fallback (`ratarmount-remote/src/lib.rs:1461`–`:1470`).
   Thus signed-URL resolution completes on the constructing thread or a joined
   scoped task, with no detached owner of the transport/budget mutex at fork.
3. Use a **positive constructor capability table**, default Unsupported, for
   each selected backend and its complete dependency subtree. Only explicitly
   `ParentSynchronous` or `DeferredWorkers` constructors are admitted in daemon
   mode. A source kind or an active-worker counter alone cannot certify an
   unregistered producer. The initial table admits verified in-tree synchronous
   local folder/archive/codec constructors and the deferred zstd/direct HTTP
   range paths above. Scoped parallel work, such as eager AutoMount
   (`automount.rs:617`–`:633`) and ZIP hashing (`ratarmount-formats-zip/src/lib.rs:1266`),
   is eligible only when all descendants obey the context and the scope has
   joined before handoff. Each admitted constructor must have a concrete
   lifetime justification and coverage in PR2; no blanket local/HTTP approval.
   Storage coverage is also mandatory in both modes. An admitted daemon source
   with SQLite must additionally supply the source-connection handoff below;
   an idle connection or MemIndex projection is not an exemption. Opaque
   already-open library sources cannot enter daemon Fork-N in v1.
4. V1 refuses daemon torrent sources, SSH ProxyJump pump mode
   (`ratarmount-remote/src/ssh.rs:941`, `:997`), Hub-cache background-publication
   mode (`hf_cache.rs:933`–`:949`) and unaudited foreign rapidgzip worker
   lifetimes (`gzip_rapidgzip.rs:21`, `:257`–`:265`); any other constructor
   without an admitted dependency subtree also refuses. Refuse before the
   actual constructor/runtime starts, with exit 2 and foreground guidance;
   do not silently change a requested backend or cache mode. Resolve effective
   SSH config before connecting, so implicit ProxyJump is covered; reject a
   Hub cache bridge before attaching it to an otherwise admitted HTTP source,
   including when the URL is not spelled as a Hub input.
   `with_hub_cache` is `http_pool.rs:269`, called from `hf.rs:780` and `:791`.
   `http_pool.rs:420` `observe_chunk` forwards into an already attached hub
   cache; that call is the observe path. Early detectable
   modes fail before factory/mkdir. Dispatch guards enforce the same rule if
   inputs/settings change or a fallback chooses a different backend. Nested
   discovery returns `Unsupported`, never `process::exit`; the daemon capability
   policy stays attached after fork. Foreground remains eligible subject to
   storage admission. Torrent detection covers every swarm/seed policy as specified above; `never` still
   starts verification (`torrent/mod.rs:216`, `torrent/verification.rs:47`).
5. The sole fork requires a proposed worker-free permit: Preparing admission
   remains closed, all scoped tasks have joined, no source executor/runtime
   has been initialized, no background job/result/destructor remains, and the
   calling thread holds no budget/transport/executor/registry guard. Every
   registered parent SQLite connection must also be closed, with no retained
   statement/transaction or source-budget hook targeting a parent connection.
   Known executor state and registered producer counts are checked without
   waiting on the locks whose orphaning is at issue; unexpected initialized/live state
   refuses **without fork**, never resets a mutex or treats cancellation/Drop
   as a join. Constructor admission and guarded scheduling provide the proof;
   counters cannot discover arbitrary bypasses. The permit must not hold a
   locked mutex across fork, and no preparation callback runs after it.
6. Keep Preparing through connection release, the fork, source-SQLite reopen
   and fresh child top DB/policy setup. After **all source connections are
   validated and all N child EXCLUSIVE locks and rebuilt policies** are
   installed, only the serving child switches to Serving. Deferred pools
   start lazily there with the originally requested settings; existing readers
   also consult the phase so parent-opened objects regain configured prefetch.
   No queue/job or thread-backed handle crosses the fork. The launcher never
   activates workers. Foreground uses the same configured settings directly.

The permit and suppression are required PR2 behavior, not a claim that these
APIs already exist. Generic restart of arbitrary worker-backed sources remains
out of v1; the closed admission table makes that an enforced restriction.

PR2 adds one Fork-N serve path: parent construction/refusals remain before a
single fork. **No inherited SQLite handle is used for serving**, including
source indexes as well as top overlay connections. `SqliteIndex` retains a
`BudgetConnection` (`ratarmount-index/src/lib.rs:556`–`:558`), and `into_read_only`
reopens disk connections *before* fork (`:1675`–`:1682`); it does not perform a
child handoff. Even compact-only indexes own an in-memory shell (`:1273`),
and pure in-memory sealing retains its connection (`:1693`). SQLAR separately
owns `Mutex<Connection>` (`ratarmount-formats-sqlar/src/lib.rs:141`). The old
top-only procedure cannot justify that broader claim.

Add proposed source-SQLite handoff participants to the daemon constructor
capability table and register **every retained connection in the prepared
source graph**, including eager nested, bind and lower/bundle sources. The
initial supported handoff is disk-backed read-only `SqliteIndex`. If the
parent-prepared graph retains in-memory/compact-shell SQLite or other owners
such as SQLAR, refuse daemon Fork-N unless PR2 supplies and tests an equally
explicit close/reopen protocol. An unaudited in-memory snapshot protocol is
outside v1. Refuse unsupported handoffs before fork with foreground guidance;
use exit 2, no Ready or sessions. Foreground remains eligible subject to
storage coverage. Sources first constructed lazily in the serving child use
fresh child-owned connections, including memory-only ones if that constructor
has affirmative storage/daemon capability admission. They have no parent
connection to hand off; no parent handle can hide in a lazy closure.

1. While Preparing, finish builds/reads, finalize statements and transactions,
   record each admitted disk index's storage identity and logical generation,
   and **close its actual parent SQLite connection**. PR2 introduces a
   disconnected lifecycle slot in the retained source object; no dummy
   SQLite connection may remain across fork. Keep the one composed Arc and
   pure Rust MemIndex data. Detach/drop its SQLite budget reservation and
   pressure hook before fork (`ratarmount-index/src/lib.rs:466`–`:470`,
   `:503`–`:516`); no callback may retain a closed parent connection. Flush
   pending top rows, release/close all parent writable top DB connections,
   and obtain the worker-free/connection-closed permit immediately before
   the sole fork. Close/preparation failure aborts without fork or serving.
2. In the child, reopen each registered source index read-only, revalidate its
   storage path and disk identity/generation against the saved snapshot, and
   verify compatibility with the retained MemIndex and cached source metadata.
   Compare content/schema and logical DB state, including WAL-visible state;
   inode/mtime alone or a fresh read of unrelated rows is insufficient. If the
   exact indexed state cannot be proved unchanged, refuse startup rather than
   combine stale memory with changed SQL rows. Recreate the budget reservation
   and pressure hook for the **new child connection**. Reopen each shared index
   once, not once per top; this preserves the single factory/composed stack.
3. Replace top connections with **fresh child connections** through a proposed
   compositing handoff/reacquisition method, set EXCLUSIVE mode and take
   `BEGIN EXCLUSIVE; COMMIT;` for every top. Recheck identity/seal/stack/tombstone
   state before serving; a handoff-window competing writer cannot be silently
   adopted from stale memory. Reopen/validation or top-lock failure serves
   nothing, releases all acquired child handles and sends no Ready. No session
   or deferred source worker starts before both source and top handoffs finish.

This explicit source protocol replaces reliance on idle inherited index
connections. It does not change foreground or legacy single-mount connection
lifetimes. The acceptance tests below exercise SQL xattrs as well as MemIndex
file reads so the source handoff cannot be accidentally omitted.

After **all N fresh child EXCLUSIVE locks are held**, also rebuild every
host-derived policy state from the locked tops before any session starts or
`Ready` is sent. Recreate each top's quota with `OverlayQuota::new` using the
validated parent configuration; its scan initializes cached bytes/files
(`overlay_policy.rs:516`–`:527`), which byte and file enforcement later read
(`:555`–`:563`, `:589`–`:600`). A handoff writer can append an existing dirty
file without changing identity or tombstones (`write_overlay.rs:952`–`:964`),
so DB verification alone cannot validate the inherited usage counters.
Parent scans are preflight only. Replace inherited policy/quota instances and
all quota-usage references with the child-owned rebuilt instances, installed
before frontend sharing (`write_overlay.rs:851`; current quota Arc wiring is
`main.rs:2676`–`:2679`). Other host-derived policy caches must likewise be
rebuilt; the immutable validated flag configuration can be retained. Each top
keeps independent counters. Scan or installation failure cancels the entire
cohort, starts no sessions and closes every child lock. Only after successful
installation does the child activate deferred source workers as specified
above. After those locks are held and before any session or `Ready`, recheck
the [hardlink limit](#hardlinks): a regular file in any top with `nlink > 1`
refuses startup, names the path, and unmounts nothing this process did not
mount. Foreground repeats the same recheck after its locks, before serving.
Foreground has no handoff gap and installs its policies while retaining its construction locks.

The daemon parent never runs overlay Drop/replay on the child's state. Parent startup success requires all N mounted paths
and successful child lock initialization. Use one 30-second readiness deadline
for the cohort; cleanup of busy mounts can outlast that readiness deadline.

Fork-N must also handle signals sent specifically to the **waiting launcher
PID**. Today's daemon parent intentionally keeps default handlers
(`overlay_commit.rs:136`), and the child detaches (`main.rs:4249`), so serving-
process watchers alone leave a gap. Add a Fork-N launcher SIGINT/SIGTERM
recording hook before startup construction/fork, using the existing atomic-
only handler pattern (`overlay_commit.rs:36`–`:40`). Propose Fork-N-specific
per-signal atomic counters/pending state (`ForkNSignalState`), used from the
launcher through child startup and serving, so a later SIGINT cannot erase a
pending SIGTERM. The launcher and each child watcher keep their own cursors;
one consumer never destructively drains another's pending signal. Check
cancellation between parent construction phases and before the fork. Keep recording handlers
inherited through child coordinator installation, and consume any signal
recorded during that transition before starting sessions. Install no watcher
thread in the launcher. This does not change legacy single-mount behavior.

Use a two-way startup channel; close each fork branch's unused endpoint
immediately and keep the child endpoint owned by the coordinator, so inherited
duplicates cannot suppress EOF. Run an interruptible launcher loop over channel
events, signal state, `waitpid(WNOHANG)` child status and the shared deadline;
`wait_until_mounted` (`main.rs:4830`) alone is insufficient. The child sends
`Ready` only after locks and all N registered sessions are ready. The launcher
checks signals, deadline and liveness before replying `Accept`. Cancellation
is sticky: once observed before acceptance it wins over queued or later
`Ready`, and the launcher exits nonzero after cleanup. Channel EOF before
`Accept` cancels child startup, including unexpected launcher loss. After the
handshake succeeds, normal launcher exit releases startup-channel ownership
without cancelling the daemon.

When the launcher records SIGINT/SIGTERM while it still owns the unreaped
child PID, forward that exact signal from normal code and enter cancellation;
never rely on process-group delivery across `setsid`. Forward later recorded
signals too, preserving the existing retry/SIGTERM fallback semantics. Timeout
or startup error uses the same cancellation path with programmatic SIGTERM.
The child coordinator latches cancellation, prevents unstarted sessions from
starting, and tracks every started session; any in-flight mount that becomes
ready after cancellation is immediately included in cleanup. On cancellation,
partial failure or timeout, unmount all started paths, join sessions/watchers
and workers, drop overlays and close DBs, then report failure and exit.
That failed-startup cleanup follows the [cleanup limit](#cleanup): unmount
only a target this process mounted, and only when the recorded `(st_dev, st_ino)`
still matches and the mount is this process's owned FUSE session. It does not
lazy-unmount. The serving SIGTERM busy-then-lazy policy below applies only to
a session this process owns after that session has started serving. The
launcher retains ownership and reaps that child before exiting nonzero. If
child-status polling instead finds an unexpected child exit before cleanup,
the launcher performs fallback unmount attempts for every cohort mountpoint
and completes reaping itself; it cannot delegate cleanup to a dead child.
Parent exit alone is never the cleanup mechanism. Preserve SIGINT's retry-
only and SIGTERM's busy-then-lazy policy, including platforms without lazy
unmount, instead of claiming teardown is bounded by the readiness deadline.

`-f` skips fork and runs all N sessions in the same foreground process using
the same coordinator. Install **N per-path signal watchers** in the serving
process, reusing the existing `signal_unmount` retry/lazy policy
(`overlay_commit.rs:220`–`:257`) with the Fork-N per-signal ledger above.
Do not reuse the legacy last-signal snapshot: `TERM_SIGNAL.store` (`:38`) and
watcher dispatch (`:274`–`:279`) lose TERM when INT follows before polling.
Every watcher and the serving coordinator independently track both signal
counters. Pending TERM keeps its busy-then-lazy action on every still-serving
path even after a later INT; INT-only remains retry-only, and later signals
can retry failed attempts. This applies to foreground, direct child signals,
launcher-forwarded signals and the handler-installation transition.
PR2 proposes `spawn_signal_fuse_unmount_for_session(mp, signals: Arc<ForkNSignalState>, session_done: Arc<AtomicBool>) -> JoinHandle<()>`:
its loop checks the per-session completion token on every iteration, including
after a signal has already been seen. Each worker sets its token on return,
including mount failure, before its watcher is joined. The existing watcher
at `:265`–`:288` cannot simply be made joinable: after an already-unmounted
path errors, `seen > 0` prevents its programmatic shutdown exit at `:285`–`:286`.
The single-mount wrapper remains unchanged. Preserve SIGINT's retry-only
behavior and SIGTERM's busy-then-lazy fallback (`:132`, `:220`–`:257`); a busy
mount is not claimed detached on platforms without lazy detach. Handle a
signal during startup as cohort cancellation, including signals forwarded
by the launcher and sessions that become ready after the first unmount attempt.
The coordinator joins every watcher using these per-session tokens,
independent of the global signal count.

External unmount of one top ends that worker and releases its references;
siblings keep serving and remain writable. A worker must **not** call the
single-top `finish_overlay_serve`: it sets process-global shutdown at
`main.rs:3689`. The coordinator owns shutdown once. Session failure cancels
startup or initiates all-path cleanup; normal unmount of one session is not
that failure. Orderly whole-process exit and signals explicitly unmount every
remaining path, join every session/notifier and watcher, stop/join shared
workers, drop all source/overlay references so pending rows flush, and only
then return or `process::exit`. `process::exit` does not drop a still-blocked
`Session` on another thread.

The archive pending-digest worker is also one process service:
`base_digest.rs:12`, `:28`–`:33` currently allows only one target, and
`:67`–`:74` updates only that overlay. PR2 proposes a cohort variant that hashes
the shared pending base once in the serving process and records the result
through Weak references into each still-pending top's owned connection.
Revalidate each top's pending stamp before recording. Preserve no-writable-index
behavior (stay pending, `:58`–`:63`) and join it once at final shutdown. Do not
loop the existing singleton helper and claim all N rows were updated.

## Delivery boundaries

**This docs PR** lands this design and the AGENTS.md regression-catalog row.
It changes no product behavior and adds no Rust or tests. It does not edit
`docs/sandbox.md` or `docs/tasks/plans/sandbox-features.md`;
`ratarmount/tests/docs_base_identity.rs` pins existing sandbox statements.

Ship order:

1. This docs PR.
2. **PR1** promotes `MountLowerStack` with no behavior change.
3. **PR2** adds the CLI, `ForkedTops`, N FUSE sessions, daemonize with
   EXCLUSIVE × N, and the acceptance tests below.

Option B, the separate Mount-in-base PR2, and serve-sandboxes stay out of
that sequence. See [Out of v1](#out-of-v1).

**PR1:** promote `MountLowerStack` into a shared
`ratarmount-compositing::lower_stack` module, with no behavior change. Keep
binary `BaseIdentity`/`MountedBase`/`mounted_base_identity`, `lower_key_for` and
view-key derivation behind binary-supplied bottom-identity and bundle-resolution
callbacks. The library must not import binary `overlay_pack`. Preserve error
formatting through an adapter where needed. This is more than moving
`cached_lower`; bundle verification must retain its current preceding view and
marker-key semantics. Expose the records/accessors needed by the binary.

Rewire mount (`main.rs:2575`), `overlay_cmd::lower_view`
(`overlay_cmd.rs:367`–`:373`, `false`), `ImportStack::open_base`
(`overlay_import.rs:106`–`:120`, caller's `allow_unsealed_lower`) and
`sandbox/run.rs:1039` (`compose` → `false` today). Retain each exact
`allow_unsealed` value. Update binary unit callers (`main.rs:9048`, `:9128`,
`:9176`, `:9214`) and `overlay_pack.rs` test callers (`:1929`, `:2993`, `:3219`,
`:3236`, `:3282`, `:3301`). Production pack uses `lower_view`.
`diff.rs:373` calls `compose_stack` directly and is not rerouted; its Shared
policy for unsealed inputs stays at `:328`–`:331` (the sealed check starts at
`:328`; `Immutability::Shared` is assigned at `:331`). PR1 tests prove existing identity,
bundle-marker, forced-stack, sealed/unsealed and offline behavior is retained.
The new frozen-snapshot and handoff behaviors belong to PR2.

**PR2:** CLI/parser integration, `ForkedTops`/`TopHandle`,
bundle preflight, pre-factory observations bound into both hasher paths,
post-mkdir mount and file-aware transitive storage identity gates with
backend/index/cache/lazy-open coverage in both serving modes, daemon worker-phase
preparation/activation with closed constructor capability admission,
source-SQLite close/reopen handoff and source-mode refusals, role-specific
journal exclusions, inside-base visibility coverage, journal classification/
cohort restamping and
incomplete-journal refusal, N sessions, one daemonization, child EXCLUSIVE × N
with policy/quota rebuilding, corpus conflicts, per-signal launcher/serving
state, cancellation/handshake/reaping, coordinated teardown, the
[BUILD-lock v1 limits](#v1-limits-keystone-build-lock), and the acceptance
tests below. The same behavior PR must update `README.md` summary tables,
`docs/formats.md` tables and Known limits, `docs/getting-started.md` command
tour, and `docs/mount-options-parity.md`, as required by the
**Feature comparisons & README** section in `AGENTS.md`.
Cover the Fork-N capability/flags, enforced transitive storage admission in
both modes, daemon source/SQLite restrictions and preparation/handoff behavior,
and inside-base alternate-path visibility. No feature is marked shipped by
this design. No new dependency is required.

This publication is the design of record for the BUILD lock. It does not claim
a planning-gate ACCEPT, and it is not Keystone code LGTM of an implementation.
Later review is Keystone LGTM at the full head SHA of each implementation PR;
Helm squash-merges that reviewed SHA.

## Acceptance for PR1/PR2 (specified here, not implemented)

Every new test is documented/named `Regression:` plus the symptom. Always-on
unit tests cover logic; kernel tests explicitly print `skip: ...` for missing
`/dev/fuse`/mount tools and cannot replace those unit tests. Existing examples
are `ratarmount/tests/fuse_lower.rs:17` and
`ratarmount/tests/overlay_exclusions.rs:211`. Proposed filter names below are not
commands that already pass on this SHA.

| Check | Observable result / appropriate layer |
|---|---|
| PR1 extraction | Existing lower, import, pack, seal, sandbox and identity tests pass with unchanged errors, marker keys and every caller's `allow_unsealed` value. |
| Shared ownership | Unit counted factory/lower constructors run once; two tops retain the same composed Arc and see a prepared artifact, with distinct dirty bytes, metadata and tombstones. One Shared row snapshot, not N reopens. |
| CLI `fork_n_` | Pure parsing covers assignment errors, N=1 and N>1, reordered names, no-lower form, optional repeated BASE sources never stolen as mountpoints, all conflict flags, force/base flags and policy/quota target support. Each commit flag is tested with no `--lower`. The early `corpus` branch rejects top-only, mount-only and paired flags with `ArgumentConflict`; ordinary `corpus LIST-FILE MOUNTPOINT` and literal source `./corpus` retain their grammar. Legacy single `-w` behavior is unchanged. |
| `fork_n_identity_` | Mount-to-base, bind, mount and top relations exercise all three checks, including hidden binds. Always-on staged fake-filesystem tests start with absent `/mnt/PhaseA` vs `/mnt/phasea` and NFC/NFD Unicode peers: early read-only checks pass; simulated mkdir makes each alias pair share an inode; final rebuilt matrix refuses before DB/marker/forced stamp/fork/session. Include absent top-root aliases, late-created top aliases, required-directory-identity failure and distinct-directory controls. Two tops *inside* a directory base succeed; mounts in/on/over tops still exit 2. Real alias-filesystem integrations explain skips. |
| `fork_n_storage_` | Always-on unit and CLI regressions in both `-f` and daemon mode refuse base `/work/A/base` under top A, equality, contained primary archives/images, composite/bind members, and an external QCOW2 whose raw or recursive QCOW2 backing is inside A. External TAR plus explicit in-A index must refuse even with MemIndex; cover both an existing sentinel index and an absent destination. Include internal VMDK extents, split volumes, index-folder selection, SQLite companion/temp/publication paths and enabled cache/materialization artifacts. Assert startup exit 2 before top DB/marker, forced stamp, archive-journal recovery, fork or sessions; existing top metadata and backing/index/cache bytes remain unchanged, and absent conflicting outputs are not created. Guard spies prove refusal before internal open/create/truncate/publication, not only after factory return. Exercise symlink/bind-view/hidden-bind and case/Unicode aliases, including post-mkdir alias transitions, required-identity failure and file-aware gate reachability. Unknown/opaque constructors refuse in both modes; fallback and optional-cache handlers cannot swallow the typed refusal. Lazy nested discovery of an unsafe backing/index after startup fails that operation before opening/mutating it; safe mounts remain usable. Disjoint primary/dependency controls, same-context nested/bind coverage, symmetric top/top and top/lower refusals and successful two-tops-inside-directory-base frozen excludes/ordinary folder reads remain. Kernel integrations explain skips and supplement these always-on cases. |
| `fork_n_daemon_sources_` | Always-on preflight/dispatch tests reject daemon positional and bind torrent sources, mixed ordinary-directory/torrent inputs, magnets, local metainfo and HTTP(S)/file metainfo URLs; run the metainfo variants with `bittorrent`. Cover every swarm policy, including `never`, and seed. Preflight refusal gives exit 2 with foreground guidance, with no factory torrent constructor/worker, invocation mkdir, top DB/marker, fork or session. A dispatch spy catches a source becoming torrent after preflight before its constructor; top-level dispatch refusal still precedes fork/serving. Nested option clones retain the policy and lazy torrent dispatch returns `Unsupported` without a constructor or process exit. Foreground passes this restriction, prepared local daemon sources still pass, and legacy single-mount behavior remains unchanged. |
| `fork_n_daemon_workers_` | Deterministic always-on tests hold budget and signed-URL transport locks on controlled worker threads, then call gated zstd/HTTP speculative entry points: they return without budget registration/reservation, pool initialization, queuing, resolver entry or spawning. Release and join those test workers before any real fork. Separately inject a registered live producer or initialized legacy executor into preparation: the permit refuses without acquiring its held resource lock or calling fork; an idle but unjoined pool also refuses. A real subprocess handoff indexes cold multi-frame `.tar.zst` using a disk index with parallel decoding/readahead and memory budgeting; assert zero parent background workers, all scoped tasks joined and child activation only after N fresh locks/policies, then concurrent FUSE-style reads through both tops complete with exact bytes and configured child speculation is observable. Repeat with direct HTTP range plus a controlled local signed-URL refresh server in a separate process: no parent prefetch or detached worker; child holds/releases the refresh barrier and both readers complete. Use bounded test deadlines to fail a hang, with barrier ordering rather than sleeps as proof. Admission tests cover each table entry/dependency subtree, SSH ProxyJump, Hub publication, foreign rapidgzip, unknown/default, overrides, changed input, bind and nested paths; no forbidden constructor is invoked. Requested settings resume in the child; foreground and legacy behavior remain covered. |
| `fork_n_excludes_` | Base `/repo`, absent `runs`, tops `runs/a`,`runs/b`: observe before factory, create `runs/indexes`, bind afterward; aggregate and both own-top entries remain `runs`. A real recursive factory with `--index-folders /repo/runs/indexes` must demonstrably create that ancestor; an external sealed lower recorded before `runs` existed still accepts, both top rows have equal expected excludes/digests, and editing an unexcluded base file refuses. Include no-lower and reopen variants, an independent journal via the library path, and an in-base lower outside `runs`; assert entries/filtered hash, not only equality. Archive/Git/remote/composite tokens retain None eligibility; anchor or new-symlink retarget before binding refuses before metadata. The sealed-lower variant proves the saved observations reached `open_with`'s walk. |
| Frozen journal eligibility | Always-on library regression seals an external lower against `/repo`, then adds existing `/repo/new.log` and supplies it as `CallerJournal` for two outside tops: frozen aggregate and both top plans omit that unrecorded journal, the actual `open_with` lower walk refuses the changed base, and no writable top metadata is created. Controls preserve a missing journal's first-missing prefix through factory mkdir and retain recorded exclusions when the journal later exists. Existing lower/cache artifacts remain eligible; do not filter all inputs by existence. Cover existing dangling-symlink journals and observation errors, and preserve legacy single-top tests (`main.rs:9238`, `:9258`, `:9297`; `ratarmount/tests/overlay_exclusions.rs:406`, `:453`). |
| Exclude reopen | Restart same cohort after dirs exist; retained `runs` reaches the lower gate; both stored digests/excludes remain, a real base edit fails, Git/new-none/non-directory cases retain semantics, CLI `none` on existing digest-bearing tops still verifies. Incompatible older cohorts refuse existing-content additions; own-overlay fallback and unreadable/hot DB cases are exercised. |
| Bundle preflight | Bundle lower's effective cache path is in snapshot even when an in-base cache ancestor was absent; no early composition/publication; pathname replacement still reads the held descriptor, in-place mutation before private copy fails expected-hash check; normal cache miss/hit retains verification-key behavior. |
| Parent failures | Sealed top, unsealed lower, stack mismatch, later-top DB/policy error and forced-stack failure occur before fork/wait. Force cannot write before the post-mkdir decisive check; directory preparation failures start no sessions. Empty top/mountpoint/parent dirs, factory index artifacts and earlier successful forced stamps remain as documented. Multi-top journal votes reject foreign state without modifying it. Recovery restamps may remain only after the final identity gate has succeeded; dedicated journal tests below specify the ordering and partial-failure behavior. |
| `fork_n_journal_` | Two existing tops plus an owned complete journal and mountpoint alias revealed by mkdir: exit 2, no recovery callback, both top DBs/archive/journal unchanged. Distinct mountpoint control: recover once per member and restamp both relevant top records (including strong pending) before unlink. Fail second top's restamp: retain journal, permit first committed restamp, retry reconciles both before unlink. Own incomplete and Deferred incomplete journals refuse before factory with standalone recovery guidance and no DB/archive/journal changes. Under-lock completeness/ownership change refuses before recovery writes; Own becoming Deferred requires retry, then all gates. Initial None members preserve stale P cleanup, D warning/retention and missing-C refusal after the final matrix; journal appearance after early None requires complete/cohort authorization. Complete Deferred recovery uses all live carriers and all voter/bundle gates. Legacy single-top torn recovery remains covered. |
| Live FUSE `fuse_fork_n` | While A and B are both up, parallel writers create a distinct new regular file on *each*. A listing includes A's name and excludes B's; B listing includes B's and excludes A's. Both re-read their own bytes; both see the prepared base; the other top's same-virtual-path lookup misses. **Symmetric live listings are the proof of correct `source`.** |
| Inside-base alternate-path visibility | Always-on source/overlay tests and live FUSE coverage use base `/repo`, A `/repo/runs/a`, B `/repo/runs/b`: A writes `/x`, B's `/x` misses or retains B's independent bytes, while B lists `/runs/a` and reads `/runs/a/x` as A's bytes. Exercise B-to-A symmetrically. Frozen digests exclude the saved subtree, but live folder traversal remains visible. No source-filtering behavior is implied by digest exclusions. |
| Post-unmount | Release each top's DB before `overlay seal`/`verify`/diff. Independent top digests and expected patches pass. These checks are supplemental and cannot replace live listings. |
| Lifecycle | External unmount A leaves B writable and its signal watcher functional; a later signal on B joins A's watcher even after a failed unmount attempt on A. Always-on watcher tests cover seen>0 cancellation. A deterministic two-session barrier holds both watchers before polling, records TERM→INT, then makes normal unmount return busy: TERM's lazy fallback must reach each still-serving path. Cover INT→TERM, INT-only (never lazy), repeated-signal retries and completed-session joins, through foreground, direct child, launcher-forwarded and handler-transition paths. SIGINT/SIGTERM and orderly exit cover all paths in foreground and daemon modes. Startup signal, session failure, partial ready timeout and child lock failure leave no orphan mount or detached child. Repeated normal unmounts allow final process exit. |
| Launcher startup cancellation | Always-on coordinator tests and live FUSE acceptance send SIGINT and SIGTERM specifically to the launcher PID before any session is ready and after A is ready while B is held at a startup barrier. Release B after cancellation: it never starts or is promptly unmounted. Cover cancellation with queued Ready, launcher channel EOF before Accept (with unused endpoints closed), and child failure/timeout, including unexpected child exit after partial mounting and launcher fallback cleanup. Require nonzero launcher status, every path unmounted, child cleanup/reaping and top DBs writable by a fresh process. Assert all-path cleanup also for sessions registered after cancellation; normal Ready/Accept permits daemon survival after launcher success. |
| Daemon locks | After daemon parent exits and both mounts are ready, a **second process** attempting SQLite `BEGIN IMMEDIATE` fails on each DB. Foreground is separately tested and is not the fork-lock test. Handoff-window competing writer/seal changes are refused or rebuilt through verified state before serving, with no stale tombstones. All child locks precede rebuilding host-derived policies; a scan/install failure releases the cohort and starts no session. |
| `fork_n_daemon_sqlite_` | Always-on lifecycle/dispatch tests enumerate every prepared source connection, refuse missing participants and unsupported in-memory/compact-shell/SQLAR owners before fork, and prove actual connection close plus source-hook detachment in the parent. Subprocess PID/connection tracing proves source handoff reopens occur in the child, one reopened index shared by both tops and no retained parent handle/statement/transaction. Use disk-index TAR xattrs queried through SQL and concurrent two-top reads so MemIndex cannot mask inherited use. Validate a handoff with memory budgeting installs fresh hooks. Source-index replacement or WAL/logical-row change during a barrier must refuse stale memory/SQL combinations; reopen/generation/budget-hook failures send no Ready and start no sessions/workers. Lazy post-fork indexes have child-owned handles and storage guards. Foreground and legacy lifetimes retain their behavior. |
| Per-top settings | Handoff barrier after parent scans A=10 bytes with a 100-byte limit: a legitimate writer appends the existing dirty file to 90 bytes without changing tombstones, exits, then child reacquires all locks and rescans. Assert rebuilt usage=90 through the installed policy and quota-usage reference; 20-byte growth is denied, 10-byte growth succeeds, B's counters are unaffected. Add file-count refresh coverage. Quota/policy failure on A does not consume B's counters; process-wide direct-I/O/readahead/passthrough settings reach each session. Pending archive hash is computed once, applied to every still-pending top; unavailable cache leaves each pending. |
| `fork_n_hardlink_nlink_at_start` | Regression: a regular file in a top already has `nlink > 1`. Refusal before fork names the path and exits 2. No session starts. The link, the file, and every top DB stay unchanged. |
| `fork_n_hardlink_nlink_after_handoff` | Regression: the extra link appears after the parent check and before the child serves. The child recheck refuses before `Ready` and before any session, names the path, and unmounts nothing this process did not mount. |
| `fork_n_self_reopen_backing_under_mountpoint` | Regression: a QCOW2 backing file (same shape for an index or sidecar) canonicalizes under a cohort mountpoint. Refusal before adoption names the path, starts no session, and does not warn and continue. An unresolvable backing path before mount is the same refusal. |
| `fork_n_cleanup_occupied_target` | Regression: a mount target that is already a mountpoint, and a mount target that is not an empty directory, each exit 2 before a session. The pre-existing mount and the directory stay unchanged. |
| `fork_n_cleanup_partial_start` | Regression: A is mounted, then B fails. Cleanup unmounts only A's recorded `(st_dev, st_ino)` and this process's owned FUSE session. An unrelated mount stays mounted. The failure path does not lazy-unmount. |

Listings are decisive because FUSE uses `source.list_dirents`
(`ratarmount-fuse/src/lib.rs:1228`), and `WriteOverlay::list_dirents` merges
host dirty names (`write_overlay.rs:5364`–`:5413`). Create can succeed even if
`source.lookup` misses (`lib.rs:1613`–`:1634`). Reopen of a created file instead
uses `overlay.has_file` → `OverlayFd` (`:2339`–`:2367`), then `pread`
(`:1517`–`:1520`); it can pass with the wrong shared-stack source. Cross-lookup and a
base read also pass in that broken wiring. Do not label them, or post-unmount
seal/diff, as the source proof.

Later implementation validation runs `cargo fmt --all`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo test --workspace` before commits, plus independently run relevant
filters/kernel tests. If run on brewtop here, prefix cargo invocations with
`CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock`. No cargo build is needed to
validate this docs-only planning stage. A 2–6-top prepared-build demonstration
is a consumer experiment after correctness tests, not a promised CI speedup.

## v1 limits (Keystone BUILD lock)

These three refusals are part of the v1 contract. Lifting any of them needs a
Keystone design note. Each has a named PR2 regression in the acceptance table.
They are startup limits on Option A. Exit 2, and no session starts, unless a
limit says a session this process already mounted is torn down under the
cleanup rule.

### Hardlinks

Refuse startup if any regular file in any top has `nlink > 1`. Walk with
`lstat`: a symlink is not a regular file, and a directory is not a regular
file. Check before fork, and recheck after daemon handoff, before serving.
Foreground repeats the recheck after its locks, before serving. The error
names the path. No session starts on that refusal.

- `fork_n_hardlink_nlink_at_start` — Regression: `nlink > 1` is already
  present. Refusal before fork names the path. The link, the file, and the
  databases stay unchanged.
- `fork_n_hardlink_nlink_after_handoff` — Regression: the extra link appears
  after the parent check, before the child serves. The child recheck refuses
  before `Ready` or any session, names the path, and unmounts nothing it did
  not mount.

### Self-reopen

Refuse if any source, dependency, or post-mount file dependency canonicalizes
under any of this process's mountpoints or top directories. The covered set is
QCOW2 backing files, index and sidecar files, and each overlay database plus
its `-wal`, `-shm`, and `-journal` companions. Open by fd and hold fds where
the existing open path allows it. Holding an fd does not replace the
canonicalization check. An unresolvable path before mount is a refusal, not a
warning.

Each top's own database is created in that top (`WriteOverlay` stores the
overlay under its root). That owning database, and its companions beside it,
are the top. The refusal fires when canonicalization places a database file,
companion, source, or dependency under a mountpoint, or places a source or
shared dependency under any top, or places a database file under a different
top. A backing file under a mountpoint is this limit even when that file is
outside every top. A not-yet-created destination whose existing ancestor
resolves is the storage gate's reserve-absent-destination rule. Failure to
resolve that ancestor, a symlink loop, or any other canonicalize error before
mount is a refusal.

- `fork_n_self_reopen_backing_under_mountpoint` — Regression: a QCOW2 backing
  file canonicalizes under a cohort mountpoint. The same shape covers an index
  or sidecar. Refusal before adoption names the path. No session starts, and
  the process does not warn and continue. An unresolvable backing path before
  mount is the same refusal.

### Cleanup

Refuse a mount target that is already a mountpoint or is not an empty
directory. A directory this process has just created for a missing mountpoint
is empty, and that empty directory is eligible when it is not already a
mountpoint. On failed startup, unmount only targets this process mounted, and
only when the recorded `(st_dev, st_ino)` still matches and the mount is this
process's owned FUSE session. Never lazy-unmount anything else. A mount this
process did not create stays mounted.

- `fork_n_cleanup_occupied_target` — Regression: a target that is already a
  mountpoint, and a target that is not an empty directory, each exit 2 before
  a session. The pre-existing mount and the directory stay unchanged.
- `fork_n_cleanup_partial_start` — Regression: A is mounted, then B fails.
  Cleanup unmounts only A's recorded `(st_dev, st_ino)` and this process's
  owned FUSE session. An unrelated mount stays mounted. The failure path does
  not lazy-unmount.

The serving SIGTERM busy-then-lazy policy (`overlay_commit.rs:220`–`:257`)
remains only for a session this process owns after that session has started
serving. Failed-startup cleanup does not use that lazy fallback.

## Out of v1

Explicitly out of scope for PR1 and PR2: Option B, the separate Mount-in-base
PR2, and serve-sandboxes. Also out of v1: Options C and D, layered commit including
no-lower Fork-N commit, sandbox supervisor/ProcessMounter rewrite, incremental
make orchestration, multi-mount control/journaling protocols, per-top option
syntax, and S8/r11 mop-up bundling. Existing identity and per-overlay latch
rules stay in force. Legacy journal behavior is unchanged; Fork-N adds the
explicit incomplete-journal refusal above. Constructors without complete
transitive storage coverage refuse both foreground and daemon Fork-N. Daemon
constructors additionally require admitted worker lifetimes and a handoff for
every retained source SQLite connection; unsupported in-memory/opaque SQLite
modes refuse as specified above. Zstd/HTTP worker deferral is required; generic
worker quiescence/restart and live source filtering of inside-base top paths are
deferred. No unrelated branch is assumed merged.
