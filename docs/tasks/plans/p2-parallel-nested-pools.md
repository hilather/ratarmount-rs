# P2: Parallel nested open pools

| Field | Value |
|-------|--------|
| **Author** | ratarmount-rs (plan-only; skeptic-reviewed) |
| **Date** | 2026-08-28 |
| **Status** | **ACCEPT** (skeptic sweeps 1–3; no blockers) |
| **Backlog** | [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md) P2 “Parallel nested open pools” |
| **Scope** | Investigate the eager parallel nested-open path vs compact `StringPool`. Decide whether a per-worker arena + parent-pool merge is justified. If not, close the item as already-isolated. If yes, specify a RAM-only merge that does **not** change the durable nested blob. |
| **Out of this train** | Durable `nestedindexes` / RNIB encoding; intra-archive parallel ZIP/TAR fill; AutoMount `PathIntern` redesign; parent `SharedArchiveIo` mutex; SIMD; lazy (`-l`) sequential mount |

This document is **plan-only**. It does not implement merge, intern, or AutoMount changes.

---

## Verdict in one paragraph

**There is no shared intern target / parent-pool argument on today’s eager parallel nested-open path.** Nested compact indexes that use `StringPool` each **own** a private `pool: StringPool` (`MemIndex` / `MemIndexBuilder` by value). Workers do not intern member names into a parent handle. The outer archive may have its own sealed `MemIndex.pool`; nothing passes that object into nested builders. Implementing “per-worker arena, then merge into parent” would **create** a shared pool the tree does not have, then pay remap / lifetime / ZIP–7z `Arc` identity cost to undo a lock that does not exist.

**Recommended disposition:** treat the lock-contention reading of P2 as **N/A (already isolated)**. Do **not** add a parent-pool merge in the default implementation train. Lock that finding with invariant tests + a backlog rewrite so the next agent does not implement a merge from the two-line bullet. A **gated** cross-archive intern (RSS only) is specified below and stays **out of the default train** until a named measurement fails.

---

## Spec

**Backlog bullets** (the P2 subsection in [`vectors-optimization.md`](../vectors-optimization.md) — only these two lines):

1. Per-worker string pool / arena during eager parallel nested open, then merge into parent pool.
2. Avoid global pool lock contention without duplicating all strings forever.

**This plan’s charter** (task prompt / Done-section context — not extra P2 bullets):

- Nested compact `StringPool` already exists; **investigate** the parallel nested open path.
- **Not** a durable-blob change.

The two backlog bullets describe an architecture (shared parent pool + worker arenas) that the investigation shows was **never built**. The close-out of the lock-contention reading stands on findings F1–F3, not on treating “investigate” as a third backlog bullet.

---

## Background: what already shipped

| Piece | Location | Today |
|-------|----------|--------|
| Compact `StringPool` | `ratarmount-index/src/mem.rs` | Byte slab + `(start,len)` spans; build `HashMap` then seal to FNV-1a + binary search; `intern()` keeps `Arc<str>` identity for ZIP/7z sidecars |
| `MemIndex` / `MemIndexBuilder` | same | Each index **owns** `pool: StringPool` by value. `finish()` seals. No `Arc<StringPool>`, no parent handle |
| Nested live table | `SqliteIndex::create_compact_only` (`ratarmount-index/src/lib.rs`) | In-process MemIndex only; `mem_builder: Mutex<Option<MemIndexBuilder>>` is **per index instance** |
| Factory nested **reader** | `ratarmount/src/factory.rs` `open_nested_reader_fn` | Forces `index_compact_only = true` so each nested ZIP/TAR/7z/CPIO/AR/… compact index is **new** |
| Factory nested **spool** | `open_nested_fn` | Does **not** set `index_compact_only`. Writes `{path}.index.sqlite` via `create_writable` — still a **private** `MemIndexBuilder` on that index |
| Durable warm import | `SqliteIndex::create_compact_from_nested_blob` | `to_mem_index()` → fresh private sealed pool; `mem_builder` is `None` (no intern-during-build) |
| ZIP/7z name share | `intern_during_build` | Locks **that** index’s `mem_builder` while filling **one** archive sequentially |
| Durable blob | `ratarmount-index/src/nested.rs` | RNIB v2 columnar `DurableFileRow` **owned strings**. `to_mem_index()` builds a **fresh** private pool. Export rematerializes `FileRow` strings from the slab |
| FR-6 parallel open | `AutoMountLayer::mount_archives_batch` (`ratarmount-compositing/src/automount.rs`) | Same-directory ≥2 archives + `parallel_nested_threads ≠ 1` → `std::thread::scope` workers call `try_mount_file`. Lazy ignores the cap |
| AutoMount key intern | `MountedTable` + `PathIntern` | **Mount-point paths only** (one string per nested root). Behind `Mutex<MountedTable>`. Not the index `StringPool` |
| Union key intern | `UnionMountSource::path_intern` | Folder-cache keys. Not on the nested-open intern path |

P1 “Union / AutoMount path maps” already interned mount-point / cache keys in crate-local `PathIntern`. Residual in the backlog: *“crate-local `PathIntern` (not the index `StringPool`).”*

---

## Investigation: parallel nested open vs pools

### Call graph (eager `-r`, no `-l`)

```text
AutoMountLayer::scan_and_mount
  └─ per folder (BFS):
       list_names_no_lazy          // holds mounted mutex during parent.list
       mount_archives_batch(archives, depth+1)
         ├─ sequential if workers≤1 or archives.len()<2
         └─ else thread::scope, N workers:
              loop { pop work queue; try_mount_file(full, depth) }
       recurse into subdirs + returned mount points

try_mount_file
  ├─ mounted.lock: contains_key(mount_point / path)     // brief
  ├─ lookup_raw → parent.lookup                         // holds mounted mutex
  ├─ mounted.lock: find_mounted_in + source_at_locked   // brief
  ├─ parent.open(member)                                // may take parent I/O mutex
  ├─ prefer open_nested_reader_fn → format open
  │     create_compact_only() or create_compact_from_nested_blob()
  │     insert_files_batch / intern_during_build        // that index’s mem_builder Mutex
  │     finish() / seal
  │     optional try_store_nested_durable → outer set_nested_index
  ├─ else temp spool → open_nested_fn(path)
  │     create_writable({path}.index.sqlite)            // private builder, not compact-only
   │     FAT/EXT4/SquashFS/Git/SQLAR: no StringPool; ISO reader: private compact pool
  └─ mounted.lock: PathIntern.intern(key) + insert      // mount-point string only
```

Parallelism is **one thread per sibling archive**, not parallel fill of one archive’s member list. Isolation holds on reader, warm-import, and spool branches: each open still gets its own builder or its own `to_mem_index()` pool. Formats without a compact `StringPool` are not a parent-pool intern path either.

### Finding F1 — no parent-pool **argument** / shared intern target

The **outer** TAR/ZIP/7z mount may already have a sealed `MemIndex.pool`. What does not exist is a handle that nested builders intern into. `MemIndex` and `MemIndexBuilder` each store `pool: StringPool` by value. `MemIndexBuilder::new()` takes no parent pool. AutoMount, `open_nested_reader_fn`, `open_nested_fn`, and `DurableNestedBlob::to_mem_index` do not pass a shared `StringPool` in.

Workers cannot contend on a parent-pool intern lock because that shared intern target does not exist.

### Finding F2 — per-open isolation already matches “per-worker arena”

Three nested-open branches, all isolated:

| Branch | Index construction | `StringPool` |
|--------|--------------------|--------------|
| Reader (`open_nested_reader_fn`) | `index_compact_only = true` → `create_compact_only()` | New private builder/slab |
| Warm import | `create_compact_from_nested_blob` → `to_mem_index()` | New private sealed pool; no `mem_builder` intern |
| Temp spool (`open_nested_fn`) | `create_writable({path}.index.sqlite)` | Private builder on that SQLite index (not compact-only) |

When the worker returns `Arc<dyn MountSource>`, that source **keeps** its own sealed (or path-index) table. There is no post-open “merge into parent” step.

FAT/EXT4/SquashFS/Git/SQLAR have **no** `StringPool`. Nested **ISO 9660** on the reader path uses `SqliteIndex::create_writable_for_open` and therefore **does** get a private compact pool. Neither case intern member names into a parent pool.

This already satisfies “do not intern member names through a global lock.” On the compact reader/import path, the worker slab **is** the live store (no second live copy of that archive’s strings).

### Finding F3 — locks that *do* exist (and are not this item)

| Lock | What it protects | Held during member intern? | This P2? |
|------|------------------|----------------------------|----------|
| `AutoMountLayer.mounted` | `PathIntern` + `NestedMount` map; also `lookup_raw` / `list_names_no_lazy` | No (one mount-point key at insert) | No — P1 residual / mutex scope |
| Batch `work` / `results` `Mutex` | Queue + mount-point `String`s | No | No |
| `SqliteIndex.mem_builder` | One archive’s builder + `intern_during_build` | Yes, **inside that archive only**, sequential ZIP/7z/`insert_files_batch` | No — not cross-worker |
| Parent `Arc<Mutex<Box<dyn SeekRead>>>` | Member I/O on ZIP/7z/ISO/… | No (payload) | No — explicit non-goal of the vector track |
| Outer SQLite via `try_store_nested_durable` / `set_nested_index` | Parallel workers writing `nestedindexes` blobs to the **same** outer index file | No (blob bytes, not intern) | No — file/conn contention; do not “fix” as a pool lock |

`lookup_raw` holds `mounted` for the whole `parent.lookup`. That can serialize metadata lookups during a parallel batch. It is **not** string-intern of member names. Do not “fix” it under this P2 title.

### Finding F4 — durable blob is already pool-id-free

`MemIndex::export_file_rows` copies path/name/linkname out of the slab into owned `FileRow` / `DurableFileRow` strings. Import rebuilds a new builder. A live parent-pool merge would not require an RNIB version bump **if** export stayed FileRow-based. This plan still forbids blob changes (spec).

### Finding F5 — ZIP/7z `Arc` identity is per-index

`intern_during_build` + post-seal `lookup_arc` keep `Arc::ptr_eq` between sidecar names and the **same** index’s pool. A merge into a parent slab would invalidate those Arcs unless sidecars are re-interned from the parent after remap. Isolation avoids that class of bug.

### Finding F6 — “duplicating all strings forever” is a different problem

The bullet can be read as: share `"usr"` / `"lib"` / `"README"` **across sibling nested archives** so N similar trees do not keep N slabs. That is **cross-archive intern (RSS)**, not lock contention. It requires a parent pool that does not exist, plus `u32` remap of every `name_id` / `linkname_id` / `PathTable.seg_ids` / dir-map key, plus a pool that **outlives** every remapped `MemIndex`. Unmount of one nested root cannot drop unique strings without a refcount or a compact (ids are indices). Eager `-r` keeps all nested mounts anyway (`#179` RAM is dominated by opening every nested body, not by duplicate `"usr"` bytes).

---

## Goals & non-goals

### Goals (this plan → later implementation PRs)

1. **Record the investigation** so P2 is not re-implemented from the two-line bullet.
2. **Default train (Phase 0):** close the lock-contention reading as N/A; add invariant tests; rewrite the backlog row.
3. **Gated train (Phase 1):** only if measurement gate **G1** fails, implement RAM-only merge as specified below. Still no RNIB change.

### Non-goals

| Item | Reason |
|------|--------|
| Shared parent `StringPool` without G1 | Invents coupling to fix a lock that is not there |
| Changing RNIB / `DurableFileRow` / `nestedindexes` DDL | Spec: not a durable-blob change |
| Parallelizing `fill_index_from_archive` / TAR parse inside one archive | Different problem (`mem_builder` Mutex). Not “eager parallel nested open” |
| Per-worker `PathIntern` then merge | Mount-point keys are tiny; intern already happens under the insert mutex |
| Narrowing `mounted` lock around `lookup` / `list` | Real, but compositing correctness (not vector intern) |
| Parent I/O mutex / solid decode / inflate | Payload; vector-track non-goal |
| Lazy sequential mount | `parallel_nested_threads` is ignored; must stay sequential |
| `factory.rs` glue for Phase 0 | Orchestrator-owned; Phase 0 stays in `ratarmount-index` + `ratarmount-compositing` tests |

---

## Key decisions

| ID | Decision |
|----|----------|
| **K1** | The lock-contention premise of P2 is **false** on current `main`. Do not add a parent pool “to avoid contention.” |
| **K2** | Default implementation is **Phase 0 only** (tests + backlog). Phase 1 is written so it can be executed later without rediscovery, but is **not** authorized until G1 fails. |
| **K3** | AutoMount `PathIntern` is **not** the “parent pool.” Do not merge mount-point keys into `StringPool`. |
| **K4** | Durable blob stays FileRow-owned strings. Phase 1 merge, if ever built, remaps **live** MemIndex ids only. |
| **K5** | ZIP/7z sidecar `Arc::ptr_eq` remains per nested index. Phase 1 must re-intern sidecars after remap or keep sidecars on the worker pool and **not** swap the live `MemIndex.pool` out from under them. Isolation (Phase 0) needs no extra rule. |
| **K6** | Do not change FR-6 scheduling (`thread::scope`, worker cap, same-dir ≥2, lazy ignore). |
| **K7** | Phase 0 must update [`vectors-optimization.md`](../vectors-optimization.md) in the same PR as the tests so the checkbox cannot stay `[ ]` with the old wording. |

---

## Measurement gate G1 (Phase 1 only)

Phase 1 is **forbidden** unless all of the following are true on a documented fixture:

1. **Overlap:** For a same-directory eager batch of \(N \ge 8\) nested archives, let \(U_i\) be `pool.unique_count()` (or slab bytes) of nested archive \(i\), and \(U_{\cup}\) the unique count of the union of those strings. \( \sum U_i \ge 2 \cdot U_{\cup} \) (at least half of interned entries are cross-archive duplicates).
2. **Absolute size:** \( \sum \mathrm{slab\_bytes}_i - \mathrm{slab\_bytes}_{\cup} \ge 1\,\mathrm{MiB} \) on that fixture (not “32 copies of a 3-file tar”).
3. **Share of `-r` RSS:** the duplicate slab is not in the noise versus member-body / decompress RSS on the same fixture (if opening the bodies dominates, merge will not move `#179`).

**Expected default:** G1 does **not** fail on heterogeneous nested trees. It *can* fail on “32 identical `usr/lib` trees in one folder.” That case is still usually body-RSS-dominated. The 1 MiB floor plus “not in the noise vs body RSS” (`#179`) will fail almost every real fixture. **G1 is a stop sign, not a live measurement program that is expected to authorize Phase 1.** G1.3 is intentionally unquantified (no single `%` of RSS is honest across codecs); if a later spike needs a number, that spike picks one on a named fixture.

There is **no** public `slab_bytes()` today (`unique_count()` only). Any G1.2 measurement would need a test-only accessor; do not add it in Phase 0 unless someone is actually running G1.

A unit-level **overlap calculator** (two `MemIndex`es from identical `FileRow`s → report \(\sum U_i\) vs \(U_{\cup}\)) may land in Phase 0 as a helper; it does **not** by itself authorize Phase 1.

---

## Phase 0 — close lock-contention reading (default train)

### Code (tests only)

Lowest layer first:

1. **`ratarmount-index`:** two `MemIndexBuilder`s filled with the same rows finish to two sealed pools. Assert:
   - each `pool_is_sealed_slab()`
   - `get(id)` equal for the same names
   - the two `StringPool` values are **distinct allocations** (not `Arc` shared; compare slab pointer or a new test-only `pool_slab_ptr` / `ptr::eq` on the slab)
   - there is no API that interns into a “parent” (compile-time: `MemIndexBuilder::new` takes no pool argument — document in the test comment)
   Name: `regression_nested_compact_pools_are_per_index` (symptom: “shared parent pool lock”).
   **Placement:** `MemIndex.pool` is private. Put this test in `ratarmount-index/src/mem.rs` `#[cfg(test)]` (can use `slab.as_ptr()` / `ptr::eq`) **or** add a `#[cfg(test)]` accessor. A `lib.rs` integration test cannot see the slab today.

2. **`ratarmount-compositing`:** extend the existing FR-6 parallel eager tests (or add one) so two real compact nested TAR (or dummy `MountSource` plus a compact-index helper) finish with **independent** intern state. If the dummy `EmptyNested` path cannot see a `StringPool`, keep the index-crate test as the invariant and only assert FR-6 still fans out (`parallel_eager_mounts_multiple_archives_same_level` / `parallel_eager_open_nested_overlaps_with_multiple_archives`). Do **not** weaken those tests.

3. **Do not** add `StringPool::merge` / `MemIndex::remap_pool` in Phase 0.

### Docs (same PR as tests)

Rewrite the P2 subsection to something equivalent to:

```text
### Parallel nested open pools

- [x] Investigated (2026-08-28): eager FR-6 workers do not intern into a
      parent StringPool. Reader = create_compact_only; warm import =
      to_mem_index(); spool = private create_writable. No shared intern target.
- Residual: cross-archive intern (RSS) is a different, gated item — see
  docs/tasks/plans/p2-parallel-nested-pools.md Phase 1 / G1. Do not treat
  G1 as a program that is expected to authorize merge.
```

Add an AGENTS.md catalog row only if Phase 0 introduces a new named regression filter (the index-crate test above).

### Docs this plan does **not** change

- [`docs/embedded-nested-archives.md`](../../embedded-nested-archives.md) — live model unchanged (still per-nested compact table).
- README nested cheat sheet / format matrices — no open/tmp change.
- Durable nested / RNIB docs.

### Ownership

| Crate | Phase 0 |
|-------|---------|
| `ratarmount-index` | Invariant test (+ optional overlap helper) |
| `ratarmount-compositing` | Only if a parallel-open test can observe isolation without factory |
| `ratarmount` / `factory.rs` | **Do not touch** |

---

## Phase 1 — RAM-only parent merge (gated; not default)

Authorized only after G1. Still plan-only here.

### Intended shape

1. Worker threads keep today’s private `MemIndexBuilder` / `StringPool` (no shared intern during parse).
2. After `finish()`, the coordinating thread (or a single merge pass after `thread::scope`) calls a new **index-crate** API, e.g. `StringPool::extend_from(&other) -> Vec<u32>` (old id → new id) and `MemIndex::rebind_pool(parent, remap)`.
3. Remap every pool id in:
   - `EntrySoa` `linkname_id` (and any future name-id column)
   - `PathTable.seg_ids`
   - `DirEntries.names` keys in **`MemIndex.dirs` and every `MemIndex.shards[i]`** (sharded dirs store the same map)
   - builder `by_key_oh` if merge happens before `finish` (prefer **after** seal: fewer maps)
4. Drop worker slabs after remap so strings are not live in two stores.
5. Sharing one slab across N nested indexes requires changing **`MemIndex.pool` from `StringPool` by value to `Arc<StringPool>`** (or equivalent). Today `StringPool: Clone` **deep-copies the slab**; putting `Arc<StringPool>` only on `AutoMountLayer` does not make nested indexes share it. After the parent is frozen, sidecar attach must use `lookup_arc` / `lookup_pooled_string` (`&self`). `intern` is `&mut self` and is the wrong API on a shared sealed pool.

### Hard constraints

- **No RNIB change.** Export still `export_file_rows()`. Warm import still `to_mem_index()` into a **private** pool (import is single-threaded per member; sharing across warm remounts would be a third design).
- **Do not intern during parse through the parent lock.** That would re-create the fictional P2 problem. Merge is post-build.
- **ZIP/7z:** after `rebind_pool`, re-run sidecar name attach via `lookup_pooled_string` / `lookup_arc` on the **shared** pool so `Arc::ptr_eq` holds again (`intern` needs `&mut` and must not run on a frozen shared parent). Test with the existing ZIP/7z pool-share unit tests plus a two-archive merge.
- **Unmount:** parent slab does not shrink. Document: unique strings from a dropped nested mount remain until AutoMount drop. Acceptable only because eager `-r` already retains all nested sources.
- **Injection point:** `try_mount_file` stores `Arc<dyn MountSource>`. `MountSource` has no `as_any` / downcast / pool / `MemIndex` hook. A parent merge **after** open is not a small `StringPool` patch. Spike options (pick one, do not sneak all in):
  1. New narrow trait or downcast on `MountSource` (e.g. `CompactIndexMerge`) — compositing-visible.
  2. Carry a merge target on **`NestedOpenContext`** (it already carries `outer_index_path` / `write_nested_index`) into factory **before** the `Arc<dyn MountSource>` is sealed — still factory-owned glue; orchestrator territory.
  3. Merge inside each format crate before seal — **per archive**, not a parent; does not satisfy cross-archive intern.
  Phase 0 needs none of these. Phase 1 must spike (1) vs (2) first; reject if neither is smaller than the RSS win.

### Phase 1 feasibility note (pre-called)

If G1 ever fails, the first Phase 1 spike is: **can we rebind without a new trait, or only via `NestedOpenContext`?** If neither is acceptable, the spike document is the next plan; do not sneak a trait into a “pool merge” PR.

---

## Tests (Phase 0 must ship with the close-out PR)

| Test | Layer | Asserts |
|------|-------|---------|
| `regression_nested_compact_pools_are_per_index` | `ratarmount-index` `--lib` | Two builders → two sealed slabs; same logical strings; no shared parent argument |
| Existing `string_pool_interns_duplicates` / `regression_finished_memindex_is_csr_and_sealed_slab` | same | Stay green (seal + `Arc` identity) |
| `parallel_eager_mounts_multiple_archives_same_level` | `ratarmount-compositing` `--lib` | Still opens all same-dir archives |
| `parallel_eager_open_nested_overlaps_with_multiple_archives` | same | Still overlaps `open_nested` |
| `sequential_eager_still_mounts_all_archives` / lazy non-eager | same | Unchanged |
| ZIP/7z `intern_during_build` pool-share tests | format crates | Unchanged; Phase 0 must not break `Arc::ptr_eq` |

Phase 1 (only if authorized) additionally needs: remap bijection (old `get(id)` == parent `get(remap[id])`); dir list/lookup after rebind; ZIP sidecar `ptr_eq` after rebind; RNIB export/import still round-trips **without** format change; parallel eager `-r` with merge enabled matches sequential names/modes/sizes.

Skip rule: none for Phase 0 (pure unit). Do not skip on missing `7z`/`gzip`.

---

## Verification commands (Phase 0 PR)

```bash
cargo fmt --all
cargo clippy -p ratarmount-index -p ratarmount-compositing --all-targets -- -D warnings
cargo test -p ratarmount-index --lib
cargo test -p ratarmount-compositing --lib parallel_eager
cargo test -p ratarmount-compositing --lib sequential_eager
cargo test -p ratarmount-index --lib nested
```

Do not require `cargo test --workspace` for Phase 0 if scoped tests + fmt/clippy for the two crates are green; the implementer / orchestrator still runs workspace gates before merge per AGENTS.md.

---

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Next agent implements parent merge from the old bullet | High | K7: rewrite the backlog row in the same PR as Phase 0 tests |
| Phase 1 looks “specified enough” to start coding | High | Status of Phase 1 = **gated / not authorized**. Feasibility note: no `MountSource` rebind |
| G1 gamed with tiny identical tars | Medium | Absolute 1 MiB duplicate-slab floor + `#179` share check |
| Confusing `PathIntern` with `StringPool` | Medium | K3; P1 residual already says they are different |
| Holding `mounted` during `lookup` blamed on this P2 | Low | F3 table; out of train |

---

## Open questions

None that block Phase 0.

Resolved:

1. **Is there a global pool lock?** **No** (F1–F3).
2. **Should we still design merge “because the bullet says so”?** **No** for the default train (K1–K2). Phase 1 exists only behind G1 and a trait/feasibility spike.
3. **Is this a durable-blob change?** **No** (F4, K4).

---

## Implementation PR plan (after this plan is ACCEPTed)

**This plan PR:** `docs/tasks/plans/p2-parallel-nested-pools.md` only.

| PR | Contents | Merge when |
|----|----------|------------|
| **PR 1 (Phase 0)** | Index-crate invariant test; backlog rewrite; optional compositing assertion | fmt/clippy/scoped tests green; catalog row if a new filter lands |
| **PR 2 (Phase 1)** | Only if G1 documented-fail + spike says rebind is possible | Separate plan or a short spike note; not started from this document alone |

Do not combine Phase 1 into PR 1.

---

## References

- Backlog: [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md)
- Nested live model: [`docs/embedded-nested-archives.md`](../../embedded-nested-archives.md)
- FR-6: [`docs/tasks/upstream-feature-requests.md`](../upstream-feature-requests.md) #80; CLI `--parallel-nested`
- Code: `ratarmount-index/src/mem.rs` (`StringPool`, `MemIndex`, `MemIndexBuilder`), `ratarmount-index/src/lib.rs` (`create_compact_only`, `intern_during_build`, `insert_files_batch`), `ratarmount-index/src/nested.rs` (`DurableNestedBlob::to_mem_index`), `ratarmount-compositing/src/automount.rs` (`mount_archives_batch`, `try_mount_file`, `MountedTable`), `ratarmount-compositing/src/path_intern.rs`, `ratarmount/src/factory.rs` (`open_nested_reader_fn`)

---

## Skeptic review log

Process: sweep 1 is mandatory; each sweep is a **fresh** skeptic; fold blockers into this document; cap **3** sweeps then **BLOCKED**. Stop at **ACCEPT** or **BLOCKED**. No implementation in this PR.

| Sweep | Verdict | Blockers folded |
|-------|---------|-----------------|
| 1 | **ACCEPT** (no blockers). Nits folded: spec vs charter; F1 “no parent argument”; F2 reader/import/spool; F3 outer `set_nested_index`; G1 as stop-sign + no `slab_bytes()`; Phase 1 `shards` + `NestedOpenContext` injection. | None (nits only) |
| 2 | **ACCEPT** (no blockers). Nits folded: ISO reader *has* a private compact pool; Phase 0 test lives in `mem.rs`; Phase 1 needs `MemIndex.pool: Arc<StringPool>` (Clone deep-copies); sidecar attach via `lookup_arc` not `intern`. | None (nits only) |
| 3 | **ACCEPT** (no blockers). Nits not folded (cap): `unique_count()` includes empty id-0; Phase 0 index test cannot observe FR-6; `open_nested_fn` does not force `index_compact_only = false` (default is already false; either value is still a private builder). | None |

**Final: ACCEPT**

Three independent skeptics accepted. Lock-contention P2 is N/A on current `main`. Default later work is Phase 0 (invariant test + backlog rewrite), not a parent-pool merge. Phase 1 remains gated and is not authorized by this document alone. No implementation in this PR.
