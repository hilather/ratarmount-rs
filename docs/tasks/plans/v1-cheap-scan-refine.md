# V-1 — Cheap scan, then refine

| Field | Value |
|-------|--------|
| **Author** | ratarmount-rs |
| **Date** | 2026-08-28 |
| **Status** | Plan (skeptic review in progress — sweep 1 folded, awaiting sweep 2) |
| **Item** | [`vectorize-steal-patterns.md`](../vectorize-steal-patterns.md) **V-1** Cheap scan then refine (`partial`, M) |
| **Pairs with** | [`vectors-optimization.md`](../vectors-optimization.md) P0 list/dirents residual; [`beyond-parity-roadmap.md`](../beyond-parity-roadmap.md) **F-3** overlay residual |
| **Audience** | Implementers who already know `MountSource`, `MemIndex` / `EntrySoa`, F-3 locate, and `WriteOverlay` |
| **This document** | Implementation train only. **Do not implement from this file until Status is ACCEPT.** |

---

## Overview

Steal Cloudflare Vectorize’s **two-phase query** (scan a cheap representation, refine only the hits). Do **not** steal SIMD, IVF, PQ, or ANN. Member bytes stay exact.

V-1 finishes the metadata side of that split:

1. **CLI `find` / FTS stay streaming SQL** over the 0.7.x `files` / `files_fts` catalog. Allocate path strings only for emitted hits. Do **not** load `MemIndex` to answer sidecar `find`.
2. **Live control/socket / compact-only** walk **SoA columns + pool ids** (`search_cheap` / `MemIndex::scan_glob`) and allocate path strings only for emitted hits.
3. `list()` grows an additive **`ListNeed`** flag (P0 leftover). Cheap search **must not** call `list()` / `list_with(FileInfo)` — the flag is not the locate API.
4. Overlay names (creates, **COW/replace/rename-dest**, tombstones) participate in **cheap** control/socket search without a second fat catalog.
5. Regression: locate `*.fits` on a 200k-row **synthetic SoA** (and SQL `search_query` on a sidecar) stays near cheap `list_dirents` / SoA RSS, not near a fat `list()` map. **No CI 200k on-disk TAR.** Cold `factory::open_path` for a missing sidecar is **out of the RSS bar**.

This is the same toolbox as P0 density. The remaining tax is leftover `list()` callers, overlay-blind locate, compact-only search returning empty, and implementers “unifying” find onto MemIndex — not cosine math.

**Impl prompt phrase lock:** do **not** tell implementers to “hydrate `FileInfo` only on hits.” Hits are `SearchHit` / `CheapSearchHit`. `FileInfo` is getattr/open only.

---

## What this is not (hard non-goals)

| Do not | Why |
|--------|-----|
| SIMD CRC / memchr / bulk hash | `vectors-optimization.md` **P2**; zlib-rs / rapidgzip, not Vectorize |
| IVF / k-means / PQ / ANN | Members are not points in \(\mathbb{R}^{D}\); wrong `cat` is corruption |
| Approximate member contents | A 95% correct `read()` is a bug |
| Replace the 0.7.x `files` table with centroid files | One SQLite blob per snapshot (V-2) is enough |
| Load a full `MemIndex` just to run sidecar-only CLI `find` | That **raises** RSS vs streaming SQL; see [D1](#d1-two-backends-one-hit-type) |
| Run FTS5 `MATCH` over pool ids | FTS lives in `"files_fts"`; SoA has no inverted index |
| Hydrate `FileInfo` on locate (scan **or** hits) | Emit type is `SearchHit` / `CheapSearchHit` |
| Lift CLI `find` + `-w` in v1 | Overlay context is the live mount; see [D4](#d4-overlay-merge-ownership) |
| Recurse AutoMount nested children in locate | Matches today’s sidecar of `inputs[0]` only; see [D5](#d5-search_cheap-hook-and-forwards) |
| Tracker / D-Bus / mount `--index-fts` / write-then-read `echo pat > search` | F-3 residuals, not V-1 |
| V-2 snapshot pointer, V-3 remote cache, V-4 commit queue, V-5 offset-order list | Separate items |
| Change nested open / temp spool / `MountSource::open` / `factory.rs` open paths | No format-matrix update; orchestrator owns factory glue |

---

## Investigation (current code — 2026-08-28)

Two locate paths already exist. They do **not** share a catalog walker. Optimizing FUSE readdir does not automatically optimize `ratarmount find`, and vice versa.

```mermaid
flowchart TB
  subgraph cli [CLI find / today's control + socket]
    A[find::locate_hits / search_existing_sidecar]
    B[SqliteIndex::search_query]
    C[(SQLite files / files_fts)]
    A --> B --> C
    B --> H[Vec SearchHit with String path+name]
  end

  subgraph fuse [FUSE/NFS readdir — already cheap]
    D[readdir / READDIR]
    E[MountSource::list_dirents]
    F[MemIndex SoA + pool]
    D --> E --> F
  end

  cli -.->|no MountSource| X[FileVersionLayer / WriteOverlay]
  fuse --> X
```

### Wrap order (live mount) — required for overlay/search wiring

```
format MountSource
  → Transform?          (apply_compositing, factory.rs ~3162)
  → AutoMount?          (recursive, ~3165)
  → Prefix?             (disable-union multi-source, ~3207)
  → Union?              (n_sources > 1, ~3697)
  → FileVersionLayer?   (~3705)
  → Prefix?             (comp.prefix, ~3708)
  → WriteOverlay?       (main.rs ~954–958, after factory bundle)
  → ControlFolder?      (main.rs ~1123–1133, outermost)
```

Control **wraps overlay**. `tsv_search_callback` closes over `inputs[0]` + `OpenOptions` only — **no `WriteOverlay`**. Socket uses that same sidecar closure. Live `search_cheap` must be invoked on the **outer** `MountSource` (Control → overlay → …) **or** the SearchFn in `main.rs` must hold `overlay_arc` for the sidecar fallback path. Do **not** edit `factory.rs` open paths.

### CLI `find` — sidecar SQL, no `MountSource`

| Step | Location | Notes |
|------|----------|-------|
| Clap | `ratarmount/src/main.rs` `parse_args_from` ~465–488; `find_cli_error` ~569–584 | Rejects `-w` / exports; requires `PATTERN ARCHIVE` |
| Early exit | `main` ~791–800 | **Before** `factory::build_mount_source_ex` — never wraps `FileVersionLayer` or overlay |
| Query | `ratarmount/src/find.rs` `locate_hits` → `open_index_for_find` → `query_index` | Cold-index via `factory::open_path` if sidecar stale; then `SqliteIndex::search_query` |
| Warm open | `SqliteIndex::open_writable` | Leaves `mem: None` — no SoA in the find process |
| Cold/stale | `find.rs` ~198–217 | `factory::open_path` **does** seal a MemIndex when `n ≤ MEM_INDEX_MAX_FILES` (500k). That peak is **index build**, not locate. **Out of the V-1 RSS bar.** |
| Hit type | `ratarmount-index/src/search.rs` `SearchHit` | `path: String`, `name: String`, scalars. **Never `FileInfo`.** |
| SQL | `search_glob_like` ~210–247 | `SELECT` reconstructed `fullpath` + name/size/mtime/offsetheader. Basename `*.fits` predicates on `"name" GLOB` but still **materializes `fullpath` for every hit**. |
| FTS | `search_fts_match` ~249–279 | `"files_fts" MATCH` + JOIN to `files` on `(name, path, offsetheader)` |
| Compact-only | `search_query` ~112–114 | **`Ok(Vec::new())`** — silent empty |
| Limit | `DEFAULT_SEARCH_LIMIT = 10_000` | `*` on a 200k catalog emits at most 10k strings, not 200k |

`find` does **not** call `list()`, `list_dirents()`, MemIndex, FUSE, or overlay. Existing tests (`find_glob`, `find_flag_*`) assert TSV / clap, not RSS.

### Control `search/<pattern>` and socket `search`

| Surface | Location | Catalog |
|---------|----------|---------|
| Control file | `ratarmount-compositing/src/control.rs` `search_text` → `on_search` callback | Same sidecar SQL as find (`find::tsv_search_callback`) |
| Readdir of `search/` | `control.rs` ~372–374 | **Intentionally empty** (no O(catalog) listing) |
| `lookup` + `open` | `control.rs` ~452–454, 485–487 | **`search_text` runs twice** per `cat` (size then body). V-1 **accepts 2×**. Do not “fix” this by caching a `FileInfo` map. |
| Socket | `ratarmount/src/main.rs` `control_reply` ~2320–2342 | Same callback; TSV + `count N` |
| Wiring | `main.rs` ~1123–1132 | Callback closes over `inputs[0]` + `OpenOptions` only — **no `WriteOverlay`** |
| Status residual | `control.rs` `status_text` ~206–227 | Still calls **`inner.list("/")`** (fat map) to print ≤128 root names. `list_dirents` of the control dir itself does **not**. |
| `fts:` on control | `query_index` honors `fts:` prefix; callback uses `LocateOptions::default()` but still splits `fts:` | Live `scan_glob` is glob-only — see [D5](#d5-search_cheap-hook-and-forwards) |

Missing sidecar / `:memory:` → stable `error: search requires an on-disk index`. Compact-only live mounts therefore search-empty even when SoA is in RAM.

Existing `control_search` tests the **callback**, not `MountSource::search_cheap`. They stay green even if live search is wrong — new tests must pin the live path.

### FTS5

Additive `"files_fts"` (`fullpath`, `hashes`, unindexed path/name/offsetheader). Created only by `ensure_fts5` (find `--fts`), never by cold `create_writable`. `INDEX_VERSION` stays `0.7.0`. Compact-only: `ensure_fts5` is a no-op; `search_query` returns empty. `ensure_fts5` already full-rebuilds the table; do not invent a SoA rebuild.

There is **no** pool-id FTS. Porting MATCH onto `StringPool` is out of V-1.

### `list()` vs `list_dirents()` vs `list_mode()` — no “need FileInfo” flag

**Trait:** `ratarmount-core/src/lib.rs` ~312–347.

| Method | Default | Payload |
|--------|---------|---------|
| `list(path)` | required | `ListResult::Names` or **`Infos(BTreeMap<String, FileInfo>)`** |
| `list_mode` | calls `list()` | names or modes |
| `list_dirents` | calls `list_mode()`, `size = 0` | `CheapDirent { name, mode, size }` |
| `lookup` | required | one `FileInfo` |

**No `ListNeed` type exists.** Default `list_dirents` still fat-materializes on backends that only implement `list()`.

Live readdir is already cheap (FUSE `list_mode_cached`, NFS READDIR, compositing `list_dirents` overrides). Residual name-only `list()` callers: `status_text`, `AutoMount::list_names_no_lazy`. Transform `ensure_map` is a one-time BFS — **out of V-1 must-migrate**.

`FileInfo` carries `linkname: String` + `userdata: Vec<UserData>`. Fat `list("/")` on a 200k flat TAR allocates that per child.

### FileVersionLayer cheap readdir — already done for FUSE

`list_dirents` forwards `inner.list_dirents`; versions-folder synthesizes numbered `CheapDirent`s. Test `file_version_layer_list_dirents_forwards_zip_without_fat_list` asserts `list_calls == 0`.

**Find / sidecar search does not go through FileVersionLayer.** A new `search_cheap` default `None` on the trait **must forward** here. Locate must **not** emit `.versions/*` paths (SQL never did).

### MemIndex / SoA — cheap per directory, no catalog scan API

`StringPool::get(id)` is `&str`. `list_dirents(dir)` still `to_string()` per name. `list(dir)` calls `soa.to_file_info`. **No** public catalog-wide `(path_id, name_id, soa_idx)` scan. No shared glob helper matching SQL `GLOB` (`**` collapse, `/` ⇒ full path, LIKE vs GLOB — `search.rs` ~417–450).

`SqliteIndex` formats that already forward `index.list_dirents` (must all get `search_cheap` — same bar):

TAR, ZIP, 7z, CPIO, AR, WARC, CAB, ISO, ASAR, XAR, libarchive, OGG, HTML, PDF.

### Overlay vs search — F-3 residual

`WriteOverlay::list_dirents` last-wins overlay host over base by name, minus `list_deleted`. Overlay host already holds **creates, COW copies, truncates, replace, rename destinations** (`ensure_modifiable` ~288–322). Tombstones: overlay SQLite `"files"` (`deleted = 1`), keyed by `split(normpath)` → folder `""` or `"/dir"` + name. `is_deleted(path)` uses that split. Commit already `SELECT path, name FROM files WHERE deleted = 1`.

**Neither overlay host nor tombstones are in the archive sidecar until commit.**

`:temp:` is the same `WriteOverlay` type — no extra API.

---

## Goals (this train → V-1 `done`)

1. **Locate never builds `FileInfo`.** Hits are `SearchHit` / `CheapSearchHit`.
2. **SoA / pool-id scan** for live compact / format catalogs (`MemIndex::scan_glob`).
3. **Sidecar SQL find stays streaming SQL.** No MemIndex load for `ratarmount find`.
4. **FTS stays SQL `MATCH`.** `fts:` on control/socket also stays SQL (not `scan_glob`).
5. **`ListNeed`** is shipped as the P0 leftover so name-only walks *can* avoid Infos. **V-1 `done` does not depend on Slice 1 alone.**
6. **Overlay last-wins** on control/socket `-w` mounts: host paths override base hits; tombstones drop; no second fat catalog.
7. **Regression** as [D6](#d6-rss-bar) — synthetic SoA + SQL no-`FileInfo`, not a 200k TAR `find` RSS number.
8. Compact-only **live** search stops returning empty when SoA is present. Compact-only **CLI find** without a sidecar stays empty / “on-disk index.”

**V-1 checkbox rewrite** (impl PR updates `vectorize-steal-patterns.md`):

> CLI find / FTS stay streaming SQL (strings on hits only, no `FileInfo`). Live control/socket / compact-only scan SoA + pool ids. Overlay last-wins on control/socket. `ListNeed` additive.

Do not leave the source checkbox as “find / FTS stay on SoA + pool ids” — that is how implementers unify onto MemIndex.

---

## Decisions (locked for this train)

### D1. Two backends, one hit type

| Backend | When | Scan | Emit |
|---------|------|------|------|
| **SQL sidecar** | CLI `find`; control/socket when live `search_cheap` is `None`; **all `fts:` / `--fts`** | SQLite `files` / `files_fts` cursor | `SearchHit` strings for hits only |
| **Live SoA** | Control/socket when the mount stack returns `Some` from `search_cheap` (glob only) | `path_id` + `name_id` + SoA idx; glob against `pool.get` `&str` | `CheapSearchHit` strings for hits only |

**Do not** unify CLI find onto MemIndex. Warm `open_writable` has `mem: None`. Loading SoA for `ratarmount find` is the explosion D6 forbids.

**Do not** unify FTS onto SoA. Compact-only + `--fts` remains empty/no-op.

### D2. `FileInfo` is not the refine type for locate

Locate refine = path string + TSV scalars. **Never** add `FileInfo` to `SearchHit`. The source-TODO phrase “hydrate FileInfo only on hits” is **rejected** as an impl instruction (sweep 1 #6). `lookup` / `open` stay the getattr/open refine.

### D3. `ListNeed` is additive and is **not** the locate API

Do not change `list()`’s signature.

```rust
pub enum ListNeed {
    Cheap,    // must not *require* FileInfo; see caveat
    FileInfo, // today's list()
}

fn list_with(&self, path: &str, need: ListNeed) -> Option<ListResult> { /* ... */ }
```

**Caveat (default chain):** `list_with(Cheap)` is `list_dirents` as implemented. Default `list_dirents` still derives from `list()`. Un-upgraded backends stay fat. FUSE already requires `list_dirents` overrides. **`ListNeed` does not make search cheap** — search must not call `list()` / `list_with(FileInfo)` at all. Prefer `list_dirents` directly for the two migrations.

**Must migrate (P0 leftover, same PR OK):**

- `ControlFolderMountSource::status_text` → `inner.list_dirents("/")`.
- `AutoMount::list_names_no_lazy` → `src.list_dirents(&rest)` names.

**Out of must-migrate:** `TransformMountSource::ensure_map`; format `list()` impls.

**Slice 1 alone is not V-1 `done`.**

### D4. Overlay merge ownership

CLI `find` keeps rejecting `-w`. Overlay participation is control + socket on a live `-w` mount (`:temp:` included).

#### Semantics (match `list_dirents` last-wins)

Not “creates + tombstones” only:

1. Start from **base hits** (SoA or SQL).
2. Drop any hit whose path `WriteOverlay::is_deleted` (same `split(normpath)` as `mark_deleted` — **not** unslashed `join_rel` commit paths).
3. Walk overlay **host tree** (recursive `read_dir`, skip `HIDDEN_DB` + sqlite sidecars, no symlink escape — reuse `ensure_under_root`). Names that match the glob **override** the base hit with the same full path (COW / truncate / replace / rename-dest / new create). Size/mtime from `symlink_metadata` **on hits only**.
4. Tombstone rows: `SELECT path, name FROM files WHERE deleted = 1` (already used at commit). Apply via `is_deleted` / the same keys. `rmdir` already refuses nonempty — no recursive dir-tombstone hole.

**Do not** build `BTreeMap<String, FileInfo>` of overlay ∪ base.

#### `Option` collision — locked

`search_cheap` → `None` means “not implemented, caller may sidecar.” `Some(v)` means “this is the **full** answer.”

| Layer | Rule |
|-------|------|
| `WriteOverlay::search_cheap` | Return `Some(merged)` **only if** `base.search_cheap` was `Some`. If base is `None`, return **`None`** (do not emit overlay-only as a complete answer). |
| Control / socket SearchFn (`main.rs`) | (1) `outer.search_cheap(pattern)` if `Some` — already merged if overlay implemented it. (2) Else sidecar SQL (today’s callback). (3) If `overlay_arc` is `Some` **and** step 1 was `None`, merge overlay onto the SQL hits **here**. (4) `fts:` / `--fts` → step 2 only (SQL `MATCH`), then step 3 overlay merge. |

This closes overlay names on **Union** and any format that has not yet forwarded `search_cheap` (sidecar + `overlay_arc`). Live SoA + overlay on wired formats goes through `WriteOverlay::search_cheap` (`Some`).

**Residual allowed:** overlay merge on a mount with **no** sidecar and **no** `search_cheap` (compact-only Union, `:memory:`) still errors `search requires an on-disk index` unless a format impl returns `Some`. Document; do not invent a third catalog.

Union-catalog locate (merge all union sources) stays out of v1. Multi-input sidecar remains `inputs[0]`.

### D5. `search_cheap` hook and forwards

`CheapSearchHit` lives in **`ratarmount-core`** (`path`, `name`, `size`, `mtime`, `offsetheader: Option<u64>`). No cycle: core does not depend on index; index depends on core. `SearchHit` stays the SQL type; map for TSV.

```rust
fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
    None
}
```

| Impl | Behavior |
|------|----------|
| Default | `None` |
| **Every `SqliteIndex` format** that already forwards `list_dirents` | One-liner `self.index.search_cheap(pattern)` — **not** “TAR/ZIP/7z at minimum.” List: TAR, ZIP, 7z, CPIO, AR, WARC, CAB, ISO, ASAR, XAR, libarchive, OGG, HTML, PDF. |
| Index | Compact-only / live mem → `MemIndex::scan_glob`. Else SQL `search_query` mapped to `CheapSearchHit` (so `WriteOverlay` gets `Some` on warm sidecar formats too). |
| `WriteOverlay` | [D4](#d4-overlay-merge-ownership) |
| **Every compositing wrapper that forwards `list_dirents` / `content_generation`** | **Must forward `search_cheap`:** FileVersionLayer, Prefix, AutoMount, Transform, Control, `OciImageMountSource`. Default `None` is the P0 `list_dirents` bug class. |
| Union | `None` in v1 (SearchFn uses sidecar of `inputs[0]` + overlay_arc). |
| Folder / remote folder | `None` |

**Hit path identity:** TSV paths are **catalog paths** (same as today’s sidecar), **not** Prefix-rewritten or Transform-rewritten mount paths. Wrappers **forward without rewriting**. Transform/Prefix “forward” is enough **because** we lock catalog paths. (Changing that would be a product change vs current `ratarmount find` / control TSV.)

**AutoMount:** forward to the **parent** catalog only (`root` / `source_at` `/`). Do **not** BFS `mounted` children. Nested compact-only members are invisible to locate today; stay that way.

**FileVersionLayer:** forward; do not emit `.versions/*`.

**`fts:`:** if the pattern strips to FTS (`fts:` prefix or CLI `--fts`), **do not** call `scan_glob`. SQL `MATCH` only, then D4 step 3 overlay merge. Control paths pass the glob through unchanged today (`control.rs` ~196–203) and `query_index` already splits `fts:`.

**Control `search_text`:** prefer `self.inner.search_cheap` when `Some`; else `on_search` / missing-index. Keep `on_search` as sidecar fallback. Control itself **forwards** `search_cheap` to inner so a socket/SearchFn on the outer source does not `None` out.

**Factory:** Slice 3 is `main.rs` SearchFn / `overlay_arc` only. **Do not touch `factory.rs`.**

**Shared glob:** one helper with SQL `GLOB` semantics (`**` → `*`, `/` ⇒ full-path pred, LIKE vs GLOB). Tests twin `search_glob` cases in `search.rs` ~417–450. Do not reuse SMB `glob_match`.

### D6. RSS bar

**Locked meaning:**

> `FileInfo` construction count for locate (`scan_glob` / `search_query` / control TSV) on a 200k-row catalog is **0**. Peak RSS of the **locate phase** stays in the same band as holding that SoA / SQLite page cache, and **far below** `MemIndex::list("/")` / `BTreeMap<String, FileInfo>`.

**Not sufficient:** “find RSS ≤ fat `list()` RSS.”

**Not in the bar:**

- Cold/stale CLI find calling `factory::open_path` (seals MemIndex up to 500k rows). That is index build. Warm sidecar `search_query` is the locate phase.
- A real 200k-member **on-disk TAR** in default CI. Optional script may exist; missing fixture → `eprintln!("skip: …")`. **Do not claim a 200k TAR `find` RSS test exists.**
- Kernel `find "$mount"` in `benchmarks/compare-python-vs-rust.sh` (different command).

**Primary CI:**

1. Synthetic `MemIndex` 200k SoA rows, short interned names, ~1% `*.fits`. `scan_glob`: `to_file_info` count **0**; path `String` count == hit count (or ≤). Fat `list("/")` FileInfo count == N. If a runner is tight, 50k + the same counts — do not skip the happy path.
2. SQL unit: `search_query("*.fits")` never calls `to_file_info` (spy / `mem` stays `None`).
3. Dense-hit case (`*` or many `*.txt`) still 0 `FileInfo` (hit strings may hit `DEFAULT_SEARCH_LIMIT`).

`DEFAULT_SEARCH_LIMIT` stays 10_000.

### D7. SoA `scan_glob` vs SQL `fullpath`

SQL `fullpath` in the SELECT for hits is acceptable. Do not rewrite glob SQL.

`MemIndex::scan_glob`:

- Walk dir shards / `dirs`: `(path_id, name_id, last soa_idx)`.
- Skip `isgenerated` and dumpdir tombstone `linkname_id` (same as `catalog_filter_sql`).
- Basename glob: match `pool.get(name_id)` `&str` — no `String` unless hit.
- Full-path glob: reused buffer from PathTable segments; `clone` into `CheapSearchHit` on match only.
- `DEFAULT_SEARCH_LIMIT`.
- Shared glob helper ([D5](#d5-search_cheap-hook-and-forwards)).

---

## Non-goals (explicit leftovers)

- Transform `ensure_map` fat BFS.
- Union-catalog locate (all sources).
- CLI `find --write-overlay DIR`.
- Compact-only CLI `find` without a sidecar.
- In-memory FTS for compact-only.
- Raising / removing `DEFAULT_SEARCH_LIMIT`.
- Streaming TSV without `Vec<SearchHit>`.
- Caching control `search_text` as a `FileInfo` map (2× scan is accepted).
- Changing `CheapDirent` to hold pool ids.
- Offset-order find (V-5).
- Prefix/Transform rewriting locate paths to mount paths.
- AutoMount nested-child locate.

---

## Implementation train

Ownership: **index + core + compositing + format one-liners + `main.rs` SearchFn**. Orchestrator owns `factory.rs` — **this train does not edit it.**

### Slice 1 — `ListNeed` + name-only `list()` leftovers (not V-1 done)

**Files:** `ratarmount-core/src/lib.rs`; `control.rs` `status_text`; `automount.rs` `list_names_no_lazy`.

- Add `ListNeed`, `CheapSearchHit`, `list_with`, `search_cheap` default `None`.
- Counted-`list()` tests for status and AutoMount names.

### Slice 2 — SoA `scan_glob` + **all** SqliteIndex format forwards

**Files:** `ratarmount-index/src/mem.rs`; `search.rs` (shared glob + SQL map); **every** format crate listed in [D5](#d5-search_cheap-hook-and-forwards); compositing forwards (FileVersionLayer, Prefix, AutoMount, Transform, Control, OCI).

- 200k synthetic SoA: `to_file_info == 0`.
- Compact-only `scan_glob("*.fits")` hits.
- Glob twin tests vs `search_glob`.
- `search_query` compact-only still empty for SQL/CLI.
- `file_version_layer_search_cheap_forwards_without_list`; Transform/Prefix/Control/OCI forward tests; no `.versions` hits.

### Slice 3 — Overlay last-wins + control/socket SearchFn

**Files:** `write_overlay.rs`; `control.rs`; **`ratarmount/src/main.rs` only** (SearchFn + `overlay_arc`).

- `WriteOverlay::search_cheap` per [D4](#d4-overlay-merge-ownership).
- Tests: create visible; tombstone hidden; **COW/replace overrides size/mtime** (no duplicate TSV); `WriteOverlay` + base `None` → `None` (SearchFn sidecar + overlay_arc still merges); `fts:` still SQL; compact-only **control** TSV (not only `MemIndex::scan_glob`).
- Existing `find_glob` / `control_search` / `control_search_socket` / `search_fts5` stay green.
- CLI `find` + `-w` still rejected.

### Slice 4 — Docs + catalog row (same commit as behavior)

- `vectorize-steal-patterns.md` V-1: **rewritten checkbox** (SQL find + live SoA), not a silent `[x]` on the old wording.
- `beyond-parity-roadmap.md` F-3: overlay last-wins on control/socket; CLI find sidecar-only; Union live SoA residual.
- `vectors-optimization.md` P0: `ListNeed` note.
- `AGENTS.md` catalog row.
- README: one line if `-w` control search is advertised.

No `docs/embedded-nested-archives.md`.

---

## Risks and fail-closed rules

| Risk | Rule |
|------|------|
| Unify find onto MemIndex | Forbidden (D1). Warm find must keep `mem: None`. |
| `search_cheap` `Some` overlay-only when base is `None` | Forbidden (D4). Drops the catalog. |
| `search_cheap` `None` whenever overlay exists | Overlay never appears on unwired formats unless SearchFn step 3 runs. |
| Forgotten wrapper forward | Same as P0 `list_dirents`; tests on Transform, Prefix, Control, OCI, FileVersionLayer, AutoMount (parent only). |
| Overlay `overlay_file_info` for every host file | Hits only. |
| Host symlink escape | Reuse `ensure_under_root` / existing overlay escape tests. |
| Tombstone key mismatch | `is_deleted(hit.path)` / `split(normpath)`, not `join_rel`. |
| Control `search/` readdir lists the catalog | Keep empty. |
| `fts:` through `scan_glob` | Forbidden (D5). |
| Cache search as `FileInfo` map | Forbidden. 2× `search_text` is accepted. |
| `list_with(Cheap)` as “V-1 done” | Slice 1 is P0 leftover only. |
| Claim 200k TAR `find` RSS test | Do not. Synthetic + SQL spy only. |
| Touch `factory.rs` | Forbidden. |
| SMB `glob_match` | Wrong semantics. Shared SQL-GLOB helper. |
| 200k synthetic OOM | Drop to 50k; keep FileInfo-count assert; no silent skip. |

---

## Verification

Every behavior change lands with tests in the **same** PR. Name/doc `Regression:` + symptom.

| Symptom / claim | Command / test |
|-----------------|----------------|
| SoA scan does not build `FileInfo` | `cargo test -p ratarmount-index --lib scan_glob` (200k or 50k synthetic; `to_file_info` count 0) |
| SQL locate does not build `FileInfo` | `cargo test -p ratarmount-index --lib search_query` / spy `mem.is_none()` |
| Glob SoA == SQL GLOB | twin cases vs `search_glob` |
| Compact-only live locate | `scan_glob_compact` + compositing control TSV |
| CLI find still SQL / no `-w` | `cargo test -p ratarmount --bin ratarmount find_glob` · `find_flag` |
| FTS unchanged; `fts:` not SoA | `cargo test -p ratarmount-index --lib search_fts5` + new control `fts:` test |
| Control / socket TSV (callback) | `control_search` · `control_search_socket` (keep green; **not** sufficient) |
| Live `search_cheap` + overlay last-wins | `cargo test -p ratarmount-compositing --lib search_cheap` (create, tombstone, COW/replace, base `None`) |
| Wrapper forwards without `list()` | FileVersionLayer + Transform + Prefix + Control + OCI + AutoMount parent-only |
| No `.versions` hits | FileVersionLayer search test |
| `status` / AutoMount names | counted-`list()` tests |
| Cheap readdir still cheap | `list_dirents` · `file_version_layer_list_dirents` |
| Optional on-disk 200k | script + `skip:` if missing; **not** a silent pass; **not** advertised as the V-1 bar |

**New `AGENTS.md` row** (impl PR, not this plan PR):

| Symptom / fix | Commands |
|---------------|----------|
| Locate fat `FileInfo` on large catalog; overlay last-wins missing on control search | `cargo test -p ratarmount-index --lib scan_glob` · `cargo test -p ratarmount-compositing --lib search_cheap` · `find_glob` · `control_search` · `search_fts5` |

Gates: `cargo fmt --all` · `cargo clippy --workspace --all-targets -- -D warnings` · scoped tests, then `cargo test --workspace` if cross-crate.

---

## Docs delta (impl PR)

| Doc | Change |
|-----|--------|
| `docs/tasks/vectorize-steal-patterns.md` | **Rewrite** V-1 boxes (SQL find + live SoA); do not `[x]` the old SoA-for-find wording |
| `docs/tasks/beyond-parity-roadmap.md` | F-3 overlay last-wins on control/socket |
| `docs/tasks/vectors-optimization.md` | P0 `ListNeed` note |
| `AGENTS.md` | catalog row |
| `README.md` | only if `-w` control search is advertised |

This **plan** file is not user-facing product docs.

---

## Suggested impl order

1. Slice 2 (SoA scan + all format + wrapper forwards + FileInfo-count). **This is the density win.**
2. Slice 3 (overlay last-wins + SearchFn). **This is the F-3 residual.**
3. Slice 1 (`ListNeed` + status/AutoMount) — same PR OK, not sufficient for `done`.
4. Slice 4 (docs + AGENTS.md + checkbox rewrite).

---

## Skeptic review log

| Sweep | Agent | Verdict | Folded |
|-------|-------|---------|--------|
| 0 | author (pre-review) | draft | — |
| 1 | fresh Task (2026-08-28) | **REVISE** | All 4 blockers + importants 5–15. D4 `Option` collision + SearchFn step 3; overlay last-wins (COW/replace); all SqliteIndex formats; all list_dirents wrappers forward; V-1 checkbox rewrite; `ListNeed` ≠ locate done; AutoMount parent-only; `fts:` stays SQL; RSS bar excludes cold-index and 200k TAR claim; accept 2× `search_text`; tombstone keys via `is_deleted`; shared GLOB helper; no `factory.rs`. |

Sweeps 2–3: **fresh** skeptic Task (never reuse sweep-1 context). Cap 3 then BLOCKED.
