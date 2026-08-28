# Plan: P2 SQLite bulk-insert staging (SoA / batch binds)

| Field | Value |
|-------|--------|
| **Status** | Sweep 1 folded (BLOCKED → plan patched); pending sweep 2 |
| **Date** | 2026-08-28 |
| **Backlog** | [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md) P2 “SQLite bulk insert staging” |
| **Scope** | Path TAR / ZIP / 7z **cold** index build: stage rows as SoA and bind from columns into the existing `insert_files_batch` SQL |
| **Out of this train** | On-disk `files` schema change; `filestmp`; `INDEX_VERSION` bump; MemIndex / `EntrySoa` live layout; warm SQL reload; other format crates; xattr batches; true SIMD |
| **Workspace** | `ratarmount-index` owns the staging type + bind helper; `ratarmount-formats-{tar,zip,sevenzip}` switch their 512-row (or 1-row) `FileRow` windows |

This document is an implementation plan. **Do not treat it as done work.**

---

## Verdict (read this first)

**Implement a flush-window `FileRowSoa` in `ratarmount-index`, bind the existing single-row `INSERT OR REPLACE` from its columns, and point TAR / ZIP / 7z cold builders at it.** Keep `FileRow` + `insert_files_batch(&[FileRow])` as the compatibility API.

This train **does not** shrink the dominant cold-build RSS (SQLite `files` TEXT pages + sealed `MemIndex`). That dual store is the P0 residual (“SQLite `files` table shape stays unchanged”). P2 only cuts the **AoS window** sitting in front of `insert_files_batch` and stops ZIP from allocating a one-row `FileRow` per member / generated parent.

If a later change wants lower *end-of-build* RSS, that is a different item: interned / columnar on-disk `files` (explicitly forbidden here).

---

## Goals

1. Stage the TAR / ZIP / 7z cold-build flush window as **structure-of-arrays** (interned `path` / `name` / `linkname` + parallel numeric columns, **including `typeflag`**).
2. Bind SQLite from those columns. **Do not** change `create-index-tables.sql` / `INDEX_VERSION` / the `files` PRIMARY KEY.
3. Peak that changes is **only** the in-process window during build (plus ZIP’s current 1-row `insert_file` chatter). On-disk bytes and warm remount SQL stay 0.7.x.
4. Preserve every insert invariant listed under [Invariants](#invariants-do-not-break).
5. Land automated tests in the same implementation commit (AGENTS.md “Tests for every fix”).

## Non-goals

| Non-goal | Why |
|----------|-----|
| Change `files` columns, PK, or `INDEX_VERSION` | P0 residual; Python 0.7.x sidecar contract |
| Start using unused `filestmp` / `parentfolders` | Schema-adjacent; `into_read_only` already `DROP`s both; Python never inserted into `filestmp` |
| Reuse live `EntrySoa` as the SQL buffer | No `typeflag` column; empty-name rows are dropped; REPLACE is in-place by SoA index |
| Defer all SQL until `seal_mem_index` | End-of-build peak still dual-stores; couples bind to builder REPLACE / empty-name skip |
| Multi-row `VALUES (…),(…)` SQL | Unproven vs prepared `executemany` inside `BEGIN IMMEDIATE`; `512 × 15 = 7680` binds is legal on bundled SQLite but is a follow-up, not this train |
| Rewrite CPIO / AR / WARC / ASAR / ISO / … | Backlog says path TAR / ZIP / 7z. ASAR already flushes `Vec<FileRow>` chunks; others still `insert_file` |
| Warm `load_mem_index` `SqlMemRow` spike | P0 residual; not a cold-build staging bug |
| Xattr batch SoA | Separate table; not `insert_files_batch` |
| Claim a large-TAR RSS win without a bench | Dominant pages are SQLite TEXT + MemIndex, which this plan must not touch |

---

## Background (what the code does today)

Cold path mounts call `SqliteIndex::create_writable` / `create_writable_for_open`. That starts a `MemIndexBuilder` (string pool + `EntrySoa` + dir map). Each insert does **two** things:

1. **SQLite** (unless `compact_only`): prepared

   ```sql
   INSERT OR REPLACE INTO "files"
   (path, name, offsetheader, offset, size, mtime, mode, type, linkname,
    uid, gid, istar, issparse, isgenerated, recursiondepth)
   VALUES (?1,…,?15)
   ```

   inside caller `BEGIN IMMEDIATE` … `COMMIT` (`docs/cold-index-and-sparse.md`).
2. **MemIndexBuilder::push_rows**: intern path/name/link, SoA push or REPLACE on `(path_id, name_id, offsetheader)`. **Skips empty `name`.**

`into_read_only` seals the builder when `count > 0 && count <= MEM_INDEX_MAX_FILES` (500_000), or always when `compact_only`.

### Who stages `FileRow` today

| Caller | Staging | Flush |
|--------|---------|-------|
| TAR `parse_tar_from` / `flatten_nested_tars` | `Vec<FileRow>` cap 512 | `insert_files_batch` |
| TAR `ensure_parent_dirs` / dumpdir / dumpdir tombstones | push onto that `Vec` | same |
| 7z cold build | `Vec<FileRow>` | flush at 512 |
| 7z `ensure_parent_dirs` | push onto that `Vec` | same |
| ZIP `create_index` | **no window** — `insert_file` per member | 1-row `FileRow` each time |
| ZIP `ensure_parent_dirs` | `insert_file` per missing parent | 1-row |
| `insert_file` itself | builds one `FileRow` then `insert_files_batch(&[row])` | — |
| `patch.rs` / `search.rs` / index unit tests | `&[FileRow]` | keep this API |
| Other format crates | `insert_file` or ASAR chunked `FileRow` | **out of scope** |

`FileRow` is three owned `String`s (`path`, `name`, `linkname`) plus scalars. `FileRow::new` takes `impl Into<String>`, so even `&str` becomes an owned copy before bind.

### Why `EntrySoa` is the wrong SQL staging type

`EntrySoa` (`ratarmount-index/src/mem.rs`) has `offsetheader`, `offset`, `size`, `mtime`, `mode`, `linkname_id`, `uid`, `gid`, flags, `recursiondepth`. It does **not** store:

- **`typeflag`** — written to SQL `type`. TAR stores ustar type (`'5'`, `'S'`, `'D'`, …). ZIP stores **compression method** in that column (`0` store / `8` deflate). `FileInfo` / MemIndex **ignore** `type` on read (ZIP open uses `ZipMemberTable`), but the sidecar must still match Python 0.7.x.
- **Empty-name rows** — `push_row` returns early; SQL today still inserts them if a caller passes one.
- **Path/name as bindable text** — only pool ids + `PathTable`. Reconstructing TEXT at flush is fine, but REPLACE-in-place means “last 512 builder rows” is not a stable SQL window when a later row hits the same PK.

So: **new build-only SoA**, not a reuse of live `EntrySoa`.

### Honest peak picture

For a path mount of *N* members (example *N* = 200k):

| Live at once | Scale | This train? |
|--------------|-------|-------------|
| SQLite `files` TEXT pages (path/name/link **per row**) | *O(N)* | **No** — P0 residual |
| `MemIndexBuilder` SoA + pool + `by_key_oh` | *O(N)* | **No** — already SoA |
| TAR/7z `Vec<FileRow>` | *O(512)* owned strings | **Yes** — replace with interned columns |
| ZIP per-member `FileRow` + per-parent `insert_file` | *O(1)* alloc × *N* round-trips | **Yes** — 512 window + batched parents |
| TAR `generated_dirs: BTreeSet<String>` | *O(unique dirs)* | Residual (not `insert_files_batch`) |
| TAR `xattr_batch` | *O(512)* | Out of scope |

A 512-row `FileRow` window is typically hundreds of KiB, not tens of MiB. **Do not** advertise this as a large-TAR RSS fix. The user-visible wins are: (1) ZIP wall time from 1-row inserts → 512, (2) no triple-owned prefix strings in the TAR/7z window, (3) a single bind helper that cannot drift `typeflag` / REPLACE / empty-name behavior.

---

## Design

```mermaid
flowchart LR
  subgraph formats [TAR / ZIP / 7z cold parse]
    P[parsed member]
    W[FileRowSoa window cap 512]
    P --> W
  end
  subgraph index [ratarmount-index]
    B[insert_files_batch_soa]
    SQL["INSERT OR REPLACE files"]
    M[MemIndexBuilder.push_from_soa]
    B --> SQL
    B --> M
  end
  W -->|flush| B
  FileRow["insert_files_batch(&[FileRow])"] --> B
```

### New type: `FileRowSoa` (build-only, `ratarmount-index`)

Parallel columns matching `FileRow` **exactly** (so a round-trip test is mechanical):

| Column | Type | Notes |
|--------|------|-------|
| `path_id` / `name_id` / `linkname_id` | `Vec<u32>` | ids into a **window-local** `StringPool` (same intern rules as `MemIndexBuilder`, including `""` → 0) |
| `offsetheader`, `offset`, `size`, `mtime`, `mode`, `typeflag`, `uid`, `gid`, `recursiondepth` | existing `FileRow` widths | `typeflag` is first-class — this is why we do not use `EntrySoa` |
| `istar`, `issparse`, `isgenerated` | `Vec<u8>` flags or three `Vec<bool>` | match today’s SQL `0`/`1` |

API shape (names can move; behavior cannot):

- `FileRowSoa::with_capacity(512)`
- `push(...)` / `push_file_row(&FileRow)` — formats and the compat wrapper
- `len` / `clear` / `is_empty`
- **`clear` (and every flush) must drop or reset the window `StringPool` and all column vecs.** The SoA object lives for the whole `parse_tar_from` / 7z / ZIP loop. If the pool survives flush, interned TEXT becomes *O(unique strings in the archive)* — a second copy next to `MemIndexBuilder`, which violates the *O(512)* peak claim.
- `intern` is internal; callers pass `&str` (ZIP already has `intern_during_build` for sidecar `Arc` — that path stays; it is a **different** pool)

Window intern is **full path/name/linkname TEXT** in a `StringPool` (same string → same id), **not** MemIndex `PathTable` segment chains. The intern unit test asserts “same full path string → same `path_id`”, not prefix-segment sharing.

Window pool is **not** the `MemIndexBuilder` pool. Double-intern on flush is *O(unique strings in this 512-row window)* and keeps REPLACE / empty-name / compact_only logic in one function. Sharing the builder pool is possible (`intern_during_build` already locks per call) but is rejected in this train to avoid a push-by-id API and a second lifetime tying formats to `mem_builder`.

### Bind helper: one function, two entry points

Keep:

```text
SqliteIndex::insert_files_batch(&[FileRow]) -> Result<()>
SqliteIndex::insert_file(...)                 // still 1-row FileRow for other crates
```

Add:

```text
SqliteIndex::insert_files_batch_soa(&FileRowSoa) -> Result<()>
```

`insert_files_batch` becomes a thin wrapper: copy `&[FileRow]` into a stack `FileRowSoa` (or bind FileRow fields directly — **same SQL loop**, so tests that only see SQL cannot tell). Prefer: wrapper builds a temporary `FileRowSoa` **only if** we want one bind loop. Cheaper compat path: existing FileRow loop stays, SoA loop is the new one, both call a private `bind_files_row(stmt, path, name, …)` so the 15 binds cannot drift.

SQL statement **unchanged** (prepared, cached, single-row `INSERT OR REPLACE`). Still skip the SQL loop when `compact_only`. Still `push` into `MemIndexBuilder` when present (`open_writable` has `mem_builder = None` — SQL only; preserve that).

MemIndex feed from SoA: `MemIndexBuilder::push_soa_row` or reconstruct a short-lived `FileRow` **one at a time** from `pool.get(id)` for `push_row`. Reconstructing one `FileRow` per row at flush is acceptable (peak is one row, not 512). Prefer `push_row` reuse so REPLACE / empty-name skip stay in one place.

### Format wiring

**TAR** — every `Vec<FileRow>` on the cold/incremental parse path becomes `FileRowSoa`:

- `parse_tar_from`
- `flatten_nested_tars`
- `walk_tar_region` (today: `batch: &mut Vec<FileRow>`)
- `push_entry` (not `push_member`)
- `push_dumpdir_entries`
- `apply_dumpdir_deletes`
- `ensure_parent_dirs`
- `push_nested_member_as_directory` (`offsetheader+1`, `type = b'5'`)

`BATCH_FLUSH = 512` stays. Xattr batch stays `Vec<(i64, String, Vec<u8>)>`. Incremental `SqliteIndexedTar::patch_index_from` reuses `parse_tar_from` (often on `open_writable`, builder `None`) — same SoA window, SQL-only feed.

**7z** — `create_index_from_reader` (path + reader): same window type; `ensure_parent_dirs` pushes into the SoA. Member and parent `typeflag` stay `0`.

**ZIP** — insert loop is `fill_index_from_archive` (called from private `create_index` and `open_from_reader`). Introduce the same 512 window. `ensure_parent_dirs` **must** push generated parents into the window (not `insert_file`). Flush before `commit_write`. `intern_during_build` for `ZipMemberMeta.name` is unchanged (sidecar `Arc` identity). SQL `type` is the ZIP method: `0` stored, `8` deflate, **`0xffff` other** — not only 0/8.

### Rejected alternatives

| Idea | Reject |
|------|--------|
| Bind from `MemIndexBuilder` at seal only | Empty-name SQL rows vanish; `typeflag` missing; incremental `INSERT OR REPLACE` during parse goes away; end peak unchanged |
| Reuse `EntrySoa` + sidecar `typeflag` vec | Still missing empty-name; REPLACE index ≠ SQL window; formats should not poke `mem` internals |
| Multi-row `INSERT` | Follow-up if a bench on 200k ZIP beats prepared loop; not required to close P2 |
| Intern into `MemIndexBuilder` pool from formats | Mutex across parse; ZIP/7z already call `intern_during_build` for sidecars only |
| Change `FileRow` fields to `Arc<str>` | Still AoS; still 512 fat structs; does not teach the bind path columns |

---

## Invariants (do not break)

1. **On-disk `files` shape** — `create-index-tables.sql` untouched. `INDEX_VERSION` stays `"0.7.0"`.
2. **`INSERT OR REPLACE` PK** `(path, name, offsetheader)` — dumpdir dual rows (`oh`, `oh+1`), tombstones (`oh+2+i`), nested-as-directory higher `offsetheader`, incremental TAR updates.
3. **Empty `name`**: SQL insert still happens if the caller staged one; `MemIndexBuilder::push_row` still skips. Do not “clean up” this split.
4. **`compact_only`**: no `files` writes; builder still receives rows; `files_table_row_count() == 0`.
5. **`open_writable`**: `mem_builder` is `None`; SoA insert is SQL-only (content-hash / side-table writers).
6. **`typeflag` / SQL `type`**: TAR `'S'` / `'D'` / `'5'` / regular; ZIP method `0`/`8`; generated parents TAR `b'5' as i64`, ZIP/7z `0` — **byte-identical** to today.
7. **Generated parents**: `offsetheader=0`, `isgenerated=true`, `generated_dirs` still prevents duplicates. ZIP parents stay 1:1 with today’s `insert_file` rows (only the flush grouping changes).
8. **NULL `offsetheader`**: still not expressible via `FileRow` / SoA (raw SQL test `regression_null_offsetheader_rows_still_list` stays).
9. **Python completeness**: `into_read_only` still `DROP`s `filestmp` / `parentfolders`. Do not insert into them.
10. **Warm remount / tarstats**: same TEXT rows → same `load_mem_index` / `check_tarstats`.

---

## Implementation steps (when someone implements)

Ownership: **orchestrator or a single agent** — `ratarmount-index` first, then the three format crates. Do not parallelize `FileRowSoa` vs TAR helpers (the batch type is the shared API).

1. **`ratarmount-index`**: add `FileRowSoa` + `insert_files_batch_soa` + private bind helper. `insert_files_batch(&[FileRow])` keeps working (tests / patch / search / other formats).
2. **Unit tests in `ratarmount-index`** (lowest layer — required):
   - **Regression:** SoA flush of *N* rows equals `insert_files_batch(&[FileRow])` for the same inputs: every `files` column including `type`, REPLACE on duplicate PK, empty-name SQL row + MemIndex skip, `compact_only` writes zero SQL rows.
   - Intern: two rows with the **same full path string** share one `path_id` (not “shared prefix segments”).
   - `open_writable` + SoA insert does not require a builder.
   - **`FileRowSoa::clear` / post-flush:** pool unique count returns to `{""}` (id 0 only); a later push of a new path must not retain ids from the previous window.
   - **Raw SQL `type` helper:** add a small public (or `cfg(test)` + re-export) `SqliteIndex` reader such as `sql_files_type(path, name, offsetheader) -> Result<Option<i64>>`. `with_conn` is `pub(crate)`; format crates cannot SELECT today. `FileInfo` / `list` / `lookup` / MemIndex **ignore** SQL `type` (`row_to_file_info` skips column 7; `file_info_from_named_row` skips column 6; `load_mem_index` never stores it). Existing format tests that only `list`/`lookup` **cannot** catch `typeflag=0` wiring bugs.
3. **TAR format-layer `type` tests (required — not optional):** after a real cold `parse_tar_from` / `create_index`, `SELECT`/`sql_files_type` must see:
   - GNU sparse member `type = b'S' as i64`
   - dumpdir rows `type = b'D' as i64` (reg at `oh` and dir at `oh+1`)
   - generated parent `type = b'5' as i64`, `isgenerated=1`, `offsetheader=0`
   - nested-as-directory row `type = b'5' as i64` at `offsetheader+1` when flatten runs  
   Existing `pax_size_keyword` / dumpdir / flatten / incremental tests stay as the catalog net; they are **not** sufficient for `type`.
4. **ZIP format-layer `type` tests (required):** fixture with **at least one Deflate member** (`type = 8`) plus generated parents (`type = 0`, `isgenerated`). A Stored-only zip (`write_sample_zip` today) is `type=0` for members **and** parents — identical to a dropped typeflag. Also assert one `0xffff` other-method row if cheap (or document as residual and still lock 8 vs 0). Visible catalog after `commit_write`: same PK set as today’s `insert_file` path (INSERT order inside the transaction may change).
5. **7z**: switch the window. Encrypted metadata-only / wrong-password tests stay. Add a cheap `sql_files_type` assert that a regular member and a generated parent are both `0` (locks “we still write the column”).
6. **Docs in the implementation commit**:
   - Tick the P2 checkbox in [`vectors-optimization.md`](../vectors-optimization.md); keep the P0 residual sentence.
   - One line in [`docs/cold-index-and-sparse.md`](../../cold-index-and-sparse.md) that the 512 flush is SoA binds, not `Vec<FileRow>`.
   - AGENTS.md regression catalog row (see below).
   - **No** `embedded-nested-archives.md` change (nested live model unchanged). README feature tables unchanged (no user-facing flag).
7. Gates: `cargo fmt --all` then scoped clippy/test on `ratarmount-index` + the three format crates, then workspace clippy/test before merge.

### AGENTS.md catalog row (implementation commit)

| Symptom / fix | Commands |
|---------------|----------|
| SQLite bulk insert SoA window (P2) | `cargo test -p ratarmount-index --lib insert_files_batch_soa` · `cargo test -p ratarmount-index --lib sql_files_type` · `cargo test -p ratarmount-formats-tar --lib` (new `type` SELECT + dumpdir / flatten) · `cargo test -p ratarmount-formats-zip --lib` (Deflate `type=8`) · `cargo test -p ratarmount-formats-sevenzip --lib` |

Name the new index test with `Regression:` and the symptom (“fat `FileRow` window / ZIP 1-row insert”).

---

## Suggested test sketch (implementer)

```text
// ratarmount-index — lowest layer
fn regression_soa_batch_matches_file_row_sql_and_replace() {
    // A: insert_files_batch(&[FileRow × 3]) including
    //    - shared path prefix
    //    - typeflag 8 (ZIP method)
    //    - empty name
    //    - duplicate (path,name,offsetheader) REPLACE
    // B: FileRowSoa with the same logical rows
    // Assert: SELECT * FROM files ORDER BY path,name,offsetheader is identical.
    // Assert: MemIndex skips empty name; REPLACE updated size/mtime.
}

fn regression_soa_compact_only_skips_sql() { ... }

fn soa_interns_identical_full_path_ids() { ... }

fn regression_soa_clear_drops_window_pool() { ... }
```

ZIP crate: fixture with `a/b/stored.txt` (method 0) **and** `a/b/def.txt` (method 8 / Deflate) → `sql_files_type` (not `FileInfo`) must be `8` for the Deflate member and `0` for generated `a/` / `a/b/` (`isgenerated`). Stored-only fixtures cannot catch a dropped typeflag.

TAR crate: sparse `'S'`, dumpdir `'D'`, generated parent `'5'` via the same helper after a real index build (not a hand-built `FileRowSoa`).

Do **not** add a CI RSS gate. Optional local note in the implementation PR: 512-window FileRow vs SoA on a 200k synthetic insert (index crate only). Large-TAR RSS vs Python stays the P0 dual-store problem.

---

## Residuals after this train

- SQLite `files` still stores full TEXT path/name/linkname (P0).
- Warm open still materializes `SqlMemRow` strings into `MemIndexBuilder`.
- Other formats still `insert_file` / ASAR `Vec<FileRow>`.
- TAR `generated_dirs` / xattr batches still AoS.
- `EntrySoa` still has no `typeflag` (live MemIndex does not need it).
- Multi-row SQL `VALUES` not done.
- Nested compact-only already skips SQL; SoA window is optional there (still worth it so TAR flatten / nested 7z/ZIP builders share one type).

---

## Skeptic-plan-review log

Process: sweep 1 required; each sweep a **fresh** skeptic; fold blockers; cap 3 then BLOCKED. Stop at ACCEPT or BLOCKED.

| Sweep | Result | Folded |
|-------|--------|--------|
| 1 | **BLOCKED** — format-layer tests as written cannot observe SQL `type` (`FileInfo` / MemIndex drop it; Stored-only ZIP is `type=0` for members and parents) | Required TAR/ZIP/7z `sql_files_type` asserts; `SqliteIndex` raw `type` helper (`with_conn` is `pub(crate)`); `FileRowSoa::clear` resets pool; TAR symbols `push_entry` / `walk_tar_region`; ZIP loop is `fill_index_from_archive`; method `0xffff`; intern test = full-string id; mutex-coupling nit |
| 2 | *(pending)* | |
| 3 | *(pending)* | |

---

## Related

- Backlog: [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md) P0 residual + P2 item
- Cold-index history: [`docs/cold-index-and-sparse.md`](../../cold-index-and-sparse.md)
- Code: `ratarmount-index/src/lib.rs` (`insert_files_batch`, `FileRow`, `seal_mem_index`), `ratarmount-index/src/mem.rs` (`MemIndexBuilder`, `EntrySoa`), TAR/ZIP/7z cold builders
- Schema: `ratarmount-index/create-index-tables.sql` (**do not edit**)
