# V-5 — Offset-order locality (plan)

| Field | Value |
|-------|--------|
| **Item** | [`vectorize-steal-patterns.md`](../vectorize-steal-patterns.md) **V-5** (todo, S–M) |
| **Date** | 2026-08-28 |
| **Status** | **Implemented** (v1; SHA `b629e07`) |
| **Implements** | Opt-in catalog / locate order by `offsetheader` so sequential readers hit nearby archive bytes |
| **Does not implement** | k-means, IVF centroid files, ANN, cosine clustering, default `ls` sort change |
| **Ownership** | `ratarmount-index` + `ratarmount` find CLI. TAR crate for the seek-count + dumpdir regressions. **Do not** change `factory.rs` glue. |
| **Skeptic** | Sweep results appended at the end of this file |

This is an implementation plan, not the implementation. Stop at ACCEPT or BLOCKED.

---

## 1. Problem

Vectorize clusters nearby embeddings so a query opens a handful of objects. For an archive, “nearby” is **byte offset**, not cosine.

Today sequential consumers walk **path / name order**:

- `ratarmount find` / control `search` SQL is `ORDER BY fullpath, "offsetheader"` then `LIMIT` (`DEFAULT_SEARCH_LIMIT` = 10_000).
- Cheap readdir for the SQL fallback collapses into `BTreeMap<String, IndexDirent>` and returns **lexicographic name order**.
- MemIndex `list_dirents` walks `BTreeMap<u32, Vec<u32>>` (**interned name-id order**, not UTF-8) and keeps `versions.last()` (newest). Intern-id equals **insert/parse order** on the builder / `insert_files_batch` → `into_read_only` path. Warm remount via `load_mem_index` interns in `ORDER BY path, name, offsetheader` — that path is already UTF-8. Do not claim typical remount `ls -f` is pack order. Changing mem iteration to UTF-8 still changes builder / compact-only `ls -f`; that remains out of scope.
- GNU `ls` sorts names itself. `ls -f`, `find` over a mount, and `cp -R` follow FUSE readdir order (`list_dirents` as-is).
- NFSv3/v4 readdir **re-sorts children by fileid**. Fileids are assigned lazily on first visit (`id_for_path`). The first readdir **with no prior child LOOKUPs** therefore allocates sequential fileids in `list_dirents` order, then sorts those ids — so that listing **is** `list_dirents` order. A LOOKUP of `z` before READDIR already breaks that. Changing default `list_dirents` **would** change first-NFS-readdir-with-no-prior-child-ids. Do not treat NFS as immune.
- FUSE `--readahead` amortizes short reads **inside one open member**, not across readdir.

On HDD and on remote Range GET (V-3), a name-order restore of a TAR whose members were appended, concatenated, or packed in ZIP local-header / 7z pack order pays backward seeks / extra GETs.

---

## 2. Goals / non-goals

### Goals (v1)

1. **Opt-in** listing and locate by `files.offsetheader` (NULL last, never coalesced to 0).
2. Default **name order for `ls`** stays: do not change default `MountSource::list_dirents`, FUSE `readdir` / `readdirplus`, NFS readdir, overlay/union merge, or FileVersionLayer forwarding.
3. `find` output option for restore pipelines (`--offset-order`, find-argv only). Membership and `LIMIT` stay **exactly** today’s query; the flag only re-sorts that `Vec` (§4.3).
4. Two index helpers, both **v1** (V-5 “optional list_dirents / extract helper” means opt-in, not skip):
   - Per-directory `list_dirents_ordered(..., OffsetHeader)` = sort of today’s newest-wins `list_dirents` set.
   - Flatten `list_visible_files_by_offset` for sequential open of the **mounted** tree (newest-wins, dumpdir-aware). The seek-count regression uses this helper.
5. Document that F-9 `--repack-seekable` (still `todo`) must keep members in existing archive order. This plan PR already points F-9 here; the implementation PR only flips V-5 boxes.
6. Keep `regression_null_offsetheader` green; foreign indexes with NULL `offsetheader` must still cheap-readdir and warm-seal.

`find --offset-order` and `list_visible_files_by_offset` are **different sets**. A unique-name fixture makes them agree; GNU incremental / multi-version archives do not (find emits every catalog version; flatten emits the mount-visible winner only).

### Non-goals

| Item | Why |
|------|-----|
| k-means / IVF / PQ / ANN | Spec ban; members are not \(\mathbb{R}^{D}\) |
| Split the 0.7.x `files` table into centroid files | One SQLite blob stays |
| Default FUSE/NFS readdir in offset order | User-visible `ls -f`; FUSE cookies are listing **index**; first NFS readdir follows `list_dirents` via lazy fileids (§1). Residual §9.1 |
| Add `offsetheader` to [`CheapDirent`](../../../ratarmount-core/src/lib.rs) | Every constructor + FUSE dir_cache would grow; unused on the default path |
| `MountSource` trait change | Cascades through every format + compositing + NFS/FUSE mock |
| Mount flag `--readdir-order=offset` in v1 | Residual §9.1 |
| Control `search/<pattern>` / socket TSV order change | Path-component API has no query string; `LocateOptions::default()` / `SearchQuery::glob` keep `offset_order = false`. Residual §9.2 |
| Newest-wins collapse of `find` hits | Find already returns every non-generated, non-tombstone catalog row (multiple versions of one path). Offset order **re-sorts that set**; it does not change membership or LIMIT |
| Changing MemIndex intern-id readdir order to UTF-8 | Out of scope; would change FUSE `ls -f` on warm (sealed) mounts |
| ZIP/7z seek-count regressions in v1 | TAR-only for the fake-reader test. 7z shared-pack tie-break is documented, not a v1 crate test |

---

## 3. Current code (investigation)

### 3.1 `offsetheader` column

- TAR: uncompressed header start. Newest version of a name has the **highest** `offsetheader` (append / GNU incremental). SQL `lookup(..., 0)` is `ORDER BY offsetheader DESC`.
- ZIP: local-header / CD offset (`headers` already sorted; binary search).
- 7z: pack offset (`entry_by_offsets` is sorted keys + binary search). Solid members can **share** a pack offset — ties are fine; stable name tie-break. Not a v1 ZIP/7z test.
- Python / foreign non-TAR rows: **NULL**. SQL cheap readdir maps NULL → cookie `-1` (`CompactOpenCookie` treats `< 0` as none). Fat `lookup` / `row_to_file_info` uses `offsetheader.map(|v| v.max(0))`: NULL → `None`, a stored **negative** becomes `Some(0)`. Offset-order must use the cookie / `Option<i64>` path, **not** fat lookup’s `.max(0)`.
- Patch (`delete_from_offsetheader`): `IS NOT NULL AND offsetheader >= window`. NULL is **not** 0.
- `files` PK is `("path","name","offsetheader")`. SQLite `NULL != NULL`, so two NULL-oh rows for the same `(path,name)` are possible.

`regression_null_offsetheader_rows_still_list` (`ratarmount-index`) is the cheap-readdir / warm-seal contract. V-5 must not switch NULL handling to `COALESCE(offsetheader, 0)` or `row.get::<_, i64>()` (that is the bug the regression exists for).

### 3.2 SQL `SqliteIndex::list_dirents`

```1403:1458:ratarmount-index/src/lib.rs
            let mut stmt = conn.prepare_cached(
                r#"
                SELECT name, offsetheader, offset, size, mode, linkname,
                       istar, issparse, isgenerated, recursiondepth
                FROM "files"
                WHERE "path" = ?1
                ORDER BY "offsetheader"
                "#,
            )?;
            let mut by_name: BTreeMap<String, IndexDirent> = BTreeMap::new();
            // ...
                let offsetheader: Option<i64> = row.get(1)?;
                let offsetheader = offsetheader.unwrap_or(-1);
            // ...
            Ok(if got {
                Some(by_name.into_values().collect())
            } else {
                None
            })
```

`ORDER BY "offsetheader"` is already there so **later insert wins** (newest = max offset; SQLite NULLs come first and get overwritten). The returned `Vec` is **name order** via `BTreeMap`. Empty `name` is skipped. **`isgenerated` rows are kept** (search is the API that drops them). **Do not** drop the BTreeMap on the default path — that would silently change default readdir to offset order (NULLs first).

**No raw multi-row-per-name SQL listing** for the offset-order API either: `files` can hold two offsets for one name.

### 3.3 MemIndex `list_dirents`

`DirEntries.names` is `BTreeMap<u32, Vec<u32>>`. Iteration is by **name id**, newest = `versions.last()` after versions are sorted by `soa.offsetheader`. Cookie carries `soa.offsetheader[i]` (`-1` if none). Same newest-wins set; order is not UTF-8 and not offset.

How `self.mem` gets built (do not mix these in tests):

| Path | How names are interned | Default `list_dirents` order |
|------|------------------------|------------------------------|
| `insert_files_batch` then `into_read_only()` | Insert / parse order | Intern-id (insert `z` then `a` → `z`, `a`) |
| `create_writable` + **raw SQL** + `into_read_only()` | `mem_builder` empty; `seal_mem_index` does **not** `load_mem_index`; `self.mem` stays `None` | SQL UTF-8 (this is how `regression_null_offsetheader` “seals” today — `FileRow` cannot express NULL) |
| Warm remount: `open_writable` → `load_mem_index` | SQL `ORDER BY path, name, offsetheader` | Intern-id **equals UTF-8** |

Intern-id pin tests **must** use `insert_files_batch` (`z` then `a`) → `into_read_only()`. Do **not** use raw SQL for that pin. A sealed-mem **NULL** offset-order case, if required: file-backed index + raw SQL NULL + **drop** + `open_writable` + `into_read_only` (`load_mem_index`, NULL → `-1`). `create_writable` + raw SQL + `into_read_only` does **not** project mem.

### 3.4 TAR / ZIP / 7z `MountSource::list_dirents`

Map `IndexDirent` → `CheapDirent { name, mode, size }` and **drop the cookie**. TAR also filters GNU dumpdir tombstones via `linkname == "\0GNU.dumpdir.delete"` **after** newest-wins. Lookup: if the newest row is a tombstone, **all** versions of that name are hidden.

Correct dumpdir rule (same as TAR mount APIs):

1. Newest-wins **including** `\0GNU.dumpdir.delete` rows (max `offsetheader`).
2. **Then** omit the name if the winner is a tombstone.

**Forbidden:** filter tombstones first, then pick newest remaining (that resurrects a live `oh=100` after a delete at `oh=500`).

ZIP/7z have no dumpdir filter.

### 3.5 FileVersionLayer

[`versioning.rs`](../../../ratarmount-compositing/src/versioning.rs):

- Plain path: `inner.list_dirents` forwarded unchanged (whatever order the format already uses).
- `foo.versions/`: synthetic `1..=n` names, `S_IFREG|0444`, **size 0**, no offset. Version 1 is oldest.
- Newest-wins for the plain path is the inner source’s job (`lookup(..., 0)` / last SoA version).

V-5 must **not** sort the versions folder by archive offset (that would list oldest-first and change `ls` of `.versions`). Offset-order helpers live **under** FileVersionLayer (index / find), not in the wrapper.

Existing `file_version_layer_list_dirents_forwards_zip_without_fat_list` only pins a **one-version** folder (`name == "1"`). v1 adds an n≥2 pin: listing is `["1","2"]`, not offset order of the two versions.

### 3.6 Compositing

WriteOverlay / Union merge dirents through `BTreeMap<String, _>` → name order even if the base ever returned offset order. Another reason not to teach default `list_dirents` a new order: wrappers would throw it away unless every wrapper grew an order flag.

### 3.7 find / search

`SearchHit` already has `offsetheader: Option<i64>`. Glob and FTS both `ORDER BY fullpath, offsetheader LIMIT ?3`. `SearchQuery` has `pattern`, `fts`, `include_hashes`, `limit` — no order field yet. Search omits `isgenerated` and dumpdir **rows** (not newest-wins collapse). Two catalog versions of one path are two hits.

Find-argv flags are stripped **before** clap (`--fts`, boolean `--hashes`) so they cannot steal `PATTERN` / `ARCHIVE`. A new flag must use the same trap: `#[arg(skip)]` on `Args`, exact token `--offset-order` in `strip_find_only_flags`, **not** a clap `#[arg]` (value-taking longs steal `PATTERN`).

Control `search/<pattern>` (`tsv_search_callback`) and socket `search` use `LocateOptions::default()`. New `offset_order` defaults **false**; `SearchQuery::glob` / `fts` set it false. Do not thread the flag through control.

### 3.8 FUSE vs NFS listing order

| Surface | Order today | Cookie |
|---------|-------------|--------|
| FUSE `readdir` | `list_dirents` order after `.` / `..` | Listing **index** (`next_offset = i+1`) |
| NFS v3/v4 | Children sorted by fileid; first visit allocates fileids in `list_dirents` order | fileid |
| Overlay/Union | Re-BTreeMap by name | n/a |

v1 locality is **find + index helpers**, not NFS/FUSE readdir. Do not “fix” NFS fileid assignment as part of V-5. Do not change default `list_dirents` on the theory that NFS is immune.

---

## 4. Design

### 4.1 One Rust comparator (source of truth)

Do **not** rely on SQLite `NULLS LAST` for correctness (mem path has no SQL; dialect footgun). After the existing newest-wins collapse, sort in Rust.

**One shared function** in `ratarmount-index` (find/search must call it; do not write a second `SearchHit` sort that `unwrap_or(0)`):

```text
fn cmp_offset_then_name(...)  // used by list_dirents_ordered, flatten, search
NULL / cookie.offsetheader < 0  →  last
else                            →  offsetheader ASC
tie                             →  UTF-8 name ASC  (SearchHit: fullpath ASC)
still tied (two NULL oh, same fullpath — PK allows it)
                                →  stable input order
```

Use `slice::sort` / `sort_by`, **not** `sort_unstable_by`.

**Forbidden:** `COALESCE(offsetheader, 0)`, `unwrap_or(0)`, `row.get::<_, i64>(offsetheader)` on a nullable column, fat `row_to_file_info`’s `.max(0)`.

### 4.2 Index API (lowest layer)

Do **not edit** the bodies of `SqliteIndex::list_dirents` or `MemIndex::list_dirents`. Those two functions already differ in default order (SQL UTF-8 vs mem intern-id). “Unchanged” means each backend keeps **its** current function; `DirentOrder::Name` equals **that** function on that backend. NULL → `-1`, no error, `isgenerated` kept, empty names skipped.

Add:

```text
pub enum DirentOrder { Name, OffsetHeader }

impl SqliteIndex {
    pub fn list_dirents_ordered(&self, path: &str, order: DirentOrder)
        -> Result<Option<Vec<IndexDirent>>>;
}
```

**Normative equality (implementers: do not invent a second SQL):**

```text
list_dirents_ordered(path, Name)          == list_dirents(path)
list_dirents_ordered(path, OffsetHeader)  == sort(list_dirents(path)?, §4.1)
```

`DirentOrder::Name` means “today’s `list_dirents`”, including sealed intern-id order. Do not “fix” mem to UTF-8.

Newest-wins for this API is **exactly** `list_dirents` / `versions.last()`: max `offsetheader`; NULL/`cookie < 0` never beats a real offset and is never treated as `0`. No raw `SELECT … ORDER BY offsetheader` that emits two rows per name.

**Flatten (v1, not optional):**

```text
pub fn list_visible_files_by_offset(&self) -> Result<Vec<VisibleMember>>
// VisibleMember { path, name, cookie }
// Payload members for sequential open: newest-wins regular files
// (not dirs/symlinks). Not a `tar -x` header list.
```

Algorithm (must match walking every directory’s `list_dirents` then TAR dumpdir filter):

1. For each `(path, name)`, take the newest-wins row **including** dumpdir tombstones — same collapse as `list_dirents` / `versions.last()` (max oh; NULL last / never 0).
2. Drop the name if the winner’s `linkname` is `\0GNU.dumpdir.delete`.
3. Keep **payload** members only: `(mode & S_IFMT) == S_IFREG`, not dumpdir-tombstone, not generated, **not typeflag `'1'` hardlinks**. Mem SoA does not store typeflag; the portable test is `S_IFREG` + nonempty `linkname` (only `'5'`/`/` → dir and `'2'` → symlink in TAR `push_entry`). TAR `open` does **not** follow the hardlink target (size 0 → empty `Cursor`; else stencil at **this** member’s offset) — still exclude hardlinks from the sequential-payload list. Dirs and `'2'` symlinks are dropped. Dumpdir `D` meta is `S_IFREG` at `oh` plus `S_IFDIR` at `oh+1`; newest-wins is the directory, so “drop dirs” already drops `D` names. Devices/fifos as `S_IFREG` with empty linkname stay (rare).
4. **Global** sort of the surviving rows with §4.1 (`path`/`name` as the name key).

**Forbidden as flatten:** concatenate per-directory `list_dirents_ordered(..., OffsetHeader)` in directory-name / intern-id / walk order. That is not a global offset sort (interleaved dirs keep intra-dir runs and still seek backward).

Prefer sealed MemIndex (every dir, `versions.last()`, then steps 2–4) when `self.mem` is present; otherwise one SQL scan + the **same** Rust collapse (BTreeMap or equivalent), **not** “filter tombstones then MAX(offsetheader)”.

Not a `MountSource` method.

### 4.3 find CLI

Find-argv only, boolean, same strip style as `--fts`:

```bash
ratarmount find --offset-order '*.fits' archive.tar
```

Wiring (copy **boolean `--fts`**, not value-taking `--hashes`):

- Expand `strip_find_only_flags` to return `(Vec, find_fts, find_hashes, find_offset_order)` (or an equivalent extra bool). Exact token `--offset-order`, **no value**.
- `Args.find_offset_order: bool` with `#[arg(skip)]` — **not** a clap `#[arg]`.
- In the `if args.find` block (~`main.rs` `LocateOptions { fts, include_hashes, fill_hashes }`), set `offset_order` **only** from `args.find_offset_order`.
- `LocateOptions.offset_order` / `SearchQuery.offset_order` default **false**.
- `SearchQuery::glob` / `fts` constructors stay `offset_order: false`.
- `query_index` must set `SearchQuery.offset_order` from `loc.offset_order` **after** `..SearchQuery::glob(pattern)` / `fts(...)` (the `..` reset would otherwise drop the flag).
- Control `tsv_search_callback` keeps `LocateOptions::default()` (path order). Do not thread the flag through control.

**LIMIT (not alternatives — pick this one):**

Membership, filters, hashes, and `LIMIT` stay **exactly** today’s query (`ORDER BY fullpath, offsetheader LIMIT n`) for **both glob and FTS**. `--offset-order` **only re-sorts** that `Vec` with the shared §4.1 function. A 10_001st path-order hit is still dropped. Do **not** change SQL `ORDER BY` so that LIMIT becomes offset-order top-N.

Default find TSV order stays `fullpath, offsetheader`.

Clap-steal cases:

- `find --offset-order '*.fits' a.tar` keeps both positionals.
- `find --fts --offset-order '*.fits' a.tar` same.
- `find --offset-order a.tar` still errors “PATTERN ARCHIVE”.
- `ratarmount --offset-order a.tar mnt` is unknown (not a mount flag).

Do **not** add `--sort=offset` as an optional-value flag (value can steal the pattern).

### 4.4 TAR / ZIP / 7z

No `MountSource` change. Format crates keep mapping `list_dirents()` → today’s `CheapDirent` order.

The seek-count regression is **TAR-only** in v1: `list_visible_files_by_offset` + a counting `Read+Seek` wrapper on member opens (or archive `SeekFrom::Start`). ZIP/7z crate tests are residual.

7z shared pack offset: documented; if a later PR adds a 7z test, assert name tie-break and no extra backward seek versus name order. Solid prefix-from-0 inflate is unchanged (existing 7z sequential tests).

### 4.5 FileVersionLayer / overlay

No production code change. Tests:

- Default `FileVersionLayer::list_dirents` for a real directory equals inner.
- `.versions` with **n≥2**: names `["1","2"]` in that order, not archive-offset order of the two versions.
- Overlay-only names have no `offsetheader`; they must not appear in the **index** flatten helper (they are not catalog rows). Find is sidecar-only today — unchanged.

### 4.6 F-9 note

Already pointed from [`beyond-parity-roadmap.md`](../beyond-parity-roadmap.md) F-9 to this plan. Implementation PR does not need to re-add the sentence; only flip V-5 checkboxes when code lands. Rewriter copies members in **input offset order** (do not name-sort while packing).

---

## 5. Tests (same PR as the implementation; required)

Layer: index unit first, then find CLI, then flatten + fake-reader restore. Names use `Regression:` per `AGENTS.md`.

| Test | Crate | Asserts |
|------|--------|---------|
| SQL (unsealed) default `list_dirents` is UTF-8 | `ratarmount-index` | `a.txt` before `z.txt` even if `z` has a lower `offsetheader` |
| Builder-sealed mem default is **intern-id**, not UTF-8 | `ratarmount-index` | **`insert_files_batch`** (`z` then `a`) → `into_read_only()` → listing is `z` then `a`. Do **not** use raw SQL (that path never builds mem). Do **not** sort mem by name to make this pass |
| `DirentOrder::Name` equals `list_dirents()` | `ratarmount-index` | On unsealed SQL **and** builder-sealed mem (each equals **that** backend’s `list_dirents`) |
| `list_dirents_ordered(..., OffsetHeader)` is offset ASC, name tie-break | `ratarmount-index` | `z` (oh=100) before `a` (oh=500) on unsealed SQL and builder-sealed mem |
| Offset-order membership equals default `list_dirents` | `ratarmount-index` | Same names / cookies; includes `isgenerated` if present; only order differs |
| **Regression: NULL `offsetheader` still lists on offset-order path** | `ratarmount-index` | Foreign NULL row present; cookie `< 0`; not treated as 0; sorts **after** real offsets; default `list_dirents` + `regression_null_offsetheader` still pass. SQL path: raw insert (same as today’s regression). Optional mem-NULL: file-backed + drop + `open_writable` + `into_read_only` (`load_mem_index`); not `create_writable`+raw+seal |
| Newest-wins unchanged | `ratarmount-index` | Two rows same name, oh=100 and oh=500 → one dirent, cookie 500, in both orders |
| Newest-wins NULL vs `0` | `ratarmount-index` | Same `(path,name)`, NULL + `oh=0` → one dirent, cookie **`0`** (not `< 0`). `COALESCE`/`unwrap_or(0)` only collides here |
| **Regression: dumpdir newest-then-filter** | `ratarmount-formats-tar` or index with dumpdir linkname | Live `oh=100` + tombstone `oh=500` → flatten and TAR-filtered offset list **omit** the name (must not resurrect `oh=100`) |
| Shared comparator + NULL find hit | `ratarmount-index` search | Search uses the same `cmp_offset_then_name`; a raw-SQL NULL `offsetheader` hit sorts **after** real offsets ( `FileRow` cannot express NULL) |
| Find default TSV order unchanged | `ratarmount` (`find.rs`) | Existing `find_glob` paths stay `/a.fits` then `/dir/b.fits` when those match path order |
| **Regression: find `--offset-order` TSV follows `offsetheader` (CLI path)** | `ratarmount` bin | Must exercise **`find::run` after `parse_args_from`** or `CARGO_BIN_EXE_ratarmount find --offset-order …` — **not** only `locate_hits` with a hand-built `LocateOptions`. Unique-name archive packed `z` then `a`; default find `a` then `z`; flag emits `z` then `a` |
| Find `--offset-order` does not change LIMIT membership | `ratarmount-index` search | Glob **and** FTS: three rows; path order A,B,C; offset order C,A,B; `limit=2` + offset_order → **A,B** re-sorted by offset, not C+A |
| **Regression: find `--offset-order` does not steal PATTERN/ARCHIVE** | `ratarmount` bin | Mirror `find_flag_fts_*`; also `--fts --offset-order '*.fits' a.tar`; `ratarmount --offset-order a.tar mnt` is unrecognized |
| Control / socket TSV order unchanged | `ratarmount` / compositing | When `SearchQuery.offset_order` exists, `tsv_search_callback` / socket `search` still path-order |
| **Regression: offset-ordered restore has zero backward seeks** | `ratarmount-formats-tar` | Uses **`list_visible_files_by_offset`**, not find. N≥32 unique payload files in **≥2 directories**, packed so archive order **interleaves** dirs (e.g. `z/m00`, `a/m00`, `z/m01`, `a/m01`, …) and basenames are shuffled vs offset. Offset list: **zero** backward `SeekFrom::Start` (Start whose offset is strictly less than the previous Start; the first Start is not backward). Name-order control on the **same set**: **≥1** backward Start (fixture is actually shuffled). Concatenating per-dir offset lists is **forbidden** and this fixture fails that bug |
| FileVersionLayer `.versions` n≥2 | `ratarmount-compositing` | Listing `["1","2"]`; existing `file_version_layer_list_dirents_*` stay green |

Skip policy: if `tar` is missing, the archive-build test `eprintln!("skip: …")` and **still** run the pure index / fake-seek unit tests.

Keep green (run separately; `cargo test` does not treat `|` as OR):

```text
cargo test -p ratarmount-index --lib regression_null_offsetheader
cargo test -p ratarmount-compositing --lib file_version_layer_list_dirents
cargo test -p ratarmount-formats-tar --lib list_dirents
cargo test -p ratarmount --bin ratarmount find_flag
cargo test -p ratarmount --bin ratarmount find_glob
```

### AGENTS.md catalog row (implementation PR)

| Symptom / fix | Commands |
|---------------|----------|
| Offset-order restore / find walks name order | `cargo test -p ratarmount-index --lib dirent_order` · `cargo test -p ratarmount --bin ratarmount find_offset_order` · `cargo test -p ratarmount-formats-tar --lib regression_offset_order_seeks` |

---

## 6. Docs (implementation PR)

| Doc | Change |
|-----|--------|
| [`README.md`](../../../README.md) find snippet | Show `find --offset-order '*.fits' archive.tar` next to `--fts` |
| [`vectorize-steal-patterns.md`](../vectorize-steal-patterns.md) V-5 | Flip still-open boxes as they land; keep status `todo` until code exists |
| [`beyond-parity-roadmap.md`](../beyond-parity-roadmap.md) F-9 | Already pointed at this plan; no further edit required in the code PR |
| [`docs/mount-options-parity.md`](../../mount-options-parity.md) | **No** new mount option in v1. Find-argv-only flags are not mount options |
| [`AGENTS.md`](../../../AGENTS.md) | Catalog row above |
| Nested / tmp matrices | **No** — open path unchanged |

This plan-only PR: this file + a pointer from V-5 “Still open” + the F-9 sentence. No README feature-table claim until code exists.

---

## 7. Implementation sketch (for the later code PR)

1. `ratarmount-index`: shared `cmp_offset_then_name` (`sort`/`sort_by`) + `DirentOrder` + `list_dirents_ordered` as `sort(list_dirents)` + `list_visible_files_by_offset` (global, hardlinks excluded) + tests (NULL, newest-wins including NULL vs 0, dumpdir, builder-sealed intern-id, LIMIT glob+FTS).
2. `SearchQuery.offset_order` default false; Rust sort with the **same** comparator **after** today’s glob/FTS collect + LIMIT. Do not change SQL `ORDER BY`.
3. `ratarmount` find: expand `strip_find_only_flags`; `#[arg(skip)]`; set `LocateOptions.offset_order` in the `if args.find` block; `query_index` writes `SearchQuery.offset_order` after `..glob`/`fts`; CLI-path TSV test; control stays default.
4. TAR seek-count regression on the flatten helper + dumpdir newest-then-filter.
5. FileVersionLayer n≥2 listing pin (compositing test only).
6. Docs + AGENTS.md row.
7. `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings` then scoped tests in §5.

Do not wire FUSE, NFS, overlay, or FileVersionLayer production code.

---

## 8. Risks

| Risk | Mitigation |
|------|------------|
| Dropping SQL `BTreeMap` “because we already ORDER BY offsetheader” | Default path keeps the map; offset API is `sort(list_dirents)` |
| Raw SQL offset listing emits two versions per name | Forbidden; equality to `list_dirents` set |
| Filter-then-newest resurrects dumpdir-deleted names | Newest-wins including tombstones, then drop |
| `--offset-order` + LIMIT becomes offset top-N | Re-sort after today’s path-order LIMIT only |
| NULL = 0 clusters foreign rows with the first TAR member | Sentinel `-1` / `None` last; dedicated regression |
| `--offset-order PATTERN` parsed as optional value | `#[arg(skip)]` + boolean find-argv strip only |
| Find lists old versions; restore cats stale bytes | Flag re-orders hits; flatten helper is newest-wins for extract |
| Sealed-mem UTF-8 “fix” changes warm `ls -f` | `Name` == today’s `list_dirents`; sealed test pins intern-id |
| First NFS readdir (no prior child ids) follows `list_dirents` | Do not change default order; residual §9.1 |
| Per-dir offset concat looks “strictly fewer” seeks | Interleaved multi-dir fixture + **zero** backward on flatten |
| Find TSV unit test without CLI wire | CLI-path TSV regression; `query_index` after `..glob` |
| Raw-SQL “seal” used for intern-id pin | `insert_files_batch` only; raw SQL does not build mem |
| 7z solid: offset order does not avoid prefix-from-0 inflate | Locality is pack-offset order; existing 7z sequential tests stay the contract |

---

## 9. Residuals (not v1)

1. FUSE/NFS mount option to emit readdir in offset order (`ls -f` / `find` over the mount). Would need FUSE cookie = stable identity (not listing index) and NFS fileids allocated in offset order — a different project. First NFS readdir today follows `list_dirents` via lazy fileids.
2. Control `search` / socket TSV offset order (second path or `order=` in the pattern).
3. Overlay names in offset-aware extract (overlay has no archive offset; copy those last or first).
4. F-9 rewriter (separate roadmap item); this plan only constrains member order.
5. [x] ZIP/7z seek-count / shared-pack tie tests (`regression_offset_order_seeks` in zip + sevenzip; 7z CLI skip + `regression_offset_order_shared_pack_name_tie_break` synthetic table).
6. **10k-member restore** as originally written in V-5 still-open: bench / `#[ignore]` / env-gated, **not** a default-CI gate. v1 gate is interleaved multi-dir N≥32 (§5). 10k is operator-scale story.

---

## 10. Acceptance

v1 is done when:

- Default `list_dirents` is unchanged on unsealed SQL (UTF-8) and **builder-sealed** mem (intern-id via `insert_files_batch`); FUSE/NFS production paths untouched.
- `find --offset-order` re-sorts today’s hit set (same LIMIT membership) and is NULL-safe / clap-steal-safe.
- `list_dirents_ordered(..., OffsetHeader)` is `sort(list_dirents)`.
- `list_visible_files_by_offset` is shipped; dumpdir is newest-then-filter; seek-count uses this helper on an interleaved multi-dir fixture: flatten has **zero** backward seeks; name-order control has ≥1.
- No k-means / ANN / catalog split.
- `regression_null_offsetheader` and FileVersionLayer cheap-readdir tests stay green.

---

## Skeptic-plan-review

Protocol: never skip sweep 1; fresh Task skeptic each sweep; cap 3; fold blockers; stop at ACCEPT or BLOCKED.

### Sweep 1 — CHANGES_REQUIRED (folded)

Skeptic: Task `bc-6c69d1d6-6ea7-5ccf-9cea-4955e0447007`.

Must-fix folded:

1. `--offset-order` + LIMIT: re-sort after today’s path-order LIMIT only; `limit=2` test.
2. Dumpdir: newest-wins including tombstones, then omit; live 100 + tomb 500 omits the name.
3. `list_dirents_ordered` = `sort(list_dirents)`; no raw multi-row SQL; newest-wins = max oh.
4. Flatten helper is v1; seek-count uses it; find vs flatten sets documented.
5. Default-order tests split SQL UTF-8 vs sealed intern-id; `Name` == `list_dirents()` on both.

Should-fix folded: NFS first-readdir = `list_dirents` via lazy fileids; 10k → residual §9.6; `.versions` n≥2 pin; flatten = payload members; §5.5 refs → §9; control `offset_order` false; clap `#[arg(skip)]` + combo cases; `isgenerated` kept on list API; TAR-only seek test; no fat `.max(0)`; F-9 pointer already present; stable order for two NULL oh.

### Sweep 2 — CHANGES_REQUIRED (folded)

Skeptic: Task `bc-c260ff83-15d3-56a1-9a71-96ef6191e098`.

Must-fix folded:

1. Seek fixture: ≥2 dirs, interleaved pack order; flatten → **zero** backward Start; name-order control → ≥1; per-dir concat forbidden.
2. Find CLI fully wired (`strip_find_only_flags`, `if args.find`, `query_index` after `..glob`/`fts`); TSV order test is CLI path, not hand-built `LocateOptions`.
3. Intern-id pin = `insert_files_batch` → `into_read_only` only; do not claim `load_mem_index` remount is intern-id ≠ UTF-8; raw SQL + seal does not build mem.

Should-fix folded: hardlink `'1'` excluded from flatten; shared comparator + NULL search hit; NULL vs `oh=0` newest-wins → cookie 0; FTS+LIMIT test; `sort` not `sort_unstable`; do not edit the two `list_dirents` bodies; NFS “no prior child ids”.

### Sweep 3 — ACCEPT

Skeptic: Task `bc-ae1752c3-f2f3-57d9-a996-088b3d693383`.

No must-fix blockers. Startable if the implementer follows the normative equalities and the §5 table.

Nits folded without reopening design: hardlink exclusion stays; rationale corrected (`open` does not follow the target). Dumpdir `D` already drops via newest-wins → directory row. Residual nits that must **not** reopen: do not “fix” `regression_null_offsetheader` onto `load_mem_index`; do not UTF-8-sort mem iteration; do not expand payload; no second LIMIT rule; no second dumpdir policy.

**Stop.** Do not implement in this PR.

---

## Skeptic-code-review (implementation PR)

Protocol: never skip sweep 1; fresh Task skeptic each sweep; cap 3; fold blockers; stop at ACCEPT or BLOCKED.

### Sweep 1 — ACCEPT

Skeptic: Task `bc-aaace12c-36fe-584b-9402-a7d6e7215389`.

No must-fix or should-fix blockers. Normative equalities hold: `list_dirents` bodies unchanged; `list_dirents_ordered(OffsetHeader) == sort(list_dirents)`; flatten is global; dumpdir newest-then-filter; find `--offset-order` is boolean find-argv and re-sorts after path-order LIMIT; NULL stays `-1` / last.

Nits that must **not** reopen design: SHA filled as `b629e07`; `all_path_ids` may `sort_unstable` (comparator stays `sort_by`); CLI TSV may skip if the bin is missing; seek log uses `cookie.offset`. Residuals §9 stay closed.

**Stop.** ACCEPT.
