# V-5 — Offset-order locality (plan)

| Field | Value |
|-------|--------|
| **Item** | [`vectorize-steal-patterns.md`](../vectorize-steal-patterns.md) **V-5** (todo, S–M) |
| **Date** | 2026-08-28 |
| **Status** | Draft plan (skeptic-plan-review in progress) |
| **Implements** | Optional catalog / locate order by `offsetheader` so sequential readers hit nearby archive bytes |
| **Does not implement** | k-means, IVF centroid files, ANN, cosine clustering, default `ls` sort change |
| **Ownership** | `ratarmount-index` + `ratarmount` find CLI. Format crates only for regressions. **Do not** change `factory.rs` glue. |
| **Skeptic** | Sweep results appended at the end of this file |

This is an implementation plan, not the implementation. Stop at ACCEPT or BLOCKED.

---

## 1. Problem

Vectorize clusters nearby embeddings so a query opens a handful of objects. For an archive, “nearby” is **byte offset**, not cosine.

Today sequential consumers walk **path / name order**:

- `ratarmount find` / control `search` SQL is `ORDER BY fullpath, "offsetheader"`.
- Cheap readdir for the SQL fallback collapses into `BTreeMap<String, IndexDirent>` and returns **lexicographic name order**.
- MemIndex `list_dirents` walks `BTreeMap<u32, Vec<u32>>` (**interned name-id order**, not UTF-8 name order) and keeps `versions.last()` (newest).
- GNU `ls` sorts names itself. `ls -f`, `find` over a mount, and `cp -R` follow FUSE readdir order (`list_dirents` as-is).
- NFSv3/v4 readdir **re-sorts children by fileid**, so changing `list_dirents` order would **not** change NFS listing order.
- FUSE `--readahead` amortizes short reads **inside one open member**, not across readdir.

On HDD and on remote Range GET (V-3), a name-order restore of a TAR whose members were appended, concatenated, or packed in ZIP local-header / 7z pack order pays backward seeks / extra GETs.

---

## 2. Goals / non-goals

### Goals (v1)

1. **Opt-in** listing and locate by `files.offsetheader` (NULL last, never coalesced to 0).
2. Default **name order for `ls`** stays: do not change default `MountSource::list_dirents`, FUSE `readdir` / `readdirplus`, NFS readdir, overlay/union merge, or FileVersionLayer forwarding.
3. `find` output option for restore pipelines (`--offset-order`, find-argv only).
4. Index helper that yields the **same newest-wins set** as today’s per-directory `list_dirents`, sorted by offset (extract helper).
5. Document that F-9 `--repack-seekable` (still `todo`) must keep members in existing archive order (already true for tar-in-order; do not shuffle).
6. Keep `regression_null_offsetheader` green; foreign indexes with NULL `offsetheader` must still cheap-readdir and warm-seal.

### Non-goals

| Item | Why |
|------|-----|
| k-means / IVF / PQ / ANN | Spec ban; members are not \(\mathbb{R}^{D}\) |
| Split the 0.7.x `files` table into centroid files | One SQLite blob stays |
| Default FUSE/NFS readdir in offset order | User-visible `ls -f` / in-progress FUSE cookies (index into the listing); NFS already sorts by fileid |
| Add `offsetheader` to [`CheapDirent`](../../../ratarmount-core/src/lib.rs) | Every constructor + FUSE dir_cache would grow; unused on the default path |
| `MountSource` trait change | Cascades through every format + compositing + NFS/FUSE mock |
| Mount flag `--readdir-order=offset` in v1 | See §5.5 residual |
| Control `search/<pattern>` order change | Path-component API has no query string; default TSV stays `fullpath` order |
| Newest-wins collapse of `find` hits | Find already returns every non-generated, non-tombstone catalog row (multiple versions of one path). Offset order **re-sorts that set**; it does not change membership |
| Changing MemIndex intern-id readdir order to UTF-8 | Out of scope; `ls` already sorts |

---

## 3. Current code (investigation)

### 3.1 `offsetheader` column

- TAR: uncompressed header start. Newest version of a name has the **highest** `offsetheader` (append / GNU incremental).
- ZIP: local-header / CD offset (`headers` already sorted; binary search).
- 7z: pack offset (`entry_by_offsets` is sorted keys + binary search). Solid members can **share** a pack offset — ties are fine; stable name tie-break.
- Python / foreign non-TAR rows: **NULL**. SQL cheap readdir maps NULL → cookie `-1` (`CompactOpenCookie` treats `< 0` as none). Fat `lookup` keeps `UserData::Tar.offsetheader = None`.
- Patch (`delete_from_offsetheader`): `IS NOT NULL AND offsetheader >= window`. NULL is **not** 0.

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

`ORDER BY "offsetheader"` is already there so **later insert wins** (newest). The returned `Vec` is **name order** via `BTreeMap`. SQLite sorts NULL first; those rows still enter the map. **Do not** “optimize” this by dropping the BTreeMap on the default path — that would silently change default readdir to offset order.

### 3.3 MemIndex `list_dirents`

`DirEntries.names` is `BTreeMap<u32, Vec<u32>>`. Iteration is by **name id**, newest = `versions.last()`. Cookie carries `soa.offsetheader[i]` (`-1` if none). Same newest-wins set; order is not UTF-8 and not offset.

### 3.4 TAR / ZIP / 7z `MountSource::list_dirents`

Map `IndexDirent` → `CheapDirent { name, mode, size }` and **drop the cookie**. TAR also filters GNU dumpdir tombstones via `linkname == "\0GNU.dumpdir.delete"`. Offset-order helpers must apply the **same** tombstone filter when used as an extract list.

### 3.5 FileVersionLayer

[`versioning.rs`](../../../ratarmount-compositing/src/versioning.rs):

- Plain path: `inner.list_dirents` forwarded unchanged (whatever order the format already uses).
- `foo.versions/`: synthetic `1..=n` names, `S_IFREG|0444`, **size 0**, no offset. Version 1 is oldest.
- Newest-wins for the plain path is the inner source’s job (`lookup(..., 0)` / last SoA version).

V-5 must **not** sort the versions folder by archive offset (that would list oldest-first and change `ls` of `.versions`). Offset-order helpers live **under** FileVersionLayer (index / find), not in the wrapper.

`file_version_layer_list_dirents_forwards_zip_without_fat_list` stays the cheap-readdir contract.

### 3.6 Compositing

WriteOverlay / Union merge dirents through `BTreeMap<String, _>` → name order even if the base ever returned offset order. Another reason not to teach default `list_dirents` a new order: wrappers would throw it away unless every wrapper grew an order flag.

### 3.7 find / search

`SearchHit` already has `offsetheader: Option<i64>`. Glob and FTS both `ORDER BY fullpath, offsetheader`. `SearchQuery` has `pattern`, `fts`, `include_hashes`, `limit` — no order field yet.

Find-argv flags are stripped **before** clap (`--fts`, boolean `--hashes`) so they cannot steal `PATTERN` / `ARCHIVE`. A new flag must use the same trap.

Control `search/<pattern>` and socket `search` reuse path-order TSV. Leave that order in v1 (stable scripts). Residual: a second virtual dir is not worth it.

### 3.8 FUSE vs NFS listing order

| Surface | Order today | Cookie |
|---------|-------------|--------|
| FUSE `readdir` | `list_dirents` order after `.` / `..` | Listing **index** |
| NFS v3/v4 | Children **sorted by fileid** | fileid |
| Overlay/Union | Re-BTreeMap by name | n/a |

NFS sequential `ls` / readahead therefore does **not** follow archive offset even if `list_dirents` did. v1 locality is **find + index helper**, not NFS readdir. Do not “fix” NFS fileid assignment as part of V-5.

---

## 4. Design

### 4.1 One Rust comparator (source of truth)

Do **not** rely on SQLite `NULLS LAST` for correctness (mem path has no SQL; dialect footgun). After the existing newest-wins collapse, sort in Rust:

```text
NULL / cookie.offsetheader < 0  →  last
else                            →  offsetheader ASC
tie                             →  UTF-8 name ASC
```

Same rule for `SearchHit.offsetheader: Option<i64>` (`None` last, then `fullpath` tie-break).

**Forbidden:** `COALESCE(offsetheader, 0)`, `unwrap_or(0)`, `row.get::<_, i64>(offsetheader)` on a nullable column.

### 4.2 Index API (lowest layer)

Keep `SqliteIndex::list_dirents` / `MemIndex::list_dirents` **byte-identical** (name / intern-id order, NULL → `-1`, no error).

Add:

```text
pub enum DirentOrder { Name, OffsetHeader }

impl SqliteIndex {
    pub fn list_dirents_ordered(&self, path: &str, order: DirentOrder)
        -> Result<Option<Vec<IndexDirent>>>;
}
```

- `DirentOrder::Name` → today’s `list_dirents` (including SQL BTreeMap / mem name-id order). Do not “fix” mem to UTF-8 here.
- `DirentOrder::OffsetHeader` → same rows (newest-wins, empty names skipped), then the comparator in §4.1.

MemIndex gets the same method (or `list_dirents` + a crate-private `sort_index_dirents`).

Optional flatten for restore (same newest-wins rule as walking every directory):

```text
pub fn list_visible_files_by_offset(&self) -> Result<Vec<VisibleMember>>
// VisibleMember { path, name, cookie } — regular files only, dumpdir/generated omitted
```

Implement with one SQL scan + Rust newest-wins keyed by `(path, name)` (last non-NULL-or-higher offset wins; if both NULL, last row wins) **or** reuse sealed MemIndex: every dir, `versions.last()`, skip dirs/tombstones, sort. Prefer the mem path when sealed (FUSE-warm) and SQL when not.

This is the “extract helper”. It is **not** a `MountSource` method in v1.

### 4.3 find CLI

Find-argv only, boolean, same strip style as `--fts`:

```bash
ratarmount find --offset-order '*.fits' archive.tar
```

- `LocateOptions` / `SearchQuery` grow `offset_order: bool` (default false).
- When set: after the existing query (same limit, same filters, same hashes), sort hits with §4.1. Alternatively `ORDER BY` in SQL **plus** the same Rust sort so NULL/`Option` matches mem and FTS.
- Default find TSV order stays `fullpath, offsetheader`.
- `--offset-order` on a **mount** argv (`ratarmount --offset-order a.tar mnt`) is unknown (not a global clap field).
- Clap-steal: `find --offset-order '*.fits' a.tar` keeps both positionals; `find --offset-order a.tar` still errors “PATTERN ARCHIVE”.

Do **not** add `--sort=offset` as an optional-value flag (value can steal the pattern).

### 4.4 TAR / ZIP / 7z

No `MountSource` change. Format crates keep mapping `list_dirents()` → name-ordered `CheapDirent`.

Regressions that need a real archive (pread monotonicity) live in `ratarmount-formats-tar` (and optionally zip/7z) using the index helper + a counting `Read+Seek` wrapper around the archive file or member opens.

7z: shared pack offset → 0 backward seeks between those members if the test opens in that order; still assert **no extra** backward seek versus name order.

### 4.5 FileVersionLayer / overlay

No code change. Tests:

- Default `FileVersionLayer::list_dirents("/")` order equals inner (name / current).
- `.versions` listing stays `1..=n`.
- Overlay-only names have no `offsetheader`; they must not appear in the **index** helper (they are not catalog rows). Find is sidecar-only today — unchanged.

### 4.6 F-9 note (docs only in this work)

When `--repack-seekable` is implemented, the rewriter copies members in **input offset order** (do not sort by name while packing). Tar-in-order already satisfies this. Add a sentence to F-9 in [`beyond-parity-roadmap.md`](../beyond-parity-roadmap.md) when F-9 lands; the V-5 implementation PR can add a one-line pointer from F-9 → this plan so the producer does not shuffle.

This plan PR may add that pointer now (docs-only, no behavior).

---

## 5. Tests (same PR as the implementation; required)

Layer: index unit first, then find CLI, then one fake-reader restore. Names use `Regression:` per `AGENTS.md`.

| Test | Crate | Asserts |
|------|--------|---------|
| Default `list_dirents` still name-ordered (SQL BTreeMap) | `ratarmount-index` | `a.txt` before `z.txt` even if `z` has a lower `offsetheader` |
| `list_dirents_ordered(..., OffsetHeader)` is offset ASC, name tie-break | `ratarmount-index` | `z` (oh=100) before `a` (oh=500) |
| **Regression: NULL `offsetheader` still lists on offset-order path** | `ratarmount-index` | Foreign NULL row present; cookie `< 0`; not treated as 0; sorts **after** real offsets; `list_dirents` (default) + `regression_null_offsetheader` still pass |
| Newest-wins unchanged | `ratarmount-index` | Two rows same name, oh=100 and oh=500 → one dirent, cookie 500, in both orders |
| MemIndex offset order uses `versions.last()` cookie | `ratarmount-index` | Same as newest-wins |
| Find default TSV order unchanged | `ratarmount` (`find.rs`) | Existing `find_glob` paths stay `/a.fits` then `/dir/b.fits` when those match path order |
| Find `--offset-order` TSV follows `offsetheader` | `ratarmount` | Archive packed `z` then `a`; default find `a` then `z`; flag emits `z` then `a` |
| **Regression: find `--offset-order` does not steal PATTERN/ARCHIVE** | `ratarmount` bin | Mirror `find_flag_fts_does_not_steal_archive`; `--offset-order` is not a mount flag |
| **Regression: offset-ordered restore does fewer backward seeks than name order** | `ratarmount-formats-tar` (or index + fake `Seek`) | Counting seek wrapper; N≥32 members **name-shuffled vs archive order**; offset list → 0 (or strictly fewer) backward `SeekFrom::Start` than name list. Do **not** require a 10k-member fixture in default CI — 32–256 is enough to catch a name-sort bug; comment that 10k is the operator-scale story |
| TAR dumpdir tombstones omitted from extract helper | `ratarmount-formats-tar` | Same filter as cheap readdir |
| FileVersionLayer default dirents unchanged | `ratarmount-compositing` | Existing `file_version_layer_list_dirents_*` stay green; no new sort |

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
| [`beyond-parity-roadmap.md`](../beyond-parity-roadmap.md) F-9 | One line: keep member offset order (link this plan) |
| [`docs/mount-options-parity.md`](../../mount-options-parity.md) | **No** new mount option in v1. Find-argv-only flags are not mount options; mention in the find/control row if that table grows find flags |
| [`AGENTS.md`](../../../AGENTS.md) | Catalog row above |
| Nested / tmp matrices | **No** — open path unchanged |

This plan-only PR: add this file + a pointer from V-5 “Still open” to `docs/tasks/plans/v5-offset-order-locality.md`. No README feature-table claim until code exists.

---

## 7. Implementation sketch (for the later code PR)

1. `ratarmount-index`: comparator + `DirentOrder` + `list_dirents_ordered` + tests (NULL, newest-wins, default unchanged).
2. `SearchQuery.offset_order` + Rust sort after glob/FTS collect.
3. `ratarmount` find: strip `--offset-order` like `--fts`; `LocateOptions`; clap-steal + TSV order tests.
4. TAR (optional ZIP) seek-count regression + dumpdir filter on the flatten helper if that helper is in this PR.
5. Docs + AGENTS.md row.
6. `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings` then scoped tests in §5.

Do not wire FUSE, NFS, overlay, or FileVersionLayer.

---

## 8. Risks

| Risk | Mitigation |
|------|------------|
| Dropping SQL `BTreeMap` “because we already ORDER BY offsetheader” | Default path keeps the map; new method only |
| NULL = 0 clusters foreign rows with the first TAR member | Sentinel `-1` / `None` last; dedicated regression |
| `--offset-order PATTERN` parsed as optional value | Boolean find-argv strip only |
| Find lists old versions; restore cats stale bytes | Document: flag re-orders hits, does not collapse versions. Visible-tree helper is newest-wins for extract |
| NFS still name/fileid order | Accepted residual §5.5 |
| 7z solid: offset order does not avoid prefix-from-0 inflate | Locality is pack-offset order, not random-access; existing 7z sequential tests stay the contract |
| Mem default order ≠ UTF-8; a “Name” enum variant surprises | `Name` means “today’s `list_dirents`”, documented |

---

## 9. Residuals (not v1)

1. FUSE/NFS mount option to emit readdir in offset order (`ls -f` / `find` over the mount). Would need FUSE cookie = fileid-like identity, not listing index, and NFS fileids allocated in offset order — a different project.
2. Control `search` / socket TSV offset order (second path or `order=` in the pattern).
3. Overlay names in offset-aware extract (overlay has no archive offset; copy those last or first).
4. F-9 rewriter (separate roadmap item); this plan only constrains member order.

---

## 10. Acceptance

v1 is done when:

- Default `ls` / `list_dirents` / FUSE / NFS behavior is unchanged (tests in §5).
- `find --offset-order` and `list_dirents_ordered(..., OffsetHeader)` are opt-in and NULL-safe.
- Seek-count regression proves fewer backward seeks than name order.
- No k-means / ANN / catalog split.
- `regression_null_offsetheader` and FileVersionLayer cheap-readdir tests stay green.

---

## Skeptic-plan-review

Protocol: never skip sweep 1; fresh Task skeptic each sweep; cap 3; fold blockers; stop at ACCEPT or BLOCKED.

### Sweep 1

_(pending)_
