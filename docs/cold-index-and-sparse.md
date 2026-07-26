# Cold index performance + sparse TAR

## Cold index (2026-07-25)

**Problem:** indexing ~1000 empty files took **~5 s** wall time (Python ~0.03 s for the same work).

**Cause:** each `INSERT` was its own SQLite autocommit with default journal/sync settings.

**Fix (aligned with Python `SQLiteIndex._open_sql_db` + `executemany`):**

1. Build PRAGMAs on writable open: `locking_mode=EXCLUSIVE`, `temp_store=MEMORY`, `journal_mode=OFF`, `synchronous=OFF`
2. Single `BEGIN IMMEDIATE` … `COMMIT` around the full index build
3. Batched inserts (`insert_files_batch`, flush every 512 rows) with prepared statements
4. Parent directories buffered in the same batch (no per-file SQLite round-trip)

**Result (empty-1k.tar, release, this host):**

| Tool | Cold index create |
|------|-------------------|
| Rust (before) | ~5.08 s |
| Rust (after) | **~0.00 s** (&lt;10 ms) |
| Python | ~0.03 s (index) / ~0.25 s process |

Also applied `begin_write`/`commit_write` to ZIP, AR, CPIO, and libarchive builders.

## Sparse TAR

### Supported formats

| Format | Detection | Map source |
|--------|-----------|------------|
| Old GNU typeflag `S` | typeflag + realsize @ 483 | Header 386–482 + extended blocks |
| PAX GNU sparse **0.0** | `GNU.sparse.size` + repeated offset/numbytes | PAX body pairs |
| PAX GNU sparse **0.1** | `GNU.sparse.map` | Comma-separated off,len list |
| PAX GNU sparse **1.0** | `GNU.sparse.major=1` | Text map at start of data (`N\\noff\\nlen\\n…` + 512-pad) |

**Indexing:** parse PAX `x`/`g` headers; use `GNU.sparse.name` for the real path (never expose `PaxHeaders/` or `GNUSparseFile.*` placeholders); store **logical** size + `issparse=true`; `offsetheader` points at the pax header when present.

**Open:** re-parse map from `offsetheader` and build `SegmentedFile` (data + zero-hole segments).

**Tests:** `sparse.gnu.tar`, `sparse.pax.sparse-{0.0,0.1,1.0}.tar` (Python fixture tree).