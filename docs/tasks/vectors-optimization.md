# Task: Vector / density optimizations (SoA, pools, cookies)

**Status:** living backlog — P0+P1 implemented; P2 still open  
**Scope:** Compact metadata layouts — string pools, path segments, structure-of-arrays (SoA), open cookies, shards, denser maps. **Not** solid-decode / full-inflate payload work (separate tracks).

**Legend:** `[x]` done · `[ ]` open · `~` partial

“Vector tricks” here means **dense columns, interning, and avoid fat per-entry structs** (and only secondarily true SIMD on bulk buffers).

Systems patterns inspired by Cloudflare Vectorize (cheap scan + refine, snapshot index, remote read-through cache, commit coordinator, offset locality) live in [`vectorize-steal-patterns.md`](vectorize-steal-patterns.md). That file is **not** SIMD and **not** embedding IVF/PQ.

---

## Done (baseline)

- [x] Nested compact-only file table (no nested SQLite `files` as live store)
- [x] `StringPool` for nested MemIndex names / paths / link targets
- [x] Path segments (`PathTable`) for directory prefix compression
- [x] SoA entry rows (`EntrySoa`) + flags packing
- [x] Dir shards when directory count is large
- [x] `CompactOpenCookie` for open without retaining full `FileInfo` per entry
- [x] ZIP / 7z member path `Arc` share with compact pool (where wired)
- [x] ZIP Deflate single-flight inflate cache → shared `Arc<Vec<u8>>` views
- [x] FUSE sequential readahead window (amortize short decompressor reads)
- [x] Durable nestedindexes export/import (warm remount; not a create-peak RAM win)

---

## P0 — high value (same toolbox)

### FUSE list / readdir without full `FileInfo` maps

- [x] MemIndex / FUSE path: avoid building `BTreeMap<String, FileInfo>` for large dirs when only names/modes/sizes are needed
- [x] Stream or pack `(name_id, mode, size[, cookie])` into dirents from pool + SoA
- [x] Keep/extend `list_mode` (and similar) as the cheap API; fat `FileInfo` only at getattr/open boundaries
- [x] Regression: large flat directory readdir RSS + timing vs fat map materialization

Residual: `list()` still builds a fat map for callers that need full `FileInfo`. TAR `list_dirents` filters GNU dumpdir tombstones via `IndexDirent.linkname` (no `FileInfo`). Default `MountSource::list_dirents` derives from `list_mode` with `size = 0` unless a backend overrides.

Cheap `list_dirents` now also lands on compositing wrappers on the live FUSE path (Prefix, Union default B-4, AutoMount, WriteOverlay, Control, Folder, Transform, FileVersionLayer), the remaining `SqliteIndex` format crates (CPIO/AR/WARC/CAB/ISO/ASAR/XAR/libarchive/OGG/HTML/PDF), **and** EXT4 / FAT / SquashFS / Git / SQLAR / `SingleFileMountSource` / Dropbox. Union folder-cache **build** walks `list_dirents` (fat `list()` only when dirents have `mode == 0`). `--union-resolve-symlinks` `list_dirents` merges cheap dirents then resolves `S_IFLNK` winners via `lookup` (not a fat `list()` map). Control `status` dirent size is a placeholder 0 (getattr/open recompute).

HTTP/S3/SSH/SMB/WebDAV are **not** MountSources (download → factory archive); no `list_dirents` to add. Residual: FR-10 `lookup(join(listed_path, name))` may leave `S_IFLNK` on path-keyed archives listed through a symlink-to-dir. FUSE crate tests cover the fat-map skip. 2026-08-15 default-suite (v0.1.20 vs Python 1.3.0): `find` geo-mean **1.45× / 1.33×** (cold/warm); uncompressed random `cat` **1.14×** cold / **0.95×** warm. Gzip random/seq still favor Python. Filling real dirent sizes does **not** close that geo-mean (gzip nested still dominates). Expanded 2026-08-27 BIG suite (640 MiB + `.tar.zst`/`.tar.lz4`): `find` **1.26× / 1.38×**, seq. bandwidth **3.85× / 3.16×** — see [python-vs-rust-results.md](../../benchmarks/python-vs-rust-results.md).

Follow-on (cheap `find` / control search without fat maps): [`vectorize-steal-patterns.md`](vectorize-steal-patterns.md) **V-1**.

### ZIP member sidecar density

- [x] Replace or densify `HashMap<u64, ZipMemberMeta>` with SoA / parallel arrays (or sorted keys + binary search)
- [x] Columns: `offsetheader`, `data_start`, `compressed_size`, `method`, `encrypted`, `index`, name via pool id
- [x] Preserve Deflate cache keying and store-stencil open correctness
- [x] Regression: multi-file ZIP open + deflate concurrent open

Residual: inflate cache remains a runtime `HashMap` of completed members (not the sidecar). Name column is still `Arc<str>` (pool-shared when wired).

### PathTable + StringPool denser storage

- [x] Flatten path segments to CSR form: `offsets: Vec<u32>` + `seg_ids: Vec<u32>` (drop `Vec<Vec<u32>>`)
- [x] StringPool: optional single byte slab + `(start, len)` instead of `Vec<Arc<str>>` + `HashMap<Box<str>>` hot path
- [x] Prefer `u32` ids in rows; materialize `Arc`/`String` only at API boundary
- [x] Optional: after seal, freeze pool (read-only perfect hash / denser map) for nested + top-level MemIndex

Residual: PathTable `by_flat` HashMap remains for `resolve_path_id`. Post-seal name lookup is sorted FNV-1a + binary search (not a perfect hash). `intern()` Arc identity is kept after seal so ZIP/7z sidecars still `Arc::ptr_eq` the pool; `get()` still slices the slab.

### Top-level MemIndex projection (path mounts)

- [x] Ensure sealed path-mount MemIndex uses the same denser SoA + pool + segments as nested (no fat residual rows)
- [x] Audit dual SQLite build → seal path for temporary fat `FileRow` / `FileInfo` spikes; stage as SoA where cheap
- [x] Regression: large TAR cold index RSS + warm list/lookup

Residual: SQLite `files` table shape unchanged. Cold insert still stages via `MemIndexBuilder` (SoA), then `finish()` seals. SQL warm load still materializes `FileRow` strings once on the way into the builder.

---

## P1 — format / durable / maps

### Binary durable nested blob

- [x] Replace or dual-path JSON nestedindexes blob with columnar / bincode / rkyv-style encoding
- [x] Faster warm remount + smaller outer index growth under deep `-r`
- [x] Versioned schema; fail closed to cold rebuild on decode error
- [x] Keep JSON or debug dump optional for triage

Encoding: magic `RNIB`, `NESTED_BLOB_VERSION = 2`, little-endian columns. Legacy JSON v1 still dual-decodes. Corrupt / truncated / wrong version → `IndexError::Invalid` (cold rebuild). `to_json_debug` / `from_json_debug` remain for triage.

### 7z open-side density

- [x] SoA (or denser table) for open fields: `pack_offset`, `unpack_offset`, `size`, `folder_index`, path pool id
- [x] `entry_by_offsets`: sorted keys + binary search vs `HashMap<(u64,u64), usize>` on huge archives
- [x] Keep heavy `Folder` / coder graphs off the per-lookup hot path (structure already durable for nested warm)
- [x] Regression: multi-thousand-member 7z list + random open

Residual: per-member `SevenZipFileEntry` is still the fat row (path/size/folder stay there). Offset lookup is sorted keys + `idxs`; linear `find_entry` scan remains last resort. Regression is 32-member CLI fixture + an 80-key synthetic table test (not a literal multi-thousand archive in CI).

### Union / AutoMount path maps

- [x] Intern mount-point / nested keys (path_id or pool id) instead of duplicating long `String` keys
- [x] Dir / getattr caches: prefer compact cookies over full `FileInfo` clones
- [x] Regression: deep `-r` eager scan RSS with many nested roots

Residual: crate-local `PathIntern` (not the index `StringPool`). Folder-cache **build** walks `list_dirents` and copies each path string once per BFS level; the live map is `HashMap<u32, _>`. AutoMount prefix search is still linear over mounted points. No FileInfo cache of nested roots.

### Codec block maps (already close)

- [x] Keep zstd/bzip2/gzip seek maps as sealed SoA (`Vec<u64>` pairs or parallel columns), mmap-friendly
- [x] Avoid per-block structs on import/export of `zstdblocks` / `bzip2blocks` / RGZI paths
- [x] Document residual if any map still stores `Vec<(u64,u64)>` only for API convenience

Residual (API-only): Python/SQLite `zstdblocks` / `bzip2blocks` and `GzipSeekIndexBlob.points` still use `Vec<(u64, u64)>` at import/export. Live stores are `Vec<FrameInfo>`, `Arc<Vec<BlockInfo>>`, and `Vec<Checkpoint>`.

---

## P2 — situational / bulk buffers

### Hash / fingerprint fixed windows

- [x] Nested (and similar) fingerprints: fixed head/mid/tail buffers only — no full-body `Vec` unless policy requires
- [x] Content-hash fill: stream into fixed hasher state; same pattern as tarstats edge samples

Implemented as allocation-shape only (same windows / digests / progressive head-only): [`plans/p2-fingerprint-windows.md`](plans/p2-fingerprint-windows.md). Residual: ZIP STORE/`read_file_range_at` + Deflate slurp, 7z `read_member_bytes_io` (payload paths, not tarstats/nested windows).

### SQLite bulk insert staging

- [ ] Stage build rows as SoA / batch binds before `insert_files_batch` (path TAR/ZIP/7z cold build)
- [ ] Does not change on-disk SQLite shape; only peak during build

### Overlay / write path

- [x] Overlay file-info cache: compact cookie + size/mtime, not full `FileInfo` (watch size-0 / create residuals)
- [x] Regression: create then cat empty overlay file

Residual: FUSE overlay child inodes store `InodeAttrCookie` only. NFS and export-core (9P/SMB/SFTP) inode maps are still fat `FileInfo`. Not V-4 (commit queue).

### Parallel nested open pools

- [x] Investigated (2026-08-28): eager FR-6 workers do not intern into a
      parent StringPool. Reader = create_compact_only; warm import =
      to_mem_index(); spool = private create_writable. No shared intern target.
- Residual: cross-archive intern (RSS) is a different, gated item — see
  docs/tasks/plans/p2-parallel-nested-pools.md Phase 1 / G1. Do not treat
  G1 as a program that is expected to authorize merge.

### True SIMD (only on bulk)

- [~] CRC / memchr / bulk hash on multi-MB buffers (inflate output, full-file hash)
- [ ] **Not** a priority for short path-component lookups (intern + SoA locality wins first)

Residual: `--hashes` / inflate-output hash already `crc32fast`+`sha2`; 7z `parse::crc32` now `crc32fast` (trial is first file, usually small); **no** memchr-on-inflate path exists; path-component SIMD remains a non-goal. No remaining hand-rolled CRC/hash on payload buffers (memchr-on-inflate never existed). This is **not** “True SIMD on multi-MB landed.” Plan: [`plans/p2-bulk-simd.md`](plans/p2-bulk-simd.md).

---

## Explicit non-goals (do not track as vector wins)

| Residual | Why |
|----------|-----|
| Solid 7z full-folder unpack | Payload CPU/RAM; not metadata layout |
| Full Deflate member inflate cost | Payload; cache helps reuse, not first inflate size |
| Durable save-then-free during **cold** nested build | Peak still needs full compact table to export |
| SIMD on every single-name `lookup` | Overhead dominates short strings |
| IVF / PQ / ANN from Vectorize | Wrong domain — see [`vectorize-steal-patterns.md`](vectorize-steal-patterns.md) non-goals |

---

## Suggested implementation order

1. FUSE list/readdir without full `FileInfo` maps  
2. ZIP member map densification  
3. Flatten PathTable + tighter StringPool  
4. Top-level MemIndex density audit  
5. Binary durable nested blob  
6. 7z open-side SoA / entry map  
7. AutoMount / union key interning  
8. P2 items as needed  
9. Systems patterns V-1..V-5 in [`vectorize-steal-patterns.md`](vectorize-steal-patterns.md) (not density)

---

## Verification notes

- Prefer RSS + wall-time benches on large flat dirs, multi-k ZIP/7z, and nested remount (`benchmarks/compare-nested-durable.sh` for durable warm).  
- Every density change needs regression tests at the lowest layer (MemIndex unit → format open → FUSE helper if only visible there).  
- Update [`docs/embedded-nested-archives.md`](../embedded-nested-archives.md) if nested live model or durable blob format changes.

## Related

- Nested compact model: [`docs/embedded-nested-archives.md`](../embedded-nested-archives.md)  
- Nested durable: outer `nestedindexes` + factory open path  
- Code: `ratarmount-index/src/mem.rs`, format sidecars (ZIP/7z), `ratarmount-fuse` readahead/list  
- Vectorize systems steal (not SIMD): [`vectorize-steal-patterns.md`](vectorize-steal-patterns.md)
