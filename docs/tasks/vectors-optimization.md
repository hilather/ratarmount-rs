# Task: Vector / density optimizations (SoA, pools, cookies)

**Status:** living backlog — P0+P1 implemented; P2 still open  
**Scope:** Compact metadata layouts — string pools, path segments, structure-of-arrays (SoA), open cookies, shards, denser maps. **Not** solid-decode / full-inflate payload work (separate tracks).

**Legend:** `[x]` done · `[ ]` open · `~` partial

“Vector tricks” here means **dense columns, interning, and avoid fat per-entry structs** (and only secondarily true SIMD on bulk buffers).

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

Residual: `list()` still builds a fat map for callers that need full `FileInfo`. TAR `list_dirents` filters GNU dumpdir tombstones via `IndexDirent.linkname` (no `FileInfo`). Default `MountSource::list_dirents` derives from `list_mode` with `size = 0` unless a backend overrides (ZIP / 7z / TAR / MemIndex / `FileVersionLayer` do). FUSE crate tests cover the fat-map skip; live huge-dir RSS is optional evidence.

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

Residual: crate-local `PathIntern` (not the index `StringPool`). Folder-cache **build** still copies each path string once per BFS level; the live map is `HashMap<u32, _>`. AutoMount prefix search is still linear over mounted points. No FileInfo cache of nested roots.

### Codec block maps (already close)

- [x] Keep zstd/bzip2/gzip seek maps as sealed SoA (`Vec<u64>` pairs or parallel columns), mmap-friendly
- [x] Avoid per-block structs on import/export of `zstdblocks` / `bzip2blocks` / RGZI paths
- [x] Document residual if any map still stores `Vec<(u64,u64)>` only for API convenience

Residual (API-only): Python/SQLite `zstdblocks` / `bzip2blocks` and `GzipSeekIndexBlob.points` still use `Vec<(u64, u64)>` at import/export. Live stores are `Vec<FrameInfo>`, `Arc<Vec<BlockInfo>>`, and `Vec<Checkpoint>`.

---

## P2 — situational / bulk buffers

### Hash / fingerprint fixed windows

- [ ] Nested (and similar) fingerprints: fixed head/mid/tail buffers only — no full-body `Vec` unless policy requires
- [ ] Content-hash fill: stream into fixed hasher state; same pattern as tarstats edge samples

### SQLite bulk insert staging

- [ ] Stage build rows as SoA / batch binds before `insert_files_batch` (path TAR/ZIP/7z cold build)
- [ ] Does not change on-disk SQLite shape; only peak during build

### Overlay / write path

- [ ] Overlay file-info cache: compact cookie + size/mtime, not full `FileInfo` (watch size-0 / create residuals)
- [ ] Regression: create then cat empty overlay file

### Parallel nested open pools

- [ ] Per-worker string pool / arena during eager parallel nested open, then merge into parent pool
- [ ] Avoid global pool lock contention without duplicating all strings forever

### True SIMD (only on bulk)

- [ ] CRC / memchr / bulk hash on multi-MB buffers (inflate output, full-file hash)
- [ ] **Not** a priority for short path-component lookups (intern + SoA locality wins first)

---

## Explicit non-goals (do not track as vector wins)

| Residual | Why |
|----------|-----|
| Solid 7z full-folder unpack | Payload CPU/RAM; not metadata layout |
| Full Deflate member inflate cost | Payload; cache helps reuse, not first inflate size |
| Durable save-then-free during **cold** nested build | Peak still needs full compact table to export |
| SIMD on every single-name `lookup` | Overhead dominates short strings |

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

---

## Verification notes

- Prefer RSS + wall-time benches on large flat dirs, multi-k ZIP/7z, and nested remount (`benchmarks/compare-nested-durable.sh` for durable warm).  
- Every density change needs regression tests at the lowest layer (MemIndex unit → format open → FUSE helper if only visible there).  
- Update [`docs/embedded-nested-archives.md`](../embedded-nested-archives.md) if nested live model or durable blob format changes.

## Related

- Nested compact model: [`docs/embedded-nested-archives.md`](../embedded-nested-archives.md)  
- Nested durable: outer `nestedindexes` + factory open path  
- Code: `ratarmount-index/src/mem.rs`, format sidecars (ZIP/7z), `ratarmount-fuse` readahead/list  
