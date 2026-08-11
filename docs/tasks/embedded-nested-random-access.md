# Task: Embedded / nested archive random access (no temp spool)

**Goal:** Open nested archives from a parent member `Read+Seek` stream with true random member reads, without materializing to `/tmp` (or only as last resort).

**Baseline (done):**

- AutoMount `OpenNestedReaderFn` + path spool fallback
- Nested magic open for **7z / ZIP / plain TAR**
- Outer **`.tar.gz` / `.tar.zst` / `.tar.bz2` / `.tar.xz`** top-level seekable bodies
- 7z store + pure-LZMA2 progressive member streams
- TAR nested flatten + `nestedTarMembers` stencil API

**User guide:** [`docs/embedded-nested-archives.md`](../embedded-nested-archives.md) (when `/tmp` is used, parent×nested matrix).

**Done (Phase A):** nested compressed TAR (gzip/zstd/bz2/xz) + ZIP/TAR/7z from stream.

**Not yet:** stencil formats (ISO/WARC/…) from reader, image formats from reader.

---

## Capability matrix (only “capable” formats)

| ID | Stack | Random read model | Nested no-tmp today | Target |
|----|--------|-------------------|---------------------|--------|
| N0 | Outer 7z store → inner TAR/ZIP/7z | Outer stencil + inner as now | **done** | keep |
| N1 | Outer 7z solid LZMA2 → inner TAR/ZIP/7z | Progressive outer member + inner | **done** (CPU cost on deep solid) | keep + tests |
| N2 | Outer 7z → **inner `.tar.gz` / `.tgz`** | Outer member stream + nested gzip seek + TAR | **done** | keep |
| N3 | Outer 7z → inner `.tar.zst` / `.tar.bz2` / multi-block `.tar.xz` | zstd/bzip2/xz from_reader | **done** (factory) | optional fixtures |
| N4 | Outer `.tar.gz` → inner TAR/ZIP/7z | Outer gzip seek + stencil | **done** | keep + large fixtures |
| N5 | Outer TAR/ZIP → nested gzip/xz/zstd member | Nested compress from_reader | **done** | keep |
| N5b | Outer **ZIP → inner `.tar`** | ZIP store region or deflate buffer + TAR from_reader | **done** | tests |
| N6 | ZIP store nested open | Shared region stencil | **done** (factory) | multi-disk edges |
| N7 | CPIO / AR from_reader | Stencil | path only | **no-tmp** nested |
| N8 | ISO / WARC / XAR / ASAR from_reader | Extent / record stencil | path only | **no-tmp** nested |
| N9 | SquashFS / EXT4 / FAT from_reader | FS/block RA | **SquashFS+FAT+EXT4 no-tmp** (pure) | SquashFS non-LZMA; FAT; EXT4 pure; residual pure-fail/debugfs |
| — | Solid RAR / corrupt xz without Index / libarchive-only | sequential | n/a | **out of scope** here |
| — | 7z BCJ/AES multi-GB solid progressive | full-folder residual | partial | deferred (low priority) |

---

## Phase A — Nested compressed open (highest ROI)

**Owner:** `ratarmount/src/factory.rs` (+ small TAR gzip glue if needed)  
**Depends on:** existing `SharedSeekableGzip::open_*_from_reader`, zstd/bzip2/xz `*_from_reader`, `SqliteIndexedTar::create_index_gzip` / body open

### A1. Detect nested compression in `open_nested_reader_fn`

- [x] Sniff magic after rewind: gzip `1f 8b`, zstd frame, xz, bzip2 `BZh`
- [x] Name / body probe for compressed TAR
- [x] On hit: open seekable body **from the member reader** (no copy to disk)
- [x] Keep in-memory nested indexes (`index_in_memory = true`)
- [x] On unsupported inner body: error → existing temp-spool fallback (do not regress)

### A2. Nested `.tar.gz` path (N2 / N4 / N5)

- [x] `SharedSeekableGzip::open_with_threads_from_reader(member, spacing, threads, label)`
- [x] `body_looks_like_tar_gzip` / name → `SqliteIndexedTar::create_index_gzip`
- [x] Random `open` of TAR members via existing gzip stencil (no second spool)
- [x] Log: `nested reader open: {label} gzip→tar checkpoints=N`
- [x] Fix `store_tarstats` for virtual nested labels (`store_tarstats_for_label`)

### A3. Nested `.tar.zst` / `.tar.bz2` / multi-block `.tar.xz`

- [x] zstd / bzip2 / xz from_reader → TAR when body looks like TAR (same factory path)
- [x] Dedicated unit fixtures for zst/bz2/xz nested (optional)
- [x] xz single-block Index maps retained (range decode); no free random access claim for lzma-alone / Index-less corrupt xz

### A4. Tests (no `/tmp` assertion)

- [x] Unit: outer **store** 7z + `inner.tar.gz` (≥2 files) via `open_nested_reader_fn` + mid-member seek
- [x] Unit: outer **store** 7z + `inner.zip` random read no-tmp
- [x] Unit: pure Cursor `.tar.gz` → nested gzip→tar
- [ ] Unit: outer plain TAR + nested `.tar.gz` no-tmp (covered by cursor + factory path)
- [ ] Optional harness: `nested-7z-tar-gz` allowlist entry

### A5. Docs / parity

- [ ] Update `docs/parity-todo.md` AutoMount / nested row
- [ ] Note in sevenzip module docs: nested gzip TAR supported without temp when A1 lands
- [ ] Cross-link this file from `gap-implementation-batch.md`

---

## Phase B — Stencil archives from reader

**Owners:** per-format crate + factory sniff

### B1. CPIO + AR

- [x] `open_from_reader` on CPIO / AR mount sources (batch 2026-07-28 agents)
- [x] Factory nested magic: CPIO / AR in `open_nested_reader_fn`
- [ ] Optional: nested `inner.newc.cpio` in store 7z end-to-end harness

### B2. ISO 9660 / WARC / ASAR (low-hanging stencil)

- [x] ISO / WARC / ASAR `open_from_reader` (shared `Read+Seek`) — batch 2026-07-28
- [x] Factory nested detect (ISO PVD/`CD001`, WARC/, `.asar`, …)
- [x] Unit tests per crate (path + Cursor)
- [x] XAR / CAB (store/MSZIP) / SQLAR / FAT `open_from_reader` — wave2 agents
- [x] Factory wire + e2e nested CPIO/AR/WARC/ASAR tests
- [x] SquashFS nested `open_from_reader` + factory wire (non-LZMA no-tmp; classic LZMA spool residual)
- [x] EXT4 nested `open_from_reader` + factory wire (pure shared; pure-fail → spool)
- [ ] CAB LZX residual (spool → libarchive; documented FR-8)

### B3. ZIP store polish

- [x] Explicit tests: nested store ZIP in 7z + TAR inside ZIP no-tmp (factory tests)
- [x] Document deflate members: full-member inflate + cache (not progressive); still no outer temp

---

## Phase C — Disk images from reader (when practical)

### C1. SquashFS / EXT4 / FAT

- [x] SquashFS `open_from_reader` / factory nested probe (gzip/zstd/xz/…); classic LZMA residual
- [x] FAT `open_from_reader`
- [x] EXT4 `open_from_reader` / factory nested probe (pure ext4-view)
- [x] Nested `.sqfs`/`.snap`/`.squashfs` recursive default extensions + reader API
- [ ] Prefer path/mmap when parent is a real file (optional polish)

---

## Phase D — Explicit non-goals (this list)

- Pure progressive multi-GB 7z BCJ/AES (separate sevenzip task)
- Pure RAR solid random access
- Nested lrzip without materialize
- Guaranteeing zero CPU for solid outer 7z deep members (no-tmp ≠ free)

---

## Suggested agent batches (non-overlapping)

| Batch | Crates | Tasks |
|-------|--------|-------|
| 1 | `ratarmount` factory | A1–A3 nested compress open |
| 2 | `formats-sevenzip` + `compositing` tests | A4 7z→tar.gz fixtures |
| 3 | `formats-cpio` + `formats-ar` + factory | B1 |
| 4 | `formats-iso9660` + warc + xar + asar + factory | B2 |
| 5 | docs + harness | A5 + allowlist |

Run `cargo fmt --all` before every commit (CI fmt gate).

---

## Acceptance criteria (capable set)

1. **N2:** `outer.7z` (store) + `inner.tar.gz` mounts with `-r` **without** writing nested body to temp; random `cat` of ≥2 inner TAR files succeeds.
2. **N4:** large-ish outer `.tar.gz` + nested 7z still no-tmp (regression).
3. Nested plain TAR/ZIP/7z unchanged green.
4. Unsupported nested formats still fall back to temp spool (no hard fail).
5. Debug logs show `nested reader open: … gzip→tar` (or zstd/bz2) rather than only temp spool.
)
