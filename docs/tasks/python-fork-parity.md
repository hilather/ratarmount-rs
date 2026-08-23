# Tasks: Python fork improvements → Rust parity

**Source:** [hilather/ratarmount](https://github.com/hilather/ratarmount) branch `feature/sevenzip-random-access`  
**Baseline:** `origin/master` @ `1d44bec`  
**Tip (2026-07-26):** `35a089b` — *Improve 7z: BCJ2, streamed pack/AES, metadata-only encrypt*  
**Rust tree:** `/home/mbrewer/projects/ratarmount-rs`  
**Fixtures:** sibling Python checkout `tests/` (shared)

This document turns the fork’s recent work (8 commits past upstream master) into ordered implementation tasks for **ratarmount-rs**.

**Status (2026-07-26): IMPLEMENTED** — P0–P3 landed in ratarmount-rs (harness green). Remaining polish (true progressive LZMA chunk streaming for multi-GB solids without full unpack buffer; CAB LZX; lrzip) is deferred as matching Python non-goals or follow-ups.

**Note:** the header is **IMPLEMENTED**; inner `[ ]` checkboxes below are **historical** (the pre-land task list). Do not treat them as open work. Later 7z progressive AES+LZMA2 / BCJ+LZMA2 lives in [`sevenzip-random-access.md`](sevenzip-random-access.md) / [`parity-todo.md`](../parity-todo.md).

---

## Commit map (Python → Rust gap)

| Commit | Theme | Rust status |
|--------|--------|-------------|
| `231147e` | Custom `SevenZipMountSource` + pack offsets | **~ done** (baseline port; see 7z upgrade tasks) |
| `c1b437a` | LZMA2 chain / folder-level filter props | **verify** (single-coder path exists; multi-coder BCJ+LZMA2 **missing**) |
| `337e6e5` | Random-access CPIO / ISO9660 / WARC / XAR (+ stencil base) | **partial** (CPIO newc/crc only; rest = sequential libarchive) |
| `eec8e21` | Seekable LZ4 frame + block index | **missing** |
| `86198ae` | Seekable LZO, compress(.Z), LZIP, LZMA Alone | **missing** |
| `0945328` | Random-access CAB (store + MSZIP) | **missing** (libarchive sequential only) |
| `35a089b` | 7z BCJ2, streamed pack/AES, metadata-only encrypt | **missing** |
| `768927a` | Changelog / fixture docs | n/a |

Python intentionally leaves on **libarchive only**: lrzip, grzip, rpm (partial), uuencode; CAB **LZX/Quantum**.

---

## Priority tiers

| Tier | Goal |
|------|------|
| **P0** | Close 7z gap with Python tip (BCJ2, stream, metadata-only) — fork’s headline work |
| **P1** | Stencil archive backends that replace sequential libarchive opens |
| **P2** | Seekable outer codecs (LZ4 first; then LZO/LZIP/.Z/LZMA) |
| **P3** | Tests, harness, factory order, docs |

---

## P0 — SevenZip upgrades (match Python tip)

**Python refs:** `core/ratarmountcore/sevenzip.py`, `mountsource/formats/sevenzip.py`, `core/tests/test_sevenzip.py`  
**Rust refs:** `ratarmount-formats-sevenzip/{src/parse.rs,decode.rs,lib.rs}`  
**Fixtures:** `tests/bcj2-*.7z`, `bcj-lzma2-x86.7z`, `encrypted-hello.7z`, solid large 7z

### T0.1 — BCJ / Delta filter chains (single primary stream)

Python supports BCJ/Delta + LZMA/LZMA2 as multi-coder folders. Rust `is_supported_for_open` only allows **one** non-AES coder.

- [ ] Parse filter coders (`METHOD_BCJ*`, `METHOD_DELTA`) and props
- [ ] Decode pipeline: decompress codec → apply BCJ/Delta inverse filters
- [ ] Fixture: `tests/bcj-lzma2-x86.7z` (from `c1b437a`)
- [ ] Unit tests: folder props / dict size from folder-level property byte (port `test_lzma2_dict_size_*`, `test_bcj_lzma2_roundtrip`)

### T0.2 — BCJ2 multi-stream folders

Python pure-Python BCJ2 decoder; custom backend covers installers py7zr rejects.

- [ ] Support folders with BCJ2 (4 in-streams → 1 out-stream) + LZMA/LZMA2/Copy side streams
- [ ] Read **multiple pack streams** per folder (not only first pack)
- [ ] Fixtures: `tests/bcj2-default.7z`, `bcj2-lzma.7z` (+ `bcj2-x.bin` content check)
- [ ] Harness allowlist entries + factory open without falling through to libarchive

### T0.3 — Streamed pack source + AES range decrypt

Python no longer always loads full packed folder into RAM: file-backed pack reads + AES-CBC decrypt of needed ranges; streaming chunk cache for large solid folders.

Rust today: `read_packed` → full `Vec<u8>` for whole pack; small-folder full decompress; no progressive stream for large solid.

- [ ] `PackSource` abstraction: read pack range from archive path/fd
- [ ] AES-256-CBC **range** decrypt (aligned blocks) without buffering entire ciphertext
- [ ] Progressive folder decoder + chunk cache (port thresholds: small folder 4 MiB, chunk 1 MiB, max ~64 chunks)
- [ ] Mid-member seek must not require holding entire solid unpack in RAM
- [ ] Tests: `test_streaming_*`, `test_file_pack_source_matches_bytes`, large solid seek

### T0.4 — Metadata-only mount for encrypted 7z

Python: without password, **list/stat** work; `open()` errors asking for password.

Rust today: open of encrypted archive **fails entirely** if no password (or tries passwords only at open).

- [ ] Parse + index encrypted archives with empty/missing password
- [ ] `lookup` / `list` / `list_mode` succeed; `open` returns clear “password required”
- [ ] With `--password`, open behaves as today
- [ ] Port `test_encrypted_missing_password_metadata_only`

### T0.5 — SevenZip test/harness parity

- [ ] Expand `test-harness/phase9-sevenzip.txt` with BCJ2, encrypted metadata-only smoke, nested encrypted
- [ ] Port remaining `test_sevenzip.py` cases not yet covered (index reload, automount nested, streaming)
- [ ] Update `docs/tasks/sevenzip-random-access.md` checklist (mark progressive decode / BCJ2)

---

## P1 — Stencil random-access archives (replace sequential libarchive)

**Python refs:** `mountsource/formats/{stenciled,cpio,iso9660,warc,xar,cab}.py`, `core/tests/test_store_archives.py`  
**Pattern:** parse once → SQLite rows with absolute `offset` + `size` → open via stencil (`StenciledFile`).

### T1.0 — Shared `StenciledArchiveMountSource` helper (optional but DRY)

- [ ] Small Rust trait/helper: build index from row iterator + open by offset/size (mirrors Python `StenciledArchiveMountSource`)
- [ ] Reuse existing `ratarmount_compress::StenciledFile` + `ratarmount_index`

### T1.1 — CPIO completeness

Rust has **newc/crc** only (`ratarmount-formats-cpio`). Python also: **odc, binary, hpbin, hpodc**.

- [ ] Parse odc / binary / hp variants
- [ ] Fixtures: `single-file.{newc,crc,odc,bin,hpbin,hpodc}.cpio`
- [ ] Nested: `nested-tar-in-cpio.newc.cpio` + automount `-r` → `/nested/inner.tar/inner.txt`
- [ ] Factory prefers CPIO over libarchive for all supported magics

### T1.2 — ISO 9660 random-access backend

Today: `single-file.iso.bz2` via materialize + **libarchive sequential**.

- [ ] New crate or module `formats-iso9660`: PVD @ sector 16, directory walk, extent LBA → offset
- [ ] Stencil open of file extents (Rock Ridge / Joliet optional follow-up)
- [ ] Factory prefer over libarchive for ISO magic / `.iso`
- [ ] Tests: `test_store_archives.TestISO` + harness (after bzip2 materialize path)

### T1.3 — WARC random-access backend

Today: libarchive; Python custom uses **payload** offsets from `Content-Length` (note: libarchive may include HTTP headers — harness already documents md5 difference).

- [ ] Parse `WARC/1.x` records; index payload offsets + sizes; URI → safe paths
- [ ] Prefer over libarchive for WARC magic / `.warc`
- [ ] Fixtures: `hello-world.warc`, `simple-response.warc`
- [ ] Align expected digests with **Python** payload semantics (may change harness vs current libarchive lines)

### T1.4 — XAR random-access backend

- [ ] Parse XAR header + zlib TOC XML; heap offsets; store / gzip / bzip2 members
- [ ] Prefer over libarchive for `.xar`
- [ ] Fixture: `single-file.xar`

### T1.5 — CAB random-access (store + MSZIP)

- [ ] New `formats-cab`: CFHEADER / CFFOLDER / CFFILE / CFDATA
- [ ] **typeCompress none:** true multi-block stencil
- [ ] **MSZIP:** per-folder CFDATA inflate (`CK` + deflate), cache reconstructed folder stream
- [ ] **LZX / Quantum:** reject → factory fall through to libarchive (match Python)
- [ ] Fixture: `single-file.cab` + synthetic multi-file / MSZIP unit tests from `test_store_archives.TestCAB`

### T1.6 — Factory detection order

Match Python preference (custom stencil/random-access **before** libarchive):

```
… → CAB → CPIO → ISO → WARC → XAR → SevenZip → … → libarchive (long-tail / LZX CAB / etc.)
```

- [ ] Update `ratarmount/src/factory.rs` detection order + compressed-container handoff after materialize
- [ ] `--print-features` lists new backends
- [ ] Keep libarchive as fallback when custom open raises “unsupported codec”

---

## P2 — Seekable outer compression codecs

**Python refs:** `LZ4File.py`, `LZOFile.py`, `LzipFile.py`, `CompressZFile.py`, `LZMAFile.py`, `compressions.py`  
**Rust today:** gzip / bzip2 / xz / zstd only (`ratarmount-compress`)

### T2.1 — LZ4 frame (`IndexedLZ4File`)

Highest value among the new stream codecs (true block index).

- [ ] Frame parse: magic, FLG, block independence, skippable frames
- [ ] Block index: compressed offset ↔ uncompressed offset
- [ ] Independent blocks: decompress target only; dependent: decode from prior boundary
- [ ] Wire into factory for `.lz4` / `.tar.lz4` (prefer over libarchive)
- [ ] Fixtures: `simple.lz4`, `multiblock-independent.lz4`, `multiblock-dependent.lz4`, `nested-tar.skippable-frame.lz4`
- [ ] Harness: new `phase*-lz4` allowlist + cargo tests porting `test_LZ4File.py`

**Deps:** `lz4_flex` / `lz4` crate or `liblz4` FFI.

### T2.2 — LZOP / LZO (`IndexedLZOFile`)

- [ ] Parse LZOP multi-block layout; per-block index (blocks independent)
- [ ] Decompress via `liblzo2` (system) or pure crate if available
- [ ] Fixtures: `simple.lzo` (+ multiblock if present)
- [ ] Factory for `.lzo` / `.tar.lzo`

### T2.3 — LZIP multimember (`IndexedLzipFile`)

- [ ] Walk members via trailer `member_size`; per-member LZMA1 raw decode
- [ ] Seek restarts at member boundary (cache small members)
- [ ] Fixture: `simple.lzip`

### T2.4 — compress (.Z) and LZMA Alone

Python: one-shot decompress → seekable buffer (acceptable for typical sizes).

- [ ] `.Z` LZW (crate e.g. `weezl` / `lzw` or small pure impl) → `SeekableBody`
- [ ] `.lzma` FORMAT_ALONE via existing xz/lzma stack → `SeekableBody`
- [ ] Fixtures: `simple.Z`, raw `.lzma` if present; detect in factory
- [ ] Still leave **lrzip / grzip / zlib wrapper / uuencode** on materialize or libarchive (match Python “intentionally leave”)

### T2.5 — Codec registration matrix

- [ ] Extend `detect_compression` + `open_seekable_*` / materialize fallbacks
- [ ] Document in `docs/parity-todo.md` compression table
- [ ] Optional: `--use-backend` selection when multiple backends could claim a file (Python has this; Rust still fixed order)

---

## P3 — Cross-cutting tests, docs, productization

### T3.1 — Harness expansion

| New runner | Sources |
|------------|---------|
| `phase9-stencil-archives` | CPIO variants, ISO, WARC, XAR, CAB |
| `phase-lz4` / stream-codecs | LZ4, LZO, LZIP, .Z |
| extend `phase9-sevenzip` | BCJ2, encrypted metadata-only, nested encrypted |

- [ ] Wire into `run-all-phases.sh`
- [ ] Skip cleanly when optional libs missing (`liblzo2`, etc.)

### T3.2 — Unit tests in crates

- [ ] Mirror `test_store_archives.py`, `test_stream_compressions.py`, `test_LZ4File.py`, expanded `test_sevenzip.py`
- [ ] Prefer `RATARMOUNT_PY_ROOT` fixtures over copying binaries into Rust tree

### T3.3 — Docs & parity checklist

- [ ] Update `docs/parity-todo.md` rows for:
  - CAB/ISO/WARC/XAR random-access (not only “libarchive sequential”)
  - lz4/lzo/lzip/Z/lzma stream codecs
  - SevenZip BCJ2 / stream / metadata-only
- [ ] Extend `docs/phase9-formats.md` with stencil backends
- [ ] Refresh `docs/tasks/sevenzip-random-access.md` (this fork tip supersedes older “out of scope” notes for BCJ2/stream)
- [ ] README “what’s implemented” table

### T3.4 — Benchmarks (optional)

- [ ] Port or re-home `benchmarks/benchmark-7z-random-access.py` ideas for Rust (cold open + random reads on solid 7z)
- [ ] Compare custom 7z vs libarchive path; track streaming memory for multi-GB solids when T0.3 lands

---

## Suggested implementation order

1. **T0.4** metadata-only encrypted 7z — small UX/parity win  
2. **T0.1 + T0.2** BCJ/BCJ2 — unlocks real installer 7z fixtures  
3. **T0.3** streamed pack/AES + chunk cache — correctness under large solids  
4. **T1.5 CAB** + **T1.2 ISO** + **T1.3 WARC** + **T1.4 XAR** (can parallelize after T1.0 helper)  
5. **T1.1** CPIO odc/binary variants  
6. **T2.1 LZ4** then **T2.2–T2.4** other stream codecs  
7. **T3.*** harness/docs continuously with each backend  

Factory + allowlist updates should land **with** each backend, not as a big-bang at the end.

---

## Explicit non-goals (match Python fork)

| Item | Reason |
|------|--------|
| CAB LZX / Quantum custom decoder | Python falls back to libarchive |
| lrzip / grzip custom | libarchive only in Python |
| Full pure in-process SquashFS/EXT4 | Separate existing MVP track (`unsquashfs` / `debugfs`) |
| ASAR / PDF / OGG / Git / FAT | Other upstream features, not this fork branch |

---

## Acceptance (definition of “fork parity” for this branch)

Rust is at parity with `hilather/ratarmount@35a089b` for this workstream when:

1. All `tests/bcj2-*.7z` and `bcj-lzma2-x86.7z` mount and read via **custom** SevenZip backend.  
2. Encrypted 7z lists without password; open requires password.  
3. Large solid 7z open/seek does not require full pack+unpack buffers for multi-100 MB folders (streaming path).  
4. CPIO (all variants in `test_store_archives`), ISO, WARC, XAR, CAB store/MSZIP use **offset-based** open, not full sequential libarchive extract per open.  
5. LZ4 independent-block random access works on `multiblock-independent.lz4`; dependent blocks still seek correctly.  
6. LZO / LZIP / .Z / LZMA Alone open as seekable bodies for fixtures under `tests/simple.*`.  
7. Harness phases green with `RATARMOUNT_PY_ROOT` pointing at the Python tree.

---

## Quick file checklist (new Rust surface)

```
ratarmount-formats-sevenzip/   # extend parse/decode/lib (P0)
ratarmount-formats-cpio/       # extend variants (T1.1)
ratarmount-formats-iso9660/    # new (T1.2)
ratarmount-formats-warc/       # new (T1.3)
ratarmount-formats-xar/        # new (T1.4)
ratarmount-formats-cab/        # new (T1.5)
ratarmount-compress/           # lz4, lzo, lzip, z, lzma alone (P2)
ratarmount/src/factory.rs      # detection order
test-harness/phase9-*.txt      # allowlists
docs/parity-todo.md            # status table
docs/tasks/python-fork-parity.md  # this file
```
