# Task: Port SevenZip random-access backend (from hilather/ratarmount PR #1)

**Status:** **done** (2026-07-25 baseline; **2026-07-26** BCJ2 / stream pack / metadata-only encrypt; **2026-08** nested durable structure warm remount)  
**Priority:** high (parity + performance vs libarchive/py7zr)  
**Source PR:** https://github.com/hilather/ratarmount/pull/1  
**Merged commit (Python):** tip `35a089b` on branch `feature/sevenzip-random-access` in `hilather/ratarmount`

## Implementation location

| Piece | Path |
|-------|------|
| Crate | `ratarmount-formats-sevenzip/` |
| Parser | `src/parse.rs` |
| Codecs | `src/decode.rs` (Copy, LZMA/LZMA2 via liblzma raw, Deflate, BZip2, AES-256-CBC) |
| MountSource | `src/lib.rs` (`backendName=SevenZipMountSource`) |
| Factory | preferred over libarchive for `.7z` in `ratarmount/src/factory.rs` |
| CLI | `--password` (repeatable) |
| Harness | `test-harness/run-phase9-sevenzip.sh` (`phase9-sevenzip.txt`; optional 4th field = password) |
| Nested durable | outer `nestedindexes` file table **+ structure** sidecars (no header re-parse on warm hit) |

### Acceptance checklist (shipped)

- [x] `store-copy-two-files.7z` cold mount + random `cat`
- [x] `lzma2-two-files-and-medium.7z` solid open
- [x] Nested: `nested-inner-hello.7z` with `-r` → `inner-hello.7z/hello.txt`
- [x] Encrypted: `encrypted-hello.7z` with `--password secret` (unit + phase9 harness password field)
- [x] Metadata-only encrypted mount (list/stat without password; open → `PermissionDenied` / FUSE EACCES)
- [x] Unit tests + harness allowlist green
- [x] BCJ / BCJ2 multi-stream (`bcj2-*.7z`, `bcj-lzma2-x86.7z`)
- [x] FilePackSource + AES range decrypt (pack not always fully preloaded)
- [x] Nested durable warm remount: compact file table **+** archive structure sidecars

### Residual (not open P0)

| Residual | Status |
|----------|--------|
| Progressive multi-GB solid decode that never materializes full unpack for **BCJ / AES / non-pure-LZMA2** folders | **Documented residual** — pure LZMA2 large folders use `Lzma2MemberReader` with a live sequential cursor + independent-chunk resume; other solid folders may still full-folder materialize |
| Full Python `test_sevenzip.py` line-for-line scenario count | Partial harness + cargo unit coverage; expand opportunistically |
| Nested body full-content fingerprint for multi-GB solid | Store/stencil: head/mid/tail. Progressive compressed parent member: head+size only (mid/tail would fully decompress) |

## Goal (historical)

Implement a native **custom 7z MountSource** in `ratarmount-rs` that matches the Python backend’s random-access design:

- Parse 7z headers **once** and store real **pack / folder offsets** in the SQLite index  
- Open members **without** re-scanning the archive from the start  
- Prefer this backend over libarchive for `.7z` (keep a fallback for unsupported codecs)

## Python reference (sibling checkout)

| Path | Role |
|------|------|
| `core/ratarmountcore/sevenzip.py` | Header parse, pack streams, folder decode, streaming chunk cache |
| `core/ratarmountcore/mountsource/formats/sevenzip.py` | `SevenZipMountSource`, SQLite index rows, open paths |
| `core/tests/test_sevenzip.py` | 42 tests (1 skip without system `7z`) |
| `tests/*.7z` | Fixtures (store/copy, lzma2, encrypted, nested, …) |
| `benchmarks/benchmark-7z-random-access.py` | Random-access benchmark |

## Functional requirements

1. **Store / Copy members** — true random access via stencil (like TAR non-sparse).  
2. **LZMA / LZMA2 / Deflate / BZip2** — streaming folder decode with chunk cache for large solid folders (do not hold entire unpacked folder in RAM when above threshold).  
3. **Encrypted folders** — AES-256 via password trial (`--password` / passwords list); metadata-only without password.  
4. **Factory order** — try custom `sevenzip` before libarchive/py7zr-style fallbacks.  
5. **Recursive 7z-in-7z** — works with existing AutoMount (`-r`).  
6. **Index interop** — `backendName` distinct (e.g. `SevenZipMountSource` matching Python) + pack offset columns/tables as in Python schema.  
7. **Tests** — port `test_sevenzip.py` scenarios via harness allowlist; mount + `cat` fixtures under `tests/*.7z`.

## Layout

```
ratarmount-formats-sevenzip/
  src/
    lib.rs          # MountSource + index build/open + durable structure export/import
    parse.rs        # 7z header / pack / folder parse (port of sevenzip.py)
    decode.rs       # folder decompress + StreamingFolderDecoder + pure-LZMA2 progressive
```

Wire into `ratarmount/src/factory.rs` for `*.7z` detection and nested durable open.

## Regression filters

```bash
cargo test -p ratarmount-formats-sevenzip --lib encrypted
cargo test -p ratarmount-formats-sevenzip --lib durable_structure
cargo test -p ratarmount --bin ratarmount nested_durable_7z
# optional harness (needs sibling Python fixtures + built binary):
# ./test-harness/run-phase9-sevenzip.sh
```

## Implementation notes

- Reuse `ratarmount-index` bulk insert PRAGMAs / transactions.  
- Reuse `StenciledFile` / `SegmentedFile` for Copy members.  
- Solid folders: port `_DEFAULT_SMALL_FOLDER_THRESHOLD` (4 MiB) and chunk cache (1 MiB × 64).  
- Prefer existing crates (`lzma-rs` / `xz2`, `flate2`, `bzip2`) over shelling out to `7z`.  
- Nested durable: `DurableSevenZipArchive` sidecars in outer `nestedindexes` (see `docs/embedded-nested-archives.md`).

## 2026-07-26 — Python a0bc76e parity (nested spool / LZMA2 solid RA)

Ported from hilather/ratarmount `master` commit `a0bc76e` (*Fix nested 7z spool cache and LZMA2 random access for solid archives*):

- `index_lzma2_chunks` + `Lzma2RandomAccessDecoder` in `decode.rs`
- Pure LZMA2 member open uses folder-level filter decompress (not per-chunk filter rebinding)
- Packed stream cache + O(1) `(pack,unpack)` entry lookup in `SevenZipMountSource`
- Unit test: `index_lzma2_chunks_sum_unpacked_sizes`; integration: `lzma2_two_files` mid-open consistency

Nested on-disk spool is avoided when AutoMount uses the nested reader path (store outer preferred).

## 2026-08 — Nested durable structure + encrypted coverage lock

- Nested 7z warm remount imports compact file table **and** structure (folders/pack/member cookies) — no header re-parse on hit (`opened_from_durable_structure`).
- Encrypted: cargo tests for password open, metadata-only `PermissionDenied`, wrong password, nested `open_from_reader`; phase9 harness supports `|password` field.
