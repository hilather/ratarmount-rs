# Task: Port SevenZip random-access backend (from hilather/ratarmount PR #1)

**Status:** **done** (2026-07-25)  
**Priority:** high (parity + performance vs libarchive/py7zr)  
**Source PR:** https://github.com/hilather/ratarmount/pull/1  
**Merged commit (Python):** `231147e` on branch `feature/sevenzip-random-access` in `hilather/ratarmount`

## Implementation location

| Piece | Path |
|-------|------|
| Crate | `ratarmount-formats-sevenzip/` |
| Parser | `src/parse.rs` |
| Codecs | `src/decode.rs` (Copy, LZMA/LZMA2 via liblzma raw, Deflate, BZip2, AES-256-CBC) |
| MountSource | `src/lib.rs` (`backendName=SevenZipMountSource`) |
| Factory | preferred over libarchive for `.7z` in `ratarmount/src/factory.rs` |
| CLI | `--password` (repeatable) |
| Harness | `test-harness/run-phase9-sevenzip.sh` |

### Acceptance checklist

- [x] `store-copy-two-files.7z` cold mount + random `cat`
- [x] `lzma2-two-files-and-medium.7z` solid open
- [x] Nested: `nested-inner-hello.7z` with `-r` → `inner-hello.7z/hello.txt`
- [x] Encrypted: `encrypted-hello.7z` with `--password secret`
- [x] Unit tests + harness allowlist green
- [ ] Progressive streaming decoder for huge solid folders (currently full-folder cache; fine for fixtures ≤64 MiB unpacked)

## Goal

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
3. **Encrypted folders** — AES-256 via password trial (`--password` / passwords list); or clear fallback error + factory routing.  
4. **Factory order** — try custom `sevenzip` before libarchive/py7zr-style fallbacks.  
5. **Recursive 7z-in-7z** — works with existing AutoMount (`-r`).  
6. **Index interop** — `backendName` distinct (e.g. `SevenZipMountSource` matching Python) + pack offset columns/tables as in Python schema.  
7. **Tests** — port `test_sevenzip.py` scenarios via harness allowlist; mount + `cat` fixtures under `tests/*.7z`.

## Suggested Rust layout

```
ratarmount-formats-sevenzip/
  src/
    lib.rs          # MountSource + index build/open
    parse.rs        # 7z header / pack / folder parse (port of sevenzip.py)
    decode.rs       # folder decompress + StreamingFolderDecoder
```

Wire into `ratarmount/src/factory.rs` for `*.7z` detection.

## Acceptance criteria

- [ ] `store-copy-two-files.7z` cold mount + random `cat` works  
- [ ] `lzma2-two-files-and-medium.7z` solid-ish open without full re-scan per open  
- [ ] Nested: `nested-inner-hello.7z` with `-r`  
- [ ] Encrypted: `encrypted-hello.7z` with `--password secret` (or documented skip)  
- [ ] Random-access benchmark vs previous libarchive path shows clear win on multi-member archives  
- [ ] Unit/integration tests green; allowlist entry in `test-harness/`

## Out of scope (initially)

- Full pure-Rust coverage of every 7z codec py7zr supports  
- Windows/macOS packaging  
- Changing the Python tree (this task is Rust-only; Python already has the PR)

## Implementation notes

- Reuse `ratarmount-index` bulk insert PRAGMAs / transactions.  
- Reuse `StenciledFile` / `SegmentedFile` for Copy members.  
- Solid folders: port `_DEFAULT_SMALL_FOLDER_THRESHOLD` (4 MiB) and chunk cache (1 MiB × 64).  
- Prefer existing crates (`lzma-rs` / `xz2`, `flate2`, `bzip2`) over shelling out to `7z`.
