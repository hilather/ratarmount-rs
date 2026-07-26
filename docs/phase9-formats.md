# Phase 9 — long-tail formats

## Delivered (pure Rust)

| Format | Crate | `backendName` | Notes |
|--------|-------|---------------|--------|
| Unix AR | `ratarmount-formats-ar` | `ARMountSource` | GNU-style `name/` members |
| CPIO newc/crc | `ratarmount-formats-cpio` | `CpioMountSource` | Magic `070701` / `070702` |

## Delivered (system libarchive FFI)

| Format | Crate | `backendName` | Notes |
|--------|-------|---------------|--------|
| CAB, XAR, WARC, ISO, 7z, RAR, LHA, … | `ratarmount-formats-libarchive` | `LibarchiveMountSource` | Sequential re-scan on open (like Python); needs `libarchive-dev` |

Detection order in factory: ZIP → AR → CPIO → **libarchive** → TAR → single file.  
Compressed containers (e.g. `.iso.bz2`) materialize then hand off to libarchive.

## Still separate backends (optional / pure)

RAR via pure crates, SquashFS, EXT4, FAT, PDF, Git — same split as Python optional extras.

## Tests

```bash
./test-harness/run-phase9-ar-cpio.sh
./test-harness/run-phase9-libarchive.sh
```

