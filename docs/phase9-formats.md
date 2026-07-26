# Phase 9 — long-tail formats

## Delivered (pure Rust)

| Format | Crate | Notes |
|--------|-------|--------|
| Unix AR | `ratarmount-formats-ar` | GNU-style `name/` members |
| CPIO newc/crc/odc/binary | `ratarmount-formats-cpio` | Stencil offsets |
| ISO 9660 | `ratarmount-formats-iso9660` | Extent LBA stencils |
| WARC | `ratarmount-formats-warc` | Payload offsets |
| XAR | `ratarmount-formats-xar` | TOC heap offsets; gzip/bzip2 members |
| CAB store/MSZIP | `ratarmount-formats-cab` | LZX/Quantum → libarchive |
| SQLAR | `ratarmount-formats-sqlar` | Unencrypted SQLite archive |
| SevenZip (custom) | `ratarmount-formats-sevenzip` | Pack offsets; BCJ/BCJ2; AES; meta-only encrypt |
| ASAR | `ratarmount-formats-asar` | Electron pickle+JSON header; stencil files |
| OGG | `ratarmount-formats-ogg` | Page demux by stream serial |
| HTML | `ratarmount-formats-html` | Embedded `data:` URLs as virtual files |
| PDF | `ratarmount-formats-pdf` | Embedded attachments (lopdf MVP) |
| Git | `ratarmount-formats-git` | `git2` tree at HEAD/ref |

## Delivered (helper / materialize MVP)

| Format | Crate | Notes |
|--------|-------|--------|
| SquashFS | `ratarmount-formats-squashfs` | `unsquashfs` → FolderMountSource |
| EXT2/3/4 | `ratarmount-formats-ext4` | Superblock magic `0xEF53`; `debugfs rdump` → FolderMountSource |
| FAT12/16/32 | `ratarmount-formats-fat` | Pure Rust via `fatfs` crate (in-process cluster reads) |

## Delivered (system libarchive FFI)

| Format | Crate | Notes |
|--------|-------|--------|
| RAR, LHA, CAB LZX/Quantum, … | `ratarmount-formats-libarchive` | Sequential re-scan; fallback for unsupported custom codecs |

Detection order (uncompressed): 7z → ZIP → ASAR → AR → CPIO → ISO → WARC → XAR → CAB → OGG → PDF → HTML → SQLAR → SquashFS → EXT4 → FAT → libarchive → TAR → single file.  
Git: bare/`.git` dirs (worktrees need `RATARMOUNT_FORCE_GIT=1`).  
Compressed outer streams materialize (or SeekableBody for TAR), then re-detect ISO/WARC/XAR/CAB/EXT4/FAT/libarchive/TAR.

## Still open

Pure in-process SquashFS/EXT4, encrypted SQLAR, full PDF page images, GNU incremental TAR.

## Tests

```bash
./test-harness/run-phase9-ar-cpio.sh
./test-harness/run-phase9-stencil-archives.sh
./test-harness/run-phase9-libarchive.sh
./test-harness/run-phase9-sevenzip.sh
./test-harness/run-phase9-sqlar-squashfs.sh
./test-harness/run-phase9-ext4.sh
./test-harness/run-phase9-fat.sh
./test-harness/run-phase9-asar.sh
./test-harness/run-phase9-misc-formats.sh
./test-harness/run-phase-stream-codecs.sh
```

