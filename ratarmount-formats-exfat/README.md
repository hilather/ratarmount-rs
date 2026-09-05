# ratarmount-formats-exfat

Read-only [exFAT](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification) filesystem image `MountSource` for the Rust ratarmount rewrite (F-8 crate train).

This crate is **not** wired into the session factory yet. Probe order / `formats-all` land in the orchestrator factory PR. Nested AutoMount of `*.exfat` members will use `ExfatMountSource::open_from_reader` once that glue exists.

## Features

| Feature | Default | Purpose |
|---------|---------|---------|
| *(none)* | yes | RO list / lookup / open; path and stream opens |

In-process cluster reads (no loop mount, no `exfat-fuse`). Magic is OEM `"EXFAT   "` at byte 3 plus boot signature `0x55AA`. FAT12/16/32 images are rejected (`looks_like_exfat` is false on a FAT32 boot sector).

## Nested / `open_from_reader` (no host temp)

Nested exFAT members open from any `Read + Seek` stream via `ExfatMountSource::open_from_reader` (and `open_from_reader_with_offset` for a partition at a byte offset):

1. Probe the boot sector (OEM name; no filename)
2. Retain the reader under a mutex
3. Re-seek the shared body for each list / lookup / open

**No `/tmp` / `NamedTempFile` for this path.** The image is not copied into a second buffer by this crate (the parent may already hold a `Cursor` or stencil).

| Case | Behaviour |
|------|-----------|
| Nested seekable member | No host temp |
| Partitioned image | `open_with_offset` / `open_from_reader_with_offset` |
| Factory wiring | Orchestrator must call `open_from_reader` from nested AutoMount (not this crate) |

## Residuals

- Full up-case-table Unicode casefold (v1 is ASCII case-insensitive, like the FAT crate)
- TexFAT / second-FAT / allocation-bitmap consistency checks
- Whole-file buffer on `open` (same as FAT/EXT4; `ArchiveRead` is `Send`)
- Session factory / `formats-all` / nested matrix row (later PR)

## Build / test

```bash
cargo test -p ratarmount-formats-exfat --lib
cargo clippy -p ratarmount-formats-exfat --all-targets -- -D warnings
```

Always-on tests use a synthetic boot sector (magic) and a synthetic volume (list/read/`open_from_reader`/`list_dirents`). If `mkfs.exfat` is on `PATH` (or `/usr/sbin/mkfs.exfat`), an extra integration test formats a 2 MiB image and opens it; otherwise that test prints `skip: mkfs.exfat not available` and returns.
