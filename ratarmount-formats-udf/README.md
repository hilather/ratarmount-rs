# ratarmount-formats-udf

Read-only [UDF](https://www.osta.org/specs/pdf/udf201.pdf) (Universal Disk Format / ECMA-167) filesystem image `MountSource` for the Rust ratarmount rewrite (F-8 crate train).

This crate is **not** wired into the session factory yet. Probe order / `formats-all` land in the orchestrator factory PR. Nested AutoMount of UDF members will use `UdfMountSource::open_from_reader` once that glue exists.

## Features

| Feature | Default | Purpose |
|---------|---------|---------|
| *(none)* | yes | RO list / lookup / open; path and stream opens |

In-process extent reads (no loop mount, no `udftools` FUSE). Magic is a Volume Recognition Sequence **NSR02** or **NSR03** identifier starting at byte **32 KiB** (ECMA-167 volume recognition space). ISO 9660 `CD001`-only images do **not** match (`looks_like_udf` is false). Mixed ISO+UDF bridge discs **do** match when NSR02/NSR03 is present.

**UDF-primary mixed discs** (factory probe inserts `Udf` immediately before `Iso` so NSR wins over `CD001`) are **factory-PR behavior**, not this crate.

## Nested / `open_from_reader` (no host temp)

Nested UDF members open from any `Read + Seek` stream via `UdfMountSource::open_from_reader` (and `open_from_reader_with_offset` for a partition at a byte offset):

1. Probe the VRS for `NSR02`/`NSR03` (no filename)
2. Retain the reader under a mutex
3. Re-seek the shared body for each list / lookup / open

**No `/tmp` / `NamedTempFile` for this path.** The image is not copied into a second buffer by this crate (the parent may already hold a `Cursor` or stencil).

| Case | Behaviour |
|------|-----------|
| Nested seekable member | No host temp |
| Partitioned image | `open_with_offset` / `open_from_reader_with_offset` |
| Factory wiring | Orchestrator must call `open_from_reader` from nested AutoMount (not this crate) |

## Residuals

- UDF 2.50 / 2.60 **metadata partition** (type-2 `*UDF Metadata Partition` maps): listed as residual; v1 needs a type-1 partition map
- VAT (virtual allocation table) packet-written volumes
- Whole-file buffer on `open` (same as FAT/exFAT; `ArchiveRead` is `Send`)
- Session factory / `formats-all` / nested matrix row (later PR)
- Mixed-disc **probe order** (UDF before ISO) — orchestrator factory PR

## Build / test

```bash
cargo test -p ratarmount-formats-udf --lib
cargo clippy -p ratarmount-formats-udf --all-targets -- -D warnings
```

Always-on tests use a synthetic VRS (NSR02/NSR03 magic, ISO `CD001`-only negative, mixed-disc NSR still true) and a synthetic UDF 2.01 volume (list/read/`open_from_reader`/`list_dirents`). If `mkudffs` (udftools) or `mkisofs`/`genisoimage`/`xorriso` is on `PATH`, an extra integration test formats an image and opens it; otherwise that test prints `skip: mkudffs/mkisofs not available` and returns.
