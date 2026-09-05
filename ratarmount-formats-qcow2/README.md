# ratarmount-formats-qcow2

Read-only [QCOW2](https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt) virtual-disk `MountSource` for the Rust ratarmount rewrite (F-8 crate train).

Parse the QCOW2 header, map guest clusters to host clusters, then hand the raw virtual disk to [`ratarmount-formats-block`](https://github.com/hilather/ratarmount-rs/blob/main/ratarmount-formats-block/src/lib.rs) (`BlockMountSource::open_from_reader`). Partitioned images appear as `/p1/`… (FAT/EXT4). Unpartitioned superfloppy FAT/EXT4 mounts at `/`.

This crate is **not** wired into the session factory yet. Probe order / `formats-all` land in the orchestrator factory PR. Nested AutoMount of `*.qcow2` members will use `Qcow2MountSource::open_from_reader` once that glue exists.

## Features

| Feature | Default | Purpose |
|---------|---------|---------|
| *(none)* | yes | QCOW2 v2/v3 uncompressed + zlib (raw deflate) clusters; local backing file |

In-process cluster reads (no `qemu-nbd` / loop mount). Magic is `QFI\xfb` plus version 2 or 3.

## Nested / `open_from_reader` (no host temp)

Nested QCOW2 members open from any `Read + Seek` stream via `Qcow2MountSource::open_from_reader`:

1. Probe `QFI\xfb` + version 2/3 (no filename)
2. Retain the reader under a mutex; map guest offsets through L1/L2
3. Wrap the virtual disk with the block crate (or FAT/EXT4 superfloppy)

**No `/tmp` / `NamedTempFile` for this path.** The image is not copied into a second buffer by this crate (the parent may already hold a `Cursor` or stencil). Relative backing files need a real parent directory (`open(path)`); a virtual nested label cannot resolve `backing_file`.

## Residuals

- **Backing HTTP / NBD / `json:`** — v1 is a local path only (`file:` prefix stripped). Remote backing is rejected with a clear error.
- **zstd compressed clusters** — QCOW2 v3 `compression_type = 1` is residual (`Unsupported` on those clusters). zlib/deflate clusters work.
- Encrypted (AES/LUKS), external data file, extended L2 subclusters, qcow v1
- Session factory / `formats-all` / nested matrix factory wire (later PR)

## Build / test

```bash
cargo test -p ratarmount-formats-qcow2 --lib
cargo clippy -p ratarmount-formats-qcow2 --all-targets -- -D warnings
```

Always-on tests use a synthetic header (magic / version / size) and a synthetic QCOW2 wrapping MBR+FAT (list/read/`open_from_reader`/`list_dirents`). If `qemu-img` is on `PATH`, extra tests `qemu-img create` / `qemu-img convert`; otherwise those tests print `skip: qemu-img not available` and return.
