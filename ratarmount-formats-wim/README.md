# ratarmount-formats-wim

Read-only [Windows Imaging (WIM)](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/mount-and-modify-a-windows-image-using-dism) `MountSource` for the Rust ratarmount rewrite (F-8 crate train).

Detects magic `MSWIM\0\0\0` at byte 0. Mounts the **first image** as a directory tree (list / lookup / open). Nested members open from any `Read + Seek` stream via `WimMountSource::open_from_reader` with **no `/tmp` spool**.

This crate is **not** wired into the session factory yet. Probe order / `formats-all` land in the orchestrator factory PR.

## Features

| Feature | Default | Purpose |
|---------|---------|---------|
| *(none)* | yes | RO first-image list / lookup / open; path and stream opens |

In-process resource reads (no `wimlib`, no DISM). Uncompressed resources and **XPRESS** (LZ77+Huffman, [MS-XCA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/)) compressed chunks are decoded. Blob-table SHA-1 indexes payloads and is checked after decompress (fail-closed on mismatch).

## Nested / `open_from_reader` (no host temp)

Nested WIM members open from any `Read + Seek` stream via `WimMountSource::open_from_reader`:

1. Probe magic `MSWIM` (no filename)
2. Retain the reader under a mutex
3. Re-seek the shared body for each blob `open`

**No `/tmp` / `NamedTempFile` for this path.** The image is not copied into a second buffer by this crate (the parent may already hold a `Cursor` or stencil).

## Residuals

- **LZX / LZMS** compression (typical `install.wim` / ESD). `looks_like_wim` still matches `MSWIM`; `open` / `open_from_reader` returns an error naming the residual instead of returning raw compressed bytes.
- WIMBoot, solid resources, delta / split WIMs, pipable `WLPWM`
- Images after the first; XML image names as a directory prefix
- Alternate data streams; encrypted (EFS) members list but `open` is `PermissionDenied`
- **64 MiB** per-resource cap (blob table, metadata, and file payload); `open` buffers the whole member (`Cursor<Vec<u8>>`, same as FAT/exFAT)
- Session factory / `formats-all` (orchestrator PR). Crate `open_from_reader` is no-tmp when a parent already has a seekable body.

## Build / test

```bash
cargo test -p ratarmount-formats-wim --lib
cargo clippy -p ratarmount-formats-wim --all-targets -- -D warnings
```

Always-on tests use a synthetic **uncompressed** WIM (magic, list/read/`open_from_reader`/`list_dirents`, XPRESS codec round-trip). If `wimlib-imagex` is on `PATH`, an extra integration test captures a tiny directory; otherwise that test prints `skip: wimlib-imagex not available` and returns.
