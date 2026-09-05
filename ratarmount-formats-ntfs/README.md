# ratarmount-formats-ntfs

Read-only NTFS filesystem image mount source for the Rust ratarmount rewrite (F-8).

Uses Colin Finck’s pure-Rust [`ntfs`](https://crates.io/crates/ntfs) crate (v0.4, MSRV-compatible with workspace 1.74). No loop mount, no `ntfs-3g`, no journal replay.

This crate is **not** wired into the session factory in this PR. Callers use `looks_like_ntfs` / `NtfsMountSource::open` / `open_from_reader` (and the `*_with_offset` variants for a partition start). Factory probe order is an orchestrator PR.

## Nested / `open_from_reader` (no host temp)

Nested NTFS members open from any `Read + Seek` stream via `NtfsMountSource::open_from_reader` (or `open_from_reader_with_offset`):

1. Probe OEM `"NTFS    "` at byte 3 of the boot sector (plus partition offset).
2. Retain the reader under a mutex.
3. Re-parse the volume per list / lookup / open (`Ntfs` needs a mutable disk handle).

**No `/tmp` / `NamedTempFile` on this path.** The image is not copied into a second buffer by this method (the parent may already hold a `Cursor` or stencil).

## Residuals (v1)

| Topic | Behaviour |
|-------|-----------|
| **EFS** (encrypted files) | Listed; `open` returns `PermissionDenied`. No EFS decrypt. |
| **LZNT1 compression** | Listed; `open` returns `Unsupported`. `ntfs` 0.4 does not decompress; v1 fail-closes instead of returning raw compression-unit bytes. |
| **WOF / Compact OS** | Reparse + `WofCompressedData` unresolved. Unnamed `$DATA` is often empty (`cat` empty). Same residual class as junctions. |
| **ADS** (named `$DATA` streams) | Not presented as files. Only the unnamed default data stream is listed/read. |
| **Journal** | `$LogFile` is **not** replayed. Dirty volumes are mounted as on-disk. |
| **Reparse / junctions / WSL symlinks** | Treated as ordinary files/dirs if they have a default `$DATA`; not resolved. |
| Factory / AutoMount | Orchestrator must call `open_from_reader` from nested AutoMount (not this crate). |

## Tests

```bash
cargo test -p ratarmount-formats-ntfs --lib
```

Always-on unit tests cover boot-sector magic (including false on FAT32 / exFAT), FILETIME conversion, reject-bad-magic `open_from_reader`, and LZNT1/EFS `open` error-kind mapping. List/read/path-offset/`list_dirents` tests use `mkfs.ntfs` when present (`eprintln!("skip: …")` otherwise) and optionally `ntfscp` to add a user file. Default GHA does not install `ntfsprogs`, so those four tests skip in `cargo test --workspace`.
