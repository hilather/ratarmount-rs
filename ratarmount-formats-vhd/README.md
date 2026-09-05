# ratarmount-formats-vhd

Read-only [Connectix VHD](https://learn.microsoft.com/en-us/windows/win32/vstor/about-vhd) and [Microsoft VHDX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/) virtual-disk `MountSource` for the Rust ratarmount rewrite (F-8).

Guest LBA bytes are translated through a fixed map or a BAT, then handed to [`ratarmount-formats-block`](https://github.com/hilather/ratarmount-rs/blob/main/ratarmount-formats-block) (`BlockMountSource::open_from_reader`) so GPT/MBR partitions appear as `/p1/`…. Superfloppy FAT/EXT4 at virtual offset 0 is mounted at `/`.

This crate is **not** wired into the session factory yet. Probe order / `formats-all` land in the orchestrator factory PR. Nested AutoMount of `*.vhd` / `*.vhdx` members will use `VhdMountSource::open_from_reader` once that glue exists.

## Features

| Kind | Default | Notes |
|------|---------|-------|
| Fixed VHD | yes | Footer cookie `conectix` at EOF; data is `0..current_size` |
| Dynamic VHD | yes | `cxsparse` header + BAT; unallocated blocks read as zeros |
| Fixed VHDX | yes | `vhdxfile` identifier + BAT `FULLY_PRESENT` |
| Sparse VHDX (no parent) | yes | Same BAT path; `NOT_PRESENT` / `ZERO` holes |

In-process (no `qemu-nbd`, no loop mount). Detection is magic only (no `.vhd` extension fallback).

## Nested / `open_from_reader` (no host temp)

1. Probe VHDX start magic or VHD footer cookie (no filename).
2. Wrap the stream as a guest `Read + Seek` (fixed map or BAT).
3. Open GPT/MBR (or superfloppy FAT/EXT4) on that virtual disk.

**No `/tmp` / `NamedTempFile` for this path.** The container is not copied into a second buffer by this crate.

## Residuals

| Topic | Behaviour |
|-------|-----------|
| **Differencing** VHD (type 4) / VHDX `HasParent` | `open` fails with a clear error. No parent-chain walk. |
| **VHDX log** (`LogGuid` ≠ 0) | `open` fails closed. Journal replay is residual. |
| **Encrypted** VHDX | Unknown required region GUID fails closed. |
| Dynamic VHD **sector bitmap** | Allocated blocks are read as fully present. |
| VHDX **partially present** blocks | Treated as fully present (no sector-bitmap apply). |
| Factory / AutoMount nested AutoMount | Orchestrator factory PR (not this crate). |

## Tests

```bash
cargo test -p ratarmount-formats-vhd --lib
cargo clippy -p ratarmount-formats-vhd --all-targets -- -D warnings
```

Always-on: synthetic fixed VHD (MBR+FAT `p1/` list/read + `open_from_reader`), Connectix spec-offset footer (not encoder-relative), dynamic VHD BAT mapping, fixed VHDX BAT, differencing VHD/VHDX reject, VHDX `LogGuid` fail-closed, `list_dirents` sizes, superfloppy FAT at `/`. Optional `qemu-img convert` skip-if-missing.
