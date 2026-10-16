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

## VHDX compatibility

Fixed images from `qemu-img 11.1.1 convert -O vhdx -o subformat=fixed`
open through the same BAT path. For a 1 MiB guest disk, the inspected output
uses version-1 headers with zero LogGuid, a 1 MiB log at file offset 1 MiB,
BAT at 2 MiB, metadata at 3 MiB, and 8 MiB payload blocks. Its five metadata
items start at region-relative offsets `0x10000`, `0x10008`, `0x10010`,
`0x10020`, and `0x10024`.

The parser previously imposed 64 KiB alignment on every item, rejecting the
second offset. [MS-VHDX 2.6 and 2.6.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/2b46bf83-0887-4025-a9b0-d18b29f1fa9b)
allow unaligned, unordered items after the 64 KiB table. Items can also reside
beyond the first MiB of a larger metadata region; the parser reads them
individually with bounds, size, overlap, duplicate, and required-item checks.
The File Parameters and Logical Sector Size GUIDs now match
[the specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/ef27fead-4178-4756-8d0f-dc76edd7e76d).

Non-zero LogGuid still fails closed, even if the log bytes are all zero.
[MS-VHDX 2.3.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/0d588e33-23a6-4c71-b27f-87d97ac3e914)
requires finding and replaying a valid active sequence; an empty candidate
sequence is corruption, not permission to ignore a non-zero LogGuid.

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

The `regression_qemu11_vhdx_` tests reproduce packed metadata and the literal
on-disk GUIDs without qemu-img. The fixture builder also writes metadata flags
at entry byte 24 (rather than the reserved field at byte 28).
