# ratarmount-formats-vmdk

Read-only [VMDK](https://kb.vmware.com/s/article/1026266) virtual-disk `MountSource` for the Rust ratarmount rewrite (F-8 crate train).

Hosted **KDMV sparse** extents (`monolithicSparse` / `twoGbMaxExtentSparse`) are translated to a `Read + Seek` virtual disk and wrapped with [`BlockMountSource::open_from_reader`](https://github.com/hilather/ratarmount-rs/blob/main/ratarmount-formats-block/src/lib.rs) so GPT/MBR partitions appear as `/p1/`… (FAT/EXT4). A superfloppy FAT/EXT4 volume at virtual LBA 0 is mounted at `/`.

This crate is **not** wired into the session factory yet. Probe order / `formats-all` land in the orchestrator factory PR.

## Nested / `open_from_reader` (no host temp)

Nested **monolithicSparse** members open from any `Read + Seek` stream via `VmdkMountSource::open_from_reader`:

1. Probe `KDMV` magic (no filename)
2. Parse the sparse header + grain directory; reject compressed / ESXi
3. Present grain-mapped bytes to the block/FAT/EXT4 layer on the same stream

**No `/tmp` / `NamedTempFile` for this path.** Descriptor-only files that name **relative sibling** extent files need `VmdkMountSource::open` (host path). Absolute extent paths (`/etc/passwd`, `C:\…`) and `..` are rejected.

## Residuals

| Topic | Behaviour |
|-------|-----------|
| **Compressed grains** | `createType=streamOptimized` / header `FLAG_COMPRESS` / `compressAlgorithm ≠ 0` — `open` errors. Not silent zeros. `FLAG_MARKER` alone is **not** compression. |
| **ESXi grain** | COWD `vmfsSparse`, `VMFSSPARSE`, SESparse — not claimed / not mounted. |
| **Delta / snapshot** | `parentCID` ≠ `ffffffff` — residual. |
| **Absolute extent files** | Descriptor names must be relative siblings of the `.vmdk`. |
| Factory / AutoMount | Orchestrator must call `open_from_reader` from nested AutoMount (not this crate). |

## Tests

```bash
cargo test -p ratarmount-formats-vmdk --lib
cargo clippy -p ratarmount-formats-vmdk --all-targets -- -D warnings
```

Always-on tests use a synthetic KDMV sparse fixture wrapping MBR+FAT (magic, descriptor parse, list/read, `open_from_reader` no-tmp, `list_dirents` sizes, compressed/ESXi residual). No `qemu-img` required.
