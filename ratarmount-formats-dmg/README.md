# ratarmount-formats-dmg

UDIF (Apple Disk Image) **block reader** for the Rust ratarmount rewrite (F-8 crate train).

Parses the 512-byte `koly` trailer at EOF, the XML `blkx` plist, and `mish` chunk tables. Raw / ADC / zlib / bzip2 runs become a `Read + Seek` view of the inner disk. When that disk is **FAT, ISO 9660, exFAT, NTFS, EXT4, or GPT/MBR** (via those crates’ public `open_*_from_reader` / offset APIs), this crate presents that filesystem as a `MountSource`.

This crate is **not** wired into the session factory yet. Probe order / `formats-all` land in the orchestrator factory PR. Nested AutoMount of `*.dmg` members will use `DmgMountSource::open_from_reader` once that glue exists.

**There is no HFS/HFS+ crate in this workspace.** A typical macOS `.dmg` (HFS+ or APFS) does **not** mount here. Do not treat this crate as an HFS+ reader.

## Nested / `open_from_reader` (no host temp)

Nested UDIF members open from any `Read + Seek` stream:

1. Probe `koly` at `SeekFrom::End(-512)` (no filename)
2. Parse XML `blkx` / `mish` and retain the reader under a mutex
3. Decompress runs on demand (last-chunk cache); inner FS opens the same shared body

**No `/tmp` / `NamedTempFile` for this path.** The image is not copied into a second buffer by this crate.

## Residuals

| Topic | Behaviour |
|-------|-----------|
| **HFS+** | Detected (`H+`/`HX`/`BD` at partition+1024). Open fails; a GPT with only an EFI FAT (`p1/`) does **not** count as success. No `apple-hfs` / existing-path claim. |
| **APFS** | Detected (`NXSB` at partition+32). Same fail-closed residual. |
| **Encrypted DMG** (`encrcdsa` header / `cdsaencr` trailer / non-plist XML) | Open fails closed. No passphrase path. |
| **LZFSE / LZMA** chunk types | Open fails closed (not deferred to first `read`). |
| **Resource-fork-only** (no XML plist) | Residual. Modern `hdiutil` XML is required. |
| **Partitioned exFAT/NTFS** | Probed at GPT/MBR data-partition offsets (mounted at `/` when they are the data FS). Block `pN/` is FAT/EXT4 only. |
| **UDF** inner volumes | Wait on `ratarmount-formats-udf`. |
| Factory / AutoMount | Orchestrator must call `open_from_reader` (not this crate). |

## Tests

```bash
cargo test -p ratarmount-formats-dmg --lib
cargo clippy -p ratarmount-formats-dmg --all-targets -- -D warnings
```

Always-on tests use a synthetic `koly` trailer (parse + raw/ADC/zlib/bzip2 chunks + inner FAT/ISO). `hdiutil_convert_fat_udzo` runs `hdiutil convert -format UDZO` when `hdiutil` is on `PATH`; otherwise it prints `skip: hdiutil not available` and returns.
