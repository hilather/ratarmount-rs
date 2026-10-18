# ratarmount-rs — agent instructions

Always-on conventions for Grok (main session and subagents). Keep this file short; longer procedures live in `.grok/skills/`.

## CI gates (non-negotiable)

GitHub Actions job **`fmt + clippy + test`** runs **`cargo fmt --all -- --check` first**. If formatting fails, the job never reaches clippy/test, and **`FUSE phase allowlists` is skipped** (`needs: check`).

Before every commit (including worktree subagent commits):

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # or -p <crate> when scoped
cargo test --workspace                                    # or -p <crate> when scoped
```

Do **not** push code that fails `cargo fmt --check`.

Other CI jobs (cold-index benchmark gates, macOS build) can pass while fmt fails — do not treat those alone as “green CI”.

## Tests for every fix (non-negotiable)

**Every bugfix and behavior change must land with automated tests in the same
commit** (or the same PR). “Manual repro only” is not enough.

| Requirement | Detail |
|-------------|--------|
| **Regression test** | Reproduce the failure mode in code; assert the fixed behavior. Name/doc with `Regression:` and a short symptom (e.g. “Dec 31 1969 mtime”). |
| **Layer** | Prefer the lowest layer that catches the bug (parse unit → mount source → factory nested → FUSE helper). Add a higher-layer test if the bug only appears there. |
| **No skip without reason** | If a CLI tool is missing (`7z`, `gzip`), `return` early with `eprintln!("skip: …")` — do not silently pass on the happy path without a pure unit test for the core logic. |
| **Shell/CI** | Workflow-only fixes get a script under `packaging/` or `test-harness/` that CI or agents can run (e.g. empty release asset filter). |
| **Do not land** | Fix commits without new/updated tests, unless the user explicitly waived tests (rare). |

### Regression catalog (keep these green)

Run filters **separately** (`cargo test` does not treat `|` as OR).

| Symptom / fix | Commands |
|---------------|----------|
| BIG fixture builder missing tar.lz4 / multi-frame zstd | `./benchmarks/test-compare-fixtures.sh` |
| Vector-wave fixture builder missing catalog tars | `./benchmarks/test-compare-vector-wave.sh` |
| Format sweep fixture builder: missing-producer skips, corrupt or count-mismatched reads, `PREPARE_ONLY` / `NO_FUSE` regressions (AI-FMTBENCH) | `./benchmarks/test-compare-formats.sh` |
| Fixture smoke dies without Python/binary (#9) | `./benchmarks/test-compare-prepare-env.sh` · `./benchmarks/test-compare-fixtures.sh` |
| Truncated `.gz` / UnexpectedEof (FUSE short read = EOF) | `cargo test -p ratarmount-fuse --lib fill_read` · `cargo test -p ratarmount-compress --lib fuse_style` · `cargo test -p ratarmount-session --lib nested_large_plain_gzip` |
| Nested gzip concurrent wrong/truncated data | `cargo test -p ratarmount-compress --lib shared_from_reader` · `cargo test -p ratarmount-compress --lib stenciled_fuse` |
| ZIP `open_via_zip_crate` concurrent opens return a sibling's bytes or zip/bzip2 errors (shared `try_clone` cursor) | `cargo test -p ratarmount-formats-zip --lib regression_parallel_zip_crate_member_reads` |
| ZIP Stored path used a mutex `seek`+`read` on a clone that shares the Windows file pointer with `raw_file`; `read_file_range_at_into` treated `Interrupted` as fatal (#112) | `cargo test -p ratarmount-formats-zip --lib regression_parallel_stored_member_reads` · `cargo test -p ratarmount-formats-zip --lib regression_stored_file_reader` · `cargo test -p ratarmount-formats-zip --lib regression_read_exact_via` |
| ZIP `msdos_to_unix` called `libc::mktime` (missing on Windows). DOS years outside 1980–2107, invalid dates, and a non-converging DST gap are `0.0`; `civil_seconds` still accepts 1979 and 2108. 2000-02-29 and 2024-02-29 equal Feb 28 plus one day; 2100-02-29, Apr 31, hour 24 and 31, minute 60 and 63, and second 62 are `0.0` (`civil_seconds` is `None`); second 60 is real. Stored seek-from-end must stay inside the member (file and `ZipBackend::Shared`) | `cargo test -p ratarmount-formats-zip --lib regression_msdos` · `cargo test -p ratarmount-formats-zip --lib regression_msdos_calendar_edges` · `cargo test -p ratarmount-formats-zip --lib regression_stored_member_seek_from_end` · windows-lib `cargo check -p ratarmount-formats-zip -p ratarmount-formats-tar --all-targets` · `./packaging/test-windows-lib-ci.sh` |
| Concurrent readers of one uncompressed TAR read a sibling member's bytes (shared File cursor); parallel nested opens spool | `cargo test -p ratarmount-formats-tar --lib regression_parallel_` · `cargo test -p ratarmount-formats-tar --lib regression_positional_file` · `cargo test -p ratarmount-session --lib regression_parallel_nested_ar` |
| Rapidgzip path backend (Tier D POC) | `cargo test -p ratarmount-compress --features gzip-rapidgzip --lib gzip_rapidgzip` · `cargo test -p ratarmount-session --features gzip-rapidgzip --lib plain_gzip_rapidgzip` · `cargo test -p ratarmount-session --features gzip-rapidgzip --lib plain_gzip_rapidgzip_invalid` · `cargo test -p ratarmount-session --features gzip-rapidgzip --lib plain_gzip_rapidgzip_gzidx` · `cargo test -p ratarmount-session --features gzip-rapidgzip --lib nested_plain_gzip_prefer_rapidgzip` · `cargo test -p ratarmount-session --features gzip-rapidgzip --lib nested_plain_gzip_prefer_rapidgzip_fail_rewinds_to_g3` · optional ISA-L: `--features gzip-rapidgzip-isal` (+ `libisal` / `ISAL_INSTALL_PREFIX`) |
| Plain `.gz` rapidgzip GZIDX shell create (no pre-existing index) | `cargo test -p ratarmount-session --features gzip-rapidgzip --lib plain_gzip_rapidgzip_plain_gzidx` · `cargo test -p ratarmount-session --features gzip-rapidgzip --lib plain_gzip_rapidgzip_gzidx_skipped` · `cargo test -p ratarmount-session --lib gzip_seek_index_format_label` |
| 7z mtimes Dec 31 1969 (FILETIME delta) | `cargo test -p ratarmount-formats-sevenzip --lib filetime` · `cargo test -p ratarmount-formats-sevenzip --lib mtime` |
| Nested/non-solid 7z first `cat` minutes (LZMA2 prefix-from-0) | `cargo test -p ratarmount-formats-sevenzip --lib regression_sequential` · `cargo test -p ratarmount-formats-sevenzip --lib regression_independent_chunk` · `cargo test -p ratarmount-formats-sevenzip --lib regression_header_at_end` · `cargo test -p ratarmount-index --lib regression_head_only` · `cargo test -p ratarmount-session --lib regression_progressive_nested_fingerprint` |
| AES/BCJ 7z solid first `cat` minutes (pack slurp / full-folder) | `cargo test -p ratarmount-formats-sevenzip --lib regression_aes_lzma2` · `cargo test -p ratarmount-formats-sevenzip --lib regression_bcj_lzma2` · `cargo test -p ratarmount-formats-sevenzip --lib regression_aes_pack_not_slurped` · `cargo test -p ratarmount-formats-sevenzip --lib regression_encrypted_copy` |
| Encrypted nested open → EACCES not EIO | `cargo test -p ratarmount-fuse --lib io_to_errno` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted` (metadata-only PermissionDenied; password exact bytes; wrong pw fails open) |
| 7z wrong password accepted on macOS (store+AES / warm index) | `cargo test -p ratarmount-formats-sevenzip --lib encrypted_wrong_password` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted_store_aes` |
| 7z parse CRC uses crc32fast (IEEE) | `cargo test -p ratarmount-formats-sevenzip --lib crc32` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted_wrong_password` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted_store_aes` |
| Write-overlay create then cat empty (size-0 cache) | `cargo test -p ratarmount-fuse --lib overlay_file_info` |
| Overlay open after create+write (`has_file` → OverlayFd) | `cargo test -p ratarmount-fuse --lib overlay_open_after_create_write` |
| Write-mount stat re-queries unmodified archive member | `cargo test -p ratarmount-fuse --lib overlay_archive_member` |
| FUSE kernel notify on the request thread deadlocks (parent i_rwsem vs FUSE reply) | `cargo test -p ratarmount-fuse --lib notifier` |
| Concurrent FUSE writers in one directory deadlock (request-thread notify) | `cargo test -p ratarmount --test fuse_write_concurrency` |
| Kernel inval_entry only for names advertised with a non-zero entry TTL | `cargo test -p ratarmount-fuse --lib entry_advertised` |
| Overlay unlink tombstone SQL on every lookup | `cargo test -p ratarmount-compositing --lib tombstone_cache` |
| Committed tombstone stays cached when overlay prune fails | `cargo test -p ratarmount-compositing --lib forget_committed_overlay_forgets_tombstone_when_prune_fails` |
| NFS overlay create then write then read payload (size-0 cookie) | `cargo test -p ratarmount-nfs --lib overlay_open_after_create_write` · `cargo test -p ratarmount-nfs --features nfsv4 --lib overlay_open_after_create_write` · `cargo test -p ratarmount-nfs --lib get_or_open_overlay_cookie` |
| NFS overlay empty create then cat "" | `cargo test -p ratarmount-nfs --lib overlay_open_after_create_reads_empty` · `cargo test -p ratarmount-nfs --features nfsv4 --lib overlay_open_after_create_reads_empty` |
| 9P/SMB/SFTP overlay create then write then read payload (size-0 cookie) | `cargo test -p ratarmount-export-core --lib get_or_open_overlay_cookie` · `cargo test -p ratarmount-9p --lib overlay_open_after_create_write` |
| 9P overlay empty create then cat "" | `cargo test -p ratarmount-9p --lib overlay_open_after_create_reads_empty` |
| Sequential FUSE readahead window (`--readahead`, #180) | `cargo test -p ratarmount-fuse --lib readahead` |
| Plain compress no `/tmp` spool (gz/zstd/bz2) | `cargo test -p ratarmount-session --lib plain_gzip` · `cargo test -p ratarmount-session --lib plain_zstd` · nested: `cargo test -p ratarmount-session --lib nested_plain_gzip` |
| Nested no-tmp openers (factory wiring) | `cargo test -p ratarmount-session --lib nested_` (CPIO/AR/WARC/ASAR/CAB/XAR/tar.gz/zip/7z) · crate `open_from_reader` tests for ISO/SQLAR/FAT |
| Nested TAR via AutoMount reader | `cargo test -p ratarmount-compositing --lib automount_nested` |
| Nested durable indexes (ZIP/TAR/7z structure+file table/CPIO/AR) | `cargo test -p ratarmount-session --lib nested_durable` · `cargo test -p ratarmount-formats-sevenzip --lib durable_structure` · `cargo test -p ratarmount-index --lib nested` |
| Nested compact pools are per-index (no parent StringPool lock) | `cargo test -p ratarmount-index --lib regression_nested_compact_pools_are_per_index` |
| ZIP `--commit-overlay` rebuild (add/replace/delete) | `cargo test -p ratarmount-compositing --lib commit_overlay_zip` |
| Offline `--commit-overlay` splice for `.tar.zst` (incl. earlier-frame delete) | `cargo test -p ratarmount-compositing --lib commit_overlay` |
| Offline `.tar.zst` later-frame delete without `-i` (silent skip) | `cargo test -p ratarmount-compositing --lib commit_overlay_tar_zst_concatenated_delete_without_ignore_zeros` · `cargo test -p ratarmount-compositing --lib commit_overlay_tar_zst_concatenated_delete_patches_sidecar_later_frame` |
| Live `.tar.zst` later-frame delete remounted without `-i` (silent skip + forgotten tombstone) | `cargo test -p ratarmount-compositing --lib live_commit_idle_tar_zst_concatenated_delete_without_ignore_zeros` |
| Factory zstdblocks/bzip2blocks warm reimport (FR-9) | `cargo test -p ratarmount-session --lib zstd_blocks` · `cargo test -p ratarmount-session --lib bzip2_blocks` |
| Bzip2 block boundary truncates TAR listing / nested flattening / header detection; incomplete TAR header silently accepted | `cargo test -p ratarmount-formats-tar --lib regression_bzip2_block_boundary` · `cargo test -p ratarmount-formats-tar --lib regression_truncated_tar_header_is_an_error` |
| G3 RGZI warm remount (plain `.gz` + tar.gz write_index) | `cargo test -p ratarmount-session --lib gzip_rgzi` · `cargo test -p ratarmount-session --lib plain_gzip_rgzi` · `cargo test -p ratarmount-session --lib plain_gzip` |
| Single-frame `.zst` still full-decode after “repack” | `cargo test -p ratarmount-compress --lib repack_seekable` |
| Already-seekable zstd copy does not change bytes | `cargo test -p ratarmount-compress --lib repack_copies_multiframe_with_seek_table` |
| `IN == OUT` or an existing OUT is refused instead of rewritten | `cargo test -p ratarmount-compress --lib repack_refuses_same_path_and_existing_output` |
| Multi-frame without table gets a footer; `kind` is `zstd-seek-table` | `cargo test -p ratarmount-compress --lib repack_appends_seek_table` |
| Repack seek-table cSize ignores skippable gaps between frames | `cargo test -p ratarmount-compress --lib repack_skippable_gap_copies_without_footer` |
| Frame size above u32 is rejected; `--repack-force` recompresses a single frame and round-trips | `cargo test -p ratarmount-compress --lib repack_rejects_frame_size_above_u32` · `cargo test -p ratarmount-compress --lib repack_recompresses_single_frame_and_roundtrips` |
| Gzip sidecar RGZI via `export_seek_index_blob` round-trips import | `cargo test -p ratarmount-compress --lib repack_gzip_copy_writes_rgzi` · `cargo test -p ratarmount-compress --lib repack_gzip_copy_writes_gzidx_and_both` |
| Clap `--repack-seekable IN OUT` does not steal OUT as mountpoint | `cargo test -p ratarmount --bin ratarmount repack_seekable_does_not_steal_output_path` · `cargo test -p ratarmount --bin ratarmount repack_seekable_frame_size_1m_does_not_steal_archive` |
| `--repack-seekable` + `--nfs` / `-w` / mountpoint exits 2 | `cargo test -p ratarmount --bin ratarmount repack_incompatible_with_export` |
| tar → tar.zst keeps member offset order (zero backward flatten seeks) | `cargo test -p ratarmount-formats-tar --lib regression_offset_order_seeks` · `cargo test -p ratarmount --bin ratarmount repack_seekable_gzip_round_trip_without_external_zstd` |
| G3 hard GZIDX import / export polish (G3-D/E) | `cargo test -p ratarmount-compress --lib gzip_seek` (filters: `g3_d_`, `g3_e_`) |
| G3-D hard-import test counter raced across parallel tests (macOS) | `cargo test -p ratarmount-compress --lib g3_d_` |
| Warm index after archive replace (tarstats size/mtime/content) | `cargo test -p ratarmount-session --lib warm_index_rebuilds` · `cargo test -p ratarmount-index --lib check_tarstats` · `cargo test -p ratarmount-formats-tar --lib warm_index` · `cargo test -p ratarmount-formats-zip --lib warm_index` · `cargo test -p ratarmount-formats-sevenzip --lib warm_index` |
| Nested EXT4 / SquashFS no-tmp factory wire | `cargo test -p ratarmount-session --lib nested_ext4` · `cargo test -p ratarmount-session --lib nested_squashfs` · crate `open_from_reader` tests |
| F-8 factory probe order (Udf before Iso; Block after Fat/Exfat/Ntfs) | `cargo test -p ratarmount-session --lib probe_order_f8` |
| ISO 9660 uppercase/truncated names, lost POSIX metadata/symlinks (Rock Ridge/SUSP + Joliet; reader/path/warm index) | `cargo test -p ratarmount-formats-iso9660 --lib regression_` · `cargo test -p ratarmount-session --lib nested_udf_before_iso_mixed_disc` |
| Rock Ridge PX type bits override the ISO directory flag (file shown as a directory, directory shown as a file, or chr/blk/fifo/socket shown as a device node); v1–v3 sidecars keep the PX directory type | `cargo test -p ratarmount-formats-iso9660 --lib regression_rock_ridge_type_follows_directory_flag` · `cargo test -p ratarmount-formats-iso9660 --lib regression_rock_ridge_device_fifo_socket_are_regular_files` · `cargo test -p ratarmount-formats-iso9660 --lib regression_iso_metadata_v1_` |
| Damaged Joliet SVD/root (extent past EOF, directory loop, truncated record) fails or drops the ISO 9660 tree | `cargo test -p ratarmount-formats-iso9660 --lib regression_damaged_joliet_` · `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_selected_sl_directory_grafts_children` · `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_unmatched_directory_pairing_skips_sl_directories` |
| Nested Joliet SL directories, an SL directory bound via a matched descendant, an SL directory under a non-unique parent, a plain directory between an SL directory and a matched file, nested SL directories with an extent-matched file, a non-Joliet type-2 escape, and a child directory extent past EOF or exactly at the end | `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_nested_sl_directories` · `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_sl_directory_matched_descendant` · `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_sl_directory_under_non_unique_parent` · `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_sl_directory_with_plain_dir_before_match` · `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_nested_sl_with_matched_file` · `cargo test -p ratarmount-formats-iso9660 --lib regression_non_joliet_supplementary_descriptor_ignored` · `cargo test -p ratarmount-formats-iso9660 --lib regression_directory_extent_past_eof_and_exact_end` |
| Nested Joliet SL directories under a plain parent bind that parent one Joliet level too high (its mode lands on `/` and the SL directory is grafted at `/`); a plain directory after that SL run must not add a second hop | `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_nested_sl_under_plain_parent` · `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_sl_then_plain_dir_under_plain_parent` |
| Conflicting file-hop and dir-hop through one SL run must leave the plain parent unbound (mode not on `/` or `/Parent`; SL dir not grafted) | `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_sl_run_file_and_plain_dir_conflict` |
| Unmatched plain dir outside an SL subtree must not be grafted (`&&`→`||` at the graft-root guard, `==`→`!=` on the descendant walk) | `cargo test -p ratarmount-formats-iso9660 --lib regression_joliet_unmatched_plain_dir_outside_sl_not_grafted` |
| `xorriso` Rock Ridge/Joliet integration skips whenever `xorriso` is off PATH, including CI | `RATARMOUNT_REQUIRE_XORRISO=1 cargo test -p ratarmount-formats-iso9660 --lib regression_xorriso_rock_ridge_joliet` |
| Slim session graph `udf` without iso9660 still compiles `map_nested_open` | `cargo check -p ratarmount-session --no-default-features --features udf` |
| Nested exFAT no-tmp factory wire | `cargo test -p ratarmount-session --lib nested_exfat` |
| Nested UDF no-tmp / mixed-disc Udf-before-Iso | `cargo test -p ratarmount-session --lib nested_udf` |
| Nested NTFS no-tmp factory wire | `cargo test -p ratarmount-session --lib nested_ntfs` |
| FAT partition offset (superfloppy 0 / padded image) | `cargo test -p ratarmount-formats-fat --lib offset` |
| Nested exFAT no-tmp / OEM `"EXFAT   "` (F-8 crate) | `cargo test -p ratarmount-formats-exfat --lib` (always-on synthetic boot + volume; `mkfs_exfat` skip if no `mkfs.exfat`) |
| GPT/MBR partition table `p1/` listing (synthetic MBR+FAT) | `cargo test -p ratarmount-formats-block --lib mbr_fat` · `cargo test -p ratarmount-formats-block --lib gpt_fat` · `cargo test -p ratarmount-formats-block --lib looks_like` |
| GPT/MBR two FAT partitions same name serve p1 bytes for p2 | `cargo test -p ratarmount-formats-block --lib same_name` |
| UDIF `koly` parse / inner FAT no-tmp (F-8 DMG crate; HFS+ residual) | `cargo test -p ratarmount-formats-dmg --lib list_dirents` · `cargo test -p ratarmount-formats-qcow2 --lib list_dirents` |
| Fixed VHD fixture lists `p1/` (MBR+FAT, always-on; F-8 crate) | `cargo test -p ratarmount-formats-vhd --lib fixed_vhd` |
| Dynamic VHD BAT maps virtual offsets (unallocated = zeros) | `cargo test -p ratarmount-formats-vhd --lib dynamic_vhd` |
| VHDX fixed payload maps through BAT / nested no-tmp | `cargo test -p ratarmount-formats-vhd --lib vhdx` · `cargo test -p ratarmount-formats-vhd --lib open_from_reader` |
| Connectix VHD footer current_size/disk_type +4 vs qemu-img | `cargo test -p ratarmount-formats-vhd --lib parse_footer_spec_offsets` |
| VHDX non-zero LogGuid mounted without replay | `cargo test -p ratarmount-formats-vhd --lib log_guid` |
| qemu-img 11 fixed VHDX rejected: packed metadata items and wrong metadata GUIDs | `cargo test -p ratarmount-formats-vhd --lib regression_qemu11_vhdx` · `cargo test -p ratarmount-formats-vhd --lib regression_vhdx_metadata` · `cargo test -p ratarmount-formats-vhd --lib qemu_img_fixed_vhdx_skip_if_missing` |
| Nested VMDK KDMV sparse no-tmp / descriptor parse (F-8 crate) | `cargo test -p ratarmount-formats-vmdk --lib looks_like` · `cargo test -p ratarmount-formats-vmdk --lib descriptor` · `cargo test -p ratarmount-formats-vmdk --lib sparse` · `cargo test -p ratarmount-formats-vmdk --lib open_from_reader` |
| VMDK compressed / ESXi grain residual | `cargo test -p ratarmount-formats-vmdk --lib residual` |
| VMDK sidecar descriptor larger than 1 MiB fails closed | `cargo test -p ratarmount-formats-vmdk --lib oversized_sidecar` |
| VMDK extent `..` / absolute path rejected | `cargo test -p ratarmount-formats-vmdk --lib sibling_path` |
| Warm index tarstats (most formats) | `cargo test -p ratarmount-formats-{ar,cpio,iso9660,sevenzip,warc,cab,xar,asar,libarchive,ogg} --lib warm_index` (run crates separately) · also tar/zip |
| Nested tar.zst/bz2/xz no-tmp opener | `cargo test -p ratarmount-session --lib nested_tar_` |
| HTTP Cookie auth (FR-2) | `cargo test -p ratarmount-remote --lib http_cookie` · `cargo test -p ratarmount-remote --lib http_basic_and_cookie` |
| ssh_config ProxyJump / Include | `cargo test -p ratarmount-remote --lib ssh` |
| Dropbox cheap `list_dirents` | `cargo test -p ratarmount-remote --lib list_dirents` |
| Union symlink resolve (FR-10) | `cargo test -p ratarmount-compositing --lib fr10_resolve` |
| FileVersionLayer / TAR cheap readdir (no fat FileInfo map) | `cargo test -p ratarmount-compositing --lib file_version_layer_list_dirents` · `cargo test -p ratarmount-formats-tar --lib gnu_incremental_dumpdir_deletes` |
| Compositing wrappers fat readdir | `cargo test -p ratarmount-compositing --lib list_dirents` |
| Index formats missing readdirplus sizes | `cargo test -p ratarmount-formats-cpio --lib list_dirents` · `cargo test -p ratarmount-formats-ar --lib list_dirents` · `cargo test -p ratarmount-formats-warc --lib list_dirents` · `cargo test -p ratarmount-formats-cab --lib list_dirents` · `cargo test -p ratarmount-formats-iso9660 --lib list_dirents` · `cargo test -p ratarmount-formats-asar --lib list_dirents` · `cargo test -p ratarmount-formats-xar --lib list_dirents` · `cargo test -p ratarmount-formats-libarchive --lib list_dirents` · `cargo test -p ratarmount-formats-ogg --lib list_dirents` · `cargo test -p ratarmount-formats-html --lib list_dirents` · `cargo test -p ratarmount-formats-pdf --lib list_dirents` |
| Image / Git / SQLAR / SingleFile cheap `list_dirents` | `cargo test -p ratarmount-formats-ext4 --lib list_dirents` · `cargo test -p ratarmount-formats-fat --lib list_dirents` · `cargo test -p ratarmount-formats-exfat --lib list_dirents` · `cargo test -p ratarmount-formats-udf --lib list_dirents` · `cargo test -p ratarmount-formats-block --lib list_dirents` · `cargo test -p ratarmount-formats-squashfs --lib list_dirents` · `cargo test -p ratarmount-formats-git --lib list_dirents` · `cargo test -p ratarmount-formats-sqlar --lib list_dirents` · `cargo test -p ratarmount-formats-tar --lib list_dirents` · `cargo test -p ratarmount-formats-dmg --lib list_dirents` · `cargo test -p ratarmount-formats-qcow2 --lib list_dirents` · `cargo test -p ratarmount-formats-vhd --lib list_dirents` · `cargo test -p ratarmount-formats-vmdk --lib list_dirents` |
| NTFS RO list/read / nested no-tmp / offset (F-8) | always-on: `cargo test -p ratarmount-formats-ntfs --lib looks_like` · `cargo test -p ratarmount-formats-ntfs --lib open_from_reader` · `cargo test -p ratarmount-formats-ntfs --lib filetime` · `cargo test -p ratarmount-formats-ntfs --lib compressed` (LZNT1 `Unsupported`); mkfs list/read/`list_dirents`/`open_with_offset` skip without `mkfs.ntfs` (not in default GHA) |
| Nested UDF no-tmp / NSR02/NSR03 @ 32 KiB (F-8 crate) | `cargo test -p ratarmount-formats-udf --lib` (always-on synthetic VRS + volume; ISO `CD001`-only negative; mixed-disc NSR still true; `mkudffs`/`mkisofs` skip if missing) · `cargo test -p ratarmount-formats-udf --lib type3_continuation_huge_len` (type-3 AD `len=0x3FFFFFFF` fail-closed) |
| Image / Git / SQLAR / SingleFile cheap `list_dirents` | `cargo test -p ratarmount-formats-ext4 --lib list_dirents` · `cargo test -p ratarmount-formats-fat --lib list_dirents` · `cargo test -p ratarmount-formats-exfat --lib list_dirents` · `cargo test -p ratarmount-formats-block --lib list_dirents` · `cargo test -p ratarmount-formats-wim --lib list_dirents` · `cargo test -p ratarmount-formats-squashfs --lib list_dirents` · `cargo test -p ratarmount-formats-git --lib list_dirents` · `cargo test -p ratarmount-formats-sqlar --lib list_dirents` · `cargo test -p ratarmount-formats-tar --lib list_dirents` |
| WIM RO first-image list/read / nested no-tmp (F-8 crate) | `cargo test -p ratarmount-formats-wim --lib` (always-on uncompressed fixture + XPRESS codec; `wimlib_imagex` skip if no `wimlib-imagex`) |
| WIM RO first-image list/read / nested no-tmp (F-8 crate) | `cargo test -p ratarmount-formats-wim --lib` (always-on uncompressed fixture + XPRESS extra-length/sparse + SHA-1 mismatch; LZX/LZMS residual; `wimlib_imagex` skip if no `wimlib-imagex`, including `--compress=xpress`) |
| FUSE readlink extra lookup / FR-10 type mismatch | `cargo test -p ratarmount-fuse --lib readlink_uses_cached` · `cargo test -p ratarmount-fuse --lib readdirplus_dirent_type` |
| AutoMount strip-ext duplicate dirent (dir `a/` + `a.tar` → two `a`) | `cargo test -p ratarmount-compositing --lib list_dirents_strip_ext_dir_archive_collision` |
| readdirplus cached size-0 placeholder (control `status` cat empty 60s) | `cargo test -p ratarmount-fuse --lib readdirplus_placeholder_zero_size` |
| NFS stale base read after live commit with delete (offsets shift) | `cargo test -p ratarmount-nfs --lib overlay_commit_live_delete_shifts` |
| FUSE stale base read after live commit with delete (offsets shift) | `cargo test -p ratarmount-fuse --lib overlay_commit_live_delete_shifts` |
| NULL `offsetheader` row breaks cheap readdir / warm open (foreign index) | `cargo test -p ratarmount-index --lib regression_null_offsetheader` |
| SQLite bulk insert SoA window (P2) | `cargo test -p ratarmount-index --lib insert_files_batch_soa` · `cargo test -p ratarmount-index --lib sql_files_type` · `cargo test -p ratarmount-formats-tar --lib regression_sql_type` · `cargo test -p ratarmount-formats-zip --lib regression_sql_type_deflate` · `cargo test -p ratarmount-formats-sevenzip --lib regression_sql_files_type` |
| Crafted `inf`/`1e999` mtime panics FUSE daemon (SystemTime overflow) | `cargo test -p ratarmount-fuse --lib unix_float_to_system_time_extreme` |
| NFS readdir cookie vanished mid-listing aborts `ls`; v4 cookie 1/2 reserved | `cargo test -p ratarmount-nfs --lib readdir_start_after_and_bad_cookie` · `cargo test -p ratarmount-nfs --features nfsv4 --lib v4_readdir_cookie` |
| NFS `ls -lah` missing `.` / `..` (v3 READDIR prefix; v4 Linux injects them) | `cargo test -p ratarmount-nfs --lib readdir_dot` · `cargo test -p ratarmount-nfs --features nfsv4 --lib v4_readdir_does_not_emit` |
| Live `.tar.zst` commit truncates zero-tail members (zero-run EOF cut) | `cargo test -p ratarmount-formats-tar --lib rewrite_zero_tail` · `cargo test -p ratarmount-formats-tar --lib rewrite_mid_member_opaque_prefix` · `cargo test -p ratarmount-formats-tar --lib rewrite_all_zero_window` |
| PAX `size=` member (≥ 8 GiB / zeroed ustar field) indexes as size 0 | `cargo test -p ratarmount-formats-tar --lib pax_size_keyword` |
| Overlay rename loses symlinks / destination on COW failure; rmdir non-empty | `cargo test -p ratarmount-compositing --lib rename_base_symlink` · `cargo test -p ratarmount-compositing --lib rename_keeps_destination` · `cargo test -p ratarmount-compositing --lib rmdir_refuses` |
| #88 phase 1: rename-over must not unlink first (visible target never Some→None; tombstoned target None→Some once; overlay, archive-only, and tombstoned targets) | `cargo test -p ratarmount-compositing --lib rename_over_overlay_archive_and_tombstone` · `cargo test -p ratarmount-compositing --lib rename_visible_lookup_never_none` · `cargo test -p ratarmount-compositing --lib rename_tombstone_lookup_none_to_some_once` |
| #88 phase 1: tombstone transaction failure after host rename returns success; durable rows match the crash table when every retry fails (duplicate archive `from` accepted on remount; tombstone + host file cleared on open; a host directory does not clear a directory tombstone) | `cargo test -p ratarmount-compositing --lib rename_tx_failure_matches_crash_table` · `cargo test -p ratarmount-compositing --lib clear_tombstone_with_host_on_open` · `cargo test -p ratarmount-compositing --lib clear_tombstone_keeps_host_directory` |
| #88 phase 1: failed rename tombstone tx is retried, then queued in `pending_rows`; the next `files` write replays them; live commit refuses while replay fails and the next commit deletes archive `from` (no published duplicate) | `cargo test -p ratarmount-compositing --lib rename_tx_retry_transient` · `cargo test -p ratarmount-compositing --lib rename_tx_pending_replays_on_next_db_write` · `cargo test -p ratarmount-compositing --lib rename_tx_pending_commit_refuses_then_replays` |
| #88 phase 1: queued `a`→`x` then `x`→`y` must not resurrect `/x` (append behind a failed replay; queue lock held across take/apply/restore; unlink and present writes queue too; drop and on-exit name paths an offline `--commit-overlay` would publish) | `cargo test -p ratarmount-compositing --lib rename_tx_pending_second_rename_keeps_intermediate_hidden` · `cargo test -p ratarmount-compositing --lib rename_tx_pending_replay_holds_queue_lock` · `cargo test -p ratarmount-compositing --lib rename_tx_pending_unlink_replays_before_tombstone` · `cargo test -p ratarmount-compositing --lib rename_tx_pending_unlink_queues_behind_failed_replay` · `cargo test -p ratarmount-compositing --lib rename_tx_failed_replay_keeps_rows` · `cargo test -p ratarmount-compositing --lib restore_pending_front_keeps_older_rows_ahead` · `cargo test -p ratarmount-compositing --lib rename_tx_pending_on_exit_names_reappear_paths` · `cargo test -p ratarmount-compositing --lib rename_tx_pending_drop_logs_reappear_paths` |
| #88 phase 1: direct-write retry holds `pending_rows` across the backoff (a concurrent `x`→`y` in that window must not resurrect `/x`); `Drop` recovers poisoned queue/db locks (`PoisonError::into_inner`); failed replay restores from the error inside `apply_pending_ops_sql`; drop log omits a re-exposed name and a path SQL already tombstones; overlay reset clears the queue; unmount joins interval/NFS/export threads and drops the overlay before `process::exit` (control search keeps only `Weak`) | `cargo test -p ratarmount-compositing --lib rename_tx_retry_window_second_thread` · `cargo test -p ratarmount-compositing --lib drop_recovers_poisoned` · `cargo test -p ratarmount-compositing --lib reset_overlay_contents_clears_pending` · `cargo test -p ratarmount-compositing --lib drop_log_omits_reexposed` · `cargo test -p ratarmount-compositing --lib drop_log_omits_sql_tombstone` · `cargo test -p ratarmount --bin ratarmount finish_overlay_serve_drops` · `cargo test -p ratarmount --bin ratarmount live_search_callback_does_not_pin` |
| Export bind failure after a listener is up skips overlay drop (`process::exit` inside `spawn_export_threads`); live interval-commit join hangs if `finish_overlay_serve` omits `request_shutdown` | `cargo test -p ratarmount --bin ratarmount finish_overlay_serve_joins_live_interval` · `cargo test -p ratarmount --bin ratarmount export_bind_failure_drops_overlay` |
| #88 phase 1: FUSE-only park before `rename_parked`/`unlink_parked` (mode 000, old-inode fstat, symlink `linkname`; `EMFILE`/`ENFILE` only) | `cargo test -p ratarmount-compositing --lib park_mode000_rename_and_unlink` · `cargo test -p ratarmount-compositing --lib park_fstat_old_inode` · `cargo test -p ratarmount-compositing --lib park_symlink_snapshot` |
| #88 phase 1: plain `rename`/`unlink` (9P/SFTP/SMB/NFS/export-core) never park, even when the park hook returns EMFILE | `cargo test -p ratarmount-compositing --lib plain_rename_and_unlink_do_not_park` |
| #88 phase 1: park open EMFILE/ENFILE fails closed (`to` unchanged; unlink removes nothing); before-tx hook is one-shot and runs after its mutex is dropped; non-Linux park open uses `O_NONBLOCK` (`O_PATH` is `cfg(target_os = "linux")`) | `cargo test -p ratarmount-compositing --lib park_open_emfile_leaves_names_unchanged` · `cargo test -p ratarmount-compositing --lib rename_before_tx_hook_is_one_shot` · `cargo test -p ratarmount-compositing --lib rename_before_tx_hook_runs_after_mutex_drop` · `cargo test -p ratarmount-compositing --lib park_open_flags_set_nonblock_off_linux` |
| #88 phase 1: park-open EACCES is metadata-only (`fd` is None, `last_fi` kept) and rename/unlink still change the names | `cargo test -p ratarmount-compositing --lib park_open_eacces_is_metadata_only` |
| #88 phase 2: detached nodeid serves old attrs/bytes (`nlink` 0, TTL 0); `FORGET` closes the parked fd only at 0; create after unlink is a new nodeid; fh-less `SETATTR` / new write `OPEN` on a detached id are `EACCES`; fh-bearing `SETATTR` truncates that fd; archive `Source` opened detached skips generation refresh; mode `000` rename/unlink still detaches | `cargo test -p ratarmount-fuse --lib detached_` · `cargo test -p ratarmount-fuse --lib forget_` · `cargo test -p ratarmount-fuse --lib create_after_unlink` · `cargo test -p ratarmount-fuse --lib create_entry_nlookup` · `cargo test -p ratarmount-fuse --lib setattr_detached` · `cargo test -p ratarmount-fuse --lib pre_rename_writer` · `cargo test -p ratarmount-fuse --lib nlookup_root` · `cargo test -p ratarmount-fuse --lib mode_000_rename_and_unlink_detach_with_fd` |
| #88 phase 2: `RLIMIT_NOFILE` soft raised to hard at FUSE start; macOS cap is `min(hard, kern.maxfilesperproc, OPEN_MAX)`; failure is logged and the mount continues | `cargo test -p ratarmount-fuse --lib nofile_soft` |
| #88 phase 2: kernel rename-over poller 0 ENOENT (overlay-backed seed and archive-member `d/final`); 300 held archive members keep old bytes; held archive member keeps old bytes across `--commit-overlay-interval`; pre-rename writer bytes are absent from the committed tar; mode `000` mv/rm | `cargo test -p ratarmount --test fuse_rename_over` |
| Unmount with many in-flight FORGETs exits 1 (`ECONNABORTED` / os error 103 from fuser 0.15 `Session::run`; clean session end, same as `ENODEV`) | `cargo test -p ratarmount-fuse --lib fuse_session_result_treats_econnaborted` · `cargo test -p ratarmount-fuse --lib notifier_exits_on_enodev` · `cargo test -p ratarmount --test fuse_rename_over many_archive` |
| #88 phase 2 stress (off by default): 1×400 and 8×100, 3 runs, both targets, 0 ENOENT | `cargo test -p ratarmount --test fuse_rename_over -- --ignored fuse_rename_over_stress` |
| #88 phase 2 leaves #92 / #91 / #84 invalidation as they are (old name + both children + parents, no destination `INVAL_ENTRY`, flush after reply, sweep still invalidates) | `cargo test -p ratarmount-fuse --lib rename_paths` · `cargo test -p ratarmount-fuse --lib rename_reply` · `cargo test -p ratarmount-fuse --lib rename_after_generation_sweep` · `cargo test -p ratarmount-fuse --lib attr_advertised` · `cargo test -p ratarmount-fuse --lib entry_advertised` · `cargo test -p ratarmount --test fuse_rename` |
| FUSE `io_to_errno` keeps raw EMFILE/ENFILE (and other unmapped raw errnos) | `cargo test -p ratarmount-fuse --lib io_to_errno_maps_raw_emfile_and_enfile` |
| crates.io dry-run packages L0 without live publish (F-10 / Q5=a) | `./packaging/test-crates-io-dry-run.sh` |
| GitHub Release dies on 0-byte assets | `./packaging/test-release-asset-filter.sh` |
| Homebrew tap cask is a formula / path-URL install / missing sha256 | `./packaging/test-homebrew-cask.sh` |
| mount.fuse.ratarmount helper puts secrets on argv / Type≠fuse.ratarmount | `./packaging/test-systemd-unit.sh` (skip systemd-analyze if no systemd; kubeconform skip-if-missing) |
| Packages portable apt CDN reset (missing glibc2.31 amd64) | `./packaging/test-packages-apt-retries.sh` |
| Portable glibc 2.31 tarball links OpenSSL 1.1 (fails to start on Arch, Ubuntu 22.04+, DGX OS) | `./packaging/test-portable-deps-selftest.sh` (no binary; CI `check` job) · `./packaging/test-portable-deps.sh` (Packages job runs it on the built binary; pass a binary or extracted tarball path locally) |
| CI apt CDN hang cancels cold-index / FUSE allowlists | `./packaging/test-ci-apt-retries.sh` |
| Windows session/index compile without FUSE (G6, no WinFsp). Session's Windows check compiles `ratarmount-compositing`; `missing_xattr_errno` must not name `libc::ENOATTR` on Linux or Windows | `./packaging/test-windows-lib-ci.sh` · `cargo test -p ratarmount-core --lib effective_ids` · `cargo test -p ratarmount-core --lib metadata_helpers` · `cargo test -p ratarmount-index --lib tar_stats_from_metadata_uses_len` · `cargo test -p ratarmount-index --lib home_dir_prefers` |
| NFS short-read / cheap-dirent empty `cat` | `cargo test -p ratarmount-nfs --lib fill_loops` · `cargo test -p ratarmount-nfs --lib readdir_size_zero` |
| NFS clap steals archive / concurrent readers | `cargo test -p ratarmount --bin ratarmount nfs_flag` · `cargo test -p ratarmount-nfs --lib concurrent_readers` |
| HTTP/WebDAV/SMB/`--ninep`/`--sftp` clap steals archive | `cargo test -p ratarmount --bin ratarmount http_flag` · `cargo test -p ratarmount --bin ratarmount ninep_flag` · `cargo test -p ratarmount --bin ratarmount webdav_flag` · `cargo test -p ratarmount --bin ratarmount smb_flag` · `cargo test -p ratarmount --bin ratarmount sftp_flag` |
| HTTP GET of gzip member truncated (short `Read::read` = EOF) | `cargo test -p ratarmount-http --lib regression_http_get_gzip` |
| SMB READ fill-loop truncated | `cargo test -p ratarmount-smb --lib regression_smb_read_fill` |
| SMB CREATE lease grants R/RH | `cargo test -p ratarmount-smb --lib lease` |
| SMB LEASE_BREAK on conflicting open/write | `cargo test -p ratarmount-smb --lib lease_break` |
| 9P Tread fill-loop truncated | `cargo test -p ratarmount-9p --lib fill_read_ninep` |
| macOS/BSD: accepted 9P/SMB sockets inherit O_NONBLOCK from the listener, so large replies fail with EAGAIN or are cut short | `cargo test -p ratarmount-9p --lib regression_accepted_socket_clears_inherited_nonblocking` · `cargo test -p ratarmount-smb --lib regression_accepted_socket_clears_inherited_nonblocking` · `cargo test -p ratarmount-remote --lib regression_accepted_socket_clears_inherited_nonblocking` |
| `docker://ubuntu:24.04` treated as a local path | `cargo test -p ratarmount-session --lib docker_ubuntu` · `cargo test -p ratarmount-remote --lib docker_ubuntu` |
| restic URL parser (absolute / extra slash / S3 residual; not a local colon name) | `cargo test -p ratarmount-formats-restic --lib parse_restic` · `cargo test -p ratarmount-remote --lib restic` · `cargo test -p ratarmount-session --lib restic` |
| restic snapshot browser (two snapshots, 1 KiB pack read, password Debug, v2 zstd fixture, RESTIC_PASSWORD_FILE) | `cargo test -p ratarmount-formats-restic --lib restic` · `cargo test -p ratarmount-session --lib restic_open` |
| restic init+backup round-trip (skip-if-no-restic) | `cargo test -p ratarmount-formats-restic --lib restic_init` |
| SFTP non-loopback without authorized_keys file | `cargo test -p ratarmount-sftp --lib regression_non_loopback` |
| NFS compositing pin (`member_seek_is_cheap`) | `cargo test -p ratarmount-compositing --lib file_version_layer_forwards` · `cargo test -p ratarmount-compositing --lib automount_forwards` |
| NFS serve stop | `cargo test -p ratarmount-nfs --lib serve_stop` |
| NFS overlay write / stale reader after truncate | `cargo test -p ratarmount-nfs --lib overlay_` · `cargo test -p ratarmount-nfs --lib writers_rofs` |
| NFS overlay rename / symlink | `cargo test -p ratarmount-nfs --lib overlay_rename` · `cargo test -p ratarmount-nfs --features nfsv4 --lib v4_overlay_rename` |
| Live overlay commit (uncompressed TAR / `.tar.zst`) | `cargo test -p ratarmount-compositing --lib live_commit` · `cargo test -p ratarmount --test commit_overlay_live` · `cargo test -p ratarmount --bin ratarmount -- live_commit` · `cargo test -p ratarmount-nfs --lib overlay_commit_live` |
| Missing `.tar` / `.tar.zst` write mount create | `cargo test -p ratarmount-compositing --lib empty_archive` · `cargo test -p ratarmount-compositing --lib is_uncompressed_tar` · `cargo test -p ratarmount --test commit_overlay_live create_missing` · `cargo test -p ratarmount --bin ratarmount -- create_missing` |
| Interval commit skips recently modified overlay files | `cargo test -p ratarmount-compositing --lib live_commit_idle` (open write fd must not persist/unlink) |
| Interval commit unpins still-open write after NFS/protocol fd reuse | `cargo test -p ratarmount-compositing --lib live_commit_idle_skips_open_write_fd_after_fd_reuse` · `cargo test -p ratarmount-compositing --lib live_commit_idle_skips_open_write_fd_after_protocol_write_fd_reuse` |
| Interval commit after overlay rename of an open write fd | `cargo test -p ratarmount-compositing --lib live_commit_idle_skips_open_write_fd_after_rename` |
| Interval/on-exit overlay commits overlap splices (V-4 coalesce) | `cargo test -p ratarmount-compositing --lib overlay_commit_queue` · `cargo test -p ratarmount --bin ratarmount overlay_commit_on_exit_waits` · `cargo test -p ratarmount --test commit_overlay_live commit_overlay_interval_on_exit` |
| NFS READ after live tar.zst overlay commit | `cargo test -p ratarmount-nfs --lib overlay_commit_live_tar_zst` |
| NFSv4.1 RO adapter (lookup/read/readdir) | `cargo test -p ratarmount-nfs --features nfsv4 --lib v4_` |
| NFSv4 overlay create/write invalidate | `cargo test -p ratarmount-nfs --features nfsv4 --lib v4_overlay` |
| NFSv4 reader idle/lease drop | `cargo test -p ratarmount-nfs --features nfsv4 --lib evict_idle` |
| NFS `--nfs-vers` 3\|4 clap | `cargo test -p ratarmount --bin ratarmount nfs_vers` |
| NFSv4 EXCHANGE_ID smoke | `cargo test -p ratarmount-nfs --features nfsv4 --lib v4_exchange_id` |
| Linux/macOS packages compile `nfsv4` + `sftp-russh` | `./packaging/test-nfsv4-features.sh` |
| Kernel NFS Docker (v3 + v4.1) | `./test-harness/nfs-docker/run.sh` (privileged Docker + real `mount -t nfs`; skip if docker/privileged unavailable; empty/wrong bytes = fail) |
| Kernel NFS Docker overlay write | `./test-harness/nfs-docker/run.sh 3 write` · `./test-harness/nfs-docker/run.sh 4 write` |
| SMB NTLM password / unsigned session | `cargo test -p ratarmount-smb --lib ntlm` · `cargo test -p ratarmount-smb --lib sign` |
| SMB 3.1.1 preauth hash | `cargo test -p ratarmount-smb --lib preauth` |
| SMB 3.1.1 encrypted READ (AES-128-GCM) | `cargo test -p ratarmount-smb --lib encrypted_read` · guest unencrypted: `cargo test -p ratarmount-smb --lib guest_311` |
| SMB 3.1.1 AES-128-CCM TRANSFORM | `cargo test -p ratarmount-smb --lib transform_aes128_ccm` |
| SMB 3.1.1 KDF signing/cipher keys (MS blog) | `cargo test -p ratarmount-smb --lib smb3_kdf_ms` |
| SMB encrypt_data without key is plaintext | `cargo test -p ratarmount-smb --lib wrap_reply_fails_closed` |
| SMB TRANSFORM nonce wrap reuses GCM nonce | `cargo test -p ratarmount-smb --lib transform_nonce_wrap` |
| SMB LOGOFF drops CipherId so re-auth is cleartext | `cargo test -p ratarmount-smb --lib logoff_keeps_cipher` |
| SMB 3.1.1 preauth without SHA-512 | `cargo test -p ratarmount-smb --lib without_sha512` |
| WebDAV LOCK 423 / COPY / Basic | `cargo test -p ratarmount-http --lib lock` · `cargo test -p ratarmount-http --lib copy` · `cargo test -p ratarmount-http --lib basic` |
| SFTP password policy / non-loopback | `cargo test -p ratarmount-sftp --lib password` · `cargo test -p ratarmount-sftp --features sftp-russh --lib password` |
| GCS GOOG1 HMAC | `cargo test -p ratarmount-remote --lib goog1` · `cargo test -p ratarmount-remote --lib hmac` |
| FTP LIST/MLSD folder | `cargo test -p ratarmount-remote --lib ftp` |
| rclone+ URL | `cargo test -p ratarmount-remote --lib rclone` · `cargo test -p ratarmount-remote --lib is_remote_url` |
| `--sftp-subsystem` clap | `cargo test -p ratarmount --bin ratarmount sftp_subsystem` |
| Last-frame splice remount rescans prefix | `cargo test -p ratarmount-formats-tar --lib regression_incremental_last_frame_no_prefix_seek` |
| Incremental `files` ≠ full `create_index_body` | `cargo test -p ratarmount-formats-tar --lib regression_incremental_equals_full_index` |
| On-exit persist leaves stale sidecar (remount full-parses) | `cargo test -p ratarmount --test commit_overlay_live on_exit_remount` · `cargo test -p ratarmount --bin ratarmount -- live_commit_on_exit_remount` |
| Live uncompressed TAR sidecar patch from EOF after unclassified delete (ghost member) | `cargo test -p ratarmount-compositing --lib regression_unclassified_delete` |
| Interval reopen | `cargo test -p ratarmount --test commit_overlay_live` · `cargo test -p ratarmount --bin ratarmount -- live_commit` |
| Pre-splice `zstdblocks` used for suffix parse | `cargo test -p ratarmount-formats-tar --lib regression_incremental_zstdblocks_fresh` |
| GNU `--append` from `pre_size` misses members | `cargo test -p ratarmount-formats-tar --lib regression_incremental_append_eof` |
| Opaque persist fail-closed | `cargo test -p ratarmount-formats-tar --lib rewrite_mid_member_opaque_prefix` |
| Opaque prefix + later valid header | `cargo test -p ratarmount-formats-tar --lib regression_incremental_opaque_then_header` |
| `find '*.fits'` without FUSE | `cargo test -p ratarmount --bin ratarmount find_glob` |
| `find` clap steals archive / pattern | `cargo test -p ratarmount --bin ratarmount find_flag` |
| Session::find composite keyset (duplicates per path) | `cargo test -p ratarmount-session --lib find_glob_pages_composite_keyset` · `cargo test -p ratarmount-index --lib search_query_after` |
| CLI find first page limit 10_000 (session parity) | `cargo test -p ratarmount --bin ratarmount find_session_parity` |
| ensure_fts5 not created on Session::open | `cargo test -p ratarmount-session --lib ensure_fts5_not_on_session_open` |
| Control read-only `search/<pattern>` | `cargo test -p ratarmount-compositing --lib control_search` |
| Socket `search` | `cargo test -p ratarmount --bin ratarmount control_search_socket` |
| FTS5 path + hashes | `cargo test -p ratarmount-index --lib search_fts5` (default `cargo test -p ratarmount-index --lib`, no extra features) |
| Inbound HEAD **archive** `Link: describedby` → fetch | `cargo test -p ratarmount-index --lib link_describedby_archive_head` · `cargo test -p ratarmount-session --lib apply_remote_index_discovery_follows_archive_link` |
| Remote sidecar XDG LRU remount 0 GET (no `.ptr`) | `cargo test -p ratarmount-index --lib meta_cache` · `cargo test -p ratarmount-index --lib remount_well_known` · `cargo test -p ratarmount-session --lib apply_remote_index` |
| Local cached sidecar reused after remote archive replace (URL-label tarstats no-op) | `cargo test -p ratarmount-session --lib apply_remote_index_local_copy_rejects` · `cargo test -p ratarmount-session --lib cached_remote_index_is_stale` · `cargo test -p ratarmount-session --lib hash_http_range_window` · `cargo test -p ratarmount-session --lib apply_remote_index_read_only_stale` · `cargo test -p ratarmount-session --lib apply_remote_index_local_copy_keeps_match` |
| Remote `{url}.index.ptr` then `{url}.index.{id}.sqlite` GET (HTTP/S3; 404/tarstats continue) | `cargo test -p ratarmount-session --lib apply_remote_index` · `cargo test -p ratarmount-remote --lib fetch_s3_pointer` · `cargo test -p ratarmount-index --lib sibling_index_pointer` |
| S3 PutObject / multipart abort on error | `cargo test -p ratarmount-remote --lib s3_put_signs_body_hash_not_empty_payload` · `cargo test -p ratarmount-remote --lib s3_multipart_signs_partnumber_and_uploadid` · `cargo test -p ratarmount-remote --lib s3_second_put_aborts_without_complete` |
| S3 V-2 pointer PUT blob-then-pointer / fail-closed leftover blob | `cargo test -p ratarmount-remote --lib put_s3_index_siblings_puts_blob_then_pointer` · `cargo test -p ratarmount-remote --lib put_s3_index_siblings_blob_500_does_not_put_pointer` · `cargo test -p ratarmount-remote --lib put_s3_index_siblings_multipart_blob_then_pointer` |
| S3 write refused for anonymous credentials; a failed multipart completion aborts the upload (F-7 write probe) | `cargo test -p ratarmount-remote --lib s3_anonymous_put_errors` · `cargo test -p ratarmount-remote --lib s3_complete_error_body_aborts` |
| Outbound GET index.sqlite Content-Type | `cargo test -p ratarmount-http --lib index_content_type` |
| Local `oci:{digest}` cache skips referrer | `cargo test -p ratarmount-remote --lib oci_referrer_not_fetched_on_cache_hit` |
| OCI referrer GET on miss | `cargo test -p ratarmount-remote --lib oci_referrer` |
| Publish local sidecar | `cargo test -p ratarmount --bin ratarmount publish_index` · `publish_index_flag` clap-steal |
| Immutable index pointer / `--index-id` (V-2b) | `cargo test -p ratarmount-index --lib index_pointer` · `cargo test -p ratarmount-index --lib bind_local_index_id` · `cargo test -p ratarmount --bin ratarmount publish_index` · `cargo test -p ratarmount --bin ratarmount index_id` |
| Fingerprint / tarstats full-hash slurps body `Vec` | `cargo test -p ratarmount-index --lib fingerprint` · `cargo test -p ratarmount-index --lib archive_full_hash` · `cargo test -p ratarmount-index --lib compute_hashes` · keep `regression_head_only` + `cargo test -p ratarmount-session --lib regression_progressive_nested_fingerprint` |
| Offset-order restore / find walks name order | `cargo test -p ratarmount-index --lib dirent_order` · `cargo test -p ratarmount --bin ratarmount find_offset_order` · `cargo test -p ratarmount-formats-tar --lib regression_offset_order_seeks` · `cargo test -p ratarmount-formats-zip --lib regression_offset_order_seeks` · `cargo test -p ratarmount-formats-sevenzip --lib regression_offset_order` |
| Overlay-only extract after offset flatten (dummy cookie seeks) | `cargo test -p ratarmount-compositing --lib overlay_only` · `N_RESTORE=10000 ./benchmarks/compare-vector-wave.sh` (env-gated, not default CI) |
| Locate fat `FileInfo` on large catalog; overlay last-wins missing on control search | `cargo test -p ratarmount-index --lib scan_glob` · `cargo test -p ratarmount-compositing --lib search_cheap` · `find_glob` · `control_search` · `search_fts5` |
| Torn sidecar during `-c` (tmp+rename / dest unlinked at create) | `cargo test -p ratarmount-index --lib regression_reader_survives` · `cargo test -p ratarmount-index --lib regression_drop_unpublished` · `cargo test -p ratarmount-session --lib regression_store_zstd_blocks_in_index_missing_path` |
| Folder live glob without fat `list()` / symlink-to-`/etc` TSV leak | `cargo test -p ratarmount-compositing --lib search_cheap` (filters: `folder_globs`, `folder_limit`) |
| Union locate forwards `sources[0]` / drops later catalog | `cargo test -p ratarmount-compositing --lib search_cheap` (filters: `union_merges`, `union_empty`, `union_none_if_any`, `union_limit`) |
| OCI locate forwards `layers[0]` / emits `.wh.*` / misses whiteouts | `cargo test -p ratarmount-compositing --lib search_cheap` (filters: `oci_applies_whiteouts`, `oci_none_if_any`, `oci_empty`, `oci_higher_layer`) |
| Session pages 1k-entry TAR (page size 50) | `cargo test -p ratarmount-session --lib list_dirents_page` |
| Session catalog does not reprint harness line / second MemIndex | `cargo test -p ratarmount-session --lib catalog_open_silent` · `cargo test -p ratarmount-index --lib open_catalog_read_only` |
| GNU incremental dumpdir name absent from page 1 | `cargo test -p ratarmount-session --lib list_dirents_page_dumpdir` · `cargo test -p ratarmount-index --lib list_dirents_page` |
| `read_range` 4 KiB from 100 MiB member (no full slurp) | `cargo test -p ratarmount-session --lib read_range_capped` |
| Encrypted 7z member `read_range` / `extract_to` is BadPassword | `cargo test -p ratarmount-session --lib read_range_encrypted_7z` · `cargo test -p ratarmount-session --lib extract_to_encrypted_7z` |
| Extract one member to disk | `cargo test -p ratarmount-session --lib extract_to` |
| Extract short/truncated member reports success (silent dest truncate) | `cargo test -p ratarmount-session --lib extract_to_short_member` |
| Extract path-escape reject (`../`, absolute) | `cargo test -p ratarmount-session --lib extract_to_path_escape` |
| Extract writes through dest-dir / dest symlink out of dest_dir | `cargo test -p ratarmount-session --lib extract_to_path_escape_via_dest_dir_symlink` · `cargo test -p ratarmount-session --lib extract_to_path_escape_via_prior_archive_symlink` · `cargo test -p ratarmount-session --lib extract_to_replace_unlinks_dest_symlink` · `cargo test -p ratarmount-session --lib extract_to_skip_does_not_follow_dangling_dest_symlink` |
| Extract-all keyset does not use list_visible_files_by_offset | `cargo test -p ratarmount-session --lib extract_all_keyset` · `cargo test -p ratarmount-index --lib list_extract_payload_page` |
| Extract cancel mid-copy unlinks truncated dest | `cargo test -p ratarmount-session --lib extract_to_cancel_unlinks_partial` |
| Extract Replace+cancel destroys pre-existing dest (`File::create` then unlink) | `cargo test -p ratarmount-session --lib extract_to_replace_cancel_preserves_existing` · `cargo test -p ratarmount-session --lib extract_to_replace_cancel_preserves_dest_symlink` · `cargo test -p ratarmount-session --lib extract_to_replace_refuses_dest_directory` |
| Recreate::Never missing sidecar / tarstats mismatch / no rebuild | `cargo test -p ratarmount-session --lib recreate_never` |
| Temp index unlinked on Drop and failed open | `cargo test -p ratarmount-session --lib index_policy_temp` |
| Sibling unwritable parent → SiblingNotWritable (no `:memory:`) | `cargo test -p ratarmount-index --lib sibling_not_writable` · `cargo test -p ratarmount-session --lib resolve_sibling` |
| local-index-v1 LRU / UserCache writes meta-v3 | `cargo test -p ratarmount-index --lib local_index` · `cargo test -p ratarmount-session --lib resolve_user_cache` |
| payload-v1 member cache (sha256; skip :memory:/overlay; not under local-index-v1) | `cargo test -p ratarmount-index --lib payload_cache` · `cargo test -p ratarmount-compositing --lib payload_cache` |
| CliCompat still `:memory:` last resort | `cargo test -p ratarmount-index --lib resolve_index_location_unwritable` · `cargo test -p ratarmount-session --lib resolve_clicompat` |
| IndexJob progress < 4 events / 1k TAR as sole proof | `cargo test -p ratarmount-session --lib index_job_progress_events` · `cargo test -p ratarmount-index --lib regression_index_build_hooks_progress_ticks` |
| IndexJob cancel at ~50% leaves dest sidecar valid; tmp gone | `cargo test -p ratarmount-session --lib index_job_cancel` · `cargo test -p ratarmount-index --lib regression_cancel_does_not_publish_tmp` |
| IndexJob sidecar opens with factory/CLI path (G7.1) | `cargo test -p ratarmount-session --lib index_job_g7_factory_opens_job_sidecar` |
| Session::open of a CLI-written sidecar (G7.2) | `cargo test -p ratarmount-session --lib index_job_g7_session_opens_cli_sidecar` |
| IndexJob sidecar not 0.7.x / Python 0.7.x cannot open | `cargo test -p ratarmount-session --lib index_job_sidecar_python_07` · `./test-harness/run-indexjob-python-interop.sh` |
| Factory “cancelled” substring in a path maps to Cancelled | `cargo test -p ratarmount-session --lib map_factory_error_cancelled_in_path` |
| IndexJob Temp Drop unlinks the returned sidecar | `cargo test -p ratarmount-session --lib index_job_temp_sidecar_survives_run` |
| Nested flatten/AutoMount cancel publishes over dest | `cargo test -p ratarmount-session --lib index_job_cancel_nested_flatten_keeps_dest` |
| Session not `Send` / L2 probe order reorder | `cargo test -p ratarmount-session --lib session_send` · `cargo test -p ratarmount-session --lib ordered_format_backends` |
| Session HTTP Range (`http-export`) | `cargo test -p ratarmount-session --features http-export --lib http::` |
| Declared MSRV lower than the toolchain the workspace needs (README/Cargo.toml drift) | `./test-harness/test-msrv-ci.sh` · CI job `msrv` |
| FUSE `rename(2)` ENOSYS on `-w` (#86; temp-then-rename writers); rename kernel invalidation (cross-dir new parent, flush after reply) | `cargo test -p ratarmount --test fuse_rename` · `cargo test -p ratarmount-fuse --lib rename_paths` · `cargo test -p ratarmount-fuse --lib rename_reply` · `cargo test -p ratarmount-fuse --lib io_to_errno_maps_already_exists` |
| FUSE `-w`: generation sweep / rename rebind cleared the stable cache, so a later write/truncate/rename/dir change sent no kernel attr invalidation (60s stale attr) | `cargo test -p ratarmount-fuse --lib after_generation_sweep` · `cargo test -p ratarmount-fuse --lib attr_advertised` |
| FUSE rename of a 60s-cached member (to a new name or over a cached one): held fd read as `(deleted)` in /proc; destination must stay fresh (host append) | `cargo test -p ratarmount --test fuse_rename fuse_rename_cached_source` |
| Overlay opened with an empty/partial tombstone set on a SQL error (unlinked archive members reappear) | `cargo test -p ratarmount-compositing --lib overlay_open_fails_when` |
| Unopenable overlay database gives a bare SQLite error with no path or recovery hint; a locked one (another mount) must say "in use", never "move it aside" (#89 follow-up) | `cargo test -p ratarmount --test overlay_open_error` |
| Startup exits 101 when the launcher's stdout/stderr pipe has no reader (#93; `println!` panics on EPIPE) | `cargo test -p ratarmount --test startup_broken_stdio` |
| Index harness status line and `ratarmount` binary-crate `println!`/`eprintln!` panic (exit 101) when the reader goes away after startup (#93 follow-up; `ratarmount-compositing` commit / create-if-missing prints are covered too). Format-crate progress lines (`Creating offset dictionary`) and session-factory messages (#102) use shared no-panic macros in `ratarmount-core`. The other 13 format crates (ar, asar, cab, cpio, html, iso9660, libarchive, ogg, pdf, sevenzip, warc, xar, zip) share that import but are not each driven against a closed pipe. Remaining residual: the remote folder-listing line | `cargo test -p ratarmount-index --lib print_status_survives_dead_stdout` · `cargo test -p ratarmount --bin ratarmount quiet_print` · `cargo test -p ratarmount-compositing --lib quiet_print` · `cargo test -p ratarmount-formats-tar --lib create_index_survives_dead_stdout` · `cargo test -p ratarmount-session --lib factory_prints_survive_dead_stdout` (compositing drives create-if-missing, offline plan, confirm prompt, Canceled / Committed lines; the GNU tar relay shares the crate-wide shadow; tar drives `SqliteIndexedTar::create_index`; session drives the factory rebuild `eprintln!` and then `create_index`) |
| Missing or table-less overlay DB silently recreated on `-w` open (tombstones lost, unlinked members reappear) (#96) | `cargo test -p ratarmount-compositing --lib overlay_open_` · `cargo test -p ratarmount-compositing --lib overlay_marker` · `cargo test -p ratarmount-compositing --lib overlay_commit_plan_refuses` |
| Overlay DB / marker names visible and mutable through the mount (create truncated the DB; FUSE replied EIO); legacy marker left behind (#97 follow-up) | `cargo test -p ratarmount-compositing --lib overlay_internal_names` (incl. `_ignore_ascii_case`) · `cargo test -p ratarmount-compositing --lib overlay_markers_fail_closed` · `cargo test -p ratarmount-compositing --lib overlay_refusal_lists` · `cargo test -p ratarmount-compositing --lib overlay_commit_refusal` · `cargo test -p ratarmount-fuse --lib overlay_internal_name` |
| fuser 0.18 upgrade changes init, ACLs, wire replies, notifications or detached inode lifetime (AI-0a) | `cargo test -p ratarmount-fuse --lib fuser_` |
| fuser Config rejects ordered mount flags or owner-only auto_unmount (AI-0a) | `cargo test -p ratarmount --test fuse_rename_over fuse_fuser_` |
| HTTP prefetch blocks seek/drop, overfetches headers, retains transient errors, exceeds shared budget, changes gateway timeouts, or leaks credentials to the redirect host (AI-0b) | `cargo test -p ratarmount-remote --lib http_pool` · `cargo test -p ratarmount-session --lib apply_remote_index` |
| Safetensors malformed headers, ranges, dtype sizes, naming collisions, reserved root names (AI-ST) | `cargo test -p ratarmount-formats-tensors --lib safetensors_` · `cargo test -p ratarmount-formats-tensors --lib collision_naming` · `cargo test -p ratarmount-formats-tensors --lib gguf_reserved_root_names` |
| GGUF KV parsing, quantized sizes, alignment, truncation and big-endian rejection (AI-ST) | `cargo test -p ratarmount-formats-tensors --lib gguf_` |
| Tensor cheap readdir, warm index, nested reads; factory detection, aliases, nested no-spool (AI-ST) | `cargo test -p ratarmount-formats-tensors --lib list_dirents` · `cargo test -p ratarmount-formats-tensors --lib warm_index` · `cargo test -p ratarmount-formats-tensors --lib nested_` · `cargo test -p ratarmount-session --lib tensors` |
| Session member extent exposes header/compressed/nested offsets (AI-0d) | `cargo test -p ratarmount-session --lib member_extent` |
| Offset paging duplicates/skips files, burdens cold builds, or mutates protected sidecars (AI-0d) | `cargo test -p ratarmount-session --lib iter_by_offset_page` · `cargo test -p ratarmount-index --lib offset_page` |
| Session codec parallelization discarded (AI-0d) | `cargo test -p ratarmount-session --lib parallelization_` |
| Policy errno additions change historical protocol errors (AI-0c) | `cargo test -p ratarmount-fuse -p ratarmount-export-core -p ratarmount-smb --lib preserves_legacy_raw_errors` · `cargo test -p ratarmount-nfs --features nfsv4 --lib preserves_legacy_raw_errors` |
| Frontend writes bypass the overlay policy or lose readonly/quota errors (AI-0c) | `cargo test -p ratarmount-compositing --lib regression_overlay_policy` · `cargo test -p ratarmount-export-core -p ratarmount-fuse -p ratarmount-nfs -p ratarmount-9p -p ratarmount-sftp -p ratarmount-smb -p ratarmount-http --lib regression_overlay_policy` |
| FUSE WRITE loses EIO or holds the handle table during I/O; unlinked descriptors evade quota (AI-0c) | `cargo test -p ratarmount-fuse --lib regression_write_handle` · `cargo test -p ratarmount-fuse --lib regression_overlay_io` · `cargo test -p ratarmount-compositing --lib regression_unlinked_writers` · `cargo test -p ratarmount-fuse --lib regression_orphan_quota` |
| COW rejects small truncates or blocks writers; cleanup failure repeats commits; poisoned policy (AI-0c) | `cargo test -p ratarmount-compositing --lib regression_truncate_large_member` · `cargo test -p ratarmount-compositing --lib regression_slow_cow` · `cargo test -p ratarmount-compositing --lib regression_rename_retry` · `cargo test -p ratarmount-compositing --lib regression_commit_cleanup_read_dir` · `cargo test -p ratarmount-compositing --lib regression_policy_panic` · `cargo test -p ratarmount-compositing --lib regression_readonly_trunc` |
| Crash mid-copy leaves a short overlay file that remount and `--commit-overlay` publish; a short EOF (`Ok(0)` before the member size, or before `min(size, truncate hint)` on the quota path) is not published (#126) | `cargo test -p ratarmount-compositing --lib regression_cow_crash_mid_copy_hides_partial_and_skips_commit` · `cargo test -p ratarmount-compositing --lib regression_overlay_policy_accounts_partial_cow_failure` · `cargo test -p ratarmount-compositing --lib regression_overlay_policy_accounts_short_cow_eof_slack` · `cargo test -p ratarmount-compositing --lib regression_cow_short_eof_default_path_not_published` · `cargo test -p ratarmount-compositing --lib regression_cow_v3_unreadable_dir_reopen` · `cargo test -p ratarmount-compositing --lib regression_cow_v3_second_open_keeps_staging` · `cargo test -p ratarmount-compositing --lib regression_cow_v3_already_exists_refunds` · `cargo test -p ratarmount-compositing --lib regression_cow_v3_persist_error_refunds` · `cargo test -p ratarmount-compositing --lib regression_cow_v3_dir_fsync_error_keeps_charge` · `cargo test -p ratarmount-compositing --lib regression_cow_policy_applies_member_mode_and_mtime` |
| Explicit git ref silently falls back to HEAD (AI-GIT) | `cargo test -p ratarmount-formats-git --lib regression_bad_ref` |
| Synthetic .git leaks history/source SHA, trusts an altered cache, or reports dirty status (AI-GIT) | `cargo test -p ratarmount-formats-git --lib regression_synthetic` · `cargo test -p ratarmount-session --lib git_tests` · `cargo test -p ratarmount --test fuse_git_synthetic` |
| Python URL/error mapping, embedding round trip, or concurrent ranged readers regress (AI-PY1) | `cargo test -p ratarmount-python --features embedding` · `ratarmount-python/.venv/bin/pytest ratarmount-python/tests` |
| Overlay read-only globs miss a mutation (rename/parent rename/COW parent swap) or quota is exceeded under concurrency, COW, unlink or startup scan (AI-SB1) | `cargo test -p ratarmount-compositing --lib overlay_policy::tests` · `cargo test -p ratarmount-9p -p ratarmount-nfs --lib regression_sandbox_policy_denials` · `cargo test -p ratarmount-nfs --features nfsv4 --lib regression_sandbox_policy_denials` |
| overlay-stats creates a missing DB, miscounts, or the verb steals its directory; policy flags without -w (AI-SB1) | `cargo test -p ratarmount --bin ratarmount overlay_stats::tests` · `cargo test -p ratarmount --bin ratarmount sandbox_cli_tests` |
| FUSE sandbox read-only rule / quota not enforced on a real mount (AI-SB1) | `cargo test -p ratarmount --test fuse_rename fuse_sandbox_readonly_and_quota` |
| hf:// parsing/auth precedence, stale or over-expanded listings, CDN credential or signed-URL leakage, malformed pagination, 429 handling, shared resolve (AI-HF1) | `cargo test -p ratarmount-remote --lib hf::` · `cargo test -p ratarmount-remote --lib regression_http_cached_redirect_transport_error_redacts_signature` |
| hf:// recursive routing tags as filenames, stale commit indexes, unpinned sibling indexes (AI-HF1) | `cargo test -p ratarmount-session --lib regression_hf` · `cargo test -p ratarmount-index --lib regression_hf` · `cargo test -p ratarmount --bin ratarmount regression_http_debug_logging_hides_signed_request_urls` |
| Passthrough exposes archive headers or next-member bytes, bypasses overlay policy, negotiates without CAP_SYS_ADMIN (stack depth), retries denied registrations, or loses backing registrations (AI-PT) | `cargo test -p ratarmount-fuse --lib passthrough` · `cargo test -p ratarmount-fuse --lib fuser_passthrough` |
| Backing extents disappear through wrappers or expose compressed TAR bytes (AI-PT) | `cargo test -p ratarmount-compositing --lib backing_extent` · `cargo test -p ratarmount-formats-tar --lib backing_extent` |
| Passthrough CLI parsing or on-mount byte mismatch / unprivileged auto and on (AI-PT) | `cargo test -p ratarmount --bin ratarmount passthrough` · `cargo test -p ratarmount --test fuse_passthrough` |
| Python fsspec chaining, torch/WebDataset sample grouping, 32-thread reads without the Archive lock, wheel workflow (AI-PY2) | `cargo test -p ratarmount-python --features embedding` (Python suite: docs/python.md "Install from source") |
| Offline overlay patches lose binary, rename, symlink, mode or newline changes (AI-SB2) | `cargo test -p ratarmount --bin ratarmount diff::` |
| Offline diff exit codes, stdout contamination, DB creation, or dirty git base (AI-SB2) | `cargo test -p ratarmount --test diff` |
| Commit range copies corrupt unaligned bytes or fail on unsupported syscalls (AI-CM1) | `cargo test -p ratarmount-compress --lib fastcopy` |
| Interrupted append leaves a torn archive or rolls back over newer commits (aliases, reused inode, device change, corrupt journal), or patches a stale sidecar (AI-CM1) | `cargo test -p ratarmount-compress --lib append_journal` · `cargo test -p ratarmount-compositing --lib append_` · `cargo test -p ratarmount-session --lib append_` · `cargo test -p ratarmount-formats-tar --lib append_offset` · `cargo test -p ratarmount-compositing --lib commit_overlay_append` |
| Live append failure serves a torn archive, disables intervals on untouched-archive errors, or FUSE readers fail (AI-CM1) | `cargo test -p ratarmount-compositing --lib live_commit_append` · `cargo test -p ratarmount --test commit_overlay_live commit_overlay_append_recovery_before_mount_open` · `cargo test -p ratarmount --test commit_overlay_live commit_overlay_live_append_fuse_inode_and_readers` |
| Shards split samples, vary by worker count, misalign stored data, or verbs steal positionals (AI-SH) | `cargo test -p ratarmount --bin ratarmount regression_shard` |
| export-index offsets/frame columns wrong, detached sidecar loses zstdblocks, stdout banners corrupt exports (AI-SH) | `cargo test -p ratarmount --bin ratarmount regression_export` · `cargo test -p ratarmount --no-default-features --bin ratarmount regression_export` · `cargo test -p ratarmount-compress --lib regression_frame_writer` |
| HF/cloud index publication ordering, token leakage, WAL omission, oversize, or repeated remote TAR scan after discovery (AI-HF2) | `cargo test -p ratarmount --bin ratarmount publish_index` · `cargo test -p ratarmount-remote --lib publish` |
| Container uid/gid/umask missing from Unix attributes; unclear allow_other failure (AI-SB3) | `cargo test -p ratarmount-core --lib regression_attribute_mapping` · `cargo test -p ratarmount-fuse -p ratarmount-nfs -p ratarmount-9p -p ratarmount-sftp --lib sandbox_attr_tests` · `cargo test -p ratarmount-nfs --features nfsv4 --lib sandbox_attr_tests` |
| --sandbox preset steals arguments or the RAM overlay leaks on shutdown/signal (AI-SB3) | `cargo test -p ratarmount --bin ratarmount sandbox_preset_tests` · `cargo test -p ratarmount --test overlay_tmpfs` · `cargo test -p ratarmount --test fuse_rename fuse_sandbox_mapped_owners` |
| Snapshot credentials on argv, exit codes, git tree export history, dedup and reader round-trip (AI-SNAP) | `cargo test -p ratarmount --bin ratarmount snapshot::` |
| hf:// cached reads refetch or completed files lack linked/LFS sha256 verification (AI-RC) | `cargo test -p ratarmount-remote --lib hf_range_cache` |
| ETag changes fail reads, small random reads overfetch, prefetch stops at cached windows, cache hits consume prefetch permits (AI-RC) | `cargo test -p ratarmount-remote --lib http_range_cache` |
| Shared payload/range LRU stalls or grows unbounded, unsafe/corrupt entries reused, completion blocks reads (AI-RC) | `cargo test -p ratarmount-index --lib range_cache` · `cargo test -p ratarmount-index --lib payload_cache` |
| --bind subpath validation, bound git synthetic head, corpus lazy open / LRU, image+repo union on a real mount (AI-UN) | `cargo test -p ratarmount-session --lib regression_source_bind` · `cargo test -p ratarmount --bin ratarmount corpus_cli_tests` · `cargo test -p ratarmount --test fuse_image_repo` |
| Overlay user xattrs lost on commit/remount, non-user namespaces writable, xattr edits copy payloads, find --xattr filters, manifest atomicity (AI-PV) | `cargo test -p ratarmount-compositing --lib regression_provenance` · `cargo test -p ratarmount-fuse --lib regression_provenance` · `cargo test -p ratarmount-formats-tar --lib regression_provenance` · `cargo test -p ratarmount --bin ratarmount regression_provenance` · `cargo test -p ratarmount --test fuse_provenance` |
| Docker volume plugin refcounts, persistence, child supervision, secrets on argv (AI-DK) | `cargo test -p ratarmount-volume-plugin` · `./packaging/docker-volume-plugin/test-docker.sh` |
| Portable tarball links OpenSSL 1.1 (fails on Arch/Ubuntu 22.04+); AUR/Nix/conda/Homebrew formula drafts (AI-PKG) | `./packaging/test-portable-deps.sh` · `./packaging/test-aur.sh` · `./packaging/test-nix.sh` · `./packaging/test-conda.sh` · `./packaging/test-homebrew-formula.sh` |
| crates.io dry-run check expects a stale MSRV | `./packaging/test-crates-io-dry-run.sh` |
| Zstd decode-ahead corrupts seeks, blocks cancellation, exceeds reservations, or disengages under 128 KiB FUSE reads (AI-PERF) | `cargo test -p ratarmount-compress --lib regression_decode_ahead` · `cargo test -p ratarmount-session --lib regression_parallelization_one_and_four` |
| FUSE readahead window seeks backward at its boundary (cancels decode-ahead) or request pages fall back wrongly; direct-I/O flags leak onto overlay files (AI-PERF) | `cargo test -p ratarmount-fuse --lib readahead` · `cargo test -p ratarmount-fuse --lib regression_sequential_reads_negotiate_large_pages` · `cargo test -p ratarmount-fuse --lib regression_direct_io` · `cargo test -p ratarmount --bin ratarmount regression_direct_io` · `cargo test -p ratarmount --test fuse_zstd_direct_io` |
| Python mount()/Archive.mount lifecycle, credentials on argv, index publish pointer (AI-PY3) | `cargo test -p ratarmount-python --features embedding` (Python suite: see docs/python.md "Install from source") |
| Rolling series: size/time roll, discovery with gaps, sealed-archive mutations, deleted generation while mounted (AI-CM2) | `cargo test -p ratarmount-compositing --lib rolling` · `cargo test -p ratarmount --test rolling_archives` |
| huggingface_hub cache sharing writes partial/unverified blobs, wrong modes, stale refs, blocks reads; hf-cache:// offline (AI-HF3) | `cargo test -p ratarmount-remote --lib hf_cache` · `cargo test -p ratarmount-remote --lib hf::` |
| Sandbox daemon protocol, socket permissions, crash isolation, restart reconciliation, attempt isolation and diffs (AI-SB4) | `cargo test -p ratarmount --bin ratarmount sandbox` · `cargo test -p ratarmount --test sandbox` |
| Memory budget accountant, degraded paths under a tiny budget, zip inflate cache byte bound, status pools (AI-MEM) | `cargo test -p ratarmount-core --lib budget` · `cargo test -p ratarmount --test memory_budget` · `cargo test -p ratarmount-formats-zip --lib inflate_cache` |
| Atomic*::fetch_update deprecated on Rust 1.99 (CI) but try_update missing on MSRV 1.90 | `cargo test -p ratarmount-core --lib try_update` |
| hf:// live write-back: archive+index+pointer not atomic, parentCommit conflict clobbers, upload redirect replayed, mount not re-pinned (AI-HFW) | `cargo test -p ratarmount --bin ratarmount regression_hf_` · `cargo test -p ratarmount-remote --lib hf_commit` |
| CSI secret leakage, conflicting publishes, lost journal ownership, cancelled requests, real FUSE read-only and per-pod overlay targets (AI-CSI) | `cargo test -p ratarmount-csi` |
| Daemon sockets (volume plugin, CSI) are created mode 0600 with no umask window: sibling `.rmsock-<pid>-<nanos>-<counter>/s`, chmod, then rename; Drop removes the staging dir if bind, chmod, or rename fails; a leftover staging dir does not block the next bind | `cargo test -p ratarmount-volume-plugin --bin ratarmount-volume-plugin owner_only_socket` · `cargo test -p ratarmount-csi --bin ratarmount-csi owner_only_socket` |
| CSI test helper retries `cannot spawn ratarmount` once | `cargo test -p ratarmount-csi --test process regression_mount_spawn_retries_once` |
| `--torrent-swarm` defaults to `never` (no public trackers/DHT/LSD unless opted in); `auto` still explicit; `--seed` needs an explicit policy; errors name the opt-in flag | `cargo test -p ratarmount-core --lib regression_torrent_swarm_default_never` · `cargo test -p ratarmount --features bittorrent --bin ratarmount torrent_policy_tests` · `cargo test -p ratarmount-remote --features bittorrent --lib regression_swarm_options_default_never` · `cargo test -p ratarmount-remote --features bittorrent --lib regression_default_policy_never_refuses_swarm_fallback` |
| Gzip backend benchmark dies without Python/FUSE (AI-GZ) | `./benchmarks/test-compare-gzip-backends-skip-python.sh` |
| Torrent padded files rejected, unverified piece bytes served, whole-file SHA-256 blocking reads, piece LRU thrash, swarm started when a web seed works, scratch growth, checksum cache poisoning (AI-BT1) | `cargo test -p ratarmount-remote --features bittorrent --lib torrent` · `cargo test -p ratarmount --features bittorrent --test torrent_features` · `./packaging/test-bittorrent-features.sh` |
| Local `*.torrent` files or `x.torrent` mountpoints treated as torrent inputs without the feature (AI-BT1) | `cargo test -p ratarmount --bin ratarmount torrent` · `cargo test -p ratarmount-remote --lib regression_built_without_bittorrent_error` · `cargo test -p ratarmount-remote --lib regression_torrent_remote_dispatch` |
| macOS: overlay root vs /private/var canonical paths, Darwin ENOTSUP errno mapping, AF_UNIX path limit message, CSI non-Linux stub | `cargo test -p ratarmount-compositing --lib regression_provenance_manifest_symlinked_overlay_parent` · `cargo test -p ratarmount --bin ratarmount regression_sandbox_socket_path_reports_platform_limit` |
| Executables built inside a write overlay are not executable (SETATTR mode/times ignored) on FUSE/NFS/9P/SFTP (AI-FIX-CHMOD) | `cargo test -p ratarmount-fuse --lib regression_fuse_setattr_mode_` · `cargo test -p ratarmount-compositing --lib regression_overlay_chmod_` · `cargo test -p ratarmount --test fuse_chmod` |
| A briefly busy FUSE mount (desktop watcher probing the new mount) fails `ratarmount -u`, SIGTERM unmount, or the control-file unmount on the first `Device or resource busy`; SIGTERM-only lazy fallback; control socket replies ok after a failed unmount; graceful test helpers retry busy a bounded time and never go lazy | `cargo test -p ratarmount --test fuse_unmount_busy` · `cargo test -p ratarmount-fuse --lib regression_unmount` · `cargo test -p ratarmount --bin ratarmount regression_sig` · `cargo test -p ratarmount --bin ratarmount regression_signal_watcher` · `cargo test -p ratarmount --bin ratarmount regression_control_reply_unmount_result` |
| Torrent LAN mode contacts DHT/trackers or public peers; seeding serves unverified pieces, ignores the upload cap, re-hashes on refresh, or keeps listening after unmount (AI-BT2) | `cargo test -p ratarmount-remote --features bittorrent --lib regression_lan_` · `cargo test -p ratarmount-remote --features bittorrent --lib regression_seed_` |
| Torrent/manifest hashes install files into the huggingface_hub cache without the Hub vouching for that commit, or replace an existing snapshot (AI-BT2) | `cargo test -p ratarmount-remote --features bittorrent --lib regression_manifest_hash_never_authorizes_hub_publication` · `cargo test -p ratarmount-remote --features bittorrent --lib regression_torrent_hub_authorization_requires_fresh_exact_commit` |
| Whole-repo hf:// / remote folder mounts scan nested archives instead of using published sibling indexes (AI-FIX-HFREPO) | `cargo test -p ratarmount-session --lib regression_hf_repo_published_index_lazy_zero_scan` · `cargo test -p ratarmount-session --lib regression_http_folder_sibling_index_validated_without_scanning` · `cargo test -p ratarmount-compositing --lib regression_lazy_listing_opens_only_the_accessed_archive` |
| Remote TAR indexing issues one range request per member header (thousands of GETs; minutes per shard) (AI-FIX-HFREPO) | `cargo test -p ratarmount-session --lib regression_remote_tar_3000_headers_use_chunk_requests` · `cargo test -p ratarmount-remote --lib regression_http_forward_headers_coalesce_and_reuse_redirect` |
| Standalone safetensors / GGUF mount lists only `__metadata__.json` / `__header__.json`; `ls mnt/layer` is ENOENT (tensor parent directories had no index rows; FUSE walks one component at a time) | `cargo test -p ratarmount-formats-tensors --lib regression_tensor_parent_directories_are_listed_and_looked_up` |

When you fix a **new** production bug, **add a row** here and ship the test in the same commit.

## Workspace layout

Rust workspace under `ratarmount-*` crates; binary is `ratarmount/`. Prefer non-overlapping crate ownership when parallelizing. Orchestrator owns `ratarmount-session/src/factory.rs` glue unless a task explicitly owns factory.

## Subagents / parallel worktrees

For isolation=`worktree` tasks, follow skill **`ratarmount-worktree-subagent`** (`.grok/skills/ratarmount-worktree-subagent/SKILL.md`). Always put a **Deliverable** block in the spawn prompt that includes `cargo fmt --all`.

## Commits

- Prefer complete sentences in commit messages.
- Subagents: **one commit, do not push** unless the user asked to publish.
- Orchestrator: cherry-pick / merge, re-run full fmt + clippy + test, then push when asked.

## Feature comparisons & README (every relevant commit)

**When a commit changes user-visible capability, update living docs in the same
commit** (or list an explicit “docs delta” for the orchestrator). Do not leave
README / parity tables stale.

| Trigger | Update |
|---------|--------|
| New/removed/changed format, codec, remote, CLI flag, nested/tmp behavior | [`docs/formats.md`](docs/formats.md) tables and its Known limits section; the grouped summary tables in [`README.md`](README.md) and the command tour in [`docs/getting-started.md`](docs/getting-started.md) when a user-visible command or format changes |
| Parity status flip (`[x]` / `~` / residual) | [`docs/parity-todo.md`](docs/parity-todo.md) |
| Mount option added/changed | [`docs/mount-options-parity.md`](docs/mount-options-parity.md) |
| Nested open / temp spool | [`docs/embedded-nested-archives.md`](docs/embedded-nested-archives.md) (+ the nested summaries in `docs/formats.md` and the README) |
| Dual-run / packaging product status | [`docs/phase12-dual-run.md`](docs/phase12-dual-run.md) / packaging notes |
| Upstream-inspired feature (from mxmlnkn/ratarmount issues) | [`docs/tasks/upstream-feature-requests.md`](docs/tasks/upstream-feature-requests.md) status row + README **Upstream** link |
| New protocol / export / beyond-parity feature (P-/F-/G- IDs) | [`docs/tasks/beyond-parity-roadmap.md`](docs/tasks/beyond-parity-roadmap.md) status |
| Upstream bug verified fixed/reproduced | [`docs/tasks/upstream-bugs-inspection.md`](docs/tasks/upstream-bugs-inspection.md) status + regression test if fixed |

If the change is pure refactor/tests with **no** user-facing behavior change, skip
doc updates (still add regression tests per above).

Skill for nested/tmp matrices: **`format-support-matrices`**.
## Releases / package builds (do this properly)

Tagging alone is not enough: **`Packages` must publish a GitHub Release with real
assets** (`.deb` / `.rpm` / portable tarballs / cosign bundles). Workflow:
[`.github/workflows/packages.yml`](.github/workflows/packages.yml).

**After every release tag, watch CI until settled** (fix failures, re-tag if needed).
Full procedure: skill **`release-tag-ci-watch`** (`.grok/skills/release-tag-ci-watch/SKILL.md`).

Linux/macOS package scripts compile **`--features nfsv4,sftp-russh,bittorrent`** (`packaging/build-native-packages.sh`, `build-appimage.sh`, `build-macos-tarball.sh`). Editing only `packages.yml` does **not** compile v4, russh or BitTorrent. Workspace MSRV is 1.90 (CI `msrv` job); default CI `fmt + clippy + test` compiles neither embednfs, russh nor librqbit. Privileged kernel-client check (not default CI): `./test-harness/nfs-docker/run.sh`. See [docs/packaging.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/packaging.md), [docs/nfs-export.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/nfs-export.md), and [docs/export.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/export.md).

### Version bump checklist

1. Bump **workspace** `version` in root [`Cargo.toml`](Cargo.toml) (Packages resolve
   version from the tag + Cargo.toml — do **not** hardcode per-job `VERSION` envs).
2. Update README / docs version strings that mention the release tag (if any).
3. `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
4. `cargo test --workspace` (or full relevant crates when the release is large).
5. Commit on `main`, then **annotated tag** `vX.Y.Z` matching Cargo version.
6. `git push origin main && git push origin vX.Y.Z`.
7. **Watch CI** (`gh run list` / `gh run watch`): **`fmt + clippy + test`** green;
   **Packages** publishes real assets (macOS-only residual OK if Linux packages ship).
8. Confirm `gh release view vX.Y.Z` has package assets. If red: fix, harden, **new patch tag**.

### What “success” looks like

| Check | Pass criteria |
|-------|----------------|
| Matrix jobs (`deb` / `rpm` / `portable` / `macos`) | Build artifacts uploaded |
| **Sign & release** | Creates/updates GitHub Release for the tag |
| [github.com/…/releases](https://github.com/hilather/ratarmount-rs/releases) | Tag has **package** assets (not only tiny sidecars) |
| Workflow overall | Prefer green; macOS-only failure is OK if Linux packages published |
| Agent did not walk away after `git push --tags` | CI watched / failures fixed |

**Workflow “failure” with empty Releases is not a release.** Builds may still
leave a downloadable **`signed-release-bundle`** Actions artifact (expires).

### Known failure modes (do not thrash tags)

1. **Empty upload files** — GitHub rejects 0-byte assets (e.g. empty `file-info.txt`).
   Flatten/upload **must skip size 0**. Symptom: release created, few tiny assets, job red.
2. **Permissions** — job needs `contents: write` (workflow already sets this). If
   `POST /releases` is 403, check repo **Settings → Actions → Workflow permissions**
   = Read and write.
3. **Do not** keep bumping `v0.1.N` to “debug” without reading **annotations** /
   the Create Release step. Prefer REST create + `::error::` / `::notice::` so
   failures are visible without private job-log auth.
4. Stuck legacy runners (e.g. scarce `macos-13`) — drop or pin to available labels;
   do not block Linux packages on one matrix leg forever.
5. **apt CDN reset** — Debian `apt-get` in the portable bullseye container can
   fail mid-fetch (`Connection reset by peer` on `libfuse3`). Symptom: Packages
   red, GitHub Release missing `portable-glibc2.31` **amd64**. `apt-get` steps
   must pass `-o Acquire::Retries=5`. Check: `./packaging/test-packages-apt-retries.sh`.

### After a bad tag

- Prefer a **new patch tag** with the fix (do not rewrite published tags).
- Incomplete releases (e.g. only `SHA256SUMS`) can stay; next tag supersedes.
- Optional: edit notes on the incomplete release pointing at the next tag.

Full packaging user docs: [`docs/packaging.md`](docs/packaging.md).

## Docs

Living parity: `docs/parity-todo.md`, `docs/tasks/gap-implementation-batch.md`, `docs/tasks/beyond-parity-roadmap.md`.

### Format / nested / temp-file matrices (keep current)

**Code that changes how archives open, nest, or use `/tmp` must update the support matrices in the same change.** Stale tables mislead users about embedded random access and temp spool.

| Doc | Role |
|-----|------|
| [`docs/embedded-nested-archives.md`](docs/embedded-nested-archives.md) | **Canonical** nested no-tmp vs temp matrix + parent×nested behavior |
| [`README.md`](README.md) · [`docs/formats.md`](docs/formats.md) | Short nested summaries (must match the canonical doc) |
| [`docs/tasks/embedded-nested-random-access.md`](docs/tasks/embedded-nested-random-access.md) | Implementation checklist |

Triggers: `open_nested_reader_fn`, AutoMount spool, format `MountSource::open`, materialize vs seekable body, TAR flatten limits.

Full procedure: skill **`format-support-matrices`** (`.grok/skills/format-support-matrices/SKILL.md`).
