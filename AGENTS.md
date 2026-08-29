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
| Fixture smoke dies without Python/binary (#9) | `./benchmarks/test-compare-prepare-env.sh` · `./benchmarks/test-compare-fixtures.sh` |
| Truncated `.gz` / UnexpectedEof (FUSE short read = EOF) | `cargo test -p ratarmount-fuse --lib fill_read` · `cargo test -p ratarmount-compress --lib fuse_style` · `cargo test -p ratarmount nested_large_plain_gzip` |
| Nested gzip concurrent wrong/truncated data | `cargo test -p ratarmount-compress --lib shared_from_reader` · `cargo test -p ratarmount-compress --lib stenciled_fuse` |
| Rapidgzip path backend (Tier D POC) | `cargo test -p ratarmount-compress --features gzip-rapidgzip --lib gzip_rapidgzip` · `cargo test -p ratarmount --features gzip-rapidgzip plain_gzip_rapidgzip` · `cargo test -p ratarmount --features gzip-rapidgzip plain_gzip_rapidgzip_invalid` · `cargo test -p ratarmount --features gzip-rapidgzip plain_gzip_rapidgzip_gzidx` · `cargo test -p ratarmount --features gzip-rapidgzip nested_plain_gzip_prefer_rapidgzip` · `cargo test -p ratarmount --features gzip-rapidgzip nested_plain_gzip_prefer_rapidgzip_fail_rewinds_to_g3` · optional ISA-L: `--features gzip-rapidgzip-isal` (+ `libisal` / `ISAL_INSTALL_PREFIX`) |
| Plain `.gz` rapidgzip GZIDX shell create (no pre-existing index) | `cargo test -p ratarmount --features gzip-rapidgzip plain_gzip_rapidgzip_plain_gzidx` · `cargo test -p ratarmount --features gzip-rapidgzip plain_gzip_rapidgzip_gzidx_skipped` · `cargo test -p ratarmount gzip_seek_index_format_label` |
| 7z mtimes Dec 31 1969 (FILETIME delta) | `cargo test -p ratarmount-formats-sevenzip --lib filetime` · `cargo test -p ratarmount-formats-sevenzip --lib mtime` |
| Nested/non-solid 7z first `cat` minutes (LZMA2 prefix-from-0) | `cargo test -p ratarmount-formats-sevenzip --lib regression_sequential` · `cargo test -p ratarmount-formats-sevenzip --lib regression_independent_chunk` · `cargo test -p ratarmount-formats-sevenzip --lib regression_header_at_end` · `cargo test -p ratarmount-index --lib regression_head_only` · `cargo test -p ratarmount --bin ratarmount regression_progressive_nested_fingerprint` |
| AES/BCJ 7z solid first `cat` minutes (pack slurp / full-folder) | `cargo test -p ratarmount-formats-sevenzip --lib regression_aes_lzma2` · `cargo test -p ratarmount-formats-sevenzip --lib regression_bcj_lzma2` · `cargo test -p ratarmount-formats-sevenzip --lib regression_aes_pack_not_slurped` · `cargo test -p ratarmount-formats-sevenzip --lib regression_encrypted_copy` |
| Encrypted nested open → EACCES not EIO | `cargo test -p ratarmount-fuse --lib io_to_errno` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted` (metadata-only PermissionDenied; password exact bytes; wrong pw fails open) |
| 7z wrong password accepted on macOS (store+AES / warm index) | `cargo test -p ratarmount-formats-sevenzip --lib encrypted_wrong_password` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted_store_aes` |
| 7z parse CRC uses crc32fast (IEEE) | `cargo test -p ratarmount-formats-sevenzip --lib crc32` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted_wrong_password` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted_store_aes` |
| Write-overlay create then cat empty (size-0 cache) | `cargo test -p ratarmount-fuse --lib overlay_file_info` |
| Overlay open after create+write (`has_file` → OverlayFd) | `cargo test -p ratarmount-fuse --lib overlay_open_after_create_write` |
| Sequential FUSE readahead window (`--readahead`, #180) | `cargo test -p ratarmount-fuse --lib readahead` |
| Plain compress no `/tmp` spool (gz/zstd/bz2) | `cargo test -p ratarmount plain_gzip` · `cargo test -p ratarmount plain_zstd` · nested: `nested_plain_gzip` |
| Nested no-tmp openers (factory wiring) | `cargo test -p ratarmount nested_` (CPIO/AR/WARC/ASAR/CAB/XAR/tar.gz/zip/7z) · crate `open_from_reader` tests for ISO/SQLAR/FAT |
| Nested TAR via AutoMount reader | `cargo test -p ratarmount-compositing --lib automount_nested` |
| Nested durable indexes (ZIP/TAR/7z structure+file table/CPIO/AR) | `cargo test -p ratarmount --bin ratarmount nested_durable` · `cargo test -p ratarmount-formats-sevenzip --lib durable_structure` · `cargo test -p ratarmount-index --lib nested` |
| Nested compact pools are per-index (no parent StringPool lock) | `cargo test -p ratarmount-index --lib regression_nested_compact_pools_are_per_index` |
| ZIP `--commit-overlay` rebuild (add/replace/delete) | `cargo test -p ratarmount-compositing --lib commit_overlay_zip` |
| Offline `--commit-overlay` splice for `.tar.zst` (incl. earlier-frame delete) | `cargo test -p ratarmount-compositing --lib commit_overlay` |
| Factory zstdblocks/bzip2blocks warm reimport (FR-9) | `cargo test -p ratarmount zstd_blocks` · `cargo test -p ratarmount bzip2_blocks` |
| G3 RGZI warm remount (plain `.gz` + tar.gz write_index) | `cargo test -p ratarmount gzip_rgzi` · `cargo test -p ratarmount plain_gzip_rgzi` · `cargo test -p ratarmount plain_gzip` |
| G3 hard GZIDX import / export polish (G3-D/E) | `cargo test -p ratarmount-compress --lib gzip_seek` (filters: `g3_d_`, `g3_e_`) |
| Warm index after archive replace (tarstats size/mtime/content) | `cargo test -p ratarmount warm_index_rebuilds` · `cargo test -p ratarmount-index --lib check_tarstats` · `cargo test -p ratarmount-formats-tar --lib warm_index` · `cargo test -p ratarmount-formats-zip --lib warm_index` · `cargo test -p ratarmount-formats-sevenzip --lib warm_index` |
| Nested EXT4 / SquashFS no-tmp factory wire | `cargo test -p ratarmount nested_ext4` · `cargo test -p ratarmount nested_squashfs` · crate `open_from_reader` tests |
| Warm index tarstats (most formats) | `cargo test -p ratarmount-formats-{ar,cpio,iso9660,sevenzip,warc,cab,xar,asar,libarchive,ogg} --lib warm_index` (run crates separately) · also tar/zip |
| Nested tar.zst/bz2/xz no-tmp opener | `cargo test -p ratarmount nested_tar_` |
| HTTP Cookie auth (FR-2) | `cargo test -p ratarmount-remote --lib http_cookie` · `cargo test -p ratarmount-remote --lib http_basic_and_cookie` |
| ssh_config ProxyJump / Include | `cargo test -p ratarmount-remote --lib ssh` |
| Dropbox cheap `list_dirents` | `cargo test -p ratarmount-remote --lib list_dirents` |
| Union symlink resolve (FR-10) | `cargo test -p ratarmount-compositing --lib fr10_resolve` |
| FileVersionLayer / TAR cheap readdir (no fat FileInfo map) | `cargo test -p ratarmount-compositing --lib file_version_layer_list_dirents` · `cargo test -p ratarmount-formats-tar --lib gnu_incremental_dumpdir_deletes` |
| Compositing wrappers fat readdir | `cargo test -p ratarmount-compositing --lib list_dirents` |
| Index formats missing readdirplus sizes | `cargo test -p ratarmount-formats-cpio --lib list_dirents` · `cargo test -p ratarmount-formats-ar --lib list_dirents` · `cargo test -p ratarmount-formats-warc --lib list_dirents` · `cargo test -p ratarmount-formats-cab --lib list_dirents` · `cargo test -p ratarmount-formats-iso9660 --lib list_dirents` · `cargo test -p ratarmount-formats-asar --lib list_dirents` · `cargo test -p ratarmount-formats-xar --lib list_dirents` · `cargo test -p ratarmount-formats-libarchive --lib list_dirents` · `cargo test -p ratarmount-formats-ogg --lib list_dirents` · `cargo test -p ratarmount-formats-html --lib list_dirents` · `cargo test -p ratarmount-formats-pdf --lib list_dirents` |
| Image / Git / SQLAR / SingleFile cheap `list_dirents` | `cargo test -p ratarmount-formats-ext4 --lib list_dirents` · `cargo test -p ratarmount-formats-fat --lib list_dirents` · `cargo test -p ratarmount-formats-squashfs --lib list_dirents` · `cargo test -p ratarmount-formats-git --lib list_dirents` · `cargo test -p ratarmount-formats-sqlar --lib list_dirents` · `cargo test -p ratarmount-formats-tar --lib list_dirents` |
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
| GitHub Release dies on 0-byte assets | `./packaging/test-release-asset-filter.sh` |
| Packages portable apt CDN reset (missing glibc2.31 amd64) | `./packaging/test-packages-apt-retries.sh` |
| CI apt CDN hang cancels cold-index / FUSE allowlists | `./packaging/test-ci-apt-retries.sh` |
| NFS short-read / cheap-dirent empty `cat` | `cargo test -p ratarmount-nfs --lib fill_loops` · `cargo test -p ratarmount-nfs --lib readdir_size_zero` |
| NFS clap steals archive / concurrent readers | `cargo test -p ratarmount --bin ratarmount nfs_flag` · `cargo test -p ratarmount-nfs --lib concurrent_readers` |
| HTTP/WebDAV/SMB/`--ninep`/`--sftp` clap steals archive | `cargo test -p ratarmount --bin ratarmount http_flag` · `cargo test -p ratarmount --bin ratarmount ninep_flag` · `cargo test -p ratarmount --bin ratarmount webdav_flag` · `cargo test -p ratarmount --bin ratarmount smb_flag` · `cargo test -p ratarmount --bin ratarmount sftp_flag` |
| HTTP GET of gzip member truncated (short `Read::read` = EOF) | `cargo test -p ratarmount-http --lib regression_http_get_gzip` |
| SMB READ fill-loop truncated | `cargo test -p ratarmount-smb --lib regression_smb_read_fill` |
| 9P Tread fill-loop truncated | `cargo test -p ratarmount-9p --lib fill_read_ninep` |
| `docker://ubuntu:24.04` treated as a local path | `cargo test -p ratarmount --bin ratarmount docker_ubuntu` · `cargo test -p ratarmount-remote --lib docker_ubuntu` |
| SFTP non-loopback without authorized_keys file | `cargo test -p ratarmount-sftp --lib regression_non_loopback` |
| NFS compositing pin (`member_seek_is_cheap`) | `cargo test -p ratarmount-compositing --lib file_version_layer_forwards` · `cargo test -p ratarmount-compositing --lib automount_forwards` |
| NFS serve stop | `cargo test -p ratarmount-nfs --lib serve_stop` |
| NFS overlay write / stale reader after truncate | `cargo test -p ratarmount-nfs --lib overlay_` · `cargo test -p ratarmount-nfs --lib writers_rofs` |
| NFS overlay rename / symlink | `cargo test -p ratarmount-nfs --lib overlay_rename` · `cargo test -p ratarmount-nfs --features nfsv4 --lib v4_overlay_rename` |
| Live overlay commit (uncompressed TAR / `.tar.zst`) | `cargo test -p ratarmount-compositing --lib live_commit` · `cargo test -p ratarmount --test commit_overlay_live` · `cargo test -p ratarmount --bin ratarmount -- live_commit` · `cargo test -p ratarmount-nfs --lib overlay_commit_live` |
| Missing `.tar` / `.tar.zst` write mount create | `cargo test -p ratarmount-compositing --lib empty_archive` · `cargo test -p ratarmount-compositing --lib is_uncompressed_tar` · `cargo test -p ratarmount --test commit_overlay_live create_missing` · `cargo test -p ratarmount --bin ratarmount -- create_missing` |
| Interval commit skips recently modified overlay files | `cargo test -p ratarmount-compositing --lib live_commit_idle` (open write fd must not persist/unlink) |
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
| WebDAV LOCK 423 / COPY / Basic | `cargo test -p ratarmount-http --lib lock` · `cargo test -p ratarmount-http --lib copy` · `cargo test -p ratarmount-http --lib basic` |
| SFTP password policy / non-loopback | `cargo test -p ratarmount-sftp --lib password` · `cargo test -p ratarmount-sftp --features sftp-russh --lib password` |
| GCS GOOG1 HMAC | `cargo test -p ratarmount-remote --lib goog1` · `cargo test -p ratarmount-remote --lib hmac` |
| FTP LIST/MLSD folder | `cargo test -p ratarmount-remote --lib ftp` |
| rclone+ URL | `cargo test -p ratarmount-remote --lib rclone` · `cargo test -p ratarmount-remote --lib is_remote_url` |
| `--sftp-subsystem` clap | `cargo test -p ratarmount --bin ratarmount sftp_subsystem` |
| Last-frame splice remount rescans prefix | `cargo test -p ratarmount-formats-tar --lib regression_incremental_last_frame_no_prefix_seek` |
| Incremental `files` ≠ full `create_index_body` | `cargo test -p ratarmount-formats-tar --lib regression_incremental_equals_full_index` |
| On-exit persist leaves stale sidecar (remount full-parses) | `cargo test -p ratarmount --test commit_overlay_live on_exit_remount` · `cargo test -p ratarmount --bin ratarmount -- live_commit_on_exit_remount` |
| Interval reopen | `cargo test -p ratarmount --test commit_overlay_live` · `cargo test -p ratarmount --bin ratarmount -- live_commit` |
| Pre-splice `zstdblocks` used for suffix parse | `cargo test -p ratarmount-formats-tar --lib regression_incremental_zstdblocks_fresh` |
| GNU `--append` from `pre_size` misses members | `cargo test -p ratarmount-formats-tar --lib regression_incremental_append_eof` |
| Opaque persist fail-closed | `cargo test -p ratarmount-formats-tar --lib rewrite_mid_member_opaque_prefix` |
| Opaque prefix + later valid header | `cargo test -p ratarmount-formats-tar --lib regression_incremental_opaque_then_header` |
| `find '*.fits'` without FUSE | `cargo test -p ratarmount --bin ratarmount find_glob` |
| `find` clap steals archive / pattern | `cargo test -p ratarmount --bin ratarmount find_flag` |
| Control read-only `search/<pattern>` | `cargo test -p ratarmount-compositing --lib control_search` |
| Socket `search` | `cargo test -p ratarmount --bin ratarmount control_search_socket` |
| FTS5 path + hashes | `cargo test -p ratarmount-index --lib search_fts5` (default `cargo test -p ratarmount-index --lib`, no extra features) |
| Inbound HEAD **archive** `Link: describedby` → fetch | `cargo test -p ratarmount-index --lib link_describedby_archive_head` · `cargo test -p ratarmount --bin ratarmount apply_remote_index_discovery_follows_archive_link` |
| Outbound GET index.sqlite Content-Type | `cargo test -p ratarmount-http --lib index_content_type` |
| Local `oci:{digest}` cache skips referrer | `cargo test -p ratarmount-remote --lib oci_referrer_not_fetched_on_cache_hit` |
| OCI referrer GET on miss | `cargo test -p ratarmount-remote --lib oci_referrer` |
| Publish local sidecar | `cargo test -p ratarmount --bin ratarmount publish_index` · `publish_index_flag` clap-steal |
| Fingerprint / tarstats full-hash slurps body `Vec` | `cargo test -p ratarmount-index --lib fingerprint` · `cargo test -p ratarmount-index --lib archive_full_hash` · `cargo test -p ratarmount-index --lib compute_hashes` · keep `regression_head_only` + `regression_progressive_nested_fingerprint` |
| Offset-order restore / find walks name order | `cargo test -p ratarmount-index --lib dirent_order` · `cargo test -p ratarmount --bin ratarmount find_offset_order` · `cargo test -p ratarmount-formats-tar --lib regression_offset_order_seeks` |
| Locate fat `FileInfo` on large catalog; overlay last-wins missing on control search | `cargo test -p ratarmount-index --lib scan_glob` · `cargo test -p ratarmount-compositing --lib search_cheap` · `find_glob` · `control_search` · `search_fts5` |
| Torn sidecar during `-c` (tmp+rename / dest unlinked at create) | `cargo test -p ratarmount-index --lib regression_reader_survives` · `cargo test -p ratarmount-index --lib regression_drop_unpublished` · `cargo test -p ratarmount --bin ratarmount regression_store_zstd_blocks_in_index_missing_path` |

When you fix a **new** production bug, **add a row** here and ship the test in the same commit.

## Workspace layout

Rust workspace under `ratarmount-*` crates; binary is `ratarmount/`. Prefer non-overlapping crate ownership when parallelizing. Orchestrator owns `ratarmount/src/factory.rs` glue unless a task explicitly owns factory.

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
| New/removed/changed format, codec, remote, CLI flag, nested/tmp behavior | [`README.md`](README.md) feature tables + Gaps section if needed |
| Parity status flip (`[x]` / `~` / residual) | [`docs/parity-todo.md`](docs/parity-todo.md) |
| Mount option added/changed | [`docs/mount-options-parity.md`](docs/mount-options-parity.md) |
| Nested open / temp spool | [`docs/embedded-nested-archives.md`](docs/embedded-nested-archives.md) (+ README cheat sheet) |
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
[`.github/workflows/packages.yml`](`.github/workflows/packages.yml`).

**After every release tag, watch CI until settled** (fix failures, re-tag if needed).
Full procedure: skill **`release-tag-ci-watch`** (`.grok/skills/release-tag-ci-watch/SKILL.md`).

Linux/macOS package scripts compile **`--features nfsv4,sftp-russh`** (`packaging/build-native-packages.sh`, `build-appimage.sh`, `build-macos-tarball.sh`). Editing only `packages.yml` does **not** compile v4 or russh. Workspace MSRV stays 1.74; default CI `fmt + clippy + test` compiles neither embednfs nor russh. Privileged kernel-client check (not default CI): `./test-harness/nfs-docker/run.sh`. See [docs/packaging.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/packaging.md), [docs/nfs-export.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/nfs-export.md), and [docs/export.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/export.md).

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
| [`README.md`](README.md) | Short nested cheat sheet (must match the canonical doc) |
| [`docs/tasks/embedded-nested-random-access.md`](docs/tasks/embedded-nested-random-access.md) | Implementation checklist |

Triggers: `open_nested_reader_fn`, AutoMount spool, format `MountSource::open`, materialize vs seekable body, TAR flatten limits.

Full procedure: skill **`format-support-matrices`** (`.grok/skills/format-support-matrices/SKILL.md`).
