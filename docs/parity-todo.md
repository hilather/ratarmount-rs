# Feature & test parity TODO (vs Python ratarmount)

Living checklist for closing the gap with [mxmlnkn/ratarmount](https://github.com/mxmlnkn/ratarmount).  
Check items off as they land; keep allowlists and `README` status table in sync.

**Legend:** `[x]` done in ratarmount-rs · `[ ]` still open · `~` partial

---

## 1. Feature parity — formats & codecs

### Archives (MountSource backends)

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| Uncompressed TAR (ustar/pax/gnu) | yes | yes | `[x]` |
| GNU sparse `S` + PAX sparse 0.0/0.1/1.0 | yes | yes | `[x]` |
| GNU incremental TAR | yes | detect + prefix strip + dumpdir `D` dual entry + `isGnuIncremental` metadata | `[x]` |
| ZIP (store/deflate, symlink, password) | yes | store/deflate; password + multi-part join + multi-disk EOCD normalize | `[x]` / `~` true per-disk offsets |
| Custom SevenZip random-access | yes (fork PR) | yes | `[x]` |
| AR / CPIO newc/crc/odc/binary | yes | yes | `[x]` |
| libarchive long-tail (RAR/LHA/…; CAB LZX) | yes | yes (sequential open) | `~` |
| Stencil CAB / ISO / WARC / XAR (fork RA) | yes (custom) | yes (store/MSZIP CAB; LZX→libarchive) | `[x]` |
| SevenZip BCJ2 + stream pack/AES + meta-only encrypt | yes | yes | `[x]` |
| SquashFS | yes | yes (backhand in-process; xz via xz2; unsquashfs for classic lzma) | `[x]` / `~` classic lzma fallback |
| EXT4 / FAT images | yes | EXT4 pure (`ext4-view`) + debugfs fallback; FAT pure | `[x]` EXT4 pure path |
| SQLAR | yes | unencrypted + encrypt detect; sqlcipher feature optional | `~` feature-gated decrypt |
| ASAR | yes | yes (stencil) | `[x]` |
| PDF / OGG / HTML | yes | PDF attachments + XObject images (JPEG/JP2/Flate PNG, CMYK, Indexed, ICCBased); OGG; HTML | `[x]` / `~` Separation/Lab residual |
| Git tree mount | yes | yes (`git2`; worktree needs `RATARMOUNT_FORCE_GIT=1`) | `~` |
| RAR pure / best-effort (beyond libarchive) | yes | libarchive only | `~` |

### Compression (seekable / outer codecs)

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| gzip (rapidgzip / seek index) | yes | **G3 Tier B seekable** for `.tar.gz`; materialize for plain `.gz` | `~` Tier C blob import still open |
| bzip2 block-parallel | yes | multi-stream + bit-block seek map (≤256 MiB compressed) via `-P` | `[x]` / `~` >256 MiB full decode |
| xz multi-block seek | yes | Index + multi-stream maps; single-block full decode | `[x]` / `~` exotic filters |
| zstd multi-frame / seek table | yes | multi-frame map + seek-table footer import | `[x]` / `~` zstdblocks import |
| lz4 / lzip / lzo / Z / lzma-alone / zlib | yes | yes (seekable) | `[x]` |
| lrz | yes (libarchive) | detect + `lrzip`/`lrunzip` materialize | `~` CLI required |
| Concatenated / multi-frame outer streams | yes | partial (`--ignore-zeros`) | `~` |
| Split files (`.001`/`.002`) | yes | yes (decimal/hex/alpha join) | `[x]` top-level + recursive AutoMount |

### Compositing & FUSE UX

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| Folder bind mount | yes | yes | `[x]` |
| Union of multiple sources | yes | yes + folder cache (depth/entries/timeout) | `[x]` |
| AutoMount recursive (`-r`) | yes | yes; nested open prefers `Read+Seek` (no tmp) for TAR/7z | `~` ZIP store / solid outer later |
| Write overlay (`-w` / `:temp:`) | yes | yes | `~` |
| `--commit-overlay` into archive | yes | yes (uncompressed + gzip/bzip2/xz TAR; GNU tar) | `[x]` common compressions |
| File version paths (`.versions/`) | yes | yes (default on; `--no-file-versions`) | `[x]` |
| Control interface socket | yes | Unix socket + in-FS `/.ratarmount-control/` | `[x]` |
| Lazy mount (`-l`) | yes | yes (mount on first access) | `[x]` |
| Path transform / strip recursive extension | yes | yes (`-s`, `--transform`, `--transform-recursive-mount-point`) | `[x]` |
| Recursive extension sets | yes | yes (`--recursive-extensions`) | `[x]` |
| Prefix (`-p`) | yes | yes | `[x]` |
| Disable union mount (subfolders) | yes | yes (`--disable-union-mount`) | `[x]` |
| Password file | yes | yes (`--password-file`) | `[x]` |
| `--use-backend` | yes | accepted (priority list stored) | `~` |
| FUSE extra options (`-o`) | yes | yes | `[x]` |
| Daemonize / foreground | yes | yes | `[x]` |
| readdirplus / attr cache | yes | yes | `[x]` |
| Full mount-option matrix | — | see [`docs/mount-options-parity.md`](mount-options-parity.md) | `~` |

### Remote I/O

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| `file://` | yes | yes | `[x]` |
| `http(s)://` (full GET) | yes | yes | `[x]` |
| HTTP Range without full download | yes | live Range for TAR/ZIP/gzip/**bzip2/xz/zstd** + materialize fallback | `[x]` |
| `s3://` | yes (fsspec) | SigV4 env + IMDS/ECS role + anonymous | `[x]` / `~` no live S3 Range |
| `ssh://` / `sftp://` | yes | yes | `~` full ssh_config parity |
| SMB / WebDAV / Dropbox | yes | WebDAV + SMB + Dropbox folder (list TTL) + ranged content download | `[x]` |
| Remote/compressed **index** download | yes | http(s)/file:// + gzip/xz/zstd/bz2 index decompress | `[x]` |

### Index / CLI

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| SQLite index 0.7.x schema | yes | yes | `[x]` |
| Cross-open Py↔Rust index (TAR core) | yes | yes | `~` compression side tables |
| `--index-file` / `:memory:` | yes | yes | `[x]` |
| `--index-folders` / XDG cache | yes | yes (CSV/JSON + defaults) | `[x]` |
| Index file hashes / xattrs | yes | `--hashes` fill + FUSE listxattr/getxattr for TAR | `[x]` / `~` non-TAR sources |
| `--use-backend` selection | yes | reorders format probe (last flag highest) | `[x]` |
| Encoding (`-e`) | yes | yes (TAR names via encoding_rs) | `[x]` |
| Debug / log-file / color | yes | `-d` + `--log-file` + color env | `[x]` / `~` full NO_COLOR matrix |
| OSS attributions | yes | yes (`--oss-attributions` / help) | `[x]` |
| Parallelization matrix (`-P backend:n`) | yes | full matrix incl. zlib/lzma/Z; true parallel where codec allows | `[x]` / `~` sequential codecs still API-only |
| Default mountpoint (strip extension) | yes | yes | `[x]` |

### Performance (ongoing)

| Item | Status |
|------|--------|
| Cold index bulk insert | `[x]` |
| In-memory index for RO mounts | `[x]` |
| FUSE open-handle reuse / caches / readdirplus | `[x]` |
| ZIP store stencil + deflate cache | `[x]` |
| SevenZip solid streaming (large folders) | `~` progressive LZMA2 + 1 MiB LRU windows (≤64); BCJ/AES still full-folder |
| Cold `find` geo-mean ≥ Python | `~` nested/compressed still lag |
| Seekable codecs (drop materialize for gzip+) | `~` all four via SeekableBody; true block maps still partial |
| Benchmark gates in CI (`rust-gates.json`) | `[x]` cold-index microbench in CI; ratio gates via `RUN_FULL_BENCH=1` |

---

## 2. Test parity

### Current Rust harness (allowlists)

~90+ fixture lines across phases 2–11 + sevenzip/sqlar/squashfs/ext4/http/remote + index interop.  
Python has **100+** fixed archives and three large shells: fixed-archive, complex-usage, remote-backend.  
Wrappers: `run-fixed-archive-subset.sh` (`RUN=1`), `run-index-interop.sh` (Py↔Rust SQLite).

### Harness expansion TODO

| Priority | Work | Exit criteria |
|----------|------|----------------|
| P0 | Expand TAR/ZIP/sparse allowlists to all Python fixtures that already pass | `~` phase2 ~26 TAR; phase6 ZIP; phase9 AR/7z grown |
| P0 | Wire `RATARMOUNT_CMD` into Python `run-fixed-archive-tests.sh` with **phase allowlists** (never full AppImage set until ready) | `[x]` `run-fixed-archive-subset.sh` |
| P0 | SevenZip: full `test_sevenzip.py` scenarios as shell/cargo tests | `~` store, lzma2, large; encrypted/nested still open |
| P1 | Complex usage: multi-source union, write-overlay commit paths, versioned files | `~` complex harness + commit-overlay; phase2 versions paths |
| P1 | Remote: SSH fixture server (`start-asyncssh-server.py`) + optional S3/MinIO | Live optional; unit always |
| P1 | Index interop golden: Py builds index → Rust mounts; reverse | `[x]` TAR+ZIP+7z py→rs; TAR rs→py |
| P2 | Full fixed-archive (≥90% of ~174 triples) | Gap list in `docs/parity-gaps.md` |
| P2 | Style/clippy/fmt + `cargo deny` / license attributions | CI |
| P2 | Perf regression job from `benchmarks/baselines/rust-gates.json` | `[x]` `benchmark-gates` CI job + `check-rust-gates.sh` |

### Suggested CI matrix (ratarmount-rs)

```text
[always]  cargo fmt --check && cargo clippy -D warnings && cargo test --workspace
[fuse]    probe /dev/fuse; run-all-phases.sh (RATARMOUNT_PY_ROOT checkout)
[bench]   check-rust-gates.sh (cold index always); RUN_FULL_BENCH=1 for ratio CSV; weekly compare optional
[optional] SSH/S3 live when secrets present
```

---

## 3. Packaging & productization

| Item | Status |
|------|--------|
| Makefile release/install | `[x]` |
| Daemonize default | `[x]` |
| AppImage / distro packages | `~` `packaging/build-appimage.sh` + desktop; needs linuxdeploy host |
| crates.io library publish policy | `[ ]` |
| Pure FUSE ABI (Annex A) | `[ ]` deferred; fuser stays product path |
| GitHub CI (fmt/clippy/test) | `[x]` `.github/workflows/ci.yml` |
| GitHub CI FUSE allowlist suite | `[x]` (fixtures from mxmlnkn/ratarmount) |
| Phase 12: Python deprecation timeline | `~` scaffold [`docs/phase12-dual-run.md`](phase12-dual-run.md) |

---

## 4. Suggested implementation order

1. ~~**CLI flag parity**~~ — done: `--index-folders`, `:memory:`, default mountpoint, `-e`, `-d`, `--log-file`, `-o`.  
2. ~~**Seekable gzip (G3 Tier B)**~~ — done for `.tar.gz`/`.tgz` via `miniz_oxide` checkpoints; plain `.gz` still materializes; Tier C import deferred.  
3. ~~**Seekable bzip2 / xz / zstd**~~ — done: shared `SeekableBody`; zstd multi-frame map; bz2/xz one-shot decode to RAM/temp (true block-parallel / xz index / zstd seek-table still open).  
4. ~~**Test harness expansion**~~ — phase2–9 allowlists grown; `run-index-interop.sh` (Py↔Rust); fixed-archive wrapper ready (`RUN=1`). Continue complex-usage subset + full fixed-archive gap list.  
5. ~~**SquashFS / SQLAR**~~ — SQLAR pure; SquashFS via `unsquashfs` MVP.  
6. ~~**`--commit-overlay`**~~ — done for uncompressed TAR via GNU tar (`--yes` for non-interactive).  
7. ~~**File versions + prefix + control**~~ — `.versions/`, `-p`, Unix control socket.  
8. ~~**Lazy + strip/transform recursive**~~ — `-l`, `-s`, `--transform-recursive-mount-point`.  
9. ~~**CI gates**~~ — fmt/clippy/test + FUSE allowlist job. Packaging notes in `docs/packaging.md`.  
10. ~~**EXT4 MVP**~~ — `debugfs` rdump → FolderMountSource; harness `phase9-ext4`.  
10b. ~~**FAT images**~~ — pure Rust `fatfs` (FAT12/16/32); harness `phase9-fat`.  
11. ~~**AppImage scaffolding**~~ — `packaging/build-appimage.sh` (linuxdeploy when installed). Full CI AppImage optional.  
12. ~~**Python fork parity**~~ — done: [`docs/tasks/python-fork-parity.md`](tasks/python-fork-parity.md).  
13. ~~**ASAR**~~ — stencil `ASARMountSource`; harness `phase9-asar`.  
14. ~~**OGG / HTML / PDF / Git / zlib**~~ — OGG demux; HTML data-URLs; PDF attachments; Git via git2; zlib seekable.  
15. ~~**Mount options CLI parity**~~ — high-impact flags: password-file, recursive-extensions, transform, disable-union, no-recreate-index, gnu-incremental, color, oss-attributions; matrix: [`docs/mount-options-parity.md`](mount-options-parity.md).  
16. **Phase 12** dual-run announce → Rust primary — scaffold: [`docs/phase12-dual-run.md`](phase12-dual-run.md); execute after residual gates.

---

## 5. Tracking

- Design: `../ratarmount/docs/design-rust-rewrite.md` (or copy into this repo later)
- Benchmarks: `benchmarks/python-vs-rust-results.md`
- Format notes: `docs/phase9-formats.md`, `docs/phase10-remote.md`, `docs/tasks/sevenzip-random-access.md`
- **Fork → Rust task list:** [`docs/tasks/python-fork-parity.md`](tasks/python-fork-parity.md) (hilather sevenzip-random-access + stencil/stream codecs)
- **Phase 12 dual-run:** [`docs/phase12-dual-run.md`](phase12-dual-run.md)
