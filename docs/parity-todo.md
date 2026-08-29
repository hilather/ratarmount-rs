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
| gzip (rapidgzip / seek index) | yes | Tier B + RGZI Tier C + best-effort **GZIDX**; opt-in **Tier D** `gzip-rapidgzip` (path/nested/Range + GZIDX, not default) | `[x]` / `~` window-dict full interop; thruput still `~` vs Python rapidgzip (G3 default; Tier D spot ~500 vs ~1100 MiB/s pre–P2/P4 re-bench — [binding residual](gzip-binding-decision.md#residual--performance-thruput--cost), [perf batch P1–P5 done](tasks/rapidgzip-perf-batch.md), [residuals R1–R5](tasks/rapidgzip-residual-batch.md); see `gzip-backend-results` when generated) |
| bzip2 block-parallel | yes | multi-stream + file-backed bit-block maps + **bzip2blocks** factory auto-import | `[x]` / `~` open-time size discovery |
| xz multi-block seek | yes | Stream Footer+Index **footer-first** range map (multi-stream + multi-block / pixz); small single-block Index; large units → full decode + temp spill | `[x]` / `~` exotic filters |
| zstd multi-frame / seek table | yes | multi-frame map + seek-table + **zstdblocks** factory auto-import; Shared concurrent-safe ([guide](zstd-random-access.md)) | `[x]` |
| lz4 / lzip / lzo / Z / lzma-alone / zlib | yes | yes (seekable) | `[x]` |
| lrz | yes (libarchive) | detect + `lrzip`/`lrunzip` materialize; **libarchive** raw/filter fallback | `~` pure in-process still open |
| Concatenated / multi-frame outer streams | yes | partial (`--ignore-zeros`) | `~` |
| Split files (`.001`/`.002`) | yes | yes (decimal/hex/alpha join) | `[x]` top-level + recursive AutoMount |

### Compositing & FUSE UX

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| Folder bind mount | yes | yes | `[x]` |
| Union of multiple sources | yes | yes + folder cache (depth/entries/timeout) | `[x]` |
| AutoMount recursive (`-r`) | yes | nested no-tmp for TAR/ZIP/7z/`.tar.gz`/CPIO/AR/ISO/WARC/ASAR/XAR/CAB·MSZIP/SQLAR/FAT/SquashFS(non-LZMA)/EXT4(pure) + TAR flatten; eager same-dir parallel nested opens (FR-6 / #80, `--parallel-nested`); default recursive includes `.sqfs`/`.snap`; see [`embedded-nested-archives.md`](embedded-nested-archives.md) | `[x]` / `~` CAB LZX, classic SquashFS LZMA, pure-fail EXT4, RAR nested still spool |
| Write overlay (`-w` / `:temp:`) | yes | yes (missing uncompressed `.tar` / `.tar.zst` created as an empty archive) | `~` |
| `--commit-overlay` into archive | yes | yes (uncompressed + gzip/bzip2/xz TAR via GNU tar; `.tar.zst` splice including earlier-frame delete; ZIP full rebuild). Create-if-missing for uncompressed `.tar` only. Live interval still rejects prefix-frame mutate. | `[x]` TAR compressions + ZIP MVP / residual live earlier-frame |
| Live `--commit-overlay-on-exit` / `--interval` | no | uncompressed TAR + `.tar.zst` last-frame rewrite (does not recompress the prefix; persist still copies the compressed prefix; on-disk sidecar patched so remount does not rescan prefix frames; `:memory:` still full-rebuild; 2× compressed disk headroom; never refuse on size; warn when last-frame uncompressed > 64 MiB). Same create-if-missing as `-w`. Interval is a per-file settle time (idle host mtime ≥ `DURATION` and no open write fd), not a dump of every overlay file. Gzip stays rejected. | `[x]` Rust-only / residual earlier-frame delete |
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
| Sequential readahead (`--readahead`) | no (issue #180) | yes (`0` off; K/M/G; max 64 MiB) | `[x]` |
| NFSv3 userspace export | no | yes (`--nfs` / `--nfs-bind`; IPv4, localhost default; `-w` overlay writes including rename/symlink) | `[x]` / residual Windows READDIR |
| NFSv4.1 userspace export | no | yes (`embednfs` 0.4.1, `--nfs --nfs-vers 4`; Linux/macOS packages compile `nfsv4`; source `--features nfsv4`, rustc ≥ 1.88; lookup/read/readdir + `-w` overlay writes including rename/symlink) | `~` / Linux kernel client **verified** (privileged Docker loopback `test-harness/nfs-docker`, 2026-08-15; not default CI); no Kerberos/LAN/Windows; no v3/v4 mux; idle-TTL-not-CLOSE; embednfs macOS-first |
| HTTP GET/HEAD export (`--http`) | no | yes (`127.0.0.1:20491`; Range 206; fill-loop) | `[x]` Rust-only |
| WebDAV export (`--webdav`) | no | PROPFIND Depth 0/1 + GET; PUT/DELETE/MKCOL/MOVE/COPY with `-w`; LOCK/UNLOCK; PROPPATCH; Basic env | `[x]` / mux residual |
| SMB 2.0.2 export (`--smb`) | no | userspace 2.0.2 subset; guest `smbclient -N` unsigned; NTLMv2 + signing when password set | `~` encrypt / 3.1.1 / Finder residual |
| 9P2000.L TCP (`--ninep`) | no | TCP `trans=tcp` port 20493; writes need `-w` | `[x]` / virtio residual |
| SFTP export (`--sftp`) | no | TCP `:20222` + `--sftp-subsystem` stdio; password env; `--features sftp-russh` (packages on; default CI off; russh MSRV 1.85) | `[x]` / russh feature note |
| Daemonize / foreground | yes | yes | `[x]` |
| readdirplus / attr cache | yes | yes | `[x]` |
| Full mount-option matrix | — | see [`docs/mount-options-parity.md`](mount-options-parity.md) | `~` |

### Remote I/O

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| `file://` | yes | yes | `[x]` |
| `http(s)://` (full GET) | yes | yes | `[x]` |
| HTTP Range without full download | yes | live Range for TAR/ZIP/gzip/**bzip2/xz/zstd** + materialize fallback | `[x]` |
| `s3://` | yes (fsspec) | SigV4 env + IMDS/ECS + anonymous + live Range (`open_s3_range` / `S3RangeFile`) + **prefix folders** (`ListObjectsV2`) | `[x]` |
| `gs://` / `az://` | yes (fsspec) | GCS XML Range + JSON list (ADC/IMDS/anonymous) + GOOG1 HMAC; Azure Range + List Blobs (SAS/SharedKey/MSI) | `[x]` |
| `ftp://` / `ftps://` | yes | REST/SIZE Range or full RETR; explicit AUTH TLS (`suppaftp` rustls); LIST/MLSD folders | `[x]` / `~` implicit FTPS :990 |
| `ssh://` / `sftp://` | yes | yes + SFTP `readdir` directory mounts | `[x]` / `~` HostName/User/Port/IdentityFile/IdentitiesOnly/ProxyJump/Include done; residual ProxyCommand / Match |
| SMB / WebDAV / Dropbox | yes | WebDAV file GET + **Depth-1 collections**; SMB `smbclient`; Dropbox folder (list TTL) + ranged content download | `[x]` / `~` inbound SMB still CLI |
| `oci://` / `docker://` | no | manifest + Bearer blob Range + overlayfs layer union | `[x]` Rust-only / eStargz residual |
| `ipfs://` / `ipns://` | yes | gateway Range + UnixFS `IPFS_API` list (no embedded node) | `[x]` |
| `rclone://remote:path` | yes (fsspec rclone) | argv `cat --offset` + `lsjson` folders; `rclone+remote:path` | `[x]` / `~` RC `--rc-serve` residual |
| HTTP/S3/SSH/WebDAV **directory** mounts | yes (fsspec) | F-1 `RemoteFolderMountSource` (autoindex / ListObjects / `readdir` / PROPFIND / FTP LIST) | `[x]` |
| Remote/compressed **index** download | yes | http(s)/file:// + gzip/xz/zstd/bz2 index decompress | `[x]` |

### Index / CLI

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| SQLite index 0.7.x schema | yes | yes | `[x]` |
| Cross-open Py↔Rust index (TAR core) | yes | yes + gzip/zstd/bzip2 side tables; factory auto-imports on open (FR-9) | `[x]` / `~` decoder import of Python blobs |
| `--index-file` / `:memory:` | yes | yes | `[x]` |
| `--index-id HEX` / `{archive}.index.ptr` | no | **added** (`--publish-index` writes pointer + keep-last-K=2; `--index-id` binds a snapshot) | `[x]` Rust-only |
| `--index-folders` / XDG cache | yes | yes (CSV/JSON + defaults) | `[x]` |
| Index file hashes / xattrs | yes | `--hashes` + FUSE xattrs for TAR/ZIP/7z; TAR PAX LIBARCHIVE/SCHILY FS xattrs | `[x]` / `~` solid 7z shared key; other formats |
| `--use-backend` selection | yes | reorders format probe (last flag highest) | `[x]` |
| Encoding (`-e`) | yes | yes (TAR names via encoding_rs) | `[x]` |
| Debug / log-file / color | yes | `-d` + `--log-file` + color env | `[x]` / `~` full NO_COLOR matrix |
| OSS attributions | yes | yes (`--oss-attributions` / help) | `[x]` |
| Parallelization matrix (`-P backend:n`) | yes | full matrix incl. zlib/lzma/Z; true parallel where codec allows; AutoMount eager nested fan-out via `--parallel-nested` / `parallel_nested_threads` (default auto) | `[x]` / `~` sequential codecs still API-only |
| Default mountpoint (strip extension) | yes | yes | `[x]` |

### Performance (ongoing)

| Item | Status |
|------|--------|
| Cold index bulk insert | `[x]` |
| In-memory index for RO mounts | `[x]` |
| FUSE open-handle reuse / caches / readdirplus | `[x]` |
| ZIP store stencil + deflate cache | `[x]` |
| SevenZip solid streaming (large folders) | `~` progressive AES+LZMA2 and native BCJ/Delta+LZMA2 (1 MiB LRU ≤64; BCJ/Delta sequential-from-0, no dict-reset resume); BCJ2 / multi-pack still full-folder |
| Cold `find` geo-mean ≥ Python | `~` nested/compressed still lag (gzip nested still dominates). Cheap `list_dirents` sizes now on EXT4/FAT/SquashFS/Git/SQLAR/`SingleFileMountSource`/Dropbox + union folder-cache/FR-10; **not** a closed geo-mean |
| Seekable codecs (drop materialize for gzip+) | `[x]` plain + TAR via SeekableBody / SingleFile; residual SquashFS/lrzip/LZX |
| Tier D rapidgzip thruput (opt-in) | `~` path/nested/Range + GZIDX wired ([P1–P5](tasks/rapidgzip-perf-batch.md) done); cold index/seq still slower than G3 on pre–P2/P4 spot and behind Python rapidgzip class thruput pending re-bench + [R1–R4](tasks/rapidgzip-residual-batch.md) |
| Benchmark gates in CI (`rust-gates.json`) | `[x]` cold-index hard job + optional `benchmark-gates-full` (`RUN_FULL_BENCH=1 ALLOW_RATIO_SKIP=1`) |

---

## 2. Test parity

### Current Rust harness (allowlists)

Summed `tests/` allowlist rows (`^tests/` in `test-harness/*.txt`): phase2 **70**, phase6 **12**, phase7 **46**, phase9 AR/CPIO **28**, SevenZip **20**, SQLAR/sqfs **20**, libarchive **13** (those seven = **209**); plus smaller phase3–5 / phase9 image+stencil+stream lists → **236** total.  
Python has **100+** fixed archives and three large shells: fixed-archive, complex-usage, remote-backend.  
Wrappers: `run-fixed-archive-subset.sh` (`RUN=1`), `run-index-interop.sh` (Py↔Rust SQLite). Do **not** create `docs/parity-gaps.md` unless leftovers are actually enumerated.

### Harness expansion TODO

| Priority | Work | Exit criteria |
|----------|------|----------------|
| P0 | Expand TAR/ZIP/sparse allowlists to all Python fixtures that already pass | `~` phase2 **70** TAR; phase6 **12** ZIP; phase7 **46** nested; phase9 AR/CPIO **28**, 7z **20**, SQLAR/sqfs **20**, libarchive **13** |
| P0 | Wire `RATARMOUNT_CMD` into Python `run-fixed-archive-tests.sh` with **phase allowlists** (never full AppImage set until ready) | `[x]` `run-fixed-archive-subset.sh` |
| P0 | SevenZip: full `test_sevenzip.py` scenarios as shell/cargo tests | `~` store, lzma2, large, folder-symlink, nested members; **encrypted** password + metadata-only unit + phase9 `|password` harness row; AES+LZMA2 / BCJ+LZMA2 cargo progressive; multi-GB BCJ2 / multi-pack solid residual |
| P1 | Complex usage: multi-source union, write-overlay commit paths, versioned files | `[x]` phase8 overlay (replace/readdir/empty-create/delete+recreate) + complex (union rightmost, B-4 both orders, commit-overlay tar/gzip/zip) + versioned FUSE (`updated-file.tar` `.versions/1,2,3`) |
| P1 | Remote: SSH fixture server (`start-asyncssh-server.py`) + optional S3/MinIO | Live optional; unit always |
| P1 | Index interop golden: Py builds index → Rust mounts; reverse | `[x]` TAR+ZIP+7z py→rs; TAR rs→py |
| P2 | Full fixed-archive (≥90% of ~174 triples) | Gap list in `docs/parity-gaps.md` |
| P2 | Style/clippy/fmt + `cargo deny` / license attributions | CI |
| P2 | Perf regression job from `benchmarks/baselines/rust-gates.json` | `[x]` `benchmark-gates` CI job + `check-rust-gates.sh` |

### Suggested CI matrix (ratarmount-rs)

```text
[always]  cargo fmt --check && cargo clippy -D warnings && cargo test --workspace
[fuse]    probe /dev/fuse; run-all-phases.sh (RATARMOUNT_PY_ROOT checkout)
[bench]   check-rust-gates.sh cold always; benchmark-gates-full = RUN_FULL_BENCH=1 ALLOW_RATIO_SKIP=1
[optional] SSH/S3 live when secrets present
```

---

## 3. Packaging & productization

| Item | Status |
|------|--------|
| Makefile release/install | `[x]` |
| Daemonize default | `[x]` |
| AppImage / distro packages | `~` `packaging/build-appimage.sh` + desktop; needs linuxdeploy host |
| crates.io library publish policy | `[x]` documented [`docs/crates-io-policy.md`](crates-io-policy.md) (no crates.io publish required for dual-run) |
| Pure FUSE ABI (Annex A) | `[ ]` deferred; fuser stays product path |
| GitHub CI (fmt/clippy/test) | `[x]` `.github/workflows/ci.yml` |
| GitHub CI FUSE allowlist suite | `[x]` (fixtures from mxmlnkn/ratarmount) |
| Phase 12: dual-run / Python deprecation timeline | `[x]` docs ready for announce [`docs/phase12-dual-run.md`](phase12-dual-run.md) (residual table + release-notes stub + how-to-announce); **not announced** — tag / deprecation date / CI-on-tag still **ops-pending** |

---

## 4. Suggested implementation order

1. ~~**CLI flag parity**~~ — done: `--index-folders`, `:memory:`, default mountpoint, `-e`, `-d`, `--log-file`, `-o`.  
2. ~~**Seekable gzip (G3 Tier B)**~~ — `.tar.gz` + plain `.gz` single-file via seekable body; Tier C RGZI import/export done.  
3. ~~**Seekable bzip2 / xz / zstd**~~ — done: shared `SeekableBody`; zstd multi-frame + seek-table + zstdblocks; xz Footer/Index range-only maps + multi-stream; bzip2 multi-stream + bit-block maps. Residual: exotic xz filters; true bzip2 bit-parallel open-time size discovery polish.  
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
16. **Phase 12** dual-run announce → Rust primary — **docs ready** (not announced): [`docs/phase12-dual-run.md`](phase12-dual-run.md) runbook + paste-ready notes; maintainer still must tag, publish packages, set deprecation date. crates.io not required: [`docs/crates-io-policy.md`](crates-io-policy.md).

---

## 5. Tracking

- Design: `../ratarmount/docs/design-rust-rewrite.md` (or copy into this repo later)
- Benchmarks: [benchmarks/python-vs-rust-results.md](../benchmarks/python-vs-rust-results.md) (v0.1.27 BIG suite vs Python 1.3.0, 2026-08-27; re-run `BIG=1 ./benchmarks/compare-python-vs-rust.sh`)
- Format notes: `docs/phase9-formats.md`, `docs/phase10-remote.md`, `docs/tasks/sevenzip-random-access.md`
- **Fork → Rust task list:** [`docs/tasks/python-fork-parity.md`](tasks/python-fork-parity.md) (hilather sevenzip-random-access + stencil/stream codecs)
- **Upstream feature requests:** [`docs/tasks/upstream-feature-requests.md`](tasks/upstream-feature-requests.md) (mxmlnkn/ratarmount issues → implementable FR list)
- **Upstream bugs inspected + fixed (2026-07-28):** [`docs/tasks/upstream-bugs-inspection.md`](tasks/upstream-bugs-inspection.md) / [`upstream-bug-fix-batch.md`](tasks/upstream-bug-fix-batch.md) — **B-4** union dir>symlink, **B-8** sparse>8GiB test, **B-10** dumpdir delete MVP, **B-119** index-min-count, **B-2** lazy-recursive docs. Optional residual: multi-archive GNU incremental `.snar` union
- **Phase 12 dual-run:** [`docs/phase12-dual-run.md`](phase12-dual-run.md)
- **crates.io policy:** [`docs/crates-io-policy.md`](crates-io-policy.md)
- **Gap batches:** [`docs/tasks/gap-implementation-batch.md`](tasks/gap-implementation-batch.md)
- **Beyond-parity roadmap (2026-08-23, leftover close-out 2026-08-24):** [`docs/tasks/beyond-parity-roadmap.md`](tasks/beyond-parity-roadmap.md) — P-1–P-10 / F-1 / F-4 / G-1 booleans landed; **P-6** / **P-10** `done`; **P-2** stays `partial` (encrypt / 3.1.1 / Finder). **F-2** incremental reindex, **F-3** locate, and **G-2** portable index are `done` (HTTP/S3/GCS/Azure sibling GET of pointer then blob then well-known; residual object-store PUT is F-7). Remaining F-5..F-10, G-3..G-5. Inbound: [`phase10-remote.md`](phase10-remote.md). Outbound: [`export.md`](export.md) + [`nfs-export.md`](nfs-export.md). gzip/rapidgzip thruput and Phase 12 announce stay residual / ops.
- **Tier D rapidgzip perf residual:** [`docs/tasks/rapidgzip-perf-batch.md`](tasks/rapidgzip-perf-batch.md) (P1–P5 done) · post-batch [`docs/tasks/rapidgzip-residual-batch.md`](tasks/rapidgzip-residual-batch.md) (R1–R5) · decision residual split in [`docs/gzip-binding-decision.md`](gzip-binding-decision.md)
