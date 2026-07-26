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
| GNU incremental TAR | yes | detect flag only | `[ ]` full semantics |
| ZIP (store/deflate, symlink, password) | yes | store/deflate; `--password` | `~` encrypted ZIP, multi-disk |
| Custom SevenZip random-access | yes (fork PR) | yes | `[x]` |
| AR / CPIO newc | yes | yes | `[x]` |
| libarchive long-tail (CAB/XAR/WARC/ISO/RAR/…) | yes | yes (sequential open) | `~` random-access quality |
| SquashFS | yes | no | `[ ]` |
| EXT4 / FAT images | yes | no (libarchive/ISO only) | `[ ]` |
| SQLAR | yes | no | `[ ]` |
| ASAR | yes | no | `[ ]` |
| PDF / OGG / HTML | yes | no | `[ ]` |
| Git tree mount | yes | no | `[ ]` |
| RAR pure / best-effort (beyond libarchive) | yes | libarchive only | `~` |

### Compression (seekable / outer codecs)

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| gzip (rapidgzip / seek index) | yes | **materialize (G3)** | `[ ]` seekable / Tier C index import |
| bzip2 block-parallel | yes | materialize | `[ ]` block map + `-P` |
| xz multi-block seek | yes | materialize | `[ ]` |
| zstd multi-frame / seek table | yes | materialize | `[ ]` |
| lz4 / lzip / lzo / lrz / Z / zlib | yes | no | `[ ]` |
| Concatenated / multi-frame outer streams | yes | partial (`--ignore-zeros`) | `~` |
| Split files (`.001`/`.002`) | yes | no | `[ ]` |

### Compositing & FUSE UX

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| Folder bind mount | yes | yes | `[x]` |
| Union of multiple sources | yes | yes | `~` cache knobs incomplete |
| AutoMount recursive (`-r`) | yes | yes | `~` extension list; strip-ext options |
| Write overlay (`-w` / `:temp:`) | yes | yes | `~` |
| `--commit-overlay` into archive | yes | no | `[ ]` |
| File version paths (`.versions/`) | yes | no | `[ ]` |
| Control interface socket | yes | no | `[ ]` |
| Lazy mount (`-l`) | yes | no | `[ ]` |
| Path transform / strip recursive extension | yes | no | `[ ]` |
| Prefix (`-p`) | yes | no | `[ ]` |
| FUSE extra options (`-o`) | yes | minimal | `[ ]` |
| Daemonize / foreground | yes | yes | `[x]` |
| readdirplus / attr cache | yes | yes | `[x]` |

### Remote I/O

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| `file://` | yes | yes | `[x]` |
| `http(s)://` (full GET) | yes | yes | `[x]` |
| HTTP Range without full download | yes | helper only | `[ ]` format readers on RangeFile |
| `s3://` | yes (fsspec) | yes (SigV4 env creds) | `~` instance-role / anonymous |
| `ssh://` / `sftp://` | yes | yes | `~` full ssh_config parity |
| SMB / WebDAV / Dropbox | yes | no | `[ ]` |
| Remote/compressed **index** download | yes | no | `[ ]` |

### Index / CLI

| Capability | Python | Rust | Status |
|------------|--------|------|--------|
| SQLite index 0.7.x schema | yes | yes | `[x]` |
| Cross-open Py↔Rust index (TAR core) | yes | yes | `~` compression side tables |
| `--index-file` / `:memory:` | yes | path only | `~` `:memory:` |
| `--index-folders` / XDG cache | yes | no | `[ ]` |
| Index file hashes / xattrs | yes | no | `[ ]` |
| `--use-backend` selection | yes | fixed factory order | `[ ]` |
| Encoding (`-e`) | yes | hard-coded utf-8 | `[ ]` |
| Debug / log-file / color | yes | env_logger only | `[ ]` |
| OSS attributions | yes | no | `[ ]` |
| Parallelization matrix (`-P backend:n`) | yes | flag reserved | `[ ]` |
| Default mountpoint (strip extension) | yes | requires explicit mp | `[ ]` |

### Performance (ongoing)

| Item | Status |
|------|--------|
| Cold index bulk insert | `[x]` |
| In-memory index for RO mounts | `[x]` |
| FUSE open-handle reuse / caches / readdirplus | `[x]` |
| ZIP store stencil + deflate cache | `[x]` |
| SevenZip solid streaming (large folders) | `[ ]` progressive decoder |
| Cold `find` geo-mean ≥ Python | `~` nested/compressed still lag |
| Seekable codecs (drop materialize for gzip+) | `[ ]` |
| Benchmark gates in CI (`rust-gates.json`) | `[ ]` |

---

## 2. Test parity

### Current Rust harness (allowlists)

~40 fixture lines across phases 2–11 + sevenzip/http/remote.  
Python has **100+** fixed archives and three large shells: fixed-archive, complex-usage, remote-backend.

### Harness expansion TODO

| Priority | Work | Exit criteria |
|----------|------|----------------|
| P0 | Expand TAR/ZIP/sparse allowlists to all Python fixtures that already pass | No silent skips for supported formats |
| P0 | Wire `RATARMOUNT_CMD` into Python `run-fixed-archive-tests.sh` with **phase allowlists** (never full AppImage set until ready) | Documented wrapper; CI job |
| P0 | SevenZip: full `test_sevenzip.py` scenarios as shell/cargo tests | store, lzma2, nested `-r`, encrypted |
| P1 | Complex usage: multi-source union, write-overlay commit paths, versioned files | Subset of `run-complex-usage-tests.sh` green |
| P1 | Remote: SSH fixture server (`start-asyncssh-server.py`) + optional S3/MinIO | Live optional; unit always |
| P1 | Index interop golden: Py builds index → Rust mounts; reverse | TAR + ZIP + 7z |
| P2 | Full fixed-archive (≥90% of ~174 triples) | Gap list in `docs/parity-gaps.md` |
| P2 | Style/clippy/fmt + `cargo deny` / license attributions | CI |
| P2 | Perf regression job from `benchmarks/baselines/rust-gates.json` | Fail on >20% regression |

### Suggested CI matrix (ratarmount-rs)

```text
[always]  cargo fmt --check && cargo clippy -D warnings && cargo test --workspace
[fuse]    probe /dev/fuse; run-all-phases.sh (RATARMOUNT_PY_ROOT checkout)
[bench]   weekly compare-python-vs-rust.sh; check rust-gates.json
[optional] SSH/S3 live when secrets present
```

---

## 3. Packaging & productization

| Item | Status |
|------|--------|
| Makefile release/install | `[x]` |
| Daemonize default | `[x]` |
| AppImage / distro packages | `[ ]` |
| crates.io library publish policy | `[ ]` |
| Pure FUSE ABI (Annex A) | `[ ]` deferred; fuser stays product path |
| Phase 12: Python deprecation timeline | `[ ]` after parity gates |

---

## 4. Suggested implementation order

1. **CLI flag parity** for harness-critical options (`--index-folders`, default mountpoint, `-e`, `-d`, `-o` pass-through).  
2. **Seekable gzip (or import Python gzip index tables)** — closes largest architectural gap vs rapidgzip.  
3. **Test harness expansion** to full fixed-archive allowlist growth + Py interop goldens.  
4. **SquashFS / EXT4 / SQLAR** as needed by allowlist failures (libarchive or pure).  
5. **`--commit-overlay`**, file versions, control interface.  
6. **Packaging (AppImage)** + CI gates.  
7. **Phase 12** announce dual-run → Rust primary.

---

## 5. Tracking

- Design: `../ratarmount/docs/design-rust-rewrite.md` (or copy into this repo later)
- Benchmarks: `benchmarks/python-vs-rust-results.md`
- Format notes: `docs/phase9-formats.md`, `docs/phase10-remote.md`, `docs/tasks/sevenzip-random-access.md`
