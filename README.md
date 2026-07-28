# ratarmount-rs

Native **Rust** rewrite of [ratarmount](https://github.com/mxmlnkn/ratarmount) — mount archives (and remote objects) as a FUSE filesystem with SQLite indexes for fast random access.

| | |
|--|--|
| **Version** | **0.1.10** ([releases](https://github.com/hilather/ratarmount-rs/releases)) |
| **Language** | Rust (edition 2021) |
| **FUSE** | `fuser` low-level (inode API) |
| **Platforms** | Linux (primary) · **macOS** (beta: arm64 + x86_64 tarballs) |
| **Upstream** | Feature parity vs [mxmlnkn/ratarmount](https://github.com/mxmlnkn/ratarmount) |
| **Living checklist** | [docs/parity-todo.md](docs/parity-todo.md) · [docs/mount-options-parity.md](docs/mount-options-parity.md) |
| **Dual-run / crates.io** | [docs/phase12-dual-run.md](docs/phase12-dual-run.md) · [docs/crates-io-policy.md](docs/crates-io-policy.md) |

```bash
make release && make install   # → ~/.local/bin/ratarmount
ratarmount archive.tar.gz mnt/
```

---

## Python ratarmount vs ratarmount-rs

Both tools mount archives over FUSE with a **shared SQLite index schema** (0.7.x interop for TAR/ZIP/7z). Python is the mature reference implementation; Rust is a native rewrite optimized for cold mount cost and resident memory.

| Dimension | Python (`mxmlnkn/ratarmount`) | Rust (`ratarmount-rs` 0.1.10) |
|-----------|------------------------------|------------------------------|
| **Runtime** | CPython + native codec libs | Single static-friendly binary |
| **FUSE** | mfusepy (fusepy fork) | `fuser` low-level |
| **Index** | SQLite 0.7.x | Same schema (TAR/ZIP/7z interop) |
| **Memory (mount)** | ~110–350 MiB typical | **~14–28 MiB** peak RSS (geo-mean **~6–8×** lower) |
| **Cold mount (geo-mean)** | baseline | **~3.6× faster** |
| **Warm mount (geo-mean)** | baseline | **~3.8× faster** |
| **Random cat / seq. read** | Often stronger on compressed TAR (rapidgzip / block maps) | Strong on large uncompressed TAR; geo-mean slightly behind Python on this host |
| **Nested archives (`-r`)** | Recursive automount | Same + **no-tmp** nested open for most stencil formats |
| **Remote** | Broad fsspec | `file` / `http(s)` / `s3` / `ssh`·`sftp` / WebDAV / SMB / Dropbox |
| **Write overlay** | Full + commit | Full + commit (TAR + gzip/bzip2/xz via GNU tar) |
| **Maturity** | Production / PyPI / AppImage | Feature-rich beta; **deb/rpm/portable + macOS arm64** on GitHub Releases |

**When to prefer Rust:** low-memory hosts, many short-lived mounts, large uncompressed TAR sequential I/O, nested archives without `/tmp` spool.  
**When to prefer Python:** maximum codec maturity (rapidgzip / bit-block bzip2), widest fsspec ecosystem, long-tail workflows already wired to the Python stack.

Rust is not a drop-in for every Python workflow yet (see [gaps](#gaps-vs-python-ratarmount)), but for common TAR/ZIP/7z mounts it is substantially leaner and usually **much faster to mount**.

---

## Features (parity with original ratarmount)

### Archives & images

| Format | Python | Rust | Notes |
|--------|:------:|:----:|-------|
| TAR (ustar / PAX / GNU) + sparse | yes | yes | GNU incremental: detect + dumpdir / prefix strip |
| ZIP (store / deflate, password) | yes | yes | Multi-part join; multi-disk EOCD normalize; residual per-disk edges |
| 7z custom pack-offset + AES / BCJ2 | yes* | yes | *fork RA work; pure LZMA2 progressive; solid BCJ/AES still heavy |
| AR / CPIO | yes | yes | `open_from_reader` (nested no-tmp) |
| ISO 9660 / WARC / XAR / CAB / ASAR | yes | yes | CAB LZX → libarchive; others stream-open for nested |
| SquashFS | yes | yes | backhand in-process; classic lzma → `unsquashfs` |
| EXT4 | yes | yes | pure `ext4-view` + `debugfs` fallback |
| FAT12/16/32 | yes | yes | Pure Rust (`fatfs`); nested `open_from_reader` |
| SQLAR | yes | yes | Unencrypted stream open (RAM deserialize); sqlcipher optional |
| PDF / OGG / HTML / Git | yes | yes | PDF attachments + common XObjects; Git may need `RATARMOUNT_FORCE_GIT=1` |
| RAR / LHA / long-tail | yes | yes | via libarchive (sequential member open) |
| Split files (`.001`) | yes | yes | decimal/hex/alpha join at open + recursive AutoMount |
| lrzip | yes | yes | CLI materialize + libarchive fallback |

### Compression (outer / seekable)

| Codec | Python | Rust | Notes |
|-------|:------:|:----:|-------|
| gzip | yes (rapidgzip / seek points) | yes | TAR **and** plain `.gz` seekable (no full materialize); RGZI Tier C import/export |
| bzip2 | yes (block-parallel) | yes | Multi-stream + `bzip2blocks` side table; residual true bit-block polish |
| xz | yes (multi-block) | yes | Index / multi-stream maps; single-block full decode residual |
| zstd | yes (seek table) | yes | Multi-frame + seek-table + `zstdblocks` import/export |
| lz4 / lzip / lzo / .Z / lzma / zlib | yes | yes | Seekable bodies in both |

### Compositing & mount UX

| Ability | Python | Rust |
|---------|:------:|:----:|
| Recursive automount (`-r`) | yes | yes — **no `/tmp`** for most nested formats ([guide](docs/embedded-nested-archives.md)) |
| Lazy mount (`-l`) | yes | yes |
| Union of multiple sources | yes | yes (+ folder cache knobs) |
| Write overlay (`-w` / `:temp:`) | yes | yes |
| `--commit-overlay` | yes | TAR + gzip/bzip2/xz (GNU tar) |
| File versions (`.versions/`) | yes | yes (default on; `--no-file-versions`) |
| Strip / transform recursive paths | yes | yes |
| Prefix (`-p`) | yes | yes |
| Control interface | in-FS folder | Unix socket **+** in-FS `/.ratarmount-control/` |
| Daemonize / foreground (`-f`) | yes | yes |
| Password / password-file | yes | yes |
| Content hashes / FUSE xattrs | yes | yes (TAR/ZIP/7z) |

### Remote

| Protocol | Python | Rust |
|----------|:------:|:----:|
| `file://` | yes | yes |
| `http(s)://` | yes | yes (full GET + **live Range** for TAR/ZIP/gzip/bzip2/xz/zstd) |
| `s3://` | yes | yes (SigV4 env + IMDS/ECS + anonymous; Range prefer) |
| `ssh://` / `sftp://` | yes | yes |
| WebDAV / SMB / Dropbox | yes | yes (folder list + ranged content) |

Full option matrix: [`docs/mount-options-parity.md`](docs/mount-options-parity.md).  
Full checklist: [`docs/parity-todo.md`](docs/parity-todo.md).

---

## Gaps vs Python ratarmount

Still missing or partial relative to upstream Python:

1. **Codec depth** — true bzip2 bit-block map / `-P` parity; exotic xz filters; rapidgzip-class throughput.
2. **Formats** — pure in-process classic SquashFS lzma (no `unsquashfs`); pure RAR; encrypted SQLAR decrypt without path/sqlcipher; residual PDF color spaces.
3. **7z solids** — multi-GB BCJ/AES still full-folder; progressive pure LZMA2 is bounded but not free.
4. **Remote** — full `ssh_config` parity; some remote index edge cases.
5. **CLI polish** — colored logs; full OSS attributions; optional Homebrew formula.
6. **Platforms** — macOS is **beta** (arm64/x86_64 tarballs + CI); needs [macFUSE or FUSE-T](docs/macos.md). Full harness parity open.

---

## Performance vs Python

Head-to-head harness: [`benchmarks/compare-python-vs-rust.sh`](benchmarks/compare-python-vs-rust.sh).  
**Latest tables (2026-07-28 refresh):** [`benchmarks/python-vs-rust-results.md`](benchmarks/python-vs-rust-results.md).

**Methodology (same spirit as upstream mounting/bandwidth benches):**

- **Cold mount**: recreate index (`-c`) until FUSE is usable  
- **Warm mount**: reuse SQLite index  
- **Random access**: median of 15 `cat`s on random files  
- **find**: metadata walk wall time  
- **Bandwidth**: sequential `cat` of a large member (MiB/s)  
- Peak RSS from `/proc/<pid>/status` `VmHWM`  
- Both tools run with `-f` for comparable process measurement  

### Geometric-mean summary (2026-07-28)

Factor **>1 ⇒ Rust better**, **&lt;1 ⇒ Python better**.

| Metric | Cold | Warm | Interpretation |
|--------|------|------|----------------|
| Mount time | **3.63×** | **3.84×** | Rust mounts much faster |
| Peak RSS | **6.47×** | **8.01×** | Rust ~6–8× leaner on average |
| Random cat (median) | **0.84×** | **0.75×** | Python slightly ahead (esp. compressed TAR) |
| find walk | **1.21×** | **1.26×** | Rust ahead on metadata walks overall |
| Seq. bandwidth | **0.88×** | **0.78×** | Python slight geo-mean edge; **large uncompressed TAR strongly favors Rust** |

### Highlight fixtures (this run)

| Archive | What stands out |
|---------|-----------------|
| `empty-1k.tar` | Cold mount **5.69×** faster; warm `find` **~4×** faster; RSS ~7× lower |
| `large-64m.tar` | Random cat **~4×** faster; sequential bandwidth **3–3.7×** higher (multi‑GiB/s) |
| `small-100.tar.gz` | Warm mount **7.76×** faster; warm RSS **25×** lower (Python ~351 MiB vs Rust ~14 MiB) |
| `small-100.tar.bz2` | Cold mount still slower on Rust (map build); random cat **~1.8×** faster once mounted |
| `small-100.zip` | Mount **~4.7×** faster; random cat mixed (Python often wins small deflate reads) |

**Caveats**

- Single-host, single-run wall times — directional, not publication-grade.  
- Compressed TAR: Python may use rapidgzip / block-parallel paths; Rust uses seekable bodies (checkpoints / frame maps) without full archive spool.  
- Re-run anytime:

```bash
export RATARMOUNT_PY_ROOT=../ratarmount
cargo build --release
./benchmarks/compare-python-vs-rust.sh
```

---

## Requirements

**Linux**

- Rust stable (`rustup default stable`)
- `libfuse3` / `fuse3`
- `libarchive` (long-tail formats)
- `zlib` headers (flate2/system zlib)
- Optional: `e2fsprogs` (`debugfs`) for EXT4 fallback, `squashfs-tools` for classic SquashFS lzma
- Sibling Python checkout for fixtures (default `../ratarmount`) for the harness

**macOS** — full guide: [`docs/macos.md`](docs/macos.md) (FUSE install, Tahoe/FSKit, build, smoke)

```bash
# FUSE — pick one (required before mount or build)
brew install --cask macfuse          # recommended
# or: brew install macos-fuse-t/homebrew-cask/fuse-t

brew install libarchive pkgconf
export PKG_CONFIG_PATH="$(brew --prefix libarchive)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

# macOS 26 Tahoe: if mounts fail, use FSKit
#   ratarmount -f -o backend=fskit archive.tar.gz mnt/
```

## Build / install

```bash
export PATH="$HOME/.cargo/bin:$PATH"
make release
make install          # → ~/.local/bin/ratarmount
# or: cargo install --path ratarmount
# macOS package: ./packaging/build-macos-tarball.sh
```

**Packages:** GitHub Actions builds Linux `.deb` / Rocky `.rpm` / portable glibc 2.31 tarballs **and macOS arm64 tarballs**, with cosign keyless signatures. Tag `v*` (e.g. **v0.1.10**) publishes a GitHub Release. (Intel macOS CI image deferred — scarce GHA runners.) See [`docs/packaging.md`](docs/packaging.md) and [`docs/macos.md`](docs/macos.md).

## Test

```bash
export RATARMOUNT_PY_ROOT="$HOME/projects/ratarmount"   # Python tree with tests/
cargo test --workspace
./test-harness/run-all-phases.sh    # or: make suite
./benchmarks/compare-python-vs-rust.sh   # optional head-to-head
```

CI (`.github/workflows/ci.yml`): `cargo fmt`, `clippy -D warnings`, `cargo test`, FUSE phase allowlists, cold-index gates, macOS build/test.

## CLI (subset)

```bash
ratarmount --print-features

# Index only
ratarmount --no-mount -c archive.tar

# Mount (daemonizes by default; -f stays attached)
ratarmount archive.tar mnt/
ratarmount -f archive.tar mnt/

# Recursive, writable, remote, encrypted 7z
ratarmount -r archive.tar mnt/
ratarmount -w /tmp/ov archive.tar mnt/
ratarmount http://host/archive.tar mnt/
ratarmount s3://bucket/key.tar mnt/
ratarmount 'ssh://user@host//path/a.tar' mnt/
ratarmount --password secret encrypted.7z mnt/

ratarmount -u mnt/
```

Harness log contract (TAR index):

- `Creating offset dictionary for …`
- `Successfully loaded offset dictionary from …`

## Layout

```
ratarmount/                 # CLI binary
ratarmount-core/            # MountSource trait, options
ratarmount-index/           # SQLite 0.7.x index
ratarmount-fuse/            # fuser low-level FS
ratarmount-compress/        # seekable codecs + stencils
ratarmount-formats-{tar,zip,ar,cpio,iso9660,warc,xar,cab,asar,ogg,html,pdf,git,sevenzip,sqlar,squashfs,ext4,fat,libarchive}/
ratarmount-compositing/     # folder, union, automount, overlay
ratarmount-remote/          # http/s3/ssh/webdav/smb/dropbox
test-harness/               # phase allowlists + runners
packaging/                  # desktop entry + AppImage / nfpm
benchmarks/                 # Python vs Rust comparison
docs/                       # decisions, phase notes, parity TODO
```

## Embedded / nested archives (`-r`)

Recursive mounts open nested archives from a **seekable parent member stream** when possible — **no copy of the nested body to `/tmp`**.

| Nested member | Temp spool? | Random read of nested contents |
|---------------|:-----------:|--------------------------------|
| `.tar` inside ZIP / TAR / 7z / `.tar.gz` | **No** | Yes (TAR stencil) |
| `.tar.gz` inside ZIP / TAR / 7z | **No** | Yes (gzip seek + TAR) |
| `.zip` / `.7z` inside those parents | **No** | Yes\* |
| CPIO / AR / ISO / WARC / ASAR / XAR / CAB (store/MSZIP) / FAT nested | **No** | Yes (stencil / shared seek) |
| Unencrypted SQLAR nested | **No** (DB in RAM) | Yes after deserialize |
| Plain nested `.gz`/`.zst`/… single-file | **No** | Seekable body single-file |
| CAB LZX / SquashFS / RAR nested | Often **yes** (fallback) | Path open after spool |

\* ZIP deflate and solid 7z still decompress (CPU/RAM); they avoid nested **disk** spool when the stream path succeeds.

Compared to Python: both support `-r`; Rust’s no-tmp nested path is explicit for stencil formats and plain seekable compress (see matrix). Full detail: **[docs/embedded-nested-archives.md](docs/embedded-nested-archives.md)**.

```bash
ratarmount -r archive.zip mnt/          # e.g. mnt/inner.tar/file.txt — no /tmp for inner.tar
RUST_LOG=debug ratarmount -r -d 2 …   # "nested reader" vs "temp spool" in logs
```

## Docs

| Doc | Topic |
|-----|--------|
| [docs/parity-todo.md](docs/parity-todo.md) | **Full feature + test parity checklist** |
| [docs/embedded-nested-archives.md](docs/embedded-nested-archives.md) | **Nested/embedded: no-tmp vs temp, random read by format** |
| [docs/mount-options-parity.md](docs/mount-options-parity.md) | CLI / mount-ability matrix |
| [docs/gzip-binding-decision.md](docs/gzip-binding-decision.md) | Gzip seek path (TAR + plain) |
| [docs/phase9-formats.md](docs/phase9-formats.md) | Long-tail formats |
| [docs/phase10-remote.md](docs/phase10-remote.md) | Remote URL backends |
| [docs/phase11-packaging.md](docs/phase11-packaging.md) | Packaging notes |
| [docs/packaging.md](docs/packaging.md) | Install packages + cosign verify |
| [docs/tasks/sevenzip-random-access.md](docs/tasks/sevenzip-random-access.md) | SevenZip backend |
| [docs/tasks/embedded-nested-random-access.md](docs/tasks/embedded-nested-random-access.md) | Nested no-tmp implementation tasks |
| [docs/cold-index-and-sparse.md](docs/cold-index-and-sparse.md) | Index perf + sparse TAR |
| [benchmarks/python-vs-rust-results.md](benchmarks/python-vs-rust-results.md) | Latest head-to-head numbers |
| [benchmarks/README.md](benchmarks/README.md) | How to re-run benches + CI gates |

## License

MIT (aligned with upstream ratarmount intent; see `Cargo.toml` workspace license).

## Related

- Upstream Python: [mxmlnkn/ratarmount](https://github.com/mxmlnkn/ratarmount)
- This fork’s releases: [hilather/ratarmount-rs releases](https://github.com/hilather/ratarmount-rs/releases)
- SevenZip random-access work: [hilather/ratarmount#1](https://github.com/hilather/ratarmount/pull/1)
