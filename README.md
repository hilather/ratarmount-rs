# ratarmount-rs

Native **Rust** rewrite of [ratarmount](https://github.com/mxmlnkn/ratarmount) — mount archives (and remote objects) as a FUSE filesystem with SQLite indexes for fast random access.

| | |
|--|--|
| **Language** | Rust (edition 2021) |
| **FUSE** | `fuser` low-level (inode API) |
| **Platforms** | Linux (primary) · **macOS** (beta: arm64 + x86_64 tarballs) |
| **Upstream** | Feature parity tracked vs [mxmlnkn/ratarmount](https://github.com/mxmlnkn/ratarmount) |
| **Living checklist** | [docs/parity-todo.md](docs/parity-todo.md) · [docs/mount-options-parity.md](docs/mount-options-parity.md) |
| **Dual-run / crates.io** | [docs/phase12-dual-run.md](docs/phase12-dual-run.md) · [docs/crates-io-policy.md](docs/crates-io-policy.md) |

```bash
make release && make install   # → ~/.local/bin/ratarmount
ratarmount archive.tar.gz mnt/
```

---

## Python vs Rust — at a glance

| Dimension | Python (`mxmlnkn/ratarmount`) | Rust (`ratarmount-rs`) |
|-----------|------------------------------|------------------------|
| **Runtime** | CPython + native codec libs | Single static-friendly binary |
| **FUSE** | mfusepy (fusepy fork) | `fuser` low-level |
| **Index** | SQLite 0.7.x | Same schema (TAR/ZIP/7z interop) |
| **Memory (mount)** | ~110–350 MiB typical | **~13–20 MiB** peak RSS (~7–9× lower geo-mean) |
| **Cold mount (geo-mean)** | baseline | **~4.5× faster** |
| **Random access / find** | Strong on some nested/ZIP shapes | Geo-mean: cold random ~1.3× Rust; warm random slightly Python; `find` ~1.2× Rust |
| **Remote** | Broad fsspec (SMB, Dropbox, …) | `http(s)`, `file`, `s3`, `ssh`/`sftp` |
| **Write overlay** | Full + commit | Full + commit (uncompressed TAR) |
| **Maturity** | Production / PyPI / AppImage | Feature-rich beta; packaging CI landing |

Rust is not a drop-in replacement for every Python workflow yet (see [gaps](#gaps-vs-python-ratarmount)), but for common TAR/ZIP/7z mounts it is substantially leaner and usually faster to mount.

---

## Features (parity with original ratarmount)

### Archives & images

| Format | Python | Rust | Notes |
|--------|:------:|:----:|-------|
| TAR (ustar / PAX / GNU) + sparse | yes | yes | GNU incremental: detect only in Rust |
| ZIP (store / deflate, password) | yes | yes | Multi-disk / full crypto still limited |
| 7z custom pack-offset + AES / BCJ2 | yes* | yes | *fork improvements; solid multi-GB progressive still open |
| AR / CPIO | yes | yes | |
| ISO 9660 / WARC / XAR / CAB / ASAR | yes | yes | CAB LZX → libarchive fallback |
| SquashFS | yes | MVP | Rust: `unsquashfs` materialize |
| EXT4 | yes | MVP | Rust: `debugfs rdump` |
| FAT12/16/32 | yes | yes | Pure Rust (`fatfs`) |
| SQLAR | yes | yes | Unencrypted; sqlcipher later |
| PDF / OGG / HTML / Git | yes | yes | PDF images deferred; Git needs `RATARMOUNT_FORCE_GIT=1` for some trees |
| RAR / LHA / long-tail | yes | yes | via libarchive (sequential member open) |
| Split files (`.001`) | yes | yes | decimal/hex/alpha join at open |
| lrzip | yes | yes | CLI materialize + libarchive fallback; pure in-process open |

### Compression (outer / seekable)

| Codec | Python | Rust | Notes |
|-------|:------:|:----:|-------|
| gzip | yes (rapidgzip / seek points) | yes | TAR path seekable; plain `.gz` may materialize |
| bzip2 | yes (block-parallel) | yes | Tier B lite (not true bit-block map / `-P`) |
| xz | yes (multi-block) | yes | Tier B lite (not full stream index) |
| zstd | yes (seek table) | yes | Multi-frame map; seek-table import open |
| lz4 / lzip / lzo / .Z / lzma / zlib | yes | yes | Seekable in both |

### Compositing & mount UX

| Ability | Python | Rust |
|---------|:------:|:----:|
| Recursive automount (`-r`) | yes | yes |
| Lazy mount (`-l`) | yes | yes |
| Union of multiple sources | yes | yes |
| Write overlay (`-w` / `:temp:`) | yes | yes |
| `--commit-overlay` | yes | uncompressed TAR (+ GNU tar) |
| File versions (`.versions/`) | yes | yes |
| Strip / transform recursive paths | yes | yes |
| Prefix (`-p`) | yes | yes |
| Control interface | in-FS folder | Unix socket |
| Daemonize / foreground (`-f`) | yes | yes |
| Password / password-file | yes | yes |

### Remote

| Protocol | Python | Rust |
|----------|:------:|:----:|
| `file://` | yes | yes |
| `http(s)://` | yes | yes (full GET; Range helper only) |
| `s3://` | yes | yes (SigV4 env creds) |
| `ssh://` / `sftp://` | yes | yes |
| SMB / WebDAV / Dropbox / GitHub fsspec | yes | — |

Full option matrix: [`docs/mount-options-parity.md`](docs/mount-options-parity.md).  
Full checklist: [`docs/parity-todo.md`](docs/parity-todo.md).

---

## Gaps vs Python ratarmount

Still missing or partial relative to upstream Python:

1. **Seekable codecs (depth)** — true bzip2 bit-block map + `-P` parallel; xz stream index; zstd seek-table / `zstdblocks` import; gzip Tier C blob import.
2. **Formats** — in-process SquashFS/EXT4 (drop helpers); encrypted SQLAR; GNU incremental TAR semantics; stronger RAR; PDF embedded images.
3. **7z solids** — large pure LZMA2 uses progressive prefix decode (≤4 MiB still full-cached); BCJ/AES folders still full-folder; chunk resume cache unfinished.
4. **Remote breadth** — SMB/WebDAV/Dropbox; HTTP Range-backed format readers (no full download); remote/compressed indexes.
5. **Index extras** — file hashes / xattrs; full compression side-table interop with Python.
6. **CLI polish** — colored logs; in-FS control folder (Rust uses a Unix socket); full `-P backend:n` matrix; OSS attributions depth.
7. **Packaging** — PyPI/AppImage ecosystem is mature for Python; Rust has distro package CI (deb/rpm/portable + cosign, macOS tarballs) and AppImage scaffolding — polish ongoing.
8. **Platforms** — **macOS is beta** (arm64/x86_64 tarballs + CI); requires [macFUSE or FUSE-T](docs/macos.md). Full harness parity and Homebrew formula still open.

---

## Performance vs Python

Head-to-head harness: [`benchmarks/compare-python-vs-rust.sh`](benchmarks/compare-python-vs-rust.sh).  
Full tables: [`benchmarks/python-vs-rust-results.md`](benchmarks/python-vs-rust-results.md).

**Methodology (same as upstream mounting/bandwidth style):**

- **Cold mount**: recreate index (`-c`) until FUSE is usable  
- **Warm mount**: reuse SQLite index  
- **Random access**: median of 15 `cat`s on random files  
- **find**: metadata walk wall time  
- **Bandwidth**: sequential `cat` of a large member (MiB/s)  
- Peak RSS from `/proc/<pid>/status` `VmHWM`  
- Both tools run with `-f` for comparable process measurement  

### Geometric-mean summary (2026-07-26 refresh)

From [`benchmarks/python-vs-rust-results.md`](benchmarks/python-vs-rust-results.md).  
Factor **>1 ⇒ Rust better**.

| Metric | Cold | Warm | Interpretation |
|--------|------|------|----------------|
| Mount time | **4.50×** | **4.00×** | Rust mounts much faster |
| Peak RSS | **7.53×** | **8.61×** | Rust ~8× leaner on average |
| Random cat (median) | **1.31×** | **0.89×** | Cold slight Rust edge; warm slight Python |
| find walk | **1.18×** | **1.31×** | Rust ahead on metadata walks overall |
| Seq. bandwidth | **1.59×** | **1.38×** | Rust ahead on sequential read overall |

### Highlight fixtures (this run)

| Archive | What stands out |
|---------|-----------------|
| `empty-1k.tar` | Cold mount **5.53×** faster; RSS ~8× lower; warm `find` **2.20×** faster |
| `large-64m.tar` | Random cat ~**4×** faster; sequential bandwidth **3.9–4.7×** higher (7+ GiB/s) |
| `small-100.tar.gz` | Warm mount **8.14×** faster; warm RSS **26.6×** lower (Python ~350 MiB vs Rust ~13 MiB) |
| `small-100.tar.xz` | Seq. bandwidth **3.6–5.4×** better for Rust on this host |
| `small-100.zip` / nested | More mixed — Python can win random cat / bandwidth on some shapes |

**Caveats**

- Single-host, single-run wall times — directional, not publication-grade.  
- Compressed TAR uses seekable outer codecs in Rust (`SeekableBody` / multi-frame maps); plain single-file `.gz` etc. may still materialize. Python may use rapidgzip / block-parallel paths.  
- Re-run anytime:

```bash
export RATARMOUNT_PY_ROOT=../ratarmount
./benchmarks/compare-python-vs-rust.sh
```

---

## Requirements

**Linux**

- Rust stable (`rustup default stable`)
- `libfuse3` / `fuse3`
- `libarchive` (long-tail formats)
- `zlib` headers (flate2/system zlib)
- Optional: `e2fsprogs` (`debugfs`) for EXT4, `squashfs-tools` for SquashFS
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

**Packages:** GitHub Actions builds Linux `.deb` / Rocky `.rpm` / portable glibc 2.31 tarballs **and macOS arm64/x86_64 tarballs**, with cosign keyless signatures. See [`docs/packaging.md`](docs/packaging.md) and [`docs/macos.md`](docs/macos.md).

## Test

```bash
export RATARMOUNT_PY_ROOT="$HOME/projects/ratarmount"   # Python tree with tests/
cargo test --workspace
./test-harness/run-all-phases.sh    # or: make suite
./benchmarks/compare-python-vs-rust.sh   # optional head-to-head
```

CI (`.github/workflows/ci.yml`): `cargo fmt`, `clippy -D warnings`, `cargo test`, plus FUSE phase allowlists against upstream fixtures.

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
ratarmount-remote/          # http/s3/ssh
test-harness/               # phase allowlists + runners
packaging/                  # desktop entry + AppImage / nfpm
benchmarks/                 # Python vs Rust comparison
docs/                       # decisions, phase notes, parity TODO
```

## Docs

| Doc | Topic |
|-----|--------|
| [docs/parity-todo.md](docs/parity-todo.md) | **Full feature + test parity checklist** |
| [docs/mount-options-parity.md](docs/mount-options-parity.md) | CLI / mount-ability matrix |
| [docs/gzip-binding-decision.md](docs/gzip-binding-decision.md) | G3 materialize decision |
| [docs/phase9-formats.md](docs/phase9-formats.md) | Long-tail formats |
| [docs/phase10-remote.md](docs/phase10-remote.md) | Remote URL backends |
| [docs/phase11-packaging.md](docs/phase11-packaging.md) | Packaging notes |
| [docs/packaging.md](docs/packaging.md) | Install packages + cosign verify |
| [docs/tasks/sevenzip-random-access.md](docs/tasks/sevenzip-random-access.md) | SevenZip backend |
| [docs/cold-index-and-sparse.md](docs/cold-index-and-sparse.md) | Index perf + sparse TAR |
| [benchmarks/python-vs-rust-results.md](benchmarks/python-vs-rust-results.md) | Latest head-to-head numbers |

## License

MIT (aligned with upstream ratarmount intent; see `Cargo.toml` workspace license).

## Related

- Upstream Python: [mxmlnkn/ratarmount](https://github.com/mxmlnkn/ratarmount)
- SevenZip random-access work: [hilather/ratarmount#1](https://github.com/hilather/ratarmount/pull/1)
