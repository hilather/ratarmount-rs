# ratarmount-rs

Native **Rust** rewrite of [ratarmount](https://github.com/mxmlnkn/ratarmount) — mount archives (and remote objects) as a FUSE filesystem with SQLite indexes for fast random access.

| | |
|--|--|
| **Language** | Rust (edition 2021) |
| **FUSE** | `fuser` low-level (inode API) |
| **Platforms (1.0)** | Linux first |
| **Design** | See [docs/parity-todo.md](docs/parity-todo.md) and the Python-tree design doc `docs/design-rust-rewrite.md` |

## What’s implemented

| Area | Status |
|------|--------|
| TAR (+ GNU/PAX sparse) + ZIP + AR + CPIO | done |
| gzip / bzip2 / xz / zstd | done via **materialize-to-temp** (G3) |
| Custom **SevenZip** pack-offset backend | done (AES + common codecs) |
| libarchive long-tail (CAB/XAR/WARC/ISO/RAR/…) | done (sequential member extract) |
| Recursive automount, union, folder, write overlay | done |
| Remote: `http(s)`, `file`, `s3`, `ssh`/`sftp` | done |
| Daemonize / `-f` / Makefile / phase harness | done |
| Head-to-head benchmarks vs Python | done (`benchmarks/`) |

**Not feature-complete vs Python yet.** Track remaining work in **[docs/parity-todo.md](docs/parity-todo.md)**.

## Parity TODO (summary)

Full checklist: [`docs/parity-todo.md`](docs/parity-todo.md).

### Feature parity — still open (high level)

1. **Seekable compression** — drop materialize for gzip/bzip2/xz/zstd; import/build compression index tables (rapidgzip-class path).  
2. **CLI flag parity** — `--index-folders`, default mountpoint, `-e` encoding, `-o` FUSE opts, `-d`/`--log-file`, `--commit-overlay`, control interface, lazy mount, path transforms, file versions.  
3. **Formats** — SquashFS, EXT4/FAT, SQLAR, ASAR, PDF/OGG/HTML, Git; better RAR; split files (`.001`).  
4. **Codecs** — lz4/lzip/lzo/lrz/Z/zlib; true `-P` parallel decoders.  
5. **Remote** — Range-backed readers (no full download); SMB/WebDAV; remote/compressed indexes.  
6. **Index** — `:memory:`, compression side-table interop with Python, hashes/xattrs.  
7. **Perf** — cold `find` / nested automount; SevenZip progressive solid decode; CI gates from `benchmarks/baselines/rust-gates.json`.  
8. **Packaging** — AppImage/distro; Phase 12 Python deprecation when gates pass.

### Test parity — still open

| Priority | Work |
|----------|------|
| **P0** | Grow phase allowlists to all fixtures for formats we already claim |
| **P0** | Phase-gated wrapper around Python `run-fixed-archive-tests.sh` |
| **P0** | SevenZip scenarios aligned with `test_sevenzip.py` |
| **P1** | Complex-usage subset (union, overlay, multi-source) |
| **P1** | Index interop goldens (Py↔Rust) |
| **P1** | Optional live SSH/S3 CI |
| **P2** | ≥90% fixed-archive triples; clippy/fmt CI; weekly bench gates |

Current harness: ~40 allowlist entries under `test-harness/`. Python: 100+ archives + fixed/complex/remote shells.

## Requirements

- Rust stable (`rustup default stable`)
- `libfuse3` / `fuse3`
- `libarchive` (long-tail formats)
- `zlib` headers (flate2/system zlib)
- Sibling Python checkout for fixtures (default `../ratarmount`) for the harness

## Build / install

```bash
export PATH="$HOME/.cargo/bin:$PATH"
make release
make install          # → ~/.local/bin/ratarmount
# or: cargo install --path ratarmount
```

## Test

```bash
export RATARMOUNT_PY_ROOT="$HOME/projects/ratarmount"   # Python tree with tests/
cargo test --workspace
./test-harness/run-all-phases.sh    # or: make suite
./benchmarks/compare-python-vs-rust.sh   # optional head-to-head
```

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
ratarmount-compress/        # materialize + stencils
ratarmount-formats-{tar,zip,ar,cpio,sevenzip,libarchive}/
ratarmount-compositing/     # folder, union, automount, overlay
ratarmount-remote/          # http/s3/ssh
test-harness/               # phase allowlists + runners
benchmarks/                 # Python vs Rust comparison
docs/                       # decisions, phase notes, parity TODO
```

## Docs

| Doc | Topic |
|-----|--------|
| [docs/parity-todo.md](docs/parity-todo.md) | **Full feature + test parity checklist** |
| [docs/gzip-binding-decision.md](docs/gzip-binding-decision.md) | G3 materialize decision |
| [docs/phase9-formats.md](docs/phase9-formats.md) | Long-tail formats |
| [docs/phase10-remote.md](docs/phase10-remote.md) | Remote URL backends |
| [docs/phase11-packaging.md](docs/phase11-packaging.md) | Packaging notes |
| [docs/tasks/sevenzip-random-access.md](docs/tasks/sevenzip-random-access.md) | SevenZip backend |
| [docs/cold-index-and-sparse.md](docs/cold-index-and-sparse.md) | Index perf + sparse TAR |
| [benchmarks/python-vs-rust-results.md](benchmarks/python-vs-rust-results.md) | Latest head-to-head numbers |

## License

MIT (aligned with upstream ratarmount intent; see `Cargo.toml` workspace license).

## Related

- Upstream Python: [mxmlnkn/ratarmount](https://github.com/mxmlnkn/ratarmount)
- SevenZip random-access work: [hilather/ratarmount#1](https://github.com/hilather/ratarmount/pull/1)
