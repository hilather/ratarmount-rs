# Phase 11 — productization, perf gates, packaging

## Test suite

```bash
export RATARMOUNT_PY_ROOT=../ratarmount   # or absolute path
cargo build --release
./test-harness/run-all-phases.sh
# or: make suite
```

Phase 11 also records loose performance smoke numbers under  
`test-harness/bench-results/smoke-*.json` (correctness is hard-fail; timings warn only).

## Install

```bash
make install
# → ~/.local/bin/ratarmount
```

Or:

```bash
cargo install --path ratarmount
```

## CLI behavior (Phase 11)

| Flag | Behavior |
|------|----------|
| (default) | **Daemonize**: child runs FUSE; parent waits until mount is ready, then exits 0 |
| `-f` / `--foreground` | Stay attached (required for many harnesses) |
| `-u` | Unmount |
| `-w` | Write overlay |
| `-r` | Recursive automount |
| URLs | `http(s)://`, `file://` |

## Pure FUSE kernel ABI

Deferred. Production path remains **`fuser` low-level** (inode API).  
A pure `/dev/fuse` implementation is optional future work (design Annex A); not required for 1.0-class MVP.

## AppImage / distro packages

Scaffold: `packaging/build-appimage.sh` (stages AppDir; runs `linuxdeploy` when installed).

```bash
./packaging/build-appimage.sh
# → dist/AppDir and optionally dist/*.AppImage
```

Short term without AppImage:

1. `cargo build --release` on target glibc
2. Ship binary + dynamic deps (`libfuse3`, `libarchive`, compression libs as linked)
3. Optional helpers: `e2fsprogs` (EXT4), `squashfs-tools` (SquashFS)
4. Or static-friendlier builds later with musl (FUSE still needs libfuse at runtime typically)

See `docs/packaging.md`.

## Release checklist

- [ ] `cargo test --workspace`
- [ ] `./test-harness/run-all-phases.sh` green
- [ ] Review `bench-results/smoke-*.json` for huge regressions
- [ ] Tag version in workspace `Cargo.toml`
- [ ] Update README phase table
- [ ] (Optional) publish crates.io libraries separately from the binary
