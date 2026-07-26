# Phase 12 — Dual-run and Python deprecation timeline

Status: **scaffolded** (2026-07-26). Announce only after remaining gates below are green.

## Goal

Run **ratarmount-rs** as the primary `ratarmount` binary for supported formats while keeping Python available as a fallback during a transition period.

## Gates before primary cutover

| Gate | Criteria |
|------|----------|
| Format parity | Core archive + codec matrix green on harness (TAR/ZIP/7z/AR/CPIO/ISO/WARC/XAR/CAB/ASAR/SQLAR/SquashFS/EXT4/FAT + gz/bz2/xz/zstd/lz4/…) |
| Fixed-archive allowlist | ≥90% of Python fixed-archive triples (track gaps in `docs/parity-gaps.md`) |
| Index interop | Py→Rust and Rust→Py for TAR (+ ZIP/7z where applicable) |
| FUSE smoke | `test-harness/run-all-phases.sh` green on CI with fixtures checkout |
| Perf | Optional: cold `find` geo-mean not worse than Python by >20% on agreed fixtures (`benchmarks/baselines/rust-gates.json`) |
| Packaging | Release binary or AppImage install path documented |

## Dual-run model (suggested)

```bash
# Ship both names during transition
ratarmount      # → Rust binary (new default)
ratarmount-py   # → Python entry point (fallback)

# Or env switch during dual-run:
# RATARMOUNT_IMPL=python|rust
```

### Install sketch

1. Install Rust binary to `~/.local/bin/ratarmount` (or system path).
2. Keep Python package as `ratarmount-py` / `python -m ratarmount`.
3. Document known gaps (encrypted ZIP multi-disk, pure SquashFS/EXT4, full PDF image extract, lrzip, …).

## Announcement checklist

- [ ] Publish comparison table from `docs/parity-todo.md`
- [ ] Tag ratarmount-rs `v0.x` / `v1.0-rc`
- [ ] Update upstream README dual-run section (Python tree)
- [ ] Set deprecation date for Python-as-primary (e.g. +2 releases)
- [ ] Open tracking issues for residual `~` / `[ ]` items

## Residual known gaps (not blocking dual-run for common paths)

- GNU incremental TAR full semantics  
- Encrypted ZIP multi-disk  
- In-process SquashFS / EXT4 (helpers still OK)  
- SQLAR sqlcipher  
- PDF page images (attachments only today)  
- Progressive multi-GB solid 7z without full unpack buffer  
- HTTP Range-backed readers  
- `--hashes` index xattrs, full `--use-backend` matrix  
- SMB / WebDAV / remote index download  

## Exit criteria for Phase 12 complete

1. Dual-run docs published; default install is Rust.  
2. CI matrix enforces fmt/clippy/test + optional FUSE harness.  
3. Python package marked maintenance / fallback only.
