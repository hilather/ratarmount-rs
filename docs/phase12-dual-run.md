# Phase 12 — Dual-run and Python deprecation timeline

Status: **docs complete / not announced** (2026-07-28).  
Announce only after cutover gates below are green and residual gaps are accepted.

Related:

- Living parity matrix: [`docs/parity-todo.md`](parity-todo.md)
- Gap batches / residual queue: [`docs/tasks/gap-implementation-batch.md`](tasks/gap-implementation-batch.md)
- Packaging install paths: [`docs/packaging.md`](packaging.md)
- crates.io policy: [`docs/crates-io-policy.md`](crates-io-policy.md)

---

## Goal

Run **ratarmount-rs** as the primary `ratarmount` binary for supported formats while keeping the Python implementation available as a fallback during a transition period.

Dual-run is a **distribution and UX** phase, not a claim of 100% Python parity. Common TAR / ZIP / 7z / compressed outer codecs and the FUSE allowlist harness are the cutover bar; long-tail formats stay documented residuals.

---

## Current parity snapshot (as of dual-run docs)

Summarized from [`parity-todo.md`](parity-todo.md) and gap batches 1–12. Prefer those files for line-item truth.

| Area | State | Notes |
|------|--------|--------|
| Core archives | **strong** | TAR (sparse + GNU incremental detect/prefix/dumpdir), ZIP store/deflate + password + multi-part join, custom 7z RA |
| Stencil long-tail | **strong** | AR/CPIO, ISO/WARC/XAR/CAB (LZX→libarchive), ASAR, SQLAR (sqlcipher feature), PDF/OGG/HTML/Git |
| Images | **good** | SquashFS in-process (`backhand` + xz via `xz2`; classic lzma → `unsquashfs`); EXT4 pure + `debugfs`; FAT pure |
| Codecs | **good** | gzip (Tier B + RGZI + best-effort GZIDX), bzip2 maps, xz index/multi-stream, zstd multi-frame + zstdblocks, lz4/lzip/lzo/Z/lzma/zlib |
| lrzip (`.lrz`) | **practical** | detect + `lrzip`/`lrunzip` materialize; **libarchive raw/filter fallback** when CLI missing; no pure in-process decoder |
| RAR / LHA / long-tail | **libarchive only** | sequential member open; no pure RAR backend |
| Compositing / UX | **strong** | union, automount, overlay + commit (common TAR compressions), versions, control socket + in-FS control, lazy/transform/prefix |
| Remote | **broad** | http(s) Range for TAR/ZIP/gzip/bzip2/xz/zstd; S3/SSH; WebDAV/SMB/Dropbox; remote + compressed index download |
| Index interop | **good** | SQLite 0.7.x; Py↔Rust TAR (+ ZIP/7z); side tables partial for some codec blobs |
| Perf / CI | **gated** | cold-index hard gate + optional full bench; fmt/clippy/test + FUSE allowlist CI |
| Packaging | **shippable** | Makefile install, deb/rpm/portable/macOS tarballs, AppImage scaffold, cosign |

**Not dual-run blockers for common paths:** pure in-process lrzip, pure RAR, PDF Separation/Lab residual, multi-GB solid 7z without full folder unpack for BCJ/AES, full fixed-archive ≥90% allowlist, pure FUSE kernel ABI (deferred).

---

## Gates before primary cutover

Realistic criteria for declaring Rust the **default** install name `ratarmount` (Python demoted to fallback).

| Gate | Criteria | How to check |
|------|----------|--------------|
| Format / codec smoke | Core matrix green: TAR/ZIP/7z/AR/CPIO/ISO/WARC/XAR/CAB/ASAR/SQLAR/SquashFS/EXT4/FAT + gz/bz2/xz/zstd/lz4/… | `./test-harness/run-all-phases.sh` with `RATARMOUNT_PY_ROOT` fixtures |
| Fixed-archive subset | Documented allowlist green; full ≥90% of Python triples tracked, not required for dual-run announce | `RUN=1 ./test-harness/run-fixed-archive-subset.sh`; gaps → `docs/parity-gaps.md` if present |
| Index interop | Py→Rust and Rust→Py for TAR; ZIP/7z where harness covers | `./test-harness/run-index-interop.sh` |
| FUSE CI | fmt/clippy/test + FUSE allowlist job green on main | `.github/workflows/ci.yml` |
| Perf (soft) | Cold index hard gate from `benchmarks/baselines/rust-gates.json`; optional full find geo-mean not worse than Python by >20% on agreed fixtures | `./benchmarks/check-rust-gates.sh`; optional `RUN_FULL_BENCH=1` |
| Packaging | Documented install: `make install`, portable tarball, and/or distro package | [`docs/packaging.md`](packaging.md) |
| Residual acceptance | Residual gaps listed below accepted in release notes / dual-run README | This doc + parity-todo `~` / `[ ]` rows |

**Cutover is OK without:** pure RAR, pure lrzip, full PDF color spaces, progressive multi-GB solid 7z for every filter stack, SMB CLI-less pure implementation, or 100% fixed-archive parity.

---

## Dual-run model

### Binary naming

During transition, ship **two** command names so operators can pin either implementation:

| Name | Implementation | Role |
|------|----------------|------|
| `ratarmount` | **Rust** (`ratarmount-rs` release binary) | New default after cutover |
| `ratarmount-py` | **Python** entry point (`python -m ratarmount` or renamed console script) | Fallback for residual gaps |

Rationale:

- Same CLI surface for common flags (`-f`, `-r`, `-w`, `-c`, index options).
- Scripts can pin `ratarmount-py` when they hit a residual gap without uninstalling Rust.
- Distro packages should not silently remove the Python package until deprecation date.

### Environment switch (optional operator control)

For wrappers that install a single path name but want runtime selection:

```bash
# Prefer explicit binaries when both are on PATH:
ratarmount …        # Rust (after cutover)
ratarmount-py …     # Python fallback

# Optional wrapper pattern (not required in the Rust binary itself):
# RATARMOUNT_IMPL=python|rust
#   python → exec ratarmount-py / python -m ratarmount
#   rust   → exec ratarmount-rs binary (default)
export RATARMOUNT_IMPL=rust
```

The Rust binary does **not** need to re-exec Python. The switch lives in a thin distro/wrapper script if both stacks are installed. Documented values:

| `RATARMOUNT_IMPL` | Behavior |
|-------------------|----------|
| unset / `rust` | Use Rust binary |
| `python` / `py` | Use Python entry point |

Harness and CI should set `RATARMOUNT_CMD` to the binary under test rather than relying on the wrapper.

### Install sketch

1. Install Rust binary to `~/.local/bin/ratarmount` (or system path via `.deb` / `.rpm` / portable tarball).  
   See [`docs/packaging.md`](packaging.md).
2. Keep Python package installed; expose `ratarmount-py` and/or `python -m ratarmount`.
3. Point release notes at residual gaps (table below) and this doc.
4. After deprecation date: default docs and packages drop Python-as-primary; Python may remain for edge formats indefinitely as maintenance mode.

```bash
# Developer dual-run on one machine
make release && make install          # Rust → ~/.local/bin/ratarmount
# Python (upstream tree or PyPI):
#   pip install ratarmount
#   ln -s "$(which ratarmount)" ~/.local/bin/ratarmount-py   # if pip overwrote name
```

---

## Residual known gaps (not blocking dual-run for common paths)

Track detail in [`parity-todo.md`](parity-todo.md) and [`tasks/gap-implementation-batch.md`](tasks/gap-implementation-batch.md). Dual-run announce may proceed with these open:

| Residual | Status | Mitigation |
|----------|--------|------------|
| **Pure RAR** (beyond libarchive) | libarchive sequential only | Use Python or accept sequential open |
| **Pure in-process lrzip** | CLI materialize + **libarchive filter fallback** | Install `lrzip`/`lrunzip` and/or libarchive with lrzip; no pure seekable decoder |
| GNU incremental TAR full semantics | detect + prefix strip + dumpdir `D` dual entry | Edge incremental dumps may differ |
| Encrypted ZIP multi-disk / true per-disk offsets | multi-part join + EOCD normalize | `~` vs Python |
| SQLAR sqlcipher | feature-gated optional | Build with feature or use Python |
| SquashFS classic lzma | `unsquashfs` fallback | Install `squashfs-tools` |
| PDF Separation/Lab (and some color spaces) | XObject JPEG/JP2/Flate path strong | Rare documents |
| Progressive multi-GB solid 7z (BCJ/AES full-folder) | progressive LZMA2 + LRU windows | Large exotic solids may use more RAM/time |
| Factory auto-wire zstdblocks/bzip2blocks from index on open | **done** | Warm open imports side tables; skips re-export when map reused |
| HTTP Range on every format | TAR/ZIP + main codecs | Others materialize |
| Full `--use-backend` / Python backend matrix | probe reorder | Priority list accepted |
| Full fixed-archive ≥90% | allowlist expanding | Track gaps; not cutover-hard |
| Pure `/dev/fuse` ABI (Annex A) | deferred | `fuser` remains product path |
| macOS harness depth / Homebrew formula | beta tarballs + CI | See [`macos.md`](macos.md) |

---

## Announcement checklist

- [ ] Publish comparison table from [`docs/parity-todo.md`](parity-todo.md) (or README gaps section) in release notes
- [ ] Tag ratarmount-rs `v0.x` / `v1.0-rc` with dual-run section linking this doc
- [ ] Update upstream / packaging README dual-run section (Rust default, `ratarmount-py` fallback)
- [ ] Set deprecation date for Python-as-primary (suggested: **+2 releases** after first dual-run tag)
- [ ] Open tracking issues for residual `~` / `[ ]` items that will not ship in the cutover tag
- [ ] Confirm FUSE harness + cold-index gate green on the tag commit
- [ ] Document install paths (binary, portable, deb/rpm, optional AppImage)

---

## Exit criteria for Phase 12 complete

1. Dual-run docs published (this file + packaging / crates.io policy); **default install name is Rust**.  
2. CI matrix enforces fmt/clippy/test + FUSE harness (and cold-index gate).  
3. Python package marked **maintenance / fallback only** after the stated deprecation date.  
4. Residual gaps above remain explicitly listed so dual-run is not mistaken for full parity.

---

## Suggested operator message (release notes stub)

```text
ratarmount-rs is now the recommended `ratarmount` binary for Linux (and beta macOS).
Keep the Python package as `ratarmount-py` during the transition for residual formats
(e.g. pure RAR edge cases, pure lrzip without CLI/libarchive). See docs/phase12-dual-run.md.
```
