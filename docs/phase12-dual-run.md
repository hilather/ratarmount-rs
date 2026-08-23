# Phase 12 — Dual-run and Python deprecation timeline

Status: **docs ready for announce / not announced** (updated 2026-07-31).  
**Dual-run has not been published** as a GitHub Release or packaging default yet.
Announce only after cutover gates below are green and residual gaps are accepted by a human maintainer.

Related:

- Living parity matrix: [`docs/parity-todo.md`](parity-todo.md)
- Gap batches / residual queue: [`docs/tasks/gap-implementation-batch.md`](tasks/gap-implementation-batch.md)
- Upstream FRs (readahead done, parallel nested open): [`docs/tasks/upstream-feature-requests.md`](tasks/upstream-feature-requests.md)
- Packaging install paths & release procedure: [`docs/packaging.md`](packaging.md)
- crates.io policy (no publish required for dual-run): [`docs/crates-io-policy.md`](crates-io-policy.md)

---

## Goal

Run **ratarmount-rs** as the primary `ratarmount` binary for supported formats while keeping the Python implementation available as a fallback during a transition period.

Dual-run is a **distribution and UX** phase, not a claim of 100% Python parity. Common TAR / ZIP / 7z / compressed outer codecs and the FUSE allowlist harness are the cutover bar; long-tail formats stay documented residuals.

---

## Current parity snapshot (as of 2026-07-31)

Summarized from [`parity-todo.md`](parity-todo.md) and gap batches 1–13. Prefer those files for line-item truth.

| Area | State | Notes |
|------|--------|--------|
| Core archives | **strong** | TAR (sparse + GNU incremental detect/prefix/dumpdir), ZIP store/deflate + password + multi-part join, custom 7z RA |
| Stencil long-tail | **strong** | AR/CPIO, ISO/WARC/XAR/CAB (LZX→libarchive), ASAR, SQLAR (sqlcipher feature), PDF/OGG/HTML/Git |
| Images | **good** | SquashFS in-process (`backhand` + xz via `xz2`; classic lzma → `unsquashfs`); EXT4 pure + `debugfs`; FAT pure |
| Codecs | **good** | gzip (Tier B + RGZI + best-effort GZIDX), bzip2 maps, xz index/multi-stream, zstd multi-frame + zstdblocks, lz4/lzip/lzo/Z/lzma/zlib |
| lrzip (`.lrz`) | **practical** | detect + `lrzip`/`lrunzip` materialize; **libarchive raw/filter fallback** when CLI missing; no pure in-process decoder |
| RAR / LHA / long-tail | **libarchive only** | sequential member open; no pure RAR backend |
| Compositing / UX | **strong** | union, automount, overlay + commit (common TAR compressions + ZIP rebuild), versions, control socket + in-FS control, lazy/transform/prefix |
| FUSE readahead | **done** | `--readahead` sequential window (FR-5 / upstream #180); not a dual-run residual |
| Nested / no-tmp | **strong** | Factory nested `open_from_reader` paths for common formats; residual path spool for some long-tail |
| Parallel nested index | **done** | FR-6 / upstream #80 — eager AutoMount same-dir fan-out; CLI `--parallel-nested N` (default auto) |
| Remote | **broad** | http(s) Range for TAR/ZIP/gzip/bzip2/xz/zstd; S3/SSH; WebDAV/SMB/Dropbox; remote + compressed index download |
| Index interop | **good** | SQLite 0.7.x; Py↔Rust TAR (+ ZIP/7z); side tables partial for some codec blobs; warm reimport for zstdblocks/bzip2blocks |
| Perf / CI | **gated** | cold-index hard gate + optional full bench; fmt/clippy/test + FUSE allowlist CI |
| Packaging | **shippable** | Makefile install, deb/rpm/portable/macOS tarballs, AppImage scaffold, cosign |

**Not dual-run blockers for common paths:** pure in-process lrzip, pure RAR, PDF Separation/Lab residual, multi-GB solid 7z **BCJ2 / multi-pack** (AES+LZMA2 and native BCJ/Delta+LZMA2 large solids are progressive), full fixed-archive ≥90% allowlist, pure FUSE kernel ABI (deferred).

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

**Cutover is OK without:** pure RAR, pure lrzip, full PDF color spaces, progressive multi-GB solid 7z for every filter stack, SMB CLI-less pure implementation, FR-6 CLI cap flag, or 100% fixed-archive parity.

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

Track detail in [`parity-todo.md`](parity-todo.md), [`tasks/gap-implementation-batch.md`](tasks/gap-implementation-batch.md), and [`tasks/upstream-feature-requests.md`](tasks/upstream-feature-requests.md). Dual-run announce may proceed with these open:

| Residual | Status | Mitigation |
|----------|--------|------------|
| **Pure RAR** (beyond libarchive) | libarchive sequential only | Use Python or accept sequential open |
| **Pure in-process lrzip** | CLI materialize + **libarchive filter fallback** | Install `lrzip`/`lrunzip` and/or libarchive with lrzip; no pure seekable decoder |
| GNU incremental TAR full semantics | detect + prefix strip + dumpdir `D` dual entry | Edge incremental dumps may differ |
| Encrypted ZIP multi-disk / true per-disk offsets | multi-part join + EOCD normalize | `~` vs Python |
| SQLAR sqlcipher | feature-gated optional | Build with feature or use Python |
| SquashFS classic lzma | `unsquashfs` fallback | Install `squashfs-tools` |
| PDF Separation/Lab (and some color spaces) | XObject JPEG/JP2/Flate path strong | Rare documents |
| Progressive multi-GB solid 7z (BCJ2 / multi-pack) | AES+LZMA2 and native BCJ/Delta+LZMA2 large solids are progressive | BCJ2 / multi-pack still full-folder |
| Factory auto-wire zstdblocks/bzip2blocks from index on open | **done** (FR-9) | Warm open imports side tables; skips re-export when map reused |
| Sequential FUSE readahead (`--readahead`) | **done** (FR-5 / #180) | Shipped; not a residual — listed so announce notes do not re-open it |
| **Parallel nested archive indexing** (FR-6 / #80) | **done** (eager AutoMount) | Same-dir fan-out default; CLI/`-P` wire residual only |
| HTTP Range on every format | TAR/ZIP + main codecs | Others materialize |
| Full `--use-backend` / Python backend matrix | probe reorder | Priority list accepted |
| Full fixed-archive ≥90% | allowlist expanding | Track gaps; not cutover-hard |
| Pure `/dev/fuse` ABI (Annex A) | deferred | `fuser` remains product path |
| macOS Homebrew formula / Intel tarball | arm64 first-class (signed tag asset); Homebrew E1 later | See [`macos.md`](macos.md) |
| Cookie HTTP auth (FR-2 residual) | Env Cookie + Basic done | Full browser jar / Set-Cookie residual only |
| Writable/rename on compressed TAR (FR-11) | Python residual too | Use overlay + commit where supported |

---

## Announcement checklist

Honest status: **nothing below is “announced” until a human tags a release and publishes notes.**
Docs can prepare text and mark readiness; ops actions stay open.

| # | Item | Readiness | Owner |
|---|------|-----------|--------|
| 1 | Residual gaps table current in this doc (incl. FR-5 done, FR-6 compositing done) | **docs-ready** `[x]` | docs |
| 2 | Comparison / gaps summary for release notes (paste stub below + parity-todo) | **docs-ready** `[x]` | docs |
| 3 | Install paths documented (binary, portable, deb/rpm, optional AppImage) | **docs-ready** `[x]` | [`packaging.md`](packaging.md) |
| 4 | crates.io not required for dual-run binary ship | **docs-ready** `[x]` | [`crates-io-policy.md`](crates-io-policy.md) |
| 5 | Dual-run model + binary naming (`ratarmount` / `ratarmount-py`) | **docs-ready** `[x]` | this doc |
| 6 | Release notes body stub (operator message) paste-ready | **docs-ready** `[x]` | this doc § below |
| 7 | Tag ratarmount-rs `v0.x` / dual-run section linking this doc | **ops-pending** `[ ]` | maintainer |
| 8 | Push tag + confirm **Packages** workflow assets on GitHub Release | **ops-pending** `[ ]` | maintainer |
| 9 | Confirm FUSE harness + cold-index gate green on the **tag commit** | **ops-pending** `[ ]` | maintainer / CI |
| 10 | Set deprecation date for Python-as-primary (suggested: **+2 releases** after first dual-run tag) | **ops-pending** `[ ]` | maintainer |
| 11 | Update packaging / product README dual-run section when cutover is real | **ops-pending** `[ ]` | maintainer (orchestrator owns large README tables) |
| 12 | Open tracking issues for residual `~` / `[ ]` items that will not ship in the cutover tag | **ops-pending** `[ ]` | maintainer |

Checklist shorthand (same items):

- [x] **docs-ready** — residual table current; comparison + install + crates.io policy; operator message stub
- [ ] **ops-pending** — tag dual-run release with notes linking this doc
- [ ] **ops-pending** — push; Packages workflow assets on the release
- [ ] **ops-pending** — FUSE + cold-index green on tag commit
- [ ] **ops-pending** — set Python-as-primary deprecation date (+2 releases after first dual-run tag)
- [ ] **ops-pending** — product README dual-run cutover wording when announce lands
- [ ] **ops-pending** — tracking issues for accepted residuals

---

## How to announce (maintainer runbook)

Ordered steps for humans. **Do not treat this section as completed work** — no tag or public announce has been made by this docs update alone.

### 0. Preconditions (same day as tag)

1. Main is green: `cargo fmt --all -- --check`, clippy `-D warnings`, `cargo test --workspace`, FUSE allowlist job, cold-index gate (`./benchmarks/check-rust-gates.sh` or CI equivalent).
2. Residual table above still matches parity-todo / FR list (especially: readahead **done**, parallel nested compositing **done** / CLI residual).
3. Decide the first dual-run tag version (workspace version today is independent of “announce ready”; bump per packaging checklist when cutting).

### 1. Version bump and tag

Follow the full packaging procedure — do not invent a second process:

- Root [`AGENTS.md`](../AGENTS.md) § **Releases / package builds**
- [`docs/packaging.md`](packaging.md) § **Agent / maintainer release procedure**
- crates.io: **not required** for dual-run binary distribution — [`docs/crates-io-policy.md`](crates-io-policy.md)

Minimum:

1. Bump workspace `version` in root `Cargo.toml`.
2. Align package workflow `VERSION` (or tag-derived VERSION — follow current `packages.yml` / packaging notes).
3. Update any README version strings that pin the release tag.
4. Commit on `main`, push, then push an **annotated** tag `vX.Y.Z` matching Cargo.

### 2. GitHub Release body

When **Sign & release** / GitHub Release is created (or when editing the release notes for the tag):

1. Paste the **Operator message / release notes stub** below (fill `vX.Y.Z` and deprecation placeholder).
2. Link this file: `docs/phase12-dual-run.md`.
3. Link install docs: `docs/packaging.md`.
4. Optionally link parity: `docs/parity-todo.md` Gaps / residual rows.

Confirm under https://github.com/hilather/ratarmount-rs/releases that the tag has **real package assets** (`.deb` / `.rpm` / portable tarballs), not only tiny sidecars. See packaging known failure modes if assets are empty.

### 3. Deprecation date

1. On the first dual-run tag notes, state: *“Python as primary install name will be deprecated after **N** further releases (target: +2 releases). Exact calendar date: **TBD** when the second post-cutover release ships.”*
2. Record the chosen date (or “after vA.B.C”) in a follow-up edit to this file and in the product README dual-run blurb.
3. Until that date: packages and docs should keep describing `ratarmount-py` / Python as supported fallback.

### 4. Post-tag verification

| Check | Pass criteria |
|-------|----------------|
| CI on tag commit | fmt/clippy/test + FUSE allowlist green |
| Cold-index | hard gate green (or documented waiver) |
| GitHub Release assets | Linux packages present; macOS optional if Linux published |
| Dual-run wording | Release notes say Rust recommended + Python fallback; **do not** claim 100% parity |
| crates.io | No publish required ([`crates-io-policy.md`](crates-io-policy.md)) |

### 5. After announce

1. Flip any “not announced” status lines in this doc to the dual-run tag id and date.
2. Open tracking issues for residuals you explicitly accept (RAR pure, lrzip pure, FR-6, etc.).
3. Orchestrator may add a short README dual-run cutover blurb; large feature tables stay orchestrator-owned.

---

## Exit criteria for Phase 12 complete

1. Dual-run docs published (this file + packaging / crates.io policy); **default install name is Rust** after ops announce.  
2. CI matrix enforces fmt/clippy/test + FUSE harness (and cold-index gate).  
3. Python package marked **maintenance / fallback only** after the stated deprecation date.  
4. Residual gaps above remain explicitly listed so dual-run is not mistaken for full parity.
5. A human has executed the **How to announce** runbook (tag + release notes + asset check) — **docs alone do not complete Phase 12.**

---

## Operator message / release notes stub

Paste into the GitHub Release for the first dual-run tag. Replace placeholders in `«…»`.

### Short (summary blurb)

```text
ratarmount-rs «vX.Y.Z» — dual-run: Rust is the recommended `ratarmount` binary
for Linux and macOS arm64. Keep the Python package as `ratarmount-py` (or
`python -m ratarmount`) for residual formats during the transition.

This is not 100% Python parity. See docs/phase12-dual-run.md for the dual-run
model, residual gaps, and deprecation timeline.
```

### Full release notes body

```text
## Dual-run: Rust primary, Python fallback

**Status:** First dual-run announcement for ratarmount-rs «vX.Y.Z».

### What changed for operators

- Install the Rust binary as `ratarmount` (deb/rpm/portable tarball, `make install`,
  or cargo path install). See docs/packaging.md.
- Keep Python ratarmount available as **`ratarmount-py`** (or `python -m ratarmount`)
  when you need a residual format or behavior not covered by Rust.
- Optional wrapper env (distro scripts only): `RATARMOUNT_IMPL=rust|python`.

### Supported well enough for default use

- TAR (incl. sparse / common GNU incremental paths), ZIP (store/deflate, password,
  multi-part join), custom 7z random access
- Common outer codecs: gzip, bzip2, xz, zstd (incl. multi-frame / block maps)
- Nested / automount paths for common parent×child formats without /tmp spool when
  the seekable reader path succeeds
- FUSE sequential readahead: `--readahead` (shipped; upstream-inspired #180)
- Union, write overlay + commit for common TAR compressions and ZIP rebuild, remote
  Range for main formats

### Known residuals (use Python or accept limits)

- Pure RAR / pure in-process lrzip (libarchive and/or CLI fallbacks only)
- Parallel nested archive indexing (perf; sequential nested index still works)
- Progressive multi-GB solid 7z BCJ2 / multi-pack (AES+LZMA2 and native BCJ/Delta+LZMA2 are progressive; Deflate/BZip2 solids still full-folder)
- Encrypted ZIP true per-disk offset edges; SQLAR without sqlcipher feature
- SquashFS classic lzma via `unsquashfs`; some PDF color spaces
- Full browser HTTP cookie jar (env Cookie MVP shipped); pure `/dev/fuse` ABI (fuser remains the product path)
- Full fixed-archive ≥90% Python triple parity (tracked, not cutover-hard)

Details and mitigations: docs/phase12-dual-run.md
Living matrix: docs/parity-todo.md

### Install sketch

  # Rust (after this release)
  # … install .deb / .rpm / portable tarball → ratarmount on PATH

  # Python fallback (example)
  pip install ratarmount
  # ensure the Python entry point is available as ratarmount-py if the
  # package and Rust binary would otherwise collide on the name `ratarmount`

### Deprecation timeline

- **Python as the primary install name** is still supported during dual-run.
- Target: deprecate Python-as-primary after **+2 releases** following «vX.Y.Z».
- Calendar date: «TBD — set when announce lands / when the +2nd release is cut».
- After that date, docs and packages treat Rust as the only default; Python may
  remain as maintenance-mode fallback for long-tail formats.

### crates.io

Library crates.io publish is **not** required to use this dual-run binary release.
Policy: docs/crates-io-policy.md

### Links

- Dual-run / cutover: docs/phase12-dual-run.md
- Packaging: docs/packaging.md
- Parity: docs/parity-todo.md
```

### One-line chat / social

```text
ratarmount-rs «vX.Y.Z»: Rust is now the recommended `ratarmount`; keep Python as
ratarmount-py for residuals. Dual-run details: docs/phase12-dual-run.md
```
