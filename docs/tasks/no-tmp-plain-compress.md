# Task: No-temp plain compressed files (all supported codecs)

**Goal:** Prefer **seekable decompress** for top-level and nested **plain** compressed payloads (not only `.tar.gz`). Materialize to `/tmp` only for residual path-only backends.

**Canonical docs to update when done:** `docs/embedded-nested-archives.md`, `README.md` (skill `format-support-matrices`).

---

## Why

Today:
- `.tar.gz` / named compressed TAR → seekable body + TAR (no spool of full payload for random open)
- Plain / ambiguous `.gz` (and non-TAR path in `open_from_seekable_body`) → **full materialize** to temp, then path probe / `SingleFileMountSource`

Seekable gzip/zstd/bzip2/xz already support random read. Temp is for path-shaped probe + single-file, not a random-read requirement.

---

## Target architecture

```text
compressed file (path or nested stream)
  → open seekable body (gzip checkpoints / zstd frames / …)
  → peek uncompressed head (Read+Seek on body)
  → if TAR / ZIP / 7z / CPIO / … with open_from_reader → that backend
  → else SingleFileMountSource over seekable body (no /tmp)
  → residual only: path-only backends → materialize or keep
```

---

## Work packages (subagents)

### P0 — Foundation (block others)

| ID | Owner | Task | Status |
|----|--------|------|--------|
| **P0.1** | `ratarmount-formats-tar` | `SingleFileMountSource::from_seekable_body` | **done** |
| **P0.2** | `ratarmount-compress` | `SeekableBody for SharedSeekableGzip` | **done** |

### P1 — Factory top-level codecs (after P0)

| ID | Owner | Task | Status |
|----|--------|------|--------|
| **P1.1** | `factory.rs` `open_gzip` | Always seekable; TAR / formats / single-file; no plain materialize | **done** |
| **P1.2** | `factory.rs` `open_from_seekable_body` | formats probe + single-file over body | **done** |
| **P1.3** | `factory.rs` nested | plain non-TAR compress → single-file, no spool | **done** |

### P2 — Probe helper + residual

| ID | Owner | Task | Status |
|----|--------|------|--------|
| **P2.1** | `factory.rs` | `try_open_formats_from_seekable_body` | **done** |
| **P2.2** | docs | matrices updated | **done** |

### Out of scope / residual (honest)

- SquashFS classic lzma unsquashfs path
- Encrypted SQLAR
- CAB LZX → libarchive
- lrzip CLI materialize when required
- Huge bodies already inside `DecodedBody` temp spill (`DEFAULT_MEMORY_CAP`) — that's codec internal, not nested spool

---

## Acceptance

1. `echo hello | gzip > f.gz` → `ratarmount f.gz mnt` serves file **without** writing full payload under TMPDIR (or only ephemeral codec spill under cap).
2. Secret TAR in `.gz` without `.tar` in name still mounts as TAR (seekable), no permanent spool.
3. Nested `data.gz` (plain) inside store 7z/ZIP opens without nested member temp spool.
4. Existing nested archive tests stay green.
5. Docs matrices updated.

---

## Suggested spawn order

1. Parallel: **P0.1** + **P0.2**
2. Then: **P1.1 + P1.2 + P1.3 + P2.1** (one factory agent or sequential regions)
3. Orchestrator: **P2.2** docs + fmt/clippy/test + push

## Deliverable (every agent)

```text
cargo fmt --all
cargo clippy -p <crate> --all-targets -- -D warnings
cargo test -p <crate>
One commit, do not push.
Docs delta for format-support-matrices if behavior changes.
```
