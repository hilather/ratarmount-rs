# Upstream feature requests (mxmlnkn/ratarmount) → ratarmount-rs

Track [upstream issues](https://github.com/mxmlnkn/ratarmount/issues) that are
closed or open with **usable maintainer notes**, and whether Rust has the
capability. Prefer implementing here when notes are concrete; link the original
issue from the README feature tables.

**Legend:** `done` · `partial` · `todo` · `defer` (design unclear / huge / out of scope)

---

## Implemented in Rust (mark in README with issue link)

| Upstream | Title | Rust status | Notes |
|----------|-------|-------------|--------|
| [#123](https://github.com/mxmlnkn/ratarmount/issues/123) | Add 7z support | **done** | Custom pack-offset + progressive LZMA2; better than libarchive-only |
| [#128](https://github.com/mxmlnkn/ratarmount/issues/128) | Add WARC support | **done** | Stencil `WarcMountSource` + nested `open_from_reader` |
| [#126](https://github.com/mxmlnkn/ratarmount/issues/126) | Add lzip support | **done** | Seekable lzip body in `ratarmount-compress` |
| [#176](https://github.com/mxmlnkn/ratarmount/issues/176) | Create index only, do not mount | **done** | `--no-mount` |
| [#151](https://github.com/mxmlnkn/ratarmount/issues/151) | Mount compression layer only | **done** / **partial** | Plain compress + `--recursion-depth`; no separate “undo TAR” flag beyond depth 0 |
| [#109](https://github.com/mxmlnkn/ratarmount/issues/109) | Support more formats | **done** / **partial** | Broad matrix; RAR/LHA still libarchive sequential |
| [#145](https://github.com/mxmlnkn/ratarmount/issues/145) | xattrs in TAR | **done** | Content-hash xattrs (`--hashes`) + TAR PAX `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*` → index + FUSE (vendor MPE/ZOS pax keys not mapped) |
| [#100](https://github.com/mxmlnkn/ratarmount/issues/100) | Use pread | **done** | FUSE low-level read path is offset-based (pread-style) |
| [#79](https://github.com/mxmlnkn/ratarmount/issues/79) | Metadata for recursive compressed TARs in outer index | **partial** | `nestedTarMembers` / flatten paths; not full Python dual-index |
| [#95](https://github.com/mxmlnkn/ratarmount/issues/95) | Indexes from un-seekable fileobj | **partial** | Materialize/spool path for some inputs; true non-seek still limited |
| [#196](https://github.com/mxmlnkn/ratarmount/issues/196) | Multi-frame / chunked zstd examples | **done** | User guide: [`docs/zstd-random-access.md`](../zstd-random-access.md) (seek-table → multi-frame → full decode; producer recipes) |
| [#154](https://github.com/mxmlnkn/ratarmount/issues/154) | ZIP commit-overlay | **done** (MVP) | Full rebuild in `ratarmount-compositing::commit_overlay`; residual encrypted/multi-part |

---

## Implementable correctly (todo list)

Prioritized by maintainer clarity + fit for Rust architecture.

### P0 — clear notes, high user value

| ID | Upstream | Work | Maintainer takeaway | Suggested ownership |
|----|----------|------|---------------------|---------------------|
| FR-1 | [#154](https://github.com/mxmlnkn/ratarmount/issues/154) | **ZIP commit-overlay** | **done** (MVP): full rebuild in `commit_overlay` — raw-copy unchanged store/deflate members; overlay files deflate; atomic replace. Residual: encrypted/multi-part/spanned ZIP, in-place append, jar/war extras | `ratarmount-compositing` |
| FR-2 | [#157](https://github.com/mxmlnkn/ratarmount/issues/157) | **HTTP(S) authentication** | Basic auth via URL / headers; cookie auth harder | `ratarmount-remote` |
| FR-3 | [#145](https://github.com/mxmlnkn/ratarmount/issues/145) | **TAR PAX `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*`** | **done** — index + `list_xattr`/`get_xattr`; skip vendor MPE/ZOS pax keys | `formats-tar` (fuse already serves index xattrs) |
| FR-4 | [#105](https://github.com/mxmlnkn/ratarmount/issues/105) | **Parallel inflate of large ZIP deflate members** | Multi-threaded access to encrypted zip discussed separately; plain deflate parallel open is in scope | `formats-zip` |

### P1 — good notes, medium design

| ID | Upstream | Work | Maintainer takeaway | Suggested ownership |
|----|----------|------|---------------------|---------------------|
| FR-5 | [#180](https://github.com/mxmlnkn/ratarmount/issues/180) | **Readahead-like option** | Performance for sequential scans | `ratarmount-fuse` + open buffering |
| FR-6 | [#80](https://github.com/mxmlnkn/ratarmount/issues/80) | **Parallel index nested archives** | Nested index work can fan out | factory / automount / index |
| FR-7 | [#196](https://github.com/mxmlnkn/ratarmount/issues/196) | **Document multi-frame / chunked zstd** | **done** — [`docs/zstd-random-access.md`](../zstd-random-access.md) | docs |
| FR-8 | Python residual | **CAB LZX nested no-tmp residual** | Use libarchive path; document | formats-cab / factory |
| FR-9 | Python residual | **Factory auto-wire zstdblocks/bzip2blocks on open** | APIs exist; wire factory fully | `ratarmount/src/factory.rs` |

### P2 — design-heavy or partial acceptance

| ID | Upstream | Work | Why deferred / hard |
|----|----------|------|---------------------|
| FR-10 | [#160](https://github.com/mxmlnkn/ratarmount/issues/160) / [#164](https://github.com/mxmlnkn/ratarmount/issues/164) | Union **symlink resolve** option | Maintainer still refining semantics; needs design flag |
| FR-11 | [#120](https://github.com/mxmlnkn/ratarmount/issues/120) | Writable/rename on compressed TAR | Explicit Python TODO; rename is hard |
| FR-12 | [#118](https://github.com/mxmlnkn/ratarmount/issues/118) | Multi-volume `tar -M` | Multi-device volume TAR |
| FR-13 | [#175](https://github.com/mxmlnkn/ratarmount/issues/175) | LD_PRELOAD / syscall wrap FS | Not FUSE; library path exists; out of product scope for now |
| FR-14 | [#192](https://github.com/mxmlnkn/ratarmount/issues/192) | SQL-free lightweight index | Competing index format; large design |
| FR-15 | Pure RAR / pure lrzip | Beyond libarchive/CLI | Accepted dual-run residual |

---

## Suggested implementation order (agents)

**Done:** FR-1 (ZIP commit-overlay MVP), FR-3 (TAR PAX xattrs), FR-7 (zstd multi-frame docs).

1. **FR-2** HTTP basic auth (`user:pass@` / `Authorization` header)  
2. **FR-4** Parallel ZIP deflate member decode  
3. **FR-5** FUSE readahead knobs  
4. **FR-9** Factory side-table auto-wire  

Update this file when status changes. Keep README **Upstream** column in sync.
