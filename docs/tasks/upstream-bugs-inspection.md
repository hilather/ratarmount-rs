# Upstream bugs (mxmlnkn/ratarmount) — inspection queue for ratarmount-rs

Source: open + closed **bug-labeled** and bug-shaped reports on
[mxmlnkn/ratarmount](https://github.com/mxmlnkn/ratarmount/issues).  
Goal: decide whether each issue can still reproduce on **ratarmount-rs**, and
file a fix or mark **N/A**.

**Legend**

| Rust status (preliminary) | Meaning |
|---------------------------|---------|
| **inspect** | Not verified; may still affect us |
| **likely OK** | We claim coverage / different architecture; still smoke if cheap |
| **partial** | Related residual already tracked in parity docs |
| **N/A** | Python/GUI/AppImage-only or not in our product surface |

Upstream has **no open issues with label `bug`** as of 2026-07-28. Below mixes
open **unlabeled** bug-shaped reports and **closed** bugs worth a regression pass.

---

## Priority inspection list

### P0 — open reports that look like real correctness / UX bugs

| ID | Upstream | Summary | Why inspect | Preliminary Rust read |
|----|----------|---------|-------------|------------------------|
| **B-1** | [#185](https://github.com/mxmlnkn/ratarmount/issues/185) | Recursive mount of **`.tzst`** fails | Nested `.tar.zst` / `.tzst` is a core path; maintainer noted recursive extension / HTML false positives | **inspect** — we open `.tar.zst` + recursive AutoMount; verify `.tzst` extension and nested HTML not over-mounted |
| **B-2** | [#179](https://github.com/mxmlnkn/ratarmount/issues/179) | Recursive mount **RAM/time** explosion (`.deb` with nested `.tar.zst` + huge trees) | Resource blow-up under `-r` is a real product risk | **partial** — no-tmp nested helps, but deep AR+zst+bz2 stacks can still cost; measure on same `linux-source-*.deb` style fixture |
| **B-3** | [#177](https://github.com/mxmlnkn/ratarmount/issues/177) | **7z index always `:memory:`** / not persisted | Users expect `--index-file` for 7z | **inspect** — Rust 7z uses SQLite; confirm path vs memory defaults and small-file index policy |
| **B-4** | [#164](https://github.com/mxmlnkn/ratarmount/issues/164) | **Inconsistent symlink handling** in union mounts | Concrete repro script; overlaps [#160](https://github.com/mxmlnkn/ratarmount/issues/160) | **inspect** — run their bash script against Rust union mount; document actual behavior |
| **B-5** | [#195](https://github.com/mxmlnkn/ratarmount/issues/195) | **Non-UTF-8 / invalid UTF-8 filenames** rejected or mangled | TAR stores raw bytes; Python warns and substitutes | **inspect** — we use `encoding_rs` / UTF-8 path; confirm surrogate / latin1 archives with `-e` |
| **B-6** | [#184](https://github.com/mxmlnkn/ratarmount/issues/184) | Mount layout vs **rar2fs** (contents not “beside” archive) | Workflow/symlink expectations | **N/A / design** — mount-point semantics differ by design; optional doc only |

### P1 — closed upstream bugs that are easy regressions for us

| ID | Upstream | Summary | Inspection action | Preliminary Rust read |
|----|----------|---------|-------------------|------------------------|
| **B-7** | [#96](https://github.com/mxmlnkn/ratarmount/issues/96) | ZIP members with **`../`** in paths missing / wrong place | Build zip with `foo/bar/../file`; list/read after normpath | **inspect** — do we normalize ZIP paths like Python fix? |
| **B-8** | [#156](https://github.com/mxmlnkn/ratarmount/issues/156) | Sparse TAR + large holes **> 8 GiB** incomplete index | Sparse map + large offset fixture if feasible | **partial** — sparse claimed; large-hole edge untested |
| **B-9** | [#23](https://github.com/mxmlnkn/ratarmount/issues/23) | GNU/PAX **sparse** wrong size/data | `sample1.tar.gz` / phase2 sparse allowlist | **likely OK** — harness covers sparse; re-run sample fixture |
| **B-10** | [#73](https://github.com/mxmlnkn/ratarmount/issues/73) | GNU **incremental** TAR errors / empty snapshots | Mount level-0 incremental; union with level-1 | **partial** — detect/prefix/dumpdir; no `.snar` delete semantics |
| **B-11** | [#158](https://github.com/mxmlnkn/ratarmount/issues/158) | **lz4** TAR loses modes (was libarchive path) | `tar \| lz4` + `ls -l` modes | **inspect** — we have seekable lz4; confirm mode bits |
| **B-12** | [#148](https://github.com/mxmlnkn/ratarmount/issues/148) | SquashFS **write bits** wrong under RO mount | `ls -l` vs loop mount | **inspect** — FUSE mode masking / RO flags |
| **B-13** | [#165](https://github.com/mxmlnkn/ratarmount/issues/165) | **`du` / st_blocks** inconsistency | `stat` + `du` on sparse and normal files | **inspect** — our FUSE sets `blocks: size.div_ceil(512)` + `blksize: 256KiB`; may still confuse `du` |
| **B-14** | [#90](https://github.com/mxmlnkn/ratarmount/issues/90) / [#133](https://github.com/mxmlnkn/ratarmount/issues/133) / [#134](https://github.com/mxmlnkn/ratarmount/issues/134) | Overlay **update/delete** / rmdir ENOTEMPTY | Overlay + commit TAR with `./` paths and deletes | **partial** — overlay fixed size-0 read; commit delete list needs repro |
| **B-15** | [#174](https://github.com/mxmlnkn/ratarmount/issues/174) | Index fails after archive **moved to S3** | Index with local path then open `s3://` | **inspect** — index path independence / absolute paths in metadata |

### P2 — closed / niche / low urgency

| ID | Upstream | Summary | Note |
|----|----------|---------|------|
| **B-16** | [#34](https://github.com/mxmlnkn/ratarmount/issues/34) | Incomplete / truncated `.tar.gz` | Progressive download; edge case |
| **B-17** | [#21](https://github.com/mxmlnkn/ratarmount/issues/21) | Missing `gzipindex` table | Old schema; SQLite 0.7.x should be fine |
| **B-18** | [#129](https://github.com/mxmlnkn/ratarmount/issues/129) | Empty mount / FUSE forbidden FS | Host FUSE config; document only |
| **B-19** | [#152](https://github.com/mxmlnkn/ratarmount/issues/152) | Progress % > 100 | Progress UI; we may not have same UI |
| **B-20** | [#189](https://github.com/mxmlnkn/ratarmount/issues/189) | AppImage arg completion | **N/A** (Python AppImage) |
| **B-21** | [#197](https://github.com/mxmlnkn/ratarmount/issues/197) / [#198](https://github.com/mxmlnkn/ratarmount/issues/198) | `--gui` hang / argparse warnings | **N/A** (no GUI in Rust) |
| **B-22** | [#146](https://github.com/mxmlnkn/ratarmount/issues/146) | Python 3.6 index | **N/A** |
| **B-23** | [#153](https://github.com/mxmlnkn/ratarmount/issues/153) | Libfuse 3.16+ | **likely OK** via `fuser`; smoke on modern fuse3 |
| **B-24** | [#76](https://github.com/mxmlnkn/ratarmount/issues/76) | macOS CI hang | **partial** — macOS beta; keep harness smoke |
| **B-25** | [#171](https://github.com/mxmlnkn/ratarmount/issues/171) | fsspec find/walk incomplete | Python fsspec API; only if we expose similar listing |
| **B-26** | [#125](https://github.com/mxmlnkn/ratarmount/issues/125) | mkdir in TAR + commit | Overlay mkdir + commit TAR |

---

## Already addressed in ratarmount-rs (for context)

These upstream bugs/features are **closed or fixed upstream**, and Rust already has intentional coverage — re-check only if a regression appears:

| Topic | Upstream | Rust |
|-------|----------|------|
| GNU sparse | #23 | Sparse PAX/GNU in TAR + harness |
| GNU incremental (basic) | #73 | Detect / dumpdir / prefix |
| 7z RA | #123 | Custom sevenzip backend |
| WARC | #128 | Dedicated backend |
| ZIP commit | #154 | MVP full rebuild (residual encrypted) |
| HTTP Basic | #157 | Done; cookies residual |
| TAR PAX FS xattrs | #145 | SCHILY/LIBARCHIVE |
| Nested no-tmp / recursive | various | AutoMount + open_from_reader |
| pread-style FUSE | #100 | Low-level FUSE offset reads |

---

## Suggested inspection workflow (agents)

For each **inspect** / **partial** row:

1. Minimal repro (script or fixture under `test-harness/` or `tmp/`).
2. Run **Python** (if available) and **Rust** side-by-side; record pass/fail.
3. Outcomes:
   - **Fixed in Rust** → add regression test + note in this file (`status: ok`)
   - **Still broken** → open internal fix task; link this ID
   - **By design** → document in README Gaps / parity-todo
4. Update this table’s “Preliminary Rust read” column when done.

### Recommended first pass (one agent or batch)

```text
B-1  .tzst recursive mount
B-3  7z --index-file persistence
B-4  union symlink script (#164)
B-5  non-UTF8 names with -e
B-7  ZIP ../ member paths
B-11 lz4 tar modes
B-13 du/st_blocks
B-2  recursive resource usage (measure only; no fix required for pass)
```

---

## Related docs

- Feature requests (not pure bugs): [`upstream-feature-requests.md`](upstream-feature-requests.md)
- Living parity: [`../parity-todo.md`](../parity-todo.md)
- Nested: [`../embedded-nested-archives.md`](../embedded-nested-archives.md)

*Generated from GitHub API snapshot 2026-07-28; re-fetch when prioritizing work.*
