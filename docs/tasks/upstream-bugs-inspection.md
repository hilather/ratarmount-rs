# Upstream bugs (mxmlnkn/ratarmount) — inspection queue for ratarmount-rs

Source: open + closed **bug-labeled** and bug-shaped reports on
[mxmlnkn/ratarmount](https://github.com/mxmlnkn/ratarmount/issues).  
Goal: decide whether each issue can still reproduce on **ratarmount-rs**, and
file a fix or mark **N/A**.

**Repro run:** 2026-07-28 against `target/release/ratarmount` 0.1.10  
**Fix batch:** 2026-07-28 — see [`upstream-bug-fix-batch.md`](upstream-bug-fix-batch.md)  
**Script / fixtures:** `tmp/upstream-bugs/run_repros.sh` (local; not committed)  
**Raw TSV:** `tmp/upstream-bugs/results/results.tsv`

**Legend**

| Rust status | Meaning |
|-------------|---------|
| **ok** | Repro passed / fixed in ratarmount-rs |
| **fail** | Reproduced a real defect on Rust |
| **partial** | Residual gap, measure-only, or incomplete fixture |
| **n/a** | Python/GUI/AppImage/host-only or not our product surface |
| **inspect** | Not yet verified (none left after this run) |

Upstream has **no open issues with label `bug`** as of 2026-07-28. Below mixes
open **unlabeled** bug-shaped reports and **closed** bugs.

---

## Summary (repro + fix batch)

| Status | Count | IDs |
|--------|------:|-----|
| **ok** | 18 | B-1, B-2, B-3, **B-4**, B-5, B-7, **B-8**, B-9, **B-10** (MVP), B-11–B-15, B-17, B-23, B-26, **B-119** |
| **partial** (acceptable / platform / deferred) | 3 | B-16, B-24; B-10 multi-archive `.snar` note under ok residual |
| **n/a** | 7 | B-6, B-18–B-22, B-25 |

**Actionable residuals from the 2026-07-28 repro pass were fixed** (B-4, B-8, B-10 MVP, B-119, B-2 docs).  
Remaining only: deferred B-16/B-24, optional B-15 S3 URL, multi-archive incremental union.

---

## Priority inspection list

### P0 — open reports that look like real correctness / UX bugs

| ID | Upstream | Summary | Result | Status |
|----|----------|---------|--------|--------|
| **B-1** | [#185](https://github.com/mxmlnkn/ratarmount/issues/185) | Recursive mount of **`.tzst`** fails | Direct + nested `.tzst` under `-r` OK | **ok** |
| **B-2** | [#179](https://github.com/mxmlnkn/ratarmount/issues/179) | Recursive mount **RAM/time** | Documented: prefer **`-l`/`--lazy`** + **`--recursion-depth`** (`65c9552`) | **ok** (documented) |
| **B-3** | [#177](https://github.com/mxmlnkn/ratarmount/issues/177) | **7z index always `:memory:`** | `--index-file` persists + reloads | **ok** |
| **B-4** | [#164](https://github.com/mxmlnkn/ratarmount/issues/164) | **Inconsistent symlink** in union mounts | **Fixed** (`580fadf`): directory wins over symlink; both mount orders list `file1`+`file2`; test `union_directory_wins_over_symlink_order_independent` | **ok** |
| **B-5** | [#195](https://github.com/mxmlnkn/ratarmount/issues/195) | **Non-UTF-8** filenames | `-e latin1` OK | **ok** |
| **B-6** | [#184](https://github.com/mxmlnkn/ratarmount/issues/184) | Mount layout vs **rar2fs** | By design | **n/a** |

#### B-4 (fixed)

Policy: if **any** source has a real directory at a path, union `lookup` returns directory (rightmost dir metadata). `list` merges directory listings and one-hop symlink follows within a source; directory entries are never overwritten by symlinks. Regression: `union_directory_wins_over_symlink_order_independent` in `ratarmount-compositing`.

### P1 — closed upstream bugs (regression candidates)

| ID | Upstream | Summary | Result | Status |
|----|----------|---------|--------|--------|
| **B-7** | [#96](https://github.com/mxmlnkn/ratarmount/issues/96) | ZIP members with **`../`** | Normalized + readable | **ok** |
| **B-8** | [#156](https://github.com/mxmlnkn/ratarmount/issues/156) | Sparse holes **> 8 GiB** | **Fixed** (`655dee5`): `u64` maps + test `sparse_map_offset_above_8gib` (9 GiB hole, no materialize) | **ok** |
| **B-9** | [#23](https://github.com/mxmlnkn/ratarmount/issues/23) | GNU/PAX **sparse** | 1 MiB sparse OK | **ok** |
| **B-10** | [#73](https://github.com/mxmlnkn/ratarmount/issues/73) | GNU **incremental** TAR | **MVP fixed** (`655dee5`): later dumpdir whiteouts hide omitted names; test `gnu_incremental_dumpdir_deletes_omitted_names`. Residual: multi-archive level0+level1 / `.snar` | **ok** (MVP) |
| **B-11** | [#158](https://github.com/mxmlnkn/ratarmount/issues/158) | **lz4** TAR modes | mode 755 | **ok** |
| **B-12** | [#148](https://github.com/mxmlnkn/ratarmount/issues/148) | SquashFS modes | 644/755/600 | **ok** |
| **B-13** | [#165](https://github.com/mxmlnkn/ratarmount/issues/165) | **`du` / st_blocks** | consistent | **ok** |
| **B-14** | [#90](https://github.com/mxmlnkn/ratarmount/issues/90) / [#133](https://github.com/mxmlnkn/ratarmount/issues/133) / [#134](https://github.com/mxmlnkn/ratarmount/issues/134) | Overlay update/delete | OK | **ok** |
| **B-15** | [#174](https://github.com/mxmlnkn/ratarmount/issues/174) | Index after archive moved | Local path move OK; S3 URL optional | **ok** |

### P2 — closed / niche / low urgency

| ID | Upstream | Summary | Result | Status |
|----|----------|---------|--------|--------|
| **B-16** | [#34](https://github.com/mxmlnkn/ratarmount/issues/34) | Truncated `.tar.gz` | Mount refused (acceptable) | **partial** |
| **B-17** | [#21](https://github.com/mxmlnkn/ratarmount/issues/21) | Missing `gzipindex` table | Modern index OK | **ok** |
| **B-18** | [#129](https://github.com/mxmlnkn/ratarmount/issues/129) | FUSE forbidden FS | Host | **n/a** |
| **B-19** | [#152](https://github.com/mxmlnkn/ratarmount/issues/152) | Progress % > 100 | Python UI | **n/a** |
| **B-20** | [#189](https://github.com/mxmlnkn/ratarmount/issues/189) | AppImage completion | Python | **n/a** |
| **B-21** | [#197](https://github.com/mxmlnkn/ratarmount/issues/197) / [#198](https://github.com/mxmlnkn/ratarmount/issues/198) | `--gui` | No GUI in Rust | **n/a** |
| **B-22** | [#146](https://github.com/mxmlnkn/ratarmount/issues/146) | Python 3.6 | N/A | **n/a** |
| **B-23** | [#153](https://github.com/mxmlnkn/ratarmount/issues/153) | Libfuse 3.16+ | Host fuse3 OK | **ok** |
| **B-24** | [#76](https://github.com/mxmlnkn/ratarmount/issues/76) | macOS CI hang | Not run here | **partial** |
| **B-25** | [#171](https://github.com/mxmlnkn/ratarmount/issues/171) | fsspec | N/A | **n/a** |
| **B-26** | [#125](https://github.com/mxmlnkn/ratarmount/issues/125) | mkdir + commit overlay | OK | **ok** |
| **B-119** | [#119](https://github.com/mxmlnkn/ratarmount/issues/119) | Skip index for small archives | **Fixed** (`3e84268`): `--index-minimum-file-count` unlinks/skips on-disk index when `COUNT(files) < min` | **ok** |

---

## Follow-up (optional only)

1. ~~B-4~~ **done** `580fadf`
2. ~~B-10 single-stream dumpdir deletes~~ **done** `655dee5` — optional later: multi-volume `.snar` union
3. ~~B-2~~ **done** docs `65c9552`
4. ~~B-8~~ **done** `655dee5`
5. ~~B-119~~ **done** `3e84268`
6. **B-15 S3** (optional): index bind when opening `s3://` after local index
7. **B-16** progressive incomplete gzip (optional)
8. **B-24** macOS CI soak (optional)

---

## Already addressed in ratarmount-rs (for context)

| Topic | Upstream | Rust |
|-------|----------|------|
| GNU sparse | #23 | **ok** |
| Sparse > 8 GiB | #156 | **ok** (`u64` + regression) |
| GNU incremental (detect + dumpdir delete MVP) | #73 | **ok** MVP |
| 7z RA + index file | #123 / #177 | **ok** |
| Union dir vs symlink | #164 | **ok** |
| Small-archive index skip | #119 | **ok** |
| Lazy recursive guidance | #179 | **ok** (docs) |
| WARC | #128 | Dedicated backend |
| ZIP commit | #154 | MVP full rebuild |
| HTTP Basic | #157 | Done |
| TAR PAX FS xattrs | #145 | SCHILY/LIBARCHIVE |
| Nested no-tmp / recursive | various | AutoMount |
| pread-style FUSE | #100 | Low-level FUSE |
| `.tzst` recursive | #185 | **ok** |
| ZIP `../` | #96 | **ok** |
| lz4 modes | #158 | **ok** |
| squashfs modes | #148 | **ok** |
| du/st_blocks | #165 | **ok** |
| overlay update/delete/mkdir+commit | #90/#125/#133/#134 | **ok** |

---

## How to re-run

```bash
cargo build -p ratarmount --release
bash tmp/upstream-bugs/run_repros.sh
column -t -s $'\t' tmp/upstream-bugs/results/results.tsv
```

Requires: FUSE (`/dev/fuse`), `zstd`, `lz4`, `7z`/`7za`, `mksquashfs`, `tar`, `python3`.

---

## Related docs

- Fix batch: [`upstream-bug-fix-batch.md`](upstream-bug-fix-batch.md)
- Feature requests: [`upstream-feature-requests.md`](upstream-feature-requests.md)
- Living parity: [`../parity-todo.md`](../parity-todo.md)
- Nested: [`../embedded-nested-archives.md`](../embedded-nested-archives.md)

*Generated from GitHub API snapshot 2026-07-28; repro + fix batch same date.*
