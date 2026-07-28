# Upstream bugs (mxmlnkn/ratarmount) — inspection queue for ratarmount-rs

Source: open + closed **bug-labeled** and bug-shaped reports on
[mxmlnkn/ratarmount](https://github.com/mxmlnkn/ratarmount/issues).  
Goal: decide whether each issue can still reproduce on **ratarmount-rs**, and
file a fix or mark **N/A**.

**Repro run:** 2026-07-28 against `target/release/ratarmount` 0.1.10  
**Script / fixtures:** `tmp/upstream-bugs/run_repros.sh` (local; not committed)  
**Raw TSV:** `tmp/upstream-bugs/results/results.tsv`

**Legend**

| Rust status | Meaning |
|-------------|---------|
| **ok** | Repro passed on ratarmount-rs (upstream bug not present / already fixed) |
| **fail** | Reproduced a real defect on Rust |
| **partial** | Residual gap, measure-only, or incomplete fixture |
| **n/a** | Python/GUI/AppImage/host-only or not our product surface |
| **inspect** | Not yet verified (none left after this run) |

Upstream has **no open issues with label `bug`** as of 2026-07-28. Below mixes
open **unlabeled** bug-shaped reports and **closed** bugs.

---

## Summary after repro pass

| Status | Count | IDs |
|--------|------:|-----|
| **ok** | 13 | B-1, B-3, B-5, B-7, B-9, B-11, B-12, B-13, B-14, B-15, B-17, B-23, B-26 |
| **partial** (actionable residual) | 5 | **B-2**, **B-4**, **B-8**, **B-10**, **B-119** |
| **partial** (acceptable / platform) | 2 | B-16, B-24 |
| **n/a** | 7 | B-6, B-18–B-22, B-25 |

**No hard fails.** Remaining work is residual behavior (union symlinks, incremental TAR delete merge, huge sparse smoke, recursive RAM, small-archive index policy).

---

## Priority inspection list

### P0 — open reports that look like real correctness / UX bugs

| ID | Upstream | Summary | Repro result (2026-07-28) | Status |
|----|----------|---------|---------------------------|--------|
| **B-1** | [#185](https://github.com/mxmlnkn/ratarmount/issues/185) | Recursive mount of **`.tzst`** fails | Direct `.tzst` + outer `.tzst` with nested `.tzst` under `-r`: `nested.tzst/msg.txt` readable | **ok** |
| **B-2** | [#179](https://github.com/mxmlnkn/ratarmount/issues/179) | Recursive mount **RAM/time** explosion | Light nested `tar`→`.tar.zst` OK (50 files). Full `linux-source-*.deb` 3 GB RAM case **not** run | **partial** — measure full deb if prioritizing perf |
| **B-3** | [#177](https://github.com/mxmlnkn/ratarmount/issues/177) | **7z index always `:memory:`** | `--index-file path` creates ~94 KiB SQLite, reloads without `-c` | **ok** |
| **B-4** | [#164](https://github.com/mxmlnkn/ratarmount/issues/164) | **Inconsistent symlink handling** in union mounts | **Still order-dependent** (see detail below) | **partial** — **open residual** |
| **B-5** | [#195](https://github.com/mxmlnkn/ratarmount/issues/195) | **Non-UTF-8** filenames | `-e latin1` shows `Lüneburg.txt` and reads content; UTF-8 default shows replacement char | **ok** |
| **B-6** | [#184](https://github.com/mxmlnkn/ratarmount/issues/184) | Mount layout vs **rar2fs** | By design (mountpoint tree, not sibling extract) | **n/a** |

#### B-4 detail (still broken / inconsistent)

Upstream script (two folders; `branch1/subdir0` → symlink to `./subdir1`):

| Order | `subdir0` type | `subdir0/subdir2` files |
|-------|----------------|-------------------------|
| branch1 then branch2 (rightmost = dir) | **directory** | `file1`, `file2` (merged) |
| branch2 then branch1 (rightmost = symlink) | **symbolic link** → `./subdir1` | `file1`, `file3` (**no `file2`**) |

Same class of bug as Python [#164](https://github.com/mxmlnkn/ratarmount/issues/164) / [#160](https://github.com/mxmlnkn/ratarmount/issues/160): symlink vs directory conflict is order-dependent and does not present a single coherent union policy. **Follow-up:** define policy (prefer real dir over symlink; or always merge through both) and add a regression test.

### P1 — closed upstream bugs (regression candidates)

| ID | Upstream | Summary | Repro result | Status |
|----|----------|---------|--------------|--------|
| **B-7** | [#96](https://github.com/mxmlnkn/ratarmount/issues/96) | ZIP members with **`../`** | `foo/bar/../escaped.txt` → `foo/escaped.txt`; `../outside.txt` → `/outside.txt`; content OK | **ok** |
| **B-8** | [#156](https://github.com/mxmlnkn/ratarmount/issues/156) | Sparse holes **> 8 GiB** | 8 GiB fixture skipped; code uses **`u64`** sparse offsets/pairs (`ratarmount-formats-tar`) — unlikely same i32-style bug | **partial** — optional large smoke |
| **B-9** | [#23](https://github.com/mxmlnkn/ratarmount/issues/23) | GNU/PAX **sparse** wrong size/data | 1 MiB PAX sparse: size + HEAD/TAIL at edges OK | **ok** |
| **B-10** | [#73](https://github.com/mxmlnkn/ratarmount/issues/73) | GNU **incremental** TAR | level-0 lists files; level-1 mounts dumpdir members; **no `.snar` delete merge** | **partial** — residual feature |
| **B-11** | [#158](https://github.com/mxmlnkn/ratarmount/issues/158) | **lz4** TAR loses modes | `stat` mode **755** on executable member | **ok** |
| **B-12** | [#148](https://github.com/mxmlnkn/ratarmount/issues/148) | SquashFS **write bits** wrong | plain=644, exec=755, secret=600 | **ok** |
| **B-13** | [#165](https://github.com/mxmlnkn/ratarmount/issues/165) | **`du` / st_blocks** | 2 MiB file: `st_blocks=4096`, `du -b` matches size | **ok** |
| **B-14** | [#90](https://github.com/mxmlnkn/ratarmount/issues/90) / [#133](https://github.com/mxmlnkn/ratarmount/issues/133) / [#134](https://github.com/mxmlnkn/ratarmount/issues/134) | Overlay **update/delete** / rmdir | update + unlink + rmdir OK under `-w` | **ok** |
| **B-15** | [#174](https://github.com/mxmlnkn/ratarmount/issues/174) | Index after archive **moved** | Same `--index-file` reused after rename/copy of archive; content OK | **ok** (S3 URL not exercised; local path move OK) |

### P2 — closed / niche / low urgency

| ID | Upstream | Summary | Result | Status |
|----|----------|---------|--------|--------|
| **B-16** | [#34](https://github.com/mxmlnkn/ratarmount/issues/34) | Incomplete / truncated `.tar.gz` | Mount refused (`gzip inflate … Buf`) — acceptable | **partial** |
| **B-17** | [#21](https://github.com/mxmlnkn/ratarmount/issues/21) | Missing `gzipindex` table | Modern index create/load OK | **ok** |
| **B-18** | [#129](https://github.com/mxmlnkn/ratarmount/issues/129) | Empty mount / FUSE forbidden FS | Host config | **n/a** |
| **B-19** | [#152](https://github.com/mxmlnkn/ratarmount/issues/152) | Progress % > 100 | Python UI | **n/a** |
| **B-20** | [#189](https://github.com/mxmlnkn/ratarmount/issues/189) | AppImage arg completion | Python AppImage | **n/a** |
| **B-21** | [#197](https://github.com/mxmlnkn/ratarmount/issues/197) / [#198](https://github.com/mxmlnkn/ratarmount/issues/198) | `--gui` hang / warnings | No `--gui` in Rust | **n/a** |
| **B-22** | [#146](https://github.com/mxmlnkn/ratarmount/issues/146) | Python 3.6 index | N/A | **n/a** |
| **B-23** | [#153](https://github.com/mxmlnkn/ratarmount/issues/153) | Libfuse 3.16+ | fusermount3 3.14.0 host; simple mount OK | **ok** |
| **B-24** | [#76](https://github.com/mxmlnkn/ratarmount/issues/76) | macOS CI hang | Not run on macOS; Linux smoke OK | **partial** |
| **B-25** | [#171](https://github.com/mxmlnkn/ratarmount/issues/171) | fsspec find/walk | No fsspec CLI/API | **n/a** |
| **B-26** | [#125](https://github.com/mxmlnkn/ratarmount/issues/125) | mkdir + commit overlay | `mkdir newdir` + file + `--commit-overlay --yes` preserved | **ok** |
| **B-119** | [#119](https://github.com/mxmlnkn/ratarmount/issues/119) | Skip index for small archives | `--index-minimum-file-count 1000` still wrote index for 1-file tar | **partial** — flag may not gate SQLite create when `--index-file` forced |

---

## Follow-up task list (actionable residuals only)

1. **B-4 / #164 — Union symlink vs directory policy**  
   - Define desired semantics when one source has a symlink and another a real directory at the same path.  
   - Implement + regression test (script from upstream issue).  
   - Related FR: [#160](https://github.com/mxmlnkn/ratarmount/issues/160).

2. **B-10 / #73 — GNU incremental delete / snapshot merge**  
   - level-0/1 mount works; missing multi-volume `.snar` delete-list union.  
   - Track under parity-todo incremental residual.

3. **B-2 / #179 — Recursive resource usage**  
   - Optional: time/RSS on `linux-source-*.deb` with `-r` vs manual nested mounts.  
   - Perf only; not a correctness bug.

4. **B-8 / #156 — Sparse > 8 GiB smoke** (optional)  
   - Code path is `u64`; low risk. Optional synthetic fixture if disk allows.

5. **B-119 / #119 — `index-minimum-file-count` vs `--index-file`**  
   - Confirm whether forced `--index-file` should still honor minimum count; document or fix.

6. **B-15 S3 path** (optional stretch)  
   - Local move OK; re-check index bind when opening `s3://` after indexing a local copy.

---

## Already addressed in ratarmount-rs (for context)

| Topic | Upstream | Rust |
|-------|----------|------|
| GNU sparse | #23 | **ok** (this run + harness) |
| GNU incremental (basic) | #73 | Detect/prefix/dumpdir; delete merge residual |
| 7z RA + index file | #123 / #177 | **ok** SQLite `--index-file` |
| WARC | #128 | Dedicated backend |
| ZIP commit | #154 | MVP full rebuild |
| HTTP Basic | #157 | Done |
| TAR PAX FS xattrs | #145 | SCHILY/LIBARCHIVE |
| Nested no-tmp / recursive | various | AutoMount + open_from_reader |
| pread-style FUSE | #100 | Low-level FUSE offset reads |
| `.tzst` recursive | #185 | **ok** this run |
| ZIP `../` | #96 | **ok** this run |
| lz4 modes | #158 | **ok** this run |
| squashfs modes | #148 | **ok** this run |
| du/st_blocks | #165 | **ok** this run |
| overlay update/delete/mkdir+commit | #90/#125/#133/#134 | **ok** this run |

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

- Feature requests: [`upstream-feature-requests.md`](upstream-feature-requests.md)
- Living parity: [`../parity-todo.md`](../parity-todo.md)
- Nested: [`../embedded-nested-archives.md`](../embedded-nested-archives.md)

*Generated from GitHub API snapshot 2026-07-28; full repro pass same date.*
