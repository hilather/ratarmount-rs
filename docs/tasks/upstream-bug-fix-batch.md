# Upstream residual bug fix batch

Source: [`upstream-bugs-inspection.md`](upstream-bugs-inspection.md) (repro pass 2026-07-28).  
Already **ok** / **n/a** items were not assigned. Subagents owned non-overlapping paths.

| Task | Upstream | Owner paths | Goal | Agent status |
|------|----------|-------------|------|--------------|
| **FIX-B4** | #164 | `ratarmount-compositing/**` | Union: directory wins over symlink; merge listings consistently | **done** — `580fadf` |
| **FIX-B10** | #73 | `ratarmount-formats-tar/**` | GNU incremental dumpdir delete (single-archive MVP) | **done** — `655dee5` (multi-archive `.snar` residual) |
| **FIX-B8** | #156 | `ratarmount-formats-tar/**` (same agent) | Regression test: sparse map offsets **> 8 GiB** (`u64`) | **done** — `655dee5` |
| **FIX-B119** | #119 | `ratarmount/src/factory.rs`, index/core/main help | Honor `--index-minimum-file-count` | **done** — `3e84268` |
| **FIX-B2** | #179 | docs only | Document `-l`/`--lazy` + recursion for large recursive mounts | **done** — cherry-pick of `0dd10d7` |

Deferred (not in this batch): B-16 progressive truncated gzip; B-15 S3 URL index bind; B-24 macOS CI.

## Merge order (completed)

1. FIX-B4 → `580fadf`
2. FIX-B10+B8 (tar) → `655dee5`
3. FIX-B119 → `3e84268`
4. FIX-B2 (docs) → this commit / cherry-pick
5. Orchestrator: status tables in `upstream-bugs-inspection.md` + workspace gates

## Residuals after batch

- **B-10:** multi-archive union of separate level-0 + level-1 tars / full `.snar` merge still open (single-stream dumpdir whiteouts done).
- **B-16 / B-24 / B-15 S3:** deferred as above.
