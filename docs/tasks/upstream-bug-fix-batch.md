# Upstream residual bug fix batch

Source: [`upstream-bugs-inspection.md`](upstream-bugs-inspection.md) (repro pass 2026-07-28).  
Already **ok** / **n/a** items are not assigned. Subagents own non-overlapping paths.

| Task | Upstream | Owner paths | Goal | Agent status |
|------|----------|-------------|------|--------------|
| **FIX-B4** | #164 | `ratarmount-compositing/**` only | Union: directory wins over symlink; merge listings consistently | pending |
| **FIX-B10** | #73 | `ratarmount-formats-tar/**` only | GNU incremental dumpdir delete / multi-snapshot residual | pending |
| **FIX-B8** | #156 | `ratarmount-formats-tar/**` (same agent as B-10) | Regression test: sparse map offsets **> 8 GiB** (`u64`) | pending |
| **FIX-B119** | #119 | `ratarmount/src/factory.rs`, `ratarmount/src/main.rs`, `ratarmount-core` options only if needed; `ratarmount-index/**` ok | Honor `--index-minimum-file-count` (skip on-disk index when below threshold) | pending |
| **FIX-B2** | #179 | docs only: `README.md`, `docs/parity-todo.md`, `docs/tasks/upstream-bugs-inspection.md`, optional `docs/embedded-nested-archives.md` | Document `-l`/`--lazy` + recursion for large recursive mounts; no perf rewrite | pending |

Deferred (not in this batch): B-16 progressive truncated gzip; B-15 S3 URL index bind; B-24 macOS CI.

## Merge order (orchestrator)

1. FIX-B4  
2. FIX-B10+B8 (tar)  
3. FIX-B119  
4. FIX-B2 (docs; may need conflict resolve on inspection doc)  
5. Orchestrator: update `upstream-bugs-inspection.md` status table + full workspace gates  

## After each fix

Mark the row **ok** / **fixed** in `upstream-bugs-inspection.md` and note the commit SHA.
