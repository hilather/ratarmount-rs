# Vector-wave benches — ratarmount-rs old vs new

**Snapshot:** 2026-08-29 · OLD **v0.1.28** (`579fa8f`) vs NEW **v0.1.29** (`7d90e5b`). Catalog N=8000. Re-run: `OLD_REF=v0.1.28 VECTOR_REMOTE=1 ./benchmarks/compare-vector-wave.sh`.

OLD **0.1.28** vs NEW **0.1.29**. Catalog N=8000.

These paths are what the FUSE `cat`/`find` BIG suite missed:

- `cold_index_many` — P2 SQLite bulk staging (`-c --no-mount`)
- `cold_index_hashes` — P2 fingerprint windows (`--hashes sha256`)
- `cold_nested_r` — nested `-c -r --no-mount`
- `find_glob` / `find_star` — V-1 CLI locate (streaming SQL)
- `control_search` — V-1 live `search/<glob>`
- `extract_*_order` — V-5 name-order vs offset-order sequential cat (overlay-only names last)
- `overlay_getattr` — P2 overlay inode cookies after create
- `remote_sidecar_second_get` — V-3 XDG LRU (VECTOR_REMOTE=1; 0 extra sidecar GETs)

| Scenario | Metric | Old | New | Relative |
|----------|--------|-----|-----|----------|
| `cold_index_hashes` | rss_kib | 20.2 MiB | 20.3 MiB | old **1.00×** better |
| `cold_index_hashes` | wall_s | 59.3 ms | 58.8 ms | new **1.01×** better |
| `cold_index_many` | rss_kib | 22.2 MiB | 22.4 MiB | old **1.01×** better |
| `cold_index_many` | wall_s | 80.9 ms | 78.2 ms | new **1.03×** better |
| `cold_nested_r` | rss_kib | 27.5 MiB | 27.7 MiB | old **1.01×** better |
| `cold_nested_r` | wall_s | 125.0 ms | 143.5 ms | old **1.15×** better |
| `control_search` | rss_kib | 22.7 MiB | 23.1 MiB | old **1.02×** better |
| `control_search` | wall_s | 15.7 ms | 11.1 ms | new **1.41×** better |
| `extract_name_order` | wall_s | 653.4 ms | 656.8 ms | old **1.01×** better |
| `extract_offset_order` | wall_s | 655.4 ms | 648.9 ms | new **1.01×** better |
| `find_glob` | wall_s | 25.3 ms | 26.5 ms | old **1.05×** better |
| `find_offset_order` | wall_s | — | 27.6 ms | — |
| `find_star` | wall_s | 25.9 ms | 24.1 ms | new **1.07×** better |
| `overlay_getattr` | rss_kib | 20.1 MiB | 20.2 MiB | old **1.00×** better |
| `overlay_getattr` | wall_s | 71.0 ms | 72.4 ms | old **1.02×** better |
| `remote_sidecar_second_get` | count | 1 | 0 | — |

Single-run medians of `RUNS` samples. Treat <10% as noise except RSS on overlay/index.

