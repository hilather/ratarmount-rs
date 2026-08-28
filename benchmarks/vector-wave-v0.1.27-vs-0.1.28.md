# Vector-wave benches — ratarmount-rs old vs new

**Snapshot:** 2026-08-28 · OLD **v0.1.27** (`850be87`) vs NEW **v0.1.28** (`579fa8f`). Catalog N=8000. Re-run: `OLD_BIN=... NEW_BIN=... ./benchmarks/compare-vector-wave.sh`.

These paths are what the FUSE `cat`/`find` BIG suite missed:

- `cold_index_many` — P2 SQLite bulk staging (`-c --no-mount`)
- `cold_index_hashes` — P2 fingerprint windows (`--hashes sha256`)
- `cold_nested_r` — nested `-c -r --no-mount`
- `find_glob` / `find_star` — V-1 CLI locate (streaming SQL)
- `control_search` — V-1 live `search/<glob>`
- `extract_*_order` — V-5 name-order vs offset-order sequential cat
- `overlay_getattr` — P2 overlay inode cookies after create

| Scenario | Metric | Old | New | Relative |
|----------|--------|-----|-----|----------|
| `cold_index_hashes` | rss_kib | 20.9 MiB | 20.1 MiB | new **1.04×** better |
| `cold_index_hashes` | wall_s | 70.1 ms | 59.0 ms | new **1.19×** better |
| `cold_index_many` | rss_kib | 21.8 MiB | 22.1 MiB | old **1.01×** better |
| `cold_index_many` | wall_s | 78.6 ms | 85.2 ms | old **1.08×** better |
| `cold_nested_r` | rss_kib | 27.0 MiB | 27.7 MiB | old **1.03×** better |
| `cold_nested_r` | wall_s | 122.2 ms | 117.2 ms | new **1.04×** better |
| `control_search` | rss_kib | 23.1 MiB | 22.7 MiB | new **1.02×** better |
| `control_search` | wall_s | 35.3 ms | 11.0 ms | new **3.21×** better |
| `extract_name_order` | wall_s | 121.8 ms | 124.3 ms | old **1.02×** better |
| `extract_offset_order` | wall_s | 119.7 ms | 121.2 ms | old **1.01×** better |
| `find_glob` | wall_s | 27.1 ms | 26.7 ms | new **1.02×** better |
| `find_offset_order` | wall_s | — | 26.3 ms | — |
| `find_star` | wall_s | 27.2 ms | 25.8 ms | new **1.05×** better |
| `overlay_getattr` | rss_kib | 19.7 MiB | 20.1 MiB | old **1.02×** better |
| `overlay_getattr` | wall_s | 75.7 ms | 74.8 ms | new **1.01×** better |

Single-run medians of `RUNS` samples. Treat <10% as noise except RSS on overlay/index.

