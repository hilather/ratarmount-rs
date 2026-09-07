# Task: Vectorize-inspired systems patterns (steal the architecture, not ANN)

**Date:** 2026-08-28
**Status:** living backlog — all `todo` / `partial`
**Source:** [Cloudflare “Building Vectorize”](https://blog.cloudflare.com/building-vectorize-a-distributed-vector-database-on-cloudflare-developer-platform/) (2024-10-22) reviewed against ratarmount-rs density + remote + overlay work.
**Legend:** `[x]` done · `[ ]` open · `~` partial · `n/a` do not copy

This is **not** SIMD and **not** embedding search. Vectorize “vectors” are ML embeddings in \(\mathbb{R}^{D}\). Our [`vectors-optimization.md`](vectors-optimization.md) “vectors” are SoA columns. Do not port IVF, PQ, or ANN. Steal the *systems* patterns: prune then refine, immutable snapshots, read-through cache, coordinator WAL, locality clustering.

Pairs with: [`beyond-parity-roadmap.md`](beyond-parity-roadmap.md) **G-2** / **G-3** / **F-2** / **F-7** / **F-9**, [`vectors-optimization.md`](vectors-optimization.md) P0 list/dirents residual + P2 overlay, [`tar-zst-live-commit-design.md`](tar-zst-live-commit-design.md), [`docs/phase10-remote.md`](../phase10-remote.md).

---

## Why this file exists

Vectorize solves “do not scan 6 GB of floats per query.” We solve “do not inflate a 6 GB member to `cat` 64 KiB.” Same instinct, different data.

Useful overlap is how they structure I/O and consistency, not how they score cosine distance.

| Vectorize piece | ratarmount analogue | Copy? |
|-----------------|---------------------|-------|
| PQ + refine with raw floats | seek map → decompress covering frame; cheap dirents → fat `FileInfo` on getattr | **pattern only** |
| IVF centroid files | path shards + offset-order member rows | **pattern only** |
| Versioned index files + atomic root manifest | sibling `.index.sqlite` / `--publish-index` / OCI referrer (G-2) | **yes — snapshot readers** |
| Cache in front of R2 | Range GET of remote archives with no pinned index/seek-map LRU | **yes — remote mounts** |
| WAL Durable Object + executor pool | overlay + `--commit-overlay` / interval (F-2 last-frame splice) | **yes — coordinator, not DO** |
| Eventual consistency as the read model | FUSE `read` after overlay `write` | **no** |
| ANN accuracy knobs (~80% → 95%) | wrong member bytes | **no** |
| Workers / Durable Objects / Queues | single-process FUSE + optional NFS | **no** |

---

## Summary table

| ID | Pattern | Status | Effort | Why it is useful here | Ownership |
|----|---------|--------|--------|-----------------------|-----------|
| V-1 | Cheap scan, then refine | `done` | M | CLI find / FTS stay streaming SQL; live control/socket / compact-only scan SoA + pool ids; overlay last-wins on control/socket | index + compositing + CLI |
| V-2 | Immutable versioned index + atomic root pointer | `partial` | M | G-2 publishes a blob; readers can still see a half-written sidecar during `-c` | index + remote + CLI |
| V-3 | Read-through cache in front of object storage | `todo` | L | Remote FUSE stalls on cold Range GET of index pages and seek maps; Cache-in-front-of-R2 is the highest-leverage steal | remote + compress + index |
| V-4 | WAL as coordinator, executor does the heavy write | `partial` | M | Live interval/on-exit queue coalesces overlapping splices; F-7 write-through still reuses that queue later | compositing + formats-tar |
| V-5 | Cluster by locality (offset order, not cosine) | `done` | S–M | Sequential extract / `tar tv` / NFS readahead walk path order today, not archive order | index + formats-tar/zip/7z |

Suggested order: **V-1** (finish cheap find) → **V-2** (snapshot index; unblocks shared remotes) → **V-3** (remote cache; needs V-2 etag) → **V-4** (commit queue) → **V-5** (optional; F-9 producer helps).

---

## V-1 — Cheap scan, then refine

**Vectorize:** Product-quantized scan over the index, then a second pass that rescores the top hits with uncompressed floats so recall climbs from ~80% to >95%.

**What is useful:** Two-phase query. Phase 1 never materializes the expensive representation. Phase 2 runs only on hits.

**What we already have:**

- Codec path: sealed SoA seek maps (gzip checkpoints, zstd frames, bzip2 blocks) → decompress only the covering unit. That *is* PQ-then-refine for payload bytes.
- Metadata path: `list_dirents` from string pool + `EntrySoa` without `BTreeMap<String, FileInfo>`. Fat `FileInfo` only at getattr / open. Documented in [`vectors-optimization.md`](vectors-optimization.md) P0.
- `ratarmount find` + `/.ratarmount-control/search/` + socket `search` (F-3) walk the 0.7.x catalog.

**Shipped (rewritten — do not read the old “find stays on SoA” wording):**

- [x] CLI `find` / FTS stay streaming SQL over `files` / `files_fts`. Allocate path strings only for emitted `SearchHit`s. Do **not** load `MemIndex` to answer sidecar `find`.
- [x] Live control/socket / compact-only walk SoA columns + pool ids (`search_cheap` / `MemIndex::scan_glob`). Hits are `SearchHit` / `CheapSearchHit`. `FileInfo` is getattr/open only.
- [x] Overlay last-wins on `-w` control/socket (creates, COW/replace, tombstones) via one SearchFn. CLI `find` still rejects `-w`.
- [x] Additive `ListNeed` (P0 leftover). It is **not** what makes search cheap.
- [x] Regression: `FileInfo` construction count is 0 on a synthetic 200k SoA `scan_glob` (not a 200k on-disk TAR `find` RSS test).
- [x] Folder live glob (`FolderMountSource::search_cheap`): host `read_dir` + `symlink_metadata`, no `list()`, no recurse into `S_IFLNK` dirs, cap `DEFAULT_SEARCH_LIMIT`. `fts:` stays `None`.
- [x] Union catalog merge (`UnionMountSource::search_cheap`): `None` if any source is `None`; `Some([])` contributes; merge path+`offsetheader` with later source winning that key; no B-4 / no `lookup`; never `sources[0]`. `fts:` stays `None`.
- [x] OCI overlayfs locate (`OciImageMountSource::search_cheap`): per-layer `search_cheap`, `None` if any layer is `None`; collect top→bottom; drop hidden/opaque; never emit `.wh.*`; never `layers[0]` alone. `fts:` stays `None`.

**Residual:** Folder host-tree glob is `Some` (`read_dir` + `symlink_metadata`; no `list()`; no recurse into `S_IFLNK` dirs). Union merge is `Some` when every source is `Some`. OCI overlayfs locate is `Some` when every layer is `Some` (whiteouts / opaque dirs; no `.wh.*` / not `layers[0]`). Marker discovery reuses the 10k locate cap (`search_cheap(".wh.*")`); huge delete layers may miss late whiteouts vs `lookup`. `--prefix` / `--transform` + `-w` last-wins is not guaranteed (catalog paths, no Transform inverse). Compact-only CLI find without a sidecar stays empty / “on-disk index.”

**Why it pays:** BIG-suite `find` is already ~1.3× Python; the remaining tax is path materialization and fat maps, not cosine math. Same toolbox as P0 density — do not invent an ANN layer.

**Do not:** approximate member *contents*. A 95% correct `cat` is corruption.

---

## V-2 — Immutable versioned index + atomic root pointer

**Vectorize:** Each IVF/metadata file is immutable and versioned. A *manifest* lists the snapshot. A *root manifest* at a deterministic R2 key is overwritten with an atomic PUT. Readers keep using snapshot N until the root pointer flips to N+1. Past versions stay around (Time Travel-shaped).

**What is useful:** Readers never open a half-written catalog. Rebuild (`-c`), `--publish-index`, and remote discovery can run while mounts stay warm on the previous blob.

**What we already have (G-2 `done`):**

- Media type `application/vnd.ratarmount.index.v1+sqlite`, inner `INDEX_VERSION` 0.7.0.
- Discovery: `--index-file` → local candidates → GET `{url}.index.ptr` then `{url}.index.{id}.sqlite` → HTTP `Link: rel="describedby"` → well-known sibling GET (http(s) + S3/GCS/Azure) → OCI 1.1 referrer on local miss.
- `--publish-index` / `--publish-index-to PATH`; HTTP `GET /.ratarmount-control/index.sqlite`.
- `check_tarstats_matches_remote` after fetch.

**Still open:**

- [x] **V-2a** local tmp+rename: `create_writable(Some(dest))` opens `{dest}.tmp.{pid}` (journal OFF, dest not unlinked). `publish_tmp` / `into_read_only` close tmp (no WAL) → rename → `self.path = dest` → open dest → WAL. Drop unpublished tmp leaves dest (stricter than old `remove_file` dest at create). Factory side-table helpers call `publish_tmp()` after writes. Pointer flip is V-2b.
- [x] **V-2b** root pointer object separate from the SQLite blob: `{schema, index_id, etag/sha256, generated_at, archive_tarstats}` in `{archive}.index.ptr` (`ratarmount.index.pointer.v1`; `index_id` = sha256(blob) 64 hex). `--publish-index` always writes it (including dest==sidecar). `--index-id HEX` pre-resolves to `opts.index_file_path`.
- [x] Keep-last-K=2 local snapshots when a pointer is written (`{archive}.index.{old_id}.sqlite` from the existing pointer id; no extra copy until then). Remount `--index-id` of N while N+1 is well-known. `-c` still publishes the well-known SQLite blob (V-2a); pointer flip is `--publish-index`.
- [x] Shared remote index **GET** (V-2c): S3/GCS/Azure/HTTP sibling GET of `{url}.index.ptr` then `{url}.index.{id}.sqlite` then well-known. Pointer/blob/tarstats failure continues describedby → well-known → OCI. **PUT** of pointer/blob is F-7 (`aws s3 cp` until then).
- [x] Regression (V-2a): reader `open_read_only` + `search_query` survives writer `create_writable`+inserts+`into_read_only`; drop mid-insert leaves dest; `check_tarstats` still rejects a replaced archive. Pointer-era remount `--index-id` (V-2b): clap-steal; dest==sidecar writes `.ptr`; tarstats mismatch refuses.

**Why it pays:** Unlocks safe `--publish-index` on NFS/S3 and remount-during-rebuild. SQLite’s own WAL is per-connection, not a cross-process object-store commit. Vectorize’s root PUT is the portable part.

**Do not:** split the 0.7.x `files` table into IVF centroid files. One SQLite blob per snapshot is enough.

---

## V-3 — Read-through cache in front of object storage

**Vectorize:** DB service in every colo reads index files through Cloudflare Cache, not cold R2. Queries stay on cached centroid files.

**What is useful:** Pin *small, hot, random-accessed* objects (index pages, seek-map slabs, nestedindexes blobs), not the whole archive. FUSE cannot hide a 100 ms Range RTT per 4 KiB SQLite page.

**What we already have:**

- Range readers: HTTP, S3, GCS, Azure, SSH, OCI blob, IPFS gateway.
- Remote folder listing TTL (`RATARMOUNT_REMOTE_LIST_TTL_SECS`, 30s).
- Local sibling index discovery; OCI `{digest}` cache then referrer (G-2).
- G-3 **content-addressed member cache** is `todo` (decompressed chunks by hash). Different layer — payload, not metadata I/O.

**Still open / landed:**

- [x] Process-local LRU (`$XDG_CACHE_HOME/ratarmount/meta-v3/`, `RATARMOUNT_META_CACHE_BYTES` default 256 MiB, `=0` disables) keyed by canonical **backend+url** (etag is a header, **not** the lookup key) for whole SQLite sidecar downloads ≤ 64 MiB (`fetch_index_http`). A remount without `.ptr` still hits.
- [ ] SQLite page / Range pager over index URLs; standalone RGZI/GZIDX **files** next to the archive (sidecar-internal `zstdblocks` / `bzip2blocks` / `nestedindexes` come along with the blob)
- [x] Skip on `file://` and `:memory:` indexes (and local `path_is_nonempty_file`).
- [x] Do **not** cache uncompressed member bodies here (that is G-3, still `todo`).
- [x] Regression: second fake-HTTP remount of a well-known sidecar does not GET again; corrupting the cached blob fails closed to refetch; pointer etag mismatch GETs once.
- [x] Bench: `VECTOR_REMOTE=1 ./benchmarks/compare-vector-wave.sh` local HTTP fixture (sidecar GET count).

**Why it pays:** Remote-first is already the product story. Density work made local `find` cheap; remote mounts still die on metadata RTT. This is the Vectorize Cache→R2 split with ANN removed.

**Depends:** V-2 pointer etag is optional revalidation only (cache key is URL-first). Complements G-3 (payload) and F-9 (producer makes maps small).

**Plan:** [`plans/v3-read-through-sidecar-cache.md`](plans/v3-read-through-sidecar-cache.md) (plan-only; implement blocked until V-2 pointer lands).

---

## V-4 — WAL as coordinator; executor does the heavy write

**Vectorize:** Durable Object WAL stores lightweight mutation *ids* (pointers to R2 payloads). One assigned executor rebuilds index files and hands the new manifest back. The WAL alone commits the root pointer. Executors are a shared pool; DOs stay small.

**What is useful:** Separate “what changed” from “rewrite the archive.” One writer owns the commit. Stalled executors do not tear the visible object.

**What we already have:**

- Overlay dir / `:temp:` is the mutation log.
- F-2: last-frame `.tar.zst` splice + uncompressed `tar --append` patch the sidecar without rescanning the prefix.
- `--commit-overlay`, `--commit-overlay-on-exit`, `--commit-overlay-interval`.
- Live ticks reject prefix-frame `.tar.zst` mutate; offline splice is the escape hatch.
- Gzip commit stays rejected; ZIP is full rebuild.

**Shipped (live queue — IntervalIdle / OnExit only):**

- [x] Single-writer live commit queue: `WriteOverlay::enqueue_commit(CommitKind::{IntervalIdle, OnExit})`. A second interval tick while inflight is `Coalesced` (does not start another `persist_by_format`). On-exit waits for inflight (2× last **DidWork** persist, min 60s); timeout logs then waits until inflight clears before one `commit_atomic` of remaining files.
- [x] Coordinator is inflight CAS + condvar. On-exit re-walks the overlay after wait (no queued plan/`commit_generation` snapshot). Executor still does last-frame splice / uncompressed `tar --append` / sidecar patch, then local `rename`.
- [x] Hot files (open write fd, younger than interval) stay in the overlay.
- [x] Prefix-frame mutate stays fail-closed via `classify_tar_zst_path` / `earlier_frame_err`. CLI `commit_overlay()` is **not** a queue job (offline prefix-rewrite escape hatch).
- [x] Regression: two interval fires during an injected long persist → second `Coalesced`; on-exit remaining-hot after wait; timeout still waits inflight (no double-append); live prefix-frame delete still `earlier_frame_err`; persist is sibling-tmp + atomic replace; `overlay_commit_live*` / `overlay_commit_live_delete_shifts` stay green.

**Still open:**

- [ ] Later: F-7 write-through uses the same live queue (executor uploads, coordinator publishes pointer from V-2). Do not put Offline `commit_overlay()` on this executor.

**Why it pays:** The residual that hurts operators is concurrent commit vs open readers, not missing Durable Objects. Coordinator + one executor is the portable part. Do not add Queues/DOs.

**Do not:** treat overlay reads as eventually consistent. FUSE/NFS `read` after `write` on `-w` must see overlay bytes immediately; only the *base archive republish* is async.

---

## V-5 — Cluster by locality (offset order)

**Vectorize:** IVF puts nearby embeddings in one centroid file so a query opens a handful of objects instead of the whole index.

**What is useful:** “Nearby” for an archive is **byte offset**, not cosine. Sequential consumers (`tar -x`, recursive copy, NFS readahead, `--readahead`) should walk members in `offsetheader` order so the backing file reads forward.

**What we already have:**

- PathTable segments + dir shards (name locality, not media locality).
- TAR index rows already store `offsetheader`; ZIP/7z sidecars store pack/data offsets; 7z `entry_by_offsets` is sorted keys + binary search.
- FUSE `--readahead` amortizes short reads *within* one open member, not across readdir order.

**Still open:**

Implementation: [`plans/v5-offset-order-locality.md`](plans/v5-offset-order-locality.md) (v1 landed; default `ls` unchanged).

- [x] Optional `list_dirents` / extract helper that yields dirents sorted by `offsetheader` (CLI flag or control file; default stays name order for `ls`).
- [x] `find` output option: offset order for restore pipelines.
- [x] Document that F-9 `--repack-seekable` should also keep members in offset order (already true for tar-in-order).
- [x] Regression: restore via offset-ordered flatten does **zero** backward seeks vs name order on an interleaved multi-dir fixture (CI: N≥32; 10k-member bench is `N_RESTORE=10000 ./benchmarks/compare-vector-wave.sh`, not default CI — see [`plans/v5-offset-order-locality.md`](plans/v5-offset-order-locality.md) §9.6).
- [x] ZIP local-header + 7z pack-offset seek-count tests (zero backward `SeekFrom::Start` on flatten vs ≥1 on name order; 7z shared-pack name tie-break; skip if `7z` CLI missing plus synthetic table) — [`plans/v5-offset-order-locality.md`](plans/v5-offset-order-locality.md) §9.5.
- [x] Overlay-only names after catalog flatten (`overlay_only_names`; no dummy `CompactOpenCookie`).

**Why it pays:** Small win locally; large win on HDD and on remote Range (V-3) where backward seeks are extra GETs. This is IVF’s “put nearby items in one file” with “nearby” redefined.

**Do not:** k-means members or split the SQLite catalog into centroid files.

---

## Explicit non-goals (do not file as follow-ups from that blog)

| Item | Why |
|------|-----|
| IVF / k-means on embeddings | Members are not points in \(\mathbb{R}^{1536}\) |
| Product quantization of file bytes | Need exact `read()` |
| ANN recall knobs | Wrong answers are corruption |
| Eventual consistency for overlay reads | POSIX/FUSE contract on `-w` |
| Durable Objects, Queues, Workers edge fan-out | Wrong runtime |
| True SIMD CRC/memchr | Tracked as vectors-optimization **P2**; zlib-rs / rapidgzip is the reference, not Vectorize |
| G-3 payload chunk cache | Already a product bet; link it, do not duplicate |

---

## Verification

- V-1: `FileInfo` count 0 on a synthetic 200k SoA `scan_glob`; SQL `search_query` keeps `mem: None`. Not a 200k on-disk TAR `find` RSS test.
- V-2: two processes, `-c` in one, `cat` in the other; pointer flip is atomic; `check_tarstats` still fires on replaced archive.
- V-3: fake HTTP Range server; GET count on remount with cached sidecar + seek map.
- V-4: two interval fires during injected long persist → second `Coalesced`; on-exit waits then one `commit_atomic` of remaining files; timeout does not splice while interval is inflight; live prefix-frame still `earlier_frame_err`; existing `overlay_commit_live*` / `commit_overlay` tests stay green.
- V-5: pread offset monotonicity on offset-ordered restore vs name-ordered.

Every behavior change needs a regression test in the same PR (see root `AGENTS.md`).

## Related

- Density / SoA: [`vectors-optimization.md`](vectors-optimization.md)
- Portable index: [`beyond-parity-roadmap.md`](beyond-parity-roadmap.md) G-2
- Member cache: G-3 (payload; not V-3)
- Incremental commit: F-2, [`tar-zst-live-commit-design.md`](tar-zst-live-commit-design.md)
- Remote I/O: [`docs/phase10-remote.md`](../phase10-remote.md)
- Producer: F-9 `--repack-seekable`
