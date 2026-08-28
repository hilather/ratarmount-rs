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
| V-1 | Cheap scan, then refine | `partial` | M | `find` / readdir / control search still pay fat maps on some paths; getattr/open is the refine pass | index + fuse + compositing |
| V-2 | Immutable versioned index + atomic root pointer | `partial` | M | G-2 publishes a blob; readers can still see a half-written sidecar during `-c` | index + remote + CLI |
| V-3 | Read-through cache in front of object storage | `todo` | L | Remote FUSE stalls on cold Range GET of index pages and seek maps; Cache-in-front-of-R2 is the highest-leverage steal | remote + compress + index |
| V-4 | WAL as coordinator, executor does the heavy write | `partial` | M | Interval / on-exit commit already splices last zstd frame; live ticks vs prefix-frame mutate need a single-writer queue | compositing + formats-tar |
| V-5 | Cluster by locality (offset order, not cosine) | `todo` | S–M | Sequential extract / `tar tv` / NFS readahead walk path order today, not archive order | index + formats-tar/zip/7z |

Suggested order: **V-1** (finish cheap find) → **V-2** (snapshot index; unblocks shared remotes) → **V-3** (remote cache; needs V-2 etag) → **V-4** (commit queue) → **V-5** (optional; F-9 producer helps).

---

## V-1 — Cheap scan, then refine

**Vectorize:** Product-quantized scan over the index, then a second pass that rescores the top hits with uncompressed floats so recall climbs from ~80% to >95%.

**What is useful:** Two-phase query. Phase 1 never materializes the expensive representation. Phase 2 runs only on hits.

**What we already have:**

- Codec path: sealed SoA seek maps (gzip checkpoints, zstd frames, bzip2 blocks) → decompress only the covering unit. That *is* PQ-then-refine for payload bytes.
- Metadata path: `list_dirents` from string pool + `EntrySoa` without `BTreeMap<String, FileInfo>`. Fat `FileInfo` only at getattr / open. Documented in [`vectors-optimization.md`](vectors-optimization.md) P0.
- `ratarmount find` + `/.ratarmount-control/search/` + socket `search` (F-3) walk the 0.7.x catalog.

**Still open:**

- [ ] `find` / control `search` / FTS hit list stay on SoA columns + pool ids; allocate `String` paths only for emitted rows.
- [ ] `list()` callers that still force a fat map on the live FUSE path (residual in vectors-optimization P0) get a typed “need FileInfo” flag instead of the default.
- [ ] Overlay-only names (F-3 residual) participate in cheap search without merging a second fat catalog.
- [ ] Regression: `find '*.fits'` RSS + wall on a 200k-member TAR vs materializing every `FileInfo`; control `search` same.

**Why it pays:** BIG-suite `find` is already ~1.3× Python; the remaining tax is path materialization and fat maps, not cosine math. Same toolbox as P0 density — do not invent an ANN layer.

**Do not:** approximate member *contents*. A 95% correct `cat` is corruption.

---

## V-2 — Immutable versioned index + atomic root pointer

**Vectorize:** Each IVF/metadata file is immutable and versioned. A *manifest* lists the snapshot. A *root manifest* at a deterministic R2 key is overwritten with an atomic PUT. Readers keep using snapshot N until the root pointer flips to N+1. Past versions stay around (Time Travel-shaped).

**What is useful:** Readers never open a half-written catalog. Rebuild (`-c`), `--publish-index`, and remote discovery can run while mounts stay warm on the previous blob.

**What we already have (G-2 `done`):**

- Media type `application/vnd.ratarmount.index.v1+sqlite`, inner `INDEX_VERSION` 0.7.0.
- Discovery: `--index-file` → local candidates → HTTP `Link: rel="describedby"` → sibling GET → OCI 1.1 referrer on local miss.
- `--publish-index` / `--publish-index-to PATH`; HTTP `GET /.ratarmount-control/index.sqlite`.
- `check_tarstats_matches_remote` after fetch.

**Still open:**

- [ ] Root pointer object separate from the SQLite blob: `{schema, index_id, etag/sha256, generated_at, archive_tarstats}`. Readers bind to `index_id`; writer publishes blob N+1 then replaces the pointer.
- [ ] `-c` writes a new sidecar (or `*.index.sqlite.tmp` + `rename`) and only then flips the pointer. Open mounts keep the mmap/connection to N.
- [ ] Shared remote index: do not PUT the live `.index.sqlite` in place (G-2 residual: no S3/GCS/Azure sibling GET/PUT in v1). Pointer + immutable key `index.{id}.sqlite` is the way to add that without torn reads.
- [ ] Optional keep-last-K snapshots (local only first). Not D1 Time Travel; just “remount --index-id” after a bad `-c`.
- [ ] Regression: mount process A stays readable while process B runs `-c` + publish; `check_tarstats` still rejects a replaced archive.

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

**Still open:**

- [ ] Process-local LRU (XDG cache dir, size cap) keyed by `(backend, url/etag, range)` for:
  - SQLite sidecar pages / whole sidecar when small
  - gzip/zstd/bz2 seek-map blobs (`zstdblocks`, `bzip2blocks`, RGZI/GZIDX)
  - outer `nestedindexes` RNIB blobs
- [ ] Revalidate with ETag / tarstats; miss → Range GET → fill cache → serve.
- [ ] Skip on `file://` and `:memory:` indexes.
- [ ] Do **not** cache uncompressed member bodies here (that is G-3).
- [ ] Regression: second mount of `s3://…/a.tar.zst` with published index does not Range-GET the sidecar again; corrupting the cached blob fails closed to refetch.
- [ ] Bench: cold vs warm remote mount wall + GET count (harness can fake HTTP).

**Why it pays:** Remote-first is already the product story. Density work made local `find` cheap; remote mounts still die on metadata RTT. This is the Vectorize Cache→R2 split with ANN removed.

**Depends:** V-2 etag/id in the pointer so cache keys stay stable across republish. Complements G-3 (payload) and F-9 (producer makes maps small).

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

**Still open:**

- [ ] Single-writer commit queue: interval/on-exit/offline enqueue one job; a second tick no-ops or coalesces instead of overlapping splices.
- [ ] Job record is lightweight (overlay file list + generation), not the spliced bytes. Executor performs splice / ZIP rebuild / sidecar patch, then the coordinator flips “visible archive + index” (local `rename`, later F-7 remote multipart).
- [ ] Hot files (open for write, younger than interval) stay in the overlay — already specified; keep that invariant in the queue.
- [ ] Prefix-frame mutate: queue must fail closed the same way live ticks do; do not start an executor that would rewrite the prefix under a reader.
- [ ] Regression: two interval fires during a long splice; readers never see a truncated `.tar.zst`; NFS/FUSE `overlay_commit_live_delete_shifts` stays green.
- [ ] Later: F-7 write-through uses the same queue (executor uploads, coordinator publishes pointer from V-2).

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

- [ ] Optional `list_dirents` / extract helper that yields dirents sorted by `offsetheader` (CLI flag or control file; default stays name order for `ls`).
- [ ] `find` output option: offset order for restore pipelines.
- [ ] Document that F-9 `--repack-seekable` should also keep members in offset order (already true for tar-in-order).
- [ ] Regression: restore of a 10k-member TAR via offset-ordered list does fewer backward seeks than name order (can count `pread` offsets in a fake reader).

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

- V-1: RSS + wall of `ratarmount find` / control `search` on large flat TAR (reuse density benches).
- V-2: two processes, `-c` in one, `cat` in the other; pointer flip is atomic; `check_tarstats` still fires on replaced archive.
- V-3: fake HTTP Range server; GET count on remount with cached sidecar + seek map.
- V-4: overlapping interval commits; existing `overlay_commit_live*` / `commit_overlay` tests stay green.
- V-5: pread offset monotonicity on offset-ordered restore vs name-ordered.

Every behavior change needs a regression test in the same PR (see root `AGENTS.md`).

## Related

- Density / SoA: [`vectors-optimization.md`](vectors-optimization.md)
- Portable index: [`beyond-parity-roadmap.md`](beyond-parity-roadmap.md) G-2
- Member cache: G-3 (payload; not V-3)
- Incremental commit: F-2, [`tar-zst-live-commit-design.md`](tar-zst-live-commit-design.md)
- Remote I/O: [`docs/phase10-remote.md`](../phase10-remote.md)
- Producer: F-9 `--repack-seekable`
