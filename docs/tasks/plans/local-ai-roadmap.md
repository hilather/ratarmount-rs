# Implement the Local AI roadmap in ratarmount-rs

Written 2026-10-16 against `main` at `db217f0`. Source document:
`~/Downloads/ratarmount-rs for Local AI Roadmap (1).md` (Oct 16, 2026,
"companion to the Local AI Plan"; this revision adds the "BitTorrent and Pirate
Face magnet links" section, tracked as AI-BT1 and AI-BT2). Goal set by the user: every proposal in that document is
fully supported by ratarmount-rs. Implementation is done by Codex workers in
git worktrees; this session orchestrates, reviews, merges and runs the gates.

The beyond-parity roadmap stays the engineering tracker for older items. This
file is the tracker for the AI items; each row's status is updated here when it
merges, and README / parity docs are updated in the same merge.

## 1. Scope decisions

| Decision | Detail |
|---|---|
| In scope | Every proposal in the document, including its "later" list: Hub write-back, the CSI driver, parallel gzip in packaged builds. |
| Not built, on the document's own terms | **Expert-overflow inference backend** (the document: "belongs inside the engine with direct `io_uring` reads") and **a checkpoint dedup store** ("content-defined chunking finds little"). Supporting the document means honoring these two non-goals. The user can override. |
| Outward-facing, prepared here, published only on the user's say-so | Seeding to a public BitTorrent swarm, PyPI wheels, conda-forge feedstock, AUR package, Homebrew core formula, nixpkgs, the `huggingface_hub` docs PR, a public Hub dataset with a published index, any `git push` / PR to GitHub. |
| Hardware not available to this session | DGX Spark / Dell GB10, the M5 MacBook, the two-Dell ConnectX-7 link. Scripts, guides and local runs on this laptop (Linux 7.2, x86_64) are delivered; the numbers on those machines need those machines. |
| Python track | Cuttable. Nothing else depends on it (see the dependency graph in section 5). The Rust APIs under it (AI-0d) stay because FUSE passthrough and the shard tool also use them. |

## 2. Corrections to the roadmap document (verified in the repo, 2026-10-16)

1. **FUSE passthrough cannot map a member's range inside an archive.** The
   kernel's `fuse_backing_map` is `{fd, flags, padding}` (checked in fuser
   0.18.0 `src/ll/ioctl.rs`); there is no offset, so a backing file is served
   from byte 0. Passthrough applies directly to overlay fds and plain files in
   folder / whole-repo mounts. For stored (uncompressed) tar members the design
   is a per-member backing file: `FICLONERANGE` (which does take source and
   destination offsets) clones the member's byte range into a cache file at zero
   cost on btrfs/XFS, with a plain copy as the fallback, then that file is the
   backing fd. Remote members use the range cache file once complete.
2. **fuser 0.15.1 has no passthrough at all.** fuser 0.18.0 (2026-07-22,
   MSRV 1.85) does (`BackingId`, `ReplyOpen::opened_passthrough`,
   `KernelConfig` max stack depth). The 0.15 → 0.18 upgrade is three major
   versions and is its own workstream (AI-0a).
3. **`--publish-index` is local only.** It copies the sidecar and writes a
   `.ptr` next to a local path (`ratarmount/src/publish_index.rs`). The
   beyond-parity roadmap's `put_s3_file` / `publish_index_to_s3` do not exist;
   remote index PUT exists only inside the live overlay commit
   (`put_s3_index_siblings`). `--publish-index hf://` needs a remote publish
   path built from scratch.
4. **There is no remote range cache.** `RATARMOUNT_PAYLOAD_CACHE_BYTES` exists
   (4 GiB default, `payload-v1/`), but it stores whole decompressed members
   keyed by sha256 and only engages with `--hashes`. Lazy model loading from
   `hf://` needs a range/chunk cache under `HttpRangeFile`.
5. **The HTTP reader is one fresh connection and one GET per `read()`.**
   `ureq` 2.12 free functions build a new `Agent` per call, there is no
   connection reuse, no readahead, no Bearer auth on `http(s)`, and the tar
   reader is behind a `Mutex`. A `/resolve/` 302 would be repeated on every
   read. ureq strips `Authorization` on redirect (correct for the CDN hop), so
   the CDN URL must be resolved once per file and reused until it expires.
6. **Data writes bypass `WriteOverlay`.** FUSE, NFS, 9P, SFTP, SMB and WebDAV
   each `pwrite` the overlay fd directly, so a quota needs a shared write
   funnel first. The three errno mappers (export-core, FUSE, NFS) match on
   `ErrorKind` and fall back to `EIO`, so `EROFS` / `EDQUOT` need explicit arms.
7. **Every commit path copies the archive.** Uncompressed TAR (offline and
   live) copies the whole file to a sibling; `.tar.zst` copies the compressed
   prefix (`ratarmount-compress/src/zstd_splice.rs:61`). There is no
   append-in-place commit.
8. **Git mounts take no ref.** The factory always passes `None`;
   `GitMountSource::with_prefix` has no caller; only bare repos / `.git` dirs
   (or `RATARMOUNT_FORCE_GIT`) use git at all.
9. **The beyond-parity roadmap has duplicate F-6/F-7/F-8/G-3/G-4/G-5 rows with
   conflicting statuses.** AI-0e cleans that up so status reads are honest.
10. **An unmerged branch, `execute-plan/0dde7c7d-integration`** (72 commits,
    merge-base `0934b9b`), has a small `ratarmount-python` crate (embedding
    only, rlib, no packaging) that ports cleanly to `main`. Only that crate is
    ported; the branch's root `Cargo.toml`, G-4 snapshot crates, winfsp mock,
    csi argv builder and `chunk_cache.rs` are not merged by this plan. The
    uncommitted wheel / CSI gRPC / quota work described in
    `partial-features-completion.md` was lost with `/tmp/grok-stack-0dde7c7d`.
11. **librqbit (9.0.1) streams on demand and has LAN discovery, but no web
    seeds.** `torrent_state/streaming.rs` gives piece-on-read streaming and
    `librqbit_lsd` gives BEP 14; there is no BEP 19 `url-list` support. The
    "web seed first" path is therefore built on AI-0b's HTTP range reader,
    fetching whole pieces from the Hugging Face web seed and checking them
    against the torrent's piece hashes, with librqbit as the swarm fallback.
    librqbit pulls in tokio and reqwest, so the backend sits behind a
    `bittorrent` cargo feature (on in package builds, off in the minimal one).

## 3. Tracking table

Model column: **astra** = `gpt-6-astra` (frontier; concurrency, kernel ABI,
crash safety, protocol design), **sol** = `gpt-6.1-sol` (workhorse feature
work), **luna** = `gpt-6-luna` (docs, packaging, scripts). Effort in brackets.

| ID | Roadmap item (section) | Wave | Model | Owned paths | Acceptance (tests + docs) | Status |
|---|---|---|---|---|---|---|
| AI-0a | fuser 0.15 → 0.18 (prereq for §8 passthrough) | 0 | astra [xhigh] | `ratarmount-fuse/**`, fuser line in Cargo.toml/lock | Whole `ratarmount-fuse` lib suite and `ratarmount` FUSE integration tests green; `cargo check --target aarch64-apple-darwin -p ratarmount-fuse` or macOS CI job green; no behavior change | todo |
| AI-0b | Pooled HTTP agent, Bearer auth, cached redirect target, parallel ranges (§3.1, §8 remote reads) | 0 | sol [xhigh] | `ratarmount-remote/src/lib.rs` (`HttpRangeFile`, auth), new `http_pool.rs` | Local test server: N reads reuse 1 connection; 302 resolved once per file and re-resolved on 403/expiry; Authorization never sent to the redirect host; sequential read of 64 MiB issues ≥4 concurrent ranges; short-read/fill-loop regressions stay green | todo |
| AI-0c | Overlay write funnel + policy hook + errno arms (prereq for §4.2, §4.3) | 0 | astra [high] | `ratarmount-compositing/src/write_overlay.rs` (hook points only), six frontends' write call sites, three errno mappers | Every frontend's data write goes through `WriteOverlay::write_at`; a test policy that denies a path yields `EROFS` on FUSE/NFS/9P/SFTP/SMB/WebDAV unit tests and `EDQUOT` likewise; no existing overlay test changes | todo |
| AI-0d | Session library-mode APIs (§5 library mode, §10 wheels) | 0 | sol [xhigh] | `ratarmount-session/**`, `ratarmount-index/src/dirent_order.rs` | `Session::member_extent(path)` returns `{file, offset, len}` only for uncompressed, non-sparse, non-encrypted members (tests for tar, tar.zst → None, sparse → None); paged `iter_by_offset(cursor, limit)` with no duplicates over 10k members; `OpenRequest.parallelization` reaches the codecs (zstd multi-frame decode test); `docs/session-api.md` updated | todo |
| AI-0e | Roadmap hygiene | 0 | luna [medium] | `docs/tasks/beyond-parity-roadmap.md` | One row per ID with the latest status; F-7 notes gs/az live PUT; G-3 notes "no range cache" | todo |
| AI-HF1 | `hf://` read backend: path format, revision pinning, auth, whole-repo tree, Xet check (§3.1, §3.3) | 1 | astra [xhigh] | new `ratarmount-remote/src/hf.rs`, `REMOTE_SCHEMES`, `remote_open.rs` arms, `ratarmount-index/src/location.rs` hf siblings | Parser tests for `hf://[datasets/|spaces/]org/name[@rev]/path` incl. `refs/pr/N` and `%2F`; revision → commit sha resolved once and stored in index metadata; tree API pagination via `Link` header (mock server, 3 pages); token from `HF_TOKEN`, `HF_TOKEN_PATH`, `$HF_HOME/token`, `~/.cache/huggingface/token`; `HF_ENDPOINT` override; gated repo 401 → clear error; whole-repo mount passes through Parquet/JSONL, archives open with `-r`; sibling `.index.ptr` discovered through resolve URLs; live test against the public Hub skipped when offline; README remote table + `docs/remote-hf.md` | todo |
| AI-RC | Remote range cache on NVMe, LRU, shared cap with payload-v1 (§6.1, §8) | 1 | sol [xhigh] | new `ratarmount-index/src/range_cache.rs`, hook in `HttpRangeFile` | Chunks keyed by verified content token (commit sha + path, ETag or `X-Linked-Etag`), never by URL alone; `RATARMOUNT_PAYLOAD_CACHE_BYTES` caps payload-v1 + range-v1 together, `0` disables; second read of a file does 0 GETs (mock server); torn chunk / symlink / wrong token tests | todo |
| AI-GIT | Git ref selection + `--git-synthetic-head` (§4.1) + many-repo prerequisite for corpus (§5) | 1 | astra [xhigh] | `ratarmount-formats-git/**`, git arm in `factory.rs`, git flags in `main.rs` | `repo.git@<rev>` and `--git-ref`; synthetic `.git` holds one parentless commit whose tree equals the mounted tree, built from tree-reachable objects only in a fresh object store (no alternates: `git cat-file --batch-all-objects` must not list the fix commit — test asserts it); `git status` clean and `git diff` works after an overlay edit; `git log` shows one commit; the synthetic `.git` lives in the overlay so git can write its index; `docs/git-mounts.md` | todo |
| AI-SB1 | `--overlay-readonly <globs>`, `--overlay-quota`, `overlay-stats` (§4.2, §4.3) | 1 | sol [high] | new `ratarmount-compositing/src/overlay_policy.rs`, flags in `main.rs` | `EROFS` on write/create/truncate/rename/unlink/mkdir under `t/**`; quota counts bytes and files across all frontends via AI-0c and returns `EDQUOT`; `ratarmount overlay-stats <dir>` prints bytes written, files touched, deleted (JSON with `--json`); tests per frontend for both | todo |
| AI-PT | FUSE passthrough (§8) | 1 | astra [xhigh] | `ratarmount-fuse/**`, new `ratarmount-core` `MountSource::backing_extent` default `None` | Negotiated only when the kernel offers it, else daemon path (test both by forcing off); passthrough for overlay fds, folder plain files, completed range-cache files, stored tar members via `FICLONERANGE` clone with copy fallback under a byte cap; `--passthrough auto|on|off`; log which path a mount uses; FUSE integration test reads identical bytes with and without; `docs/fuse-kernel-tuning.md` | todo |
| AI-CM1 | Reflink / `copy_file_range` commits, append-only commit mode (§7) | 1 | astra [xhigh] | `ratarmount-compress/src/zstd_splice.rs`, commit section of `write_overlay.rs` (`persist_*`, `commit_overlay_tar*`), `ratarmount-formats-tar/src/write.rs` | Copy sites use `FICLONE`/`FICLONERANGE`, then `copy_file_range`, then `io::copy`, logging the path taken; append-only mode for add-only intervals: journal records last valid length, appended frames + rewritten seek table, crash at each step (injected) recovers to the old or new archive on next mount — never a third state; F-2 incremental reindex reused; all existing commit regressions green | todo |
| AI-ST | safetensors + GGUF format plugin (§6.2) | 1 | sol [high] | new `ratarmount-formats-tensors/**`; factory wiring by orchestrator | Each tensor is a file at its byte range (zero-copy `StenciledFile`), `<name>.json` sidecar with dtype/shape/offsets; GGUF v3 KV header + tensor infos; `__metadata__.json`; sharded `model.safetensors.index.json` lists across shards when mounted as a folder; truncated/oversized-header fail-closed tests; README formats table | todo |
| AI-PY1 | Python binding: port, cdylib + maturin, pytest (§10) — **cuttable** | 1 | sol [high] | new `ratarmount-python/**`, `pyproject.toml` | Port only `ratarmount-python` from the integration branch; module imports in a fresh venv; `open/ls/read/mmap/iter`; GIL released on blocking calls; pytest covers paging without duplicates, `bytes` range reads, invalid range, missing member, extract skip/replace, mmap equals read for stored members; not in default workspace features | todo |
| AI-HF2 | `--publish-index` to `hf://` (and s3/gs/az) (§3.2) | 2 | sol [xhigh] | `ratarmount/src/publish_index.rs`, new `ratarmount-remote/src/hf_commit.rs` | HF commit API: preupload check, LFS batch upload for the sqlite blob, NDJSON commit with `.ptr`; blob then pointer ordering (fail-closed like V-2); mock-server tests; real-Hub test gated on `RATARMOUNT_TEST_HF_REPO` + token; README recipe for dataset authors | todo |
| AI-HF3 | Shared Hub cache + `hf-cache://` offline mounts (§3.4, §3.5) | 2 | sol [high] | `ratarmount-remote/src/hf_cache.rs`, range cache hook | Completed whole files land in `$HF_HUB_CACHE` as `blobs/<etag>` + `snapshots/<sha>/<path>` symlinks + `refs/<rev>`, atomically, never `.incomplete` partials; reads hit an existing Hub cache blob before the network; `hf-cache://org/name@rev` mounts a cached snapshot offline with archives opening in place; layout compatibility test against `huggingface_hub` when Python + package available (skip otherwise) | todo |
| AI-BT1 | `magnet:` / `.torrent` remote: lazy file tree, on-demand pieces, web seed first, piece + Hub SHA-256 checks, archives inside torrents (BitTorrent §1–4) | 2 | astra [xhigh] | new `ratarmount-remote/src/torrent/**` behind feature `bittorrent`, `REMOTE_SCHEMES`, `remote_open.rs` arm | File tree listed from metadata before any piece is fetched (magnet resolves metadata via DHT/trackers/web seed); reads fetch the pieces under the read plus `--readahead` pieces, highest priority first; BEP 19 web seed served through AI-0b with whole-piece fetch and SHA-1 piece check, swarm (librqbit streaming) only when the web seed fails or is absent; a tampered piece is refused and refetched, never returned; completed files checked against the Hub SHA-256 (from the torrent's metadata or the Hub tree API's `lfs.oid`; task records which Pirate Face provides) and refused on mismatch; v2 / hybrid torrents use per-file piece roots when present; `-r` opens tar shards in place; a `*.index.ptr`/sidecar shipped in the torrent is discovered like a sibling; tests use an in-process tracker-less swarm on loopback plus a local HTTP web seed (no public network in CI); live Pirate Face test gated on `RATARMOUNT_TEST_MAGNET`; `docs/remote-bittorrent.md` with the network-policy caveat | todo |
| AI-SB2 | `ratarmount diff <overlay> [--git]` (§4.4) | 2 | sol [high] | new `ratarmount/src/diff.rs`, read-only use of overlay DB | Unified diff of modified/added/deleted/renamed files from the overlay alone; `--git` output passes `git apply --check` on the base checkout; binary files as `GIT binary patch` or a "Binary files differ" line; symlinks and mode changes | todo |
| AI-SB3 | uid/gid mapping, `--sandbox` preset, `--overlay-tmpfs` (§4.5) | 2 | sol [high] | attr builders in FUSE/NFS/9P/SFTP, `-o` parsing, `main.rs` | `-o uid=,gid=,umask=` applied to every attr path (unit test per frontend); `--sandbox` = `allow_other,noatime,uid/gid of caller unless given, --overlay-tmpfs`; `--overlay-tmpfs` puts the overlay on `memfd`/`/dev/shm` with a size cap; clear error when `user_allow_other` is missing; `docs/sandbox.md` documents `/etc/fuse.conf` | todo |
| AI-PERF | Parallel zstd decode-ahead, `posix_fadvise`, `--direct-io` (§8) | 2 | astra [high] | `ratarmount-compress/src/zstd_seek.rs`, fuse open flags | Bounded decode-ahead pool sized by `--readahead`/`--parallelization`, frames delivered in order, cancellation on seek; sequential `cat` of a 1 GiB multi-frame shard uses >1 core and matches bytes; `POSIX_FADV_SEQUENTIAL` on archive fds; `--direct-io` sets `FOPEN_DIRECT_IO` and drops archive pages after read; benchmark script entry | todo |
| AI-SH | `ratarmount shard` + `export-index --format parquet\|jsonl` (§5) | 2 | sol [high] | new `ratarmount/src/shard.rs`, `export_index.rs`; parquet behind feature `export-parquet` (on in packages) | Packs a dir into N `.tar.zst` shards ≤ `--size`, seek table per shard, one index each, `shards.json` manifest; `--group-by-key` keeps WebDataset `basename.{jpg,json,txt}` in one frame; `--frame-per-sample`; sorted, reproducible bytes for the same input; parquet rows `path, shard, offset, size, frame, frame_offset` match index; README | todo |
| AI-PV | Provenance xattrs + sidecar manifest on commit (§7) | 2 | astra [high] | overlay xattr table + `setxattr`/`removexattr` in FUSE, `UstarMember` xattrs, index insert, `find --xattr` | `setfattr -n user.train_ok -v false` survives commit as PAX `SCHILY.xattr.user.*`, reindex, remount; `find --xattr train_ok=false`; only `user.*` writable; each commit writes `archive.manifest.jsonl` (path, size, sha256, xattrs, commit id) atomically | todo |
| AI-PY2 | fsspec `ratar://` + chained URLs, torch Dataset, WebDataset reader, wheel CI (§5, §10) — **cuttable** | 2 | sol [high] | `ratarmount-python/python/**`, `.github/workflows/python.yml` | `fsspec.open("ratar::hf://...")` and `ratar://path.tar.zst::member`; registered via entry point; `datasets` webdataset load test against a local shard set (skip if package absent); torch `Dataset` + WebDataset-style iterator over AI-SH shards; manylinux x86_64/aarch64 + macOS arm64 wheels built in CI; installed-wheel smoke test | todo |
| AI-BT2 | LAN sharing (BEP 14), opt-in `--seed` with upload cap, one cache with `hf://`, v2 preference (BitTorrent §5–7, caveats) | 3 | sol [xhigh] | `ratarmount-remote/src/torrent/**`, cache glue with AI-RC / AI-HF3 | LSD on by default for magnet mounts with `--no-lsd` to disable; two-session loopback test fetches from the LAN peer with the web seed disabled; `--seed` off by default, serves only verified pieces from the cache, `--seed-upload-limit` enforced (rate test); completed verified files stored in the Hub-style blob cache keyed by SHA-256 so `hf://` reuses them and vice versa (test both directions); BitTorrent v2 chosen when a magnet offers both v1 and v2 info hashes | todo |
| AI-CM2 | Rolling archives `--roll-every 1d\|20G` (§7) | 3 | sol [high] | roll policy module, union of series | New archive when the size/time limit is hit; series mounted as one tree; old archives removable while mounted; naming `name.000001.tar.zst`; tests for both triggers | todo |
| AI-UN | Per-source subpaths, image + repo union, `corpus` verb (§4.6, §5) | 3 | sol [high] | factory compositing glue, `main.rs` | `SRC::/repo` (or `--bind /repo=SRC`) wraps a source in `PrefixMountSource` before the union; `docker://img` + git repo at `/repo` test with a local OCI layout; `ratarmount corpus list.txt mnt/` mounts `repo@sha` lines at `org/name/`; recipe for bwrap/nspawn | todo |
| AI-SB4 | Sandbox API: `sandbox new\|list\|destroy` + Python client (§4.7) | 3 | astra [xhigh] | new `ratarmount/src/sandbox/**`, `clients/python/ratarmount_sandbox.py` | Daemon over a Unix socket (JSON lines, `0600`), one shared base per task, N overlay mounts per request, destroy unmounts and deletes; crash of an attempt mount does not affect siblings; pure-Python client (no binding) ~100 lines with a test; 64 parallel attempts integration test (FUSE, run by orchestrator) | todo |
| AI-SNAP | `ratarmount snapshot add <dir>` restic wrapper + recipe (§4.8) | 3 | sol [medium] | `ratarmount/src/snapshot.rs`, `docs/recipes/` | Wraps the `restic` binary (init if missing, backup with tags, prints the `restic:` mount path); skip test when `restic` is absent; mounted snapshot reads identical bytes | todo |
| AI-MEM | `--memory-budget` across buffers, decode windows, caches; reported by control interface (§9) | 3 | astra [high] | new `ratarmount-core/src/budget.rs`, cache registration sites | Global accountant; caches register and shrink under pressure; zip inflate cache capped by bytes; budget and usage in socket `status` and `/.ratarmount-control/status`; test that RSS-relevant caches stay under a 64 MiB budget on a stress read | todo |
| AI-DK | Docker / Podman volume plugin (§10) | 3 | sol [high] | new `ratarmount-volume-plugin/**` (binary), systemd unit | Docker plugin API v1 over `/run/docker/plugins/ratarmount.sock`: Create/Remove/Mount/Unmount/Path/Get/List/Capabilities; options `source=`, `overlay=tmpfs\|<dir>`, `ro`; HTTP-level tests without Docker; Docker integration script skipped when unavailable | todo |
| AI-PKG | AUR, Nix flake, conda recipe, Homebrew core formula draft, wheels in Packages (§9, §10) | 3 | luna [medium] | `packaging/aur/`, `flake.nix`, `packaging/conda/`, `packaging/homebrew/` | `makepkg --printsrcinfo` and `namcap` (skip if absent); `nix flake check` (skip if no nix); packaging test scripts per AGENTS.md; nothing published | todo |
| AI-BENCH | Six AI benchmarks, DGX Spark guide, NVMe placement, Apple silicon notes, two-box NFS benchmark (§8, §9) | 3 | sol [medium] | `benchmarks/ai/**`, `docs/local-ai/**` | Each benchmark script runs on this laptop at small scale and writes CSV; guide pages; results table marks GB10/M5 cells "needs hardware" | todo |
| AI-DOCS | Recipes: SWE-bench/mini-swe-agent, OpenHands/SWE-smith, vLLM/llama.cpp, WebDataset/img2dataset, DistillKit logits, Common Crawl, checkpoint archives (§6.3, §7, §10) | 3 | luna [medium] | `docs/recipes/**` | Each page has a runnable script; scripts are smoke-tested at small scale where tools exist | todo |
| AI-PY3 | `.mount()` and `.index.publish()` from Python (§10) — **cuttable** | 3 | sol [high] | `ratarmount-python/**` | Mount and unmount from Python on Linux; publish to a local path and to a mock HF server | todo |
| AI-HFW | Write-back to the Hub through the overlay (§3 open question, §later) | 4 | astra [xhigh] | `ratarmount/src/overlay_commit.rs` hf arm | Live commit of a `.tar.zst` in a dataset repo through AI-HF2's commit path, index republished, revision advanced; mock server tests; real Hub test gated | todo |
| AI-CSI | CSI node plugin (§10, §later) | 4 | astra [xhigh] | new `ratarmount-csi/**` (own binary, not in default packages) | gRPC Identity + Node over a Unix socket; supervised `ratarmount` child per volume; persisted journal for idempotent publish/unpublish across restarts; secrets via env only; per-pod overlay; manifests in `packaging/csi/`; `csi-sanity` and kind test scripts (privileged, not default CI) | todo |
| AI-GZ | Parallel gzip in packaged builds (§later) | 4 | sol [medium] | packaging feature lists | Enable `gzip-rapidgzip` in package scripts if the A/B gate shows no regression; otherwise record the measured reason and leave off | todo |

Proposals that are already covered by existing features and need only a recipe
or documentation (no new code, per the document): teacher logits as shards
(§7, AI-DOCS + AI-SH), Common Crawl WARC (§5, AI-DOCS), checkpoint archives
(§6.3, AI-DOCS after AI-CM1), the NFSv4.1 two-box share (§9, AI-BENCH).

## 4. Design notes Codex prompts must carry

- **AI-GIT:** never use git alternates or a shared object directory. Copy only
  objects reachable from the mounted tree into a fresh store, write one
  parentless commit, and generate the index with stat data matching the
  mount's attributes so `git status` does not rehash every file. The synthetic
  `.git` is materialized once per base (cached next to the index) and exposed
  writable through the overlay.
- **AI-0b / AI-HF1:** keep ureq (no tokio). One shared `Agent` per process.
  Resolve `/resolve/` redirects once per file; re-resolve on 403 / expired
  signed URL. Verify with a real Xet-backed file whether the CDN target honors
  `Range` and parallel requests before turning parallel ranges on for it;
  record the finding in `docs/remote-hf.md`.
- **AI-RC / AI-HF3:** content identity is the commit sha + path, or the file's
  ETag / `X-Linked-Etag` (sha256 for LFS files). A URL alone is never a cache
  key. Hub-cache blobs are only written when complete and verified.
- **AI-0c / AI-SB1:** the policy is evaluated in `WriteOverlay`, never in a
  frontend, so all six frontends agree. Quota counts the overlay's on-disk
  bytes including copy-on-write copies.
- **AI-CM1:** the append path must be crash-safe at every syscall boundary.
  The journal is fsynced before the first byte is appended; recovery runs on
  mount and before the next commit.
- **AI-BT1 / AI-BT2:** no test touches the public swarm or a public tracker;
  live runs are opt-in by env var. Seeding is never on by default and never
  enabled by the orchestrator on this machine. Piece verification happens
  before any byte reaches a reader or the cache.
- **AI-PT:** passthrough is negotiated, never assumed. Fallback is the current
  daemon path. macOS keeps the daemon path; measure the gap in AI-BENCH.
- **AI-PY1:** port only `ratarmount-python/` from
  `execute-plan/0dde7c7d-integration` (`git show <branch>:<path>`). Do not
  cherry-pick that branch's root `Cargo.toml`, snapshot crates, winfsp, csi or
  `chunk_cache.rs`.

## 5. Waves and dependencies

```
Wave 0  AI-0a fuser ─────────────┐        AI-0b http ──┬─────────┐      AI-0c overlay funnel ─┐     AI-0d session APIs ─┐   AI-0e docs
Wave 1  AI-PT passthrough ◄──────┘        AI-HF1 hf:// ◄┘  AI-RC ◄┘      AI-SB1 ◄──────────────┘     AI-PY1 ◄────────────┤
        AI-GIT   AI-CM1   AI-ST                                                                                          │
Wave 2  AI-BT1 (0b,HF1,RC)  AI-HF2 (HF1)  AI-HF3 (HF1,RC)  AI-SB2  AI-SB3  AI-PERF  AI-SH  AI-PV (after CM1)                AI-PY2 (PY1,SH) ◄┤
Wave 3  AI-BT2 (BT1,HF3)  AI-CM2 (CM1,PV)  AI-UN (GIT)  AI-SB4 (SB1-3,UN)  AI-SNAP  AI-MEM (RC,PERF)  AI-DK (SB3)  AI-PKG  AI-BENCH  AI-DOCS   AI-PY3 (PY2) ◄┘
Wave 4  AI-HFW (HF2,CM1)  AI-CSI (SB3)  AI-GZ
```

The Python column (AI-PY1..3) has no dependents; removing it removes nothing
else. AI-0d stays regardless (AI-PT stored members and AI-SH use it).

Mapping to the document's suggested order: its step 1 (prove on our own work)
is AI-BENCH + AI-DOCS, started in wave 3 once there is something to measure
but with the benchmark harness skeleton landing with AI-PERF; step 2 = HF1,
HF2; step 3 = SB1–SB3, GIT; step 4 = CM1; step 5 = PY1–PY3; step 6 = PT;
step 7 = ST, HF3, CM2, MEM; the BitTorrent section ("after `hf://` read
mounts, since it reuses their cache and range code") = BT1 in wave 2, BT2 in
wave 3; step 8 = SB4, DK, UN; step 9 = PV; step 10 = HFW,
CSI, GZ. Waves differ from that order only where a prerequisite forces it
(fuser upgrade before passthrough, write funnel before quotas).

## 6. Hot-file ownership

| File | Rule |
|---|---|
| `ratarmount/src/main.rs` (one flat clap `Args`, argv[1] verbs) | Each task adds its flags in one contiguous block and its verb in `parse_args_from`; the orchestrator resolves merge conflicts. New verbs live in their own module. |
| `ratarmount-compositing/src/write_overlay.rs` | One owner per wave: AI-0c (wave 0), AI-CM1 (wave 1; SB1 works in `overlay_policy.rs` only), AI-PV (wave 2), AI-CM2 (wave 3). |
| `ratarmount-session/src/factory.rs` | Orchestrator wires new formats (AI-ST); AI-GIT owns the git arm; AI-UN owns compositing glue in wave 3. |
| `ratarmount-remote/src/lib.rs` | AI-0b (wave 0), AI-HF1 (wave 1, new file plus registration lines), then additive only. |
| `Cargo.lock` | Regenerated by the orchestrator after each merge. |
| `AGENTS.md` regression catalog, `README.md`, `docs/parity-todo.md`, this table | Orchestrator, in the merge commit. Workers report their catalog row and docs delta. |

## 7. Orchestration protocol

- **Branches.** Integration branch `local-ai/integration` off `main`. Each
  task runs in its own worktree under `/home/brewerm/git/local-ai-worktrees/<id>`
  on branch `local-ai/<id>`, created from the integration tip at launch.
- **Codex invocation.**
  `codex exec -m <model> -c model_reasoning_effort=<effort> -s workspace-write
  -c sandbox_workspace_write.network_access=true --add-dir <repo>/.git
  --add-dir ~/.cargo -o <out> "<prompt>"` from the worktree root, with
  `CARGO_BUILD_JOBS=4`. At most 3–4 workers at once (12 cores).
- **Sandbox limits (preflight 2026-10-16).** Inside the Codex sandbox, network
  and `~/.cargo` writes work (crates fetch, `cargo build` passes), but `.git`
  is mounted read-only even with `--add-dir`, and `/dev/fuse` is absent.
  Therefore workers leave their change uncommitted in the worktree; the
  orchestrator reviews, commits on the worker branch (attribution lines per
  session policy), and runs every FUSE-mounting test outside the sandbox.
  Host note: `/etc/fuse.conf` has `user_allow_other` commented out, so
  `allow_other` tests (AI-SB3, AI-SB4, AI-DK) need the user to enable it.
- **Prompt contents.** Task ID and goal, the relevant section of the roadmap,
  the verified facts from section 2, the design notes from section 4, owned
  paths, acceptance tests, and the Deliverable block from
  `.grok/skills/ratarmount-worktree-subagent/SKILL.md` (fmt, scoped clippy and
  tests, regression tests named after the symptom, no commit and no push
  because of the sandbox, final report with files changed, tests added,
  AGENTS.md catalog row, docs delta, and anything that needs `/dev/fuse`).
- **Review before merge.** Diff read by the orchestrator plus an independent
  review pass for xhigh tasks; findings go back to the same Codex session
  (`codex exec resume`) rather than being patched by hand.
- **Gates on the integration branch after every merge.**
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, plus FUSE integration tests run outside the Codex
  sandbox, and feature builds touched (`nfsv4`, `sftp-russh`, `export-parquet`,
  python).
- **Publishing.** Nothing is pushed until the user asks. When asked: one PR per
  wave (or per large task) against `main`, CI watched until green.
