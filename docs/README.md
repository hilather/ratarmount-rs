# ratarmount-rs documentation

Everything is grouped by what you are trying to do. The first group is enough
for most people; the last group is for maintainers.

## Start here

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | Mounting, nested archives, finding files, remote URLs, writing, serving and tuning, one command at a time |
| [Supported formats](formats.md) | Every archive, image, codec and model format: random access, nested behaviour, write support, limits, measured numbers |
| [Install and packages](packaging.md) · [macOS](macos.md) | Release packages, signatures, building from source, macFUSE and FUSE-T |
| [Caches](caches.md) | Where indexes, downloaded ranges and Hub blobs live, and the environment variables that size them |
| [Benchmarks](benchmarks.md) | All measured results, what they mean, how to reproduce them |

## Local AI

| Page | What it covers |
|---|---|
| [Local AI guide](local-ai/index.md) | The hub for datasets, models, sandboxes and shards |
| [Hugging Face Hub](remote-hf.md) | `hf://` mounts, pinned revisions, published indexes, write-back, the shared Hub cache, `hf-cache://` offline |
| [BitTorrent and Pirate Face](remote-bittorrent.md) | Magnet and `.torrent` mounts, web seeds, verification, LAN sharing, opt-in seeding |
| [Python library](python.md) | `ratarmount_rs`: reads, mmap, iteration, fsspec, PyTorch, WebDataset, mounting and publishing from Python |
| [Dataset shards](shards.md) | `ratarmount shard` and `export-index` |
| [Tensor formats](formats-tensors.md) | Safetensors and GGUF files as directories of tensors |
| [Sandboxes](sandbox.md) | Read-only paths, quotas, RAM overlays, ownership mapping, the sandbox supervisor and its Python client |
| [Git mounts](git-mounts.md) | Mount any commit, history-free synthetic heads, pinned code corpora |
| [Provenance](provenance.md) · [Rolling archives](rolling-archives.md) | Extended attributes that survive commits; archive series that roll by size or time |
| Recipes | [SWE-bench sandboxes](recipes/swe-bench-sandboxes.md) · [image rootfs + repository](recipes/sandbox-rootfs.md) · [vLLM and llama.cpp models](recipes/local-models.md) · [WebDataset shards](recipes/webdataset-shards.md) · [teacher logits](recipes/teacher-logits.md) · [Common Crawl WARC](recipes/common-crawl-warc.md) · [checkpoint archives](recipes/checkpoint-archives.md) · [publish an index to the Hub](recipes/publish-hf-index.md) · [deduplicated snapshots](recipes/dedup-snapshots.md) |
| Hardware | [DGX Spark and GB10](local-ai/dgx-spark.md) · [NVMe placement](local-ai/nvme-placement.md) · [Apple silicon and VMs](local-ai/apple-silicon.md) · [Two boxes over NFS](local-ai/two-box-nfs.md) · [Measured results](local-ai/results.md) |

## Formats in depth

| Page | What it covers |
|---|---|
| [Nested archives and temp files](embedded-nested-archives.md) | The canonical matrix of which nested formats open without `/tmp` and how random reads behave |
| [Zstd random access](zstd-random-access.md) | Multi-frame and seek-table zstd, `--repack-seekable`, live commits, decode-ahead |
| [Gzip design decision](gzip-binding-decision.md) | Why gzip seeks the way it does and what rapidgzip parity still needs |
| [Cold index and sparse TAR](cold-index-and-sparse.md) | Index build performance and sparse member handling |
| [restic](restic.md) | Browsing restic repositories |

## Remote sources

| Page | What it covers |
|---|---|
| [Remote inputs](phase10-remote.md) | Every URL scheme, authentication, folder listings, index discovery, the persistent range cache |
| [Hugging Face Hub](remote-hf.md) · [BitTorrent](remote-bittorrent.md) | The two AI-specific backends |

## Writing

| Page | What it covers |
|---|---|
| [Writing into archives](write-overlay.md) | Overlays, offline and live commits, what each archive format supports, safety rules |
| [Sandboxes](sandbox.md) | Policies on top of overlays |
| [Zstd random access](zstd-random-access.md#live-overlay-commit) | Commit modes and the last-frame rewrite in detail |

## Serving and deployment

| Page | What it covers |
|---|---|
| [NFS export](nfs-export.md) | NFSv3 by default, NFSv4.1 opt-in, kernel client verification |
| [HTTP, WebDAV, SMB, 9P, SFTP](export.md) | The other userspace exports |
| [systemd, fstab, autofs](systemd-mount.md) | The `mount.fuse.ratarmount` helper for HPC hosts |
| [Kubernetes CSI](csi.md) · [Docker and Podman volume plugin](docker-volume-plugin.md) | Container platforms |
| [FUSE kernel tuning](fuse-kernel-tuning.md) · [Memory budget](memory-budget.md) | Passthrough, direct I/O, readahead, pool caps |

## Embedding

| Page | What it covers |
|---|---|
| [Session API](session-api.md) | The in-process Rust API that the CLI, exports and Python all use |
| [Python library](python.md) | The Python face of the same API |

## Reference matrices and trackers (maintainers)

These pages track status against the Python original and record engineering
decisions. They are accurate but terse.

- [Feature and test parity checklist](parity-todo.md) · [mount option parity](mount-options-parity.md)
- [Beyond-parity roadmap](tasks/beyond-parity-roadmap.md) · [Local AI roadmap plan](tasks/plans/local-ai-roadmap.md)
- [Upstream feature requests](tasks/upstream-feature-requests.md) · [upstream bugs inspection](tasks/upstream-bugs-inspection.md)
- [Dual-run status](phase12-dual-run.md) · [crates.io policy](crates-io-policy.md) · [provenance of the Phase 9 format work](phase9-formats.md) · [Phase 11 packaging](phase11-packaging.md)
- Design notes under [`design/`](design/) and task batches under [`tasks/`](tasks/)
