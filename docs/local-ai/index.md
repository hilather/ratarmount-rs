# Local AI with ratarmount-rs

Working with models and datasets on your own hardware means reading very large,
rarely changing files from many processes at once: a dataset of TAR shards, a
checkpoint of safetensors files, a repository that a thousand agent attempts
each need a private copy of. The usual answers are to download and extract a
copy per experiment, or to scan a shard on every start. ratarmount-rs replaces
both with a mount: the data stays where it is, every process sees it as a
directory, and only the bytes that are actually read move.

This guide is the map. Each section says what the feature does, shows the
one command that matters, and links to the page with the details.

## Datasets from the Hub, no download

```bash
ratarmount -r hf://datasets/RealMattbrewer/oxford-iiit-pet-webdataset pets/
ls pets/train/train-000000.tar/ | head
```

A `hf://` URL mounts a repository, a folder or a single file at one pinned
commit. With `-r`, TAR shards inside the repository open as folders on first
access. If the dataset author published an index next to each shard (the demo
above did, with `ratarmount --publish-index`), opening a shard reads the small
index instead of scanning the archive, and each file read becomes one HTTP
range request. Fetched ranges land in a persistent cache; completed files are
shared with the standard `huggingface_hub` cache so nothing is downloaded
twice, and `hf-cache://` browses that cache offline.

- [Hugging Face Hub](../remote-hf.md): URLs, revisions, tokens, mirrors, the shared cache, offline mounts.
- [Publish an index](../recipes/publish-hf-index.md): one command, every downloader skips the scan.
- [The demo dataset](https://huggingface.co/datasets/RealMattbrewer/oxford-iiit-pet-webdataset): 7,349 pet photos as indexed WebDataset shards, with a card that walks through every access path.

## Models without the copy

```bash
ratarmount hf://Qwen/Qwen3.8-27B@main model/            # serve the repository to vLLM or llama.cpp
ratarmount -r hf://Qwen/Qwen3.8-27B@main model/         # each .safetensors file becomes a folder of tensors
cat model/<shard>.safetensors/__metadata__.json
```

Loaders read a mounted model like any directory while ratarmount fetches
ranges on demand. Pin the commit SHA for a reproducible deployment and keep
the range cache and the Hub cache on local NVMe. Safetensors and GGUF files
mount as directories of tensors, each with a JSON sidecar, so a checkpoint can
be inspected, hashed or partially read without loading it. vLLM still loads
all weights into memory at startup; the mount saves the up-front copy, not the
RAM.

- [vLLM and llama.cpp models](../recipes/local-models.md) · [tensor formats](../formats-tensors.md) · [NVMe placement](nvme-placement.md)

## Pirate Face and BitTorrent

```bash
ratarmount 'magnet:?xt=urn:btih:<infohash>&ws=<web-seed>' model/
ratarmount --torrent-swarm lan --seed ./model.torrent donor/     # machine A: share what it has cached
ratarmount --torrent-swarm lan ./model.torrent model/            # machine B: fetch from A over the LAN
```

[Pirate Face](https://pirateface.co/how-it-works) publishes magnet links for
permissively licensed Hub models and datasets, with the Hub as a web seed.
ratarmount shows the torrent's files immediately and fetches pieces as they
are read, from the web seed first and from peers only when a seed cannot
supply a verified piece, so a mount works with zero peers and never joins the
public swarm unless it has to. Pieces are checked against the torrent hashes
and whole files against the Hub's SHA-256 where it is known. Between your own
machines, `--torrent-swarm lan` moves a model over the local network without
trackers or DHT. Seeding is off unless you pass `--seed`. The feature is
compiled into the release packages; cargo builds add `--features bittorrent`.

- [BitTorrent sources](../remote-bittorrent.md): policies, verification, LAN setup, what was checked against Pirate Face.

## Agent sandboxes

```bash
ratarmount --git-ref <base-commit> --git-synthetic-head -w attempt-07 \
  --overlay-readonly 'tests/**' --overlay-quota 2G repo.git mnt/attempt-07
ratarmount diff attempt-07 --base repo.git@<base-commit> --git > attempt-07.patch
```

One read-only snapshot of a repository at a commit, one write overlay per
attempt. The agent sees a normal checkout with a single history-free commit,
cannot modify the protected test paths, cannot write more than the quota, and
the attempt is discarded by deleting its overlay. The supervisor
(`ratarmount sandbox`) creates and destroys attempts in bulk over a Unix
socket, with a standard-library Python client, and combines a container image
with the repository when the agent needs a full rootfs. On this laptop a
sandbox attempt costs 5.2 s to set up and tear down with 64 running at once,
against 7.7 s for a git worktree and 8.1 s for `docker cp`.

- [Sandboxes](../sandbox.md) · [Git mounts](../git-mounts.md) · [SWE-bench and mini-swe-agent](../recipes/swe-bench-sandboxes.md) · [OpenHands and SWE-smith rootfs](../recipes/sandbox-rootfs.md) · [deduplicated snapshot corpora with restic](../recipes/dedup-snapshots.md)

## Shards for training

```bash
ratarmount shard ./samples -o ./shards --size 1G --group-by-key --frame-per-sample -j 4
python3 -c 'from ratarmount_rs.webdataset import samples; print(next(samples(["shards/shard-000000.tar.zst"]))["__key__"])'
```

`shard` packs a directory into reproducible TAR shards, keeps the files of one
sample together, gives each sample its own zstd frame so it can be read alone,
and writes an index per shard plus a `shards.json` manifest. Training reads
them through the Python library, a FUSE mount, or any WebDataset reader; the
library and FUSE paths reached 2,509 and 2,233 samples/s on this laptop
against 4,249 for pre-extracted files and 1,430 for the `webdataset` package
reading plain TAR.

- [Dataset shards](../shards.md) · [WebDataset and img2dataset](../recipes/webdataset-shards.md) · [teacher logits and DistillKit](../recipes/teacher-logits.md) · [Common Crawl WARC](../recipes/common-crawl-warc.md)

## Python without FUSE

```python
import ratarmount_rs
with ratarmount_rs.open("shards/shard-000000.tar.zst", parallelization=4) as archive:
    data = archive.read("/samples/0001.json")
    view = archive.mmap("/samples/0001.bin")      # zero-copy for uncompressed TAR members
```

`ratarmount_rs` opens anything the CLI opens, including `hf://`, reads members
by name or by archive order, maps stored members with no copy, provides
PyTorch map and iterable datasets, a WebDataset sample iterator, the `ratar://`
fsspec protocol for pandas, pyarrow and 🤗 `datasets`, and `mount()` and
`index.publish()` wrappers over the CLI.

- [Python library](../python.md)

## Checkpoints, traces, provenance

```bash
ratarmount -f -w ./overlay --roll-every 1d,20G --commit-overlay-interval 5s --commit-manifest traces.tar.zst mnt/
setfattr -n user.teacher -v glm-5.3-flash mnt/trace-0042.jsonl
```

Training writes into a mounted archive. Settled files are committed into
seekable `.tar.zst` while the mount is live, a series rolls to a new numbered
archive by time or size, and extended attributes set on the files are stored
in the archive where `ratarmount find --xattr` can filter on them. Restic
snapshots deduplicate many repository states for task corpora.

- [Checkpoint and trace archives](../recipes/checkpoint-archives.md) · [Writing into archives](../write-overlay.md) · [provenance](../provenance.md) · [rolling archives](../rolling-archives.md)

## Serving a second machine

```bash
ratarmount --nfs --nfs-vers 4 --nfs-bind 192.168.50.1:20490 /srv/datasets/train.tar.zst
```

One box holds the shards; the other mounts them over NFSv4.1 (or 9P, SMB,
HTTP). The [two-box procedure](two-box-nfs.md) is written for two DGX Spark
class machines over a ConnectX-7 link and runs as a loopback smoke test
anywhere.

## Memory, caches and placement

`--memory-budget SIZE` caps ratarmount's own pools (decode-ahead, HTTP
prefetch, readahead, codec and SQLite caches) and degrades to synchronous
reads instead of failing; it does not limit the kernel page cache, so pair it
with `--direct-io` for one-pass training epochs. `RATARMOUNT_PAYLOAD_CACHE_BYTES`
caps the on-disk range and payload cache, not memory. Keep indexes and
overlays on the lowest-latency drive and shards, the range cache and the Hub
cache on the big one.

- [Memory budget](../memory-budget.md) · [Caches](../caches.md) · [NVMe placement](nvme-placement.md) · [FUSE tuning](../fuse-kernel-tuning.md)

## Numbers

Every figure quoted above comes from a committed run; see
[Measured results](results.md) for the tables and run IDs and
[Benchmarks](../benchmarks.md) for the methodology. GB10 / DGX Spark and
Apple M5 columns are still marked *needs hardware*; the scripts under
`benchmarks/ai/` are ready to fill them.

## Hardware guides

- [Datasets on a DGX Spark or Dell GB10](dgx-spark.md)
- [Two-drive NVMe placement](nvme-placement.md)
- [Apple silicon and Linux VMs](apple-silicon.md)
- [Two Dells over ConnectX-7](two-box-nfs.md)
