# Local AI workflows

These recipes connect ratarmount's archive, Git, shard, and library APIs to
common model and dataset workflows. Scripts make a small local fixture by
default; FUSE examples check for `/dev/fuse` and print a skip when it is absent.

## Recipes

- [SWE-bench and mini-swe-agent](../recipes/swe-bench-sandboxes.md): one
  history-free Git snapshot per task, isolated overlay per attempt, protected
  tests, and patch export.
- [OpenHands and SWE-smith rootfs](../recipes/sandbox-rootfs.md): combine a
  container image with a repository tree and enter it with bubblewrap or
  systemd-nspawn.
- [vLLM and llama.cpp models](../recipes/local-models.md): inspect and load
  Hugging Face model files, with notes on range caching and startup reads.
- [WebDataset and img2dataset](../recipes/webdataset-shards.md): create,
  index, and consume grouped, frame-per-sample shards.
- [DistillKit and teacher logits](../recipes/teacher-logits.md): store one
  document per sample, issue range reads, and compare packed with loose files.
- [Common Crawl WARC](../recipes/common-crawl-warc.md): read response payloads
  from local or remote WARC files using the library API.
- [Checkpoint and training trace archives](../recipes/checkpoint-archives.md):
  write through an overlay, commit archives, roll trace series, and retain
  provenance.
- [Publish an index to Hugging Face](../recipes/publish-hf-index.md).
- [Deduplicated task snapshots](../recipes/dedup-snapshots.md).

## Library and remote data

Use `ratarmount_rs.open()` for indexed member reads without FUSE. Python
examples, including `Archive.read`, `Archive.iter`, `Archive.mmap`, and
WebDataset iteration, are in the [Python guide](../python.md). Use `hf://` for
Hub files and pin a revision for repeatable runs. A configured shared Hugging
Face cache can reduce duplicate downloads; the remote range cache is separate
from the decompressed payload cache, so configure each according to the
installed release's documentation.

`ratar::hf://...` chained fsspec URLs, `datasets.load_dataset("webdataset", …)`,
and `--publish-index hf://…` are described with their supported forms in the
[Python guide](../python.md) and [Hub guide](../remote-hf.md). Use those exact
examples for chained paths; `datasets` requires raw TAR shard streams.

## Related guides

- [`hf://` sources, shared cache, and range-cache settings](../remote-hf.md)
- [Git refs and synthetic heads](../git-mounts.md) and [sandbox controls](../sandbox.md)
- [Python library and fsspec APIs](../python.md)
- [Shard layout and index export](../shards.md)
- [Provenance xattrs and manifests](../provenance.md)
- [FUSE passthrough and kernel tuning](../fuse-kernel-tuning.md)
- [Persistent remote range cache settings](../phase10-remote.md#persistent-remote-range-cache-ai-rc)
- [Packaging and distribution](../packaging.md)

## Memory budget and cache limits

The documented `RATARMOUNT_PAYLOAD_CACHE_BYTES` setting limits persistent
payload and range-cache disk use; it is not a process RSS limit.
`--memory-budget SIZE` caps ratarmount's own RAM pools (decode-ahead, HTTP
prefetch, FUSE readahead, codec chunk caches, SQLite caches) and degrades them
to synchronous paths instead of failing reads; see
[memory-budget.md](../memory-budget.md). It does not limit the kernel page
cache; pair it with `--direct-io` for one-pass training reads. vLLM loads all
weights into host/device memory at startup, even when the source mount fetches
those bytes lazily.

## Resource planning

Keep active model data and the Hugging Face cache on local NVMe where possible.
Memory budgets, cache limits, and lazy opening reduce duplicate buffering, but
they do not make every consumer lazy: in particular, vLLM loads model weights
at startup. Allow for the model's host and device memory requirements before
serving requests.
