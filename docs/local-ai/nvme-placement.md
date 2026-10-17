# Two-drive placement for Local AI

Put immutable archives and remote payload traffic on the capacious NVMe, and
latency-sensitive indexes and writes on the faster NVMe. Keep every overlay
outside every ratarmount mount. These are starting placements to measure with
the [AI benchmarks](../../benchmarks/ai/README.md), not measured drive rankings.

| Data | Example placement | Reason |
|---|---|---|
| OS, Python environment, compiler | Drive A `/` | Separate tool startup from large sequential dataset reads |
| SQLite indexes and metadata cache | Drive A `/srv/ai-index` | Many small random accesses; prefer the lowest latency drive |
| Disposable/durable overlays | Drive A `/srv/ai-scratch` | Isolate small writes from sequential archive reads; retain durable outputs |
| Compressed shards and models | Drive B `/srv/ai-data` | Capacity and sustained read bandwidth |
| Remote payload/range cache | Drive B `/srv/ai-cache/payload` | Large, replaceable data; avoid filling the system drive |
| Shared Hugging Face cache | Drive B `/srv/ai-cache/huggingface` | Whole verified files can be reused by Hub tools and ratarmount |
| Checkpoints | Drive B `/srv/checkpoints` or another volume | Plan write bandwidth/free space separately from input reads |

Use private, user-owned cache directories. A setup for one user, after the
administrator has created and assigned the `/srv` directories:

```bash
mkdir -p /srv/ai-cache/payload /srv/ai-cache/huggingface /srv/ai-index /srv/ai-scratch
chmod 700 /srv/ai-cache/payload /srv/ai-cache/huggingface
export RATARMOUNT_PAYLOAD_CACHE_DIR=/srv/ai-cache/payload
export RATARMOUNT_PAYLOAD_CACHE_BYTES=4294967296
export HF_HOME=/srv/ai-cache/huggingface
export HF_HUB_CACHE="$HF_HOME/hub"
mkdir -p "$HOME/datasets/train"
ratarmount --index-file /srv/ai-index/train.sqlite \
  /srv/ai-data/train.tar.zst "$HOME/datasets/train"
```

`RATARMOUNT_PAYLOAD_CACHE_BYTES` caps the shared on-disk payload/range cache.
It does not reserve memory or cap the Hub whole-file cache. Keep the index path
unique per archive; do not pass one `--index-file` for unrelated shards. A shard
set already includes per-shard sidecars; use those or arrange separate mount
processes when relocating each index. Never hand-edit a live SQLite sidecar.

If Drive B is also the faster drive, put indexes there and measure whether
simultaneous overlay writes matter. Metadata latency, filesystem reflink support,
thermal throttling and available space can outweigh the drive's advertised
sequential rate. Never put the overlay in `/data/mnt/...`, or put the cache in
the mount it feeds: that creates recursive I/O dependencies.

Tmpfs (`--overlay-tmpfs`, or the `--sandbox` preset) helps short-lived attempts
when RAM allows. Its files and copy-up data consume memory; a userspace cache
budget does not make those pages free. On unified-memory hardware, reserve
space for the model, runtime, kernel, workers and overlay before choosing a cap.
For persistent experiments use a disk overlay and write checkpoints outside it.
The [sandbox guide](../sandbox.md) documents quotas and cleanup.

Use `df -h` and `du -sh` on these directories before scaling to GiB/TiB. Record
filesystem type, mount options, free space and which volume contains each path
with the results. The benchmark scripts use only targeted advisory eviction;
they never write `/proc/sys/vm/drop_caches` on a shared machine.
