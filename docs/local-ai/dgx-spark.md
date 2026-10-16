# Datasets on a Spark

Keep the dataset in indexed, seekable `.tar.zst` shards on NVMe, mount it
read-only for training, and put outputs in a separate directory or write overlay.
DGX Spark uses an Arm CPU and an Ubuntu 24.04 based DGX OS; use the **arm64**
package, following NVIDIA's [software stack guide](https://docs.nvidia.com/dgx/dgx-spark-porting-guide/porting/software-requirements.html).
This page also applies to the Dell GB10 workflow, but neither machine was
available for the [laptop measurements](results.md).

Download the Ubuntu 24.04 arm64 `.deb` from the project's
[release assets](https://github.com/hilather/ratarmount-rs/releases), verify its
published checksum, and install it locally:

```bash
sudo apt update
sudo apt install fuse3 ./ratarmount*arm64.deb
ratarmount --version
ratarmount --print-features
ls -l /dev/fuse
```

For containers running as another UID, enable the exact line `user_allow_other`
in `/etc/fuse.conf` (edit with `sudoedit /etc/fuse.conf`). Mount before starting
the container. A read-only bind of the FUSE mount then exposes it to training:

```bash
mkdir -p "$HOME/datasets/train" "$HOME/training-output"
ratarmount -o allow_other --memory-budget 512M --direct-io \
  /srv/datasets/train-*.tar.zst "$HOME/datasets/train"
# Set TRAIN_IMAGE to your existing arm64 training image.
docker run --rm --gpus all \
  --mount "type=bind,src=$HOME/datasets/train,dst=/data,readonly" \
  --mount "type=bind,src=$HOME/training-output,dst=/output" \
  "$TRAIN_IMAGE" python train.py --data /data --output /output
fusermount3 -u "$HOME/datasets/train"
```

`--memory-budget` requires a build containing AI-MEM; confirm it appears in
`ratarmount --help`. The worker snapshot used for the first laptop results
predates that flag. The budget controls participating userspace caches and
buffers, and is separate from GPU allocations and the kernel page cache.
`--direct-io` bypasses the FUSE member page cache and advises eviction of consumed
local archive pages. Compare it with cached reads for repeated epochs; it also
disables passthrough. It is not an `O_DIRECT` promise for the NVMe device. For
loaders relying on mmap, test normal cached mode first.

Keep the base read-only and direct checkpoints/logs to `/output`. If software
must write beside its input, use a persistent overlay outside the mount:

```bash
mkdir -p "$HOME/datasets/experiment" "$HOME/training-overlays/experiment"
ratarmount -o allow_other -w "$HOME/training-overlays/experiment" \
  /srv/datasets/train-*.tar.zst "$HOME/datasets/experiment"
# Inspect or retain the overlay after unmounting; the base stays compressed.
fusermount3 -u "$HOME/datasets/experiment"
```

`--sandbox` includes `allow_other`, caller uid/gid and a tmpfs overlay; reserve
it for disposable attempts and cap its size as described in [sandbox.md](../sandbox.md).
Tmpfs consumes the same RAM needed by training. Use disk overlays when outputs
must survive a reboot. See [NVMe placement](nvme-placement.md).

Passthrough needs Linux kernel support and root/`CAP_SYS_ADMIN`; `auto` may
fall back to daemon reads. It applies to suitable plain/overlay files. Stored
TAR members need a separate backing file containing just that member (reflink
when possible, copy otherwise); a backing fd cannot specify an archive offset.
Compressed shards continue through the decoder. Inspect logs to confirm the
negotiated path rather than assuming a kernel version makes it active.

Build a release binary and install the Python wheel in your benchmark venv,
then run the [six scripts](../../benchmarks/ai/README.md) with `--runs 3`. Start
with the defaults; scale `samples.py --samples 16384`, `cold-index.py --gib 8`
and eventually `--gib 1024` only when disk space allows. Use
`--mount-options='--memory-budget 512M --direct-io'` for a separate epoch-mode
run, recording it in another CSV. Run the 64-attempt and 32-mount defaults.
The supplied scripts never enable passthrough privileges or change host policy.

For two Dells over ConnectX-7, follow the [two-box procedure](two-box-nfs.md).
Its NFSv4.1 traffic uses TCP/IP; an RDMA-capable NIC does not make this an
NFS-over-RDMA benchmark. GB10 results remain **needs hardware**.
