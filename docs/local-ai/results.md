# Local AI measured results

Numbers from the `benchmarks/ai/` scripts on the hardware we have. Every row
names the run ID of the CSV record it comes from, so it can be checked and
rerun. GB10 / DGX Spark and Apple M5 columns stay **needs hardware** until the
scripts have run there; the [DGX guide](dgx-spark.md), [Apple notes](apple-silicon.md)
and [two-box procedure](two-box-nfs.md) say how.

## The laptop

Host `brewtop`: Intel Core i7-8750H (6 cores, 12 threads), 62 GiB RAM, NVMe
with btrfs, Linux `7.2.5-3-omarchy`, x86_64. Release build of the
`local-ai/integration` branch (`ratarmount 0.1.34`), Python 3.14, the Hub
client 1.30, `webdataset` 1.0.2, torch absent. Other builds were running on
the machine during these runs; the one-minute load was 15 to 25 unless noted.
The raw rows are in [`brewtop-2026-10-16.csv`](../../benchmarks/ai/results/brewtop-2026-10-16.csv)
and [`brewtop-2026-10-17.csv`](../../benchmarks/ai/results/brewtop-2026-10-17.csv),
which also keep earlier exploratory runs made with a debug binary inside a
sandbox without FUSE; those are not used below.

| Benchmark | Case | Laptop | Run | GB10 / DGX Spark | M5 |
|---|---|---:|---|---|---|
| Samples/s, 256 × 64 KiB + JSON, 8 workers | extracted files | 4,249 | `b99c6f5a77ac` | needs hardware | needs hardware |
| | Python library, zstd shards, sidecar indexes | 2,509 | `b99c6f5a77ac` | needs hardware | needs hardware |
| | FUSE mount of the same shards | 2,233 | `b99c6f5a77ac` | needs hardware | needs hardware |
| | `webdataset` package on plain TAR shards | 1,430 | `b99c6f5a77ac` | needs hardware | needs hardware |
| | squashfs | skip: `mksquashfs` / `squashfuse` absent | | | |
| 64 parallel attempts on zlib v1.3.1, setup + teardown per attempt | ratarmount sandbox | 5.19 s | `04456b39c3fc` | needs hardware | needs hardware (Linux VM) |
| | `git worktree add` + remove | 7.70 s | `04456b39c3fc` | needs hardware | needs hardware |
| | `docker cp` into an Alpine container | 8.05 s | `04456b39c3fc` | needs hardware | needs hardware |
| zlib `configure; make; make test`, 2 jobs | native directory | 2.45 s | `9678250cdb68` | needs hardware | needs hardware |
| | inside a sandbox mount | 3.06 s | `9678250cdb68` | needs hardware | needs hardware (Linux VM) |
| Cold open, three 8 MiB zstd shards, fresh process | scan | 0.086 s | `55cd1e42fd3d` | needs hardware | needs hardware |
| | published indexes | 0.016 s | `55cd1e42fd3d` | needs hardware | needs hardware |
| Cold union mount of the same shards | scan | 0.081 s | `55cd1e42fd3d` | needs hardware | needs hardware |
| | published indexes | 0.021 s | `55cd1e42fd3d` | needs hardware | needs hardware |
| Resident memory, 32 mounts of an 8 MiB plain TAR | ratarmount, total | 679 MiB (≈ 21 MiB each) | `0ad910c91601` | needs hardware | needs hardware (Linux VM) |
| | squashfuse, Python ratarmount | skip: not installed | | | |
| Tiny safetensors model, read and hash all tensors (0.5 MiB) | `hf download` + load | 1.35 s | `8fa9d03790f5` | needs hardware | needs hardware |
| | second load of the downloaded file | 3 ms | `8fa9d03790f5` | needs hardware | needs hardware |
| | `hf://` mount startup + first read | 0.35 s | `8fa9d03790f5` | needs hardware | needs hardware |
| | first read alone / second read through the mount | 0.17 s / 5 ms | `8fa9d03790f5` | needs hardware | needs hardware |
| Local 16 MiB read + SHA-256 (NFS comparison baseline) | | 285 MB/s | see CSV | needs hardware | needs hardware |
| Kernel NFS loopback | | skip: `mount.nfs` absent; needs root | | needs hardware | needs hardware (Linux VM) |
| Two Dells over ConnectX-7, NFSv4.1 | | needs hardware | | needs hardware | |

**zstd decode-ahead** (`benchmarks/ai/zstd-decode-ahead.sh`, 256 MiB
multi-frame member, archive in page cache, machine idle, 2026-10-16): Session
API 2,206 → 2,762 MB/s from one to four threads; `cat` through FUSE 852 →
1,251 MB/s; `dd bs=1M` with `--direct-io` 1,253 → 1,633 MB/s; `zstd -d`
1,631 MB/s. An earlier run under heavy load had shown a spurious direct-I/O
regression that disappeared when the machine was idle. Host `brewtop`,
2026-10-16; raw rows in
[`brewtop-2026-10-16-zstd-decode-ahead.csv`](../../benchmarks/ai/results/brewtop-2026-10-16-zstd-decode-ahead.csv).

**Sandbox supervisor alone** (tiny base, warm): 64 attempts cost 26 ms to set
up and 97 ms to tear down each; the 5.19 s above is dominated by mounting and
unmounting a real repository checkout under load.

## A public dataset from the Hub

<!-- HF-DATASET-RESULTS -->

`benchmarks/ai/hf-dataset.py` on 2026-10-17, release build, three runs, each
with fresh ratarmount and Hub caches and a private `HOME` so that no local
index or token exists; one-minute load 3 to 4; run `647657dac03a`. The dataset
is [`RealMattBrewer/oxford-iiit-pet-webdataset`](https://huggingface.co/datasets/RealMattBrewer/oxford-iiit-pet-webdataset)
at commit `90c62369`, and the shard is `train/train-000000.tar` (128 MiB,
3,954 members).

| Case | Median | Runs |
|---|---:|---|
| Mount the whole repository with `-r` | 0.16 s | 0.22 / 0.16 / 0.14 |
| Open the first shard through its published index (list 3,954 entries) | 1.46 s | 1.34 / 1.46 / 1.56 |
| Read `Abyssinian_1.jpg` (125 KiB) from that shard | 0.10 s | 0.11 / 0.10 / 0.10 |
| Read a second file from the same shard | 0.11 s | 0.15 / 0.11 / 0.11 |
| Mount one shard with its published index | 1.17 s | 1.55 / 1.17 / 1.13 |
| Read the same file through that mount | 0.08 s | 0.07 / 0.08 / 0.11 |
| Mount the same shard with `-c` (index ignored, remote scan) | 16.8 s | 16.8 / 16.9 / 16.3 |
| Read the same file after the scan | 0.03 s | 0.03 / 0.03 / 0.02 |

Network round trips dominate every row except the scan, which reads all 3,954
TAR headers through HTTP range requests coalesced into 4 MiB windows. The
published index turns a 17 s open into about 1.3 s, and the whole-repository
mount opens shards without scanning them. One earlier attempt of this
benchmark, before `HOME` was isolated, stalled for fifteen minutes while
listing the shard with the daemon idle. It did not recur in eighteen later
runs: three whose table survives only in a log, the three recorded above, and
a twelve-run loop with debug mount logs and stack capture armed, recorded in
[`brewtop-2026-10-17-hf-repro.csv`](../../benchmarks/ai/results/brewtop-2026-10-17-hf-repro.csv)
(slowest remote scan 40.6 s, slowest shard open 1.7 s). It is recorded here
as an open question rather than a known cause.

## What the numbers do and do not say

- Samples/s include full-content fingerprints of every sample; no image
  decoding or GPU work. All readers see the same bytes. The library case reads
  zstd shards with per-sample frames; the `webdataset` row reads plain TAR,
  because that package does not seek inside zstd. `--codec none` gives a
  matched comparison.
- The sandbox figure is mean setup plus teardown per attempt with 64 attempts
  alive at once; batch wall time is in the CSV. Git worktrees share an object
  store, Docker copies the checkout, ratarmount mounts one base with one index.
- Cold opens use fresh processes and advisory `DONTNEED` eviction; storage was
  not physically cold. Published copies were made and discovered locally
  through `--publish-index` and `--index-folders`.
- The model figure is storage I/O plus hashing, not inference or GPU transfer.
  The model is tiny, so mount startup and network round trips dominate.
- Nothing here is a GB10 or M5 measurement.

## Reproduce

```bash
cargo build --release -p ratarmount
export RATARMOUNT_BIN="$PWD/target/release/ratarmount"
python3 benchmarks/ai/build-test.py --jobs 2
python3 benchmarks/ai/model-load.py
python3 benchmarks/ai/hf-dataset.py
./benchmarks/ai/two-box-nfs.sh loopback --mib 16
docker pull alpine:3.20                      # outside timing; scripts never pull images
python3 benchmarks/ai/sandbox-attempts.py --attempts 64
python3 benchmarks/ai/mount-memory.py --mounts 32
python3 benchmarks/ai/cold-index.py --gib 0.015625
# The library sample reader needs this branch's ratarmount_rs wheel in a venv:
python3 benchmarks/ai/samples.py --samples 256 --sample-bytes 65536 --workers 8 --library-index sidecar
SIZE_MIB=256 THREADS=4 ./benchmarks/ai/zstd-decode-ahead.sh
```

The [suite README](../../benchmarks/ai/README.md) defines each timing boundary
and the optional comparators (torch, `webdataset`, Python ratarmount,
`squashfuse`, Docker). Run `AI_TEST_FUSE=1 python3 -m unittest discover -s
benchmarks/ai -p test_ai_benchmarks.py` on a host with FUSE to exercise the
sample, sandbox, build, index and RSS paths end to end, and `AI_TEST_NFS=1` with
privileges and `mount.nfs` for the NFS checksum test.
