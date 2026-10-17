# Benchmarks

Every number in the project's documentation comes from a run recorded in this
repository. This page collects them, says what each one measures, and shows
how to rerun it. All of them are single-host measurements on the hardware
named in each section. Treat them as directional and rerun the harness on your
own machine before making decisions.

## Against Python ratarmount

The head-to-head suite mounts the same fixtures with Python ratarmount 1.3.0
and ratarmount-rs and times cold mount (index build), warm mount, random
`cat`, random 64 KiB `pread` on a large member, `find` and sequential
bandwidth, sampling peak RSS of the mount process. Snapshot: ratarmount-rs
v0.1.27, 2026-08-27, 16 archives including a 640 MiB blob as `.tar`,
`.tar.zst` (4 MiB frames) and `.tar.lz4` (4 MiB blocks).

Geometric mean over all archives (a factor above 1 means ratarmount-rs is
better):

| Metric | Cold | Warm |
|---|---:|---:|
| Mount time | 5.21× | 6.76× |
| Peak RSS | 4.34× | 6.49× |
| Random `cat` | 2.84× | 2.82× |
| Random 64 KiB `pread` | 7.72× | 8.67× |
| `find` walk | 1.26× | 1.38× |
| Sequential bandwidth | 3.85× | 3.16× |

What stands out:

- Uncompressed `large-640m.tar`: sequential reads about 20× faster, 64 KiB
  reads about 18×.
- `large-640m.tar.zst`: sequential about 28×, 64 KiB reads 40–72×.
- `large-640m.tar.lz4`: sequential about 53×; Python does not seek
  independent lz4 blocks, so its random reads take hundreds of milliseconds
  against tens of microseconds here.
- Mounts are 5–9× faster and warm RSS about 6× lower (18–22 MiB against
  about 121 MiB) on almost every archive.
- Python wins small `.tar.gz` random reads (rapidgzip) and the cold mount of
  the 640 MiB `.tar.zst` by 1.69×.

Multi-GiB/s sequential figures are FUSE plus page cache with the blob in RAM,
not disk speed. Full tables: [python-vs-rust-results.md](../benchmarks/python-vs-rust-results.md).

```bash
export RATARMOUNT_PY_ROOT=../ratarmount      # a Python ratarmount checkout
cargo build --release
BIG=1 ./benchmarks/compare-python-vs-rust.sh # → benchmarks/python-vs-rust-results-big.{csv,md}
```

## Local AI workloads

Seven scripts under `benchmarks/ai/` measure the workloads the Local AI guide
is about. Each appends to `benchmarks/ai/results/<host>-<date>.csv` and prints
a table; missing tools or FUSE produce explicit `skip` rows, never a zero.
The numbers below are from the laptop `brewtop` (Intel Core i7-8750H, 6 cores,
62 GiB RAM, Linux 7.2, btrfs on NVMe) with a release build of this branch on
2026-10-16 and 2026-10-17, while other builds were running (one-minute load
15–25). Run IDs refer to rows in the committed CSVs.

| Workload | Result | Run |
|---|---|---|
| WebDataset samples/s, 256 samples of 64 KiB + JSON, 8 workers | extracted files **4,249** · Python library (`ratarmount_rs`, sidecar indexes) **2,509** · FUSE mount **2,233** · `webdataset` package on the same data as plain TAR **1,430** | `b99c6f5a77ac` |
| Agent sandbox: setup plus teardown per attempt, 64 live attempts, pinned zlib checkout | ratarmount sandbox **5.19 s** · `git worktree add` + remove **7.70 s** · `docker cp` into a container **8.05 s** | `04456b39c3fc` |
| Build and test zlib (`configure; make; make test`, 2 jobs) | inside a sandbox mount **3.06 s** · native directory **2.45 s** | `9678250cdb68` |
| Cold open of three 8 MiB zstd shards, fresh process | scanning **0.086 s** · with published indexes **0.016 s**; as one union mount 0.081 s against 0.021 s | `55cd1e42fd3d` |
| Resident memory, 32 concurrent mounts of an 8 MiB plain TAR | **679 MiB** in total, about 21 MiB per mount | `0ad910c91601` |
| Tiny safetensors model (0.5 MiB payload), read and hash every tensor | `hf download` then load **1.35 s** · `hf://` mount startup plus first read **0.35 s** (first read alone 0.17 s) · second read through the mount **5 ms** · second read of the downloaded file 3 ms | `8fa9d03790f5` |

The sandbox figure is the one the agent-training case cares about: an attempt
is a mount with its own overlay, so 64 attempts share one base and one index.
The model figure is storage I/O plus SHA-256, not inference.

**zstd decode-ahead** (256 MiB multi-frame member, archive in page cache,
idle machine, 2026-10-16): the Session API read at 2,206 MB/s on one thread
and 2,762 MB/s on four; `cat` through FUSE went from 852 to 1,251 MB/s;
`dd bs=1M` with `--direct-io` from 1,253 to 1,633 MB/s; `zstd -d` on the same
file managed 1,631 MB/s. Script: `benchmarks/ai/zstd-decode-ahead.sh`.

```bash
cargo build --release -p ratarmount
export RATARMOUNT_BIN="$PWD/target/release/ratarmount"
python3 benchmarks/ai/samples.py            # samples/s
python3 benchmarks/ai/sandbox-attempts.py   # 64 attempts (needs docker for the docker row)
python3 benchmarks/ai/build-test.py
python3 benchmarks/ai/cold-index.py
python3 benchmarks/ai/mount-memory.py
python3 benchmarks/ai/model-load.py         # network
python3 benchmarks/ai/hf-dataset.py         # network
```

What each script includes and excludes is spelled out in
[benchmarks/ai/README.md](../benchmarks/ai/README.md); the recorded laptop
tables and hardware notes are in [Local AI results](local-ai/results.md).

## A public dataset from the Hub

<!-- HF-DATASET: filled from benchmarks/ai/results (hf-dataset) -->

`benchmarks/ai/hf-dataset.py` mounts the public
[Oxford-IIIT Pet WebDataset](https://huggingface.co/datasets/RealMattbrewer/oxford-iiit-pet-webdataset)
three ways with fresh caches each time (2026-10-17, release build, medians of
three runs, run `647657dac03a`):

| Case | Median |
|---|---:|
| Mount the whole repository with `-r` | 0.16 s |
| Open the first 128 MiB shard (3,954 members) through its published index | 1.46 s |
| Read one 125 KiB file from it, first and second read | 0.10 s / 0.11 s |
| Mount one shard with its published index | 1.17 s |
| Mount the same shard with `-c`, scanning the remote TAR instead | 16.8 s |

Everything but the scan is network round trips. The published index replaces
a 17 s scan with a 1.2–1.5 s open, and the repository mount never scans a
shard. Per-run values and caveats: [Local AI results](local-ai/results.md#a-public-dataset-from-the-hub).

## Every format

<!-- FORMAT-SWEEP: filled from benchmarks/format-results.md -->

`benchmarks/compare-formats.sh` packs one deterministic corpus (1,000 × 32 KiB
files plus a 64 MiB blob) into every archive, image and model container the
local tools can produce and measures cold index, cold and warm mount, peak
RSS, random cat, 64 KiB pread, sequential bandwidth and find for each with the
Rust binary alone. Latest run: 2026-10-17, `ratarmount 0.1.34`, i7-8750H @ 2.20GHz, one-minute load
before/after 3.27 / 2.57.

| Format (fixture) | Size | Cold index (s) | Cold mount (s) | Warm mount (s) | Peak RSS warm (MiB) | Random cat (ms) | 64 KiB pread (ms) | Sequential (MiB/s) | Find (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| tar (`corpus.tar`) | 95.8 MiB | 0.097 | 0.066 | 0.014 | 21.6 | 1.0 | 0.1 | 16654 | 5.0 |
| tar.gz (`corpus.tar.gz`) | 68.3 MiB | 0.129 | 0.128 | 0.064 | 20.6 | 4.6 | 2.1 | 18986 | 2.8 |
| tar.bz2 (`corpus.tar.bz2`) | 72.4 MiB | 9.896 | 10.315 | 0.064 | 92.2 | 3.7 | 12.2 | 18538 | 2.8 |
| tar.xz (`corpus.tar.xz`) | 68.0 MiB | 0.323 | 0.312 | 0.011 | 20.1 | 34.4 | 4.9 | 19210 | 2.8 |
| tar.zst (`corpus.tar.zst`) | 67.9 MiB | 0.038 | 0.064 | 0.064 | 19.8 | 2.4 | 1.8 | 16825 | 2.8 |
| tar.lz4 (`corpus.tar.lz4`) | 68.1 MiB | 0.048 | 0.065 | 0.065 | 35.8 | 1.4 | 0.6 | 18397 | 2.7 |
| zip-deflate (`corpus.zip`) | 68.3 MiB | 0.037 | 0.064 | 0.067 | 20.4 | 1.0 | 0.0 | 16820 | 3.7 |
| zip-store (`corpus-store.zip`) | 95.3 MiB | 0.041 | 0.064 | 0.064 | 20.5 | 0.9 | 0.0 | 19044 | 2.9 |
| cpio (`corpus.cpio`) | 95.4 MiB | 0.030 | 0.064 | 0.011 | 20.0 | 0.9 | 0.0 | 19920 | 2.9 |
| ar (`corpus.ar`) | 95.3 MiB | 0.029 | 0.066 | 0.066 | 21.2 | 0.9 | 0.0 | 19285 | 2.2 |
| iso (`corpus.iso`) | 95.7 MiB | 0.027 | 0.064 | 0.064 | 20.5 | 0.9 | 0.0 | 19313 | 2.8 |
| ext4 (`corpus.ext4`) | 152.0 MiB | 0.007 | 0.011 | 0.011 | 18.2 | 1.0 | 0.0 | 2545 | 2.5 |
| mbr/ext4 (`corpus-mbr.img`) | 153.0 MiB | 0.007 | 0.011 | 0.011 | 18.7 | 1.0 | 0.0 | 2918 | 2.8 |
| qcow2/ext4 (`corpus.qcow2`) | 96.4 MiB | 0.007 | 0.011 | 0.011 | 18.6 | 1.0 | 0.0 | 2503 | 2.7 |
| safetensors (`model.safetensors`) | 64.0 MiB | 0.026 | 0.064 | 0.011 | 21.3 | 0.9 | 0.0 | 7408 | 4.1 |
| gguf (`model.gguf`) | 64.0 MiB | 0.025 | 0.064 | 0.011 | 21.2 | 0.9 | 0.0 | 6888 | 4.4 |
| nested-tar (`nested.tar`) | 136.6 MiB | 0.100 | 0.124 | 0.124 | 29.8 | 0.9 | 0.1 | 19682 | 4.3 |
| 7z (`corpus.7z`) | 68.0 MiB | 0.028 | 0.064 | 0.064 | 20.4 | 91.8 | 2.4 | 19180 | 2.7 |
| squashfs (`corpus.squashfs`) | 68.2 MiB | 0.008 | 0.012 | 0.011 | 18.2 | 1.1 | 0.0 | 2570 | 2.8 |
| fat (`corpus.fat`) | 152.0 MiB | 0.007 | 0.012 | 0.011 | 17.8 | 1.9 | 0.0 | 624 | 2.8 |
| exfat (`corpus.exfat`) | 152.0 MiB | 0.007 | 0.011 | 0.011 | 18.1 | 0.9 | 0.0 | 1681 | 2.8 |

| Fixture | Metric | Status | Reason / producer |
|---|---|---|---|
| — | — | — | None |

The annotated table and what each column means are in
[Supported formats](formats.md#measured); the raw CSV is
[benchmarks/format-results.csv](../benchmarks/format-results.csv).

```bash
cargo build --release -p ratarmount
./benchmarks/compare-formats.sh                 # → benchmarks/format-results.{csv,md}
MICRO=1 PREPARE_ONLY=1 ./benchmarks/compare-formats.sh   # fixtures only, no binary or FUSE
./benchmarks/test-compare-formats.sh            # regression smoke
```

## Other harnesses

| Harness | Measures |
|---|---|
| `benchmarks/compare-fuse-kernel-tuning.sh` | Disk `O_DIRECT` baseline against FUSE mount options (`noatime`, `--readahead`, `max_background`). Guide: [FUSE tuning](fuse-kernel-tuning.md) |
| `benchmarks/compare-gzip-isal-ab.sh` | zlib-rs against ISA-L inflate in the opt-in rapidgzip path, two binaries |
| `benchmarks/compare-nested-durable.sh` | Warm remount of nested archives with and without stored nested indexes |
| `benchmarks/compare-vector-wave.sh` | Offset-order extraction over large catalogs |
| CI `benchmark-gates` | A cold-index regression gate that runs on every pull request without FUSE |

All harnesses and their variables are described in
[benchmarks/README.md](../benchmarks/README.md).
