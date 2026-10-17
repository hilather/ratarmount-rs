# Local AI benchmarks

Run from any directory with Python 3.9+ (fixture creation uses `Random.randbytes`). Build the branch being compared first:

```bash
cargo build --release -p ratarmount --features nfsv4
export RATARMOUNT_BIN="$PWD/target/release/ratarmount"
# Use a venv with this branch's ratarmount_rs wheel for the library path.
# Optional comparisons: torch, webdataset, Python ratarmount, squashfuse/mksquashfs.
python3 benchmarks/ai/samples.py
python3 benchmarks/ai/sandbox-attempts.py
python3 benchmarks/ai/build-test.py
python3 benchmarks/ai/cold-index.py
python3 benchmarks/ai/mount-memory.py
python3 benchmarks/ai/model-load.py
./benchmarks/ai/two-box-nfs.sh loopback
```

Each script prints a Markdown table and appends rows to
`results/<hostname>-<UTC-date>.csv`. `--output PATH` chooses another CSV;
`--runs 3` repeats measurements, and `--keep` retains fixtures/logs. Raw CSV
snapshots are intentionally trackable; generated fixtures, the cached zlib
checkout and optional environments live in gitignored `.cache/`. Sandbox state
uses short private `.s????????/` directories next to this README, on the same
filesystem as the fixtures, to fit Linux Unix-socket path limits. They are
removed after shutdown; a failed unmount retains them. For longer checkout
paths, pass `--state-root /short/nvme/path` to the two sandbox scripts, keeping
state and native/worktree fixtures on the same filesystem. Supervision is
currently Linux-only; run those mount comparisons in a Linux VM on Apple silicon.

Missing prerequisites print `skip: ...` and get `status=skip` with an empty
value, never a zero-time success. A command failure, wrong bytes or timeout
gets `status=error` and a nonzero exit. Other comparisons continue. Linux FUSE
cases check `/dev/fuse` before mounting; macOS checks the runtime installation.
No script builds a binary, installs tools, pulls Docker images, drops global
page cache, or escalates privileges automatically. Scripts own their temporary
mounts and child processes and clean up on ordinary errors/interrupts; failed
unmounts preserve work directories for inspection. Avoid SIGKILL during a run.

| Script | Default small fixture | Main parameters |
|---|---|---|
| `samples.py` | 256 binary+JSON samples, 64 KiB binary, 8 workers, ~16 MiB | `--samples`, `--sample-bytes`, `--workers`, `--shard-size 2M`, `--codec zstd\|none`, `--library-index sidecar\|temp` |
| `sandbox-attempts.py` | Pinned zlib repo, 64 concurrent live attempts | `--attempts`, `--state-root`, `--docker-image` (must already be local) |
| `build-test.py` | Same zlib commit, `configure; make; make test`, 2 build jobs | `--jobs`, `--state-root` |
| `cold-index.py` | 0.015625 GiB of binary samples, 8 MiB shard limit | `--gib`, `--shard-size`, `--codec` |
| `mount-memory.py` | 32 mounts of an 8 MiB plain-TAR sample set | `--mounts`, `--samples`, `--settle` |
| `model-load.py` | Pinned public tiny BERT, ~0.5 MiB safetensors | `--repo`, `--revision`, `--file` (safetensors) |
| `two-box-nfs.sh` | 16 MiB loopback payload, NFSv4.1 | `serve\|read\|loopback`, `--mib`, `--version 3\|4`, `--host`, `--local-file` |

The samples, cold-index, mount-memory and model-load readers also accept
`--mount-options='--memory-budget 512M --direct-io'` where applicable (see each
`--help`). Flags are passed only to ratarmount; they do not configure optional
comparators. Confirm `--memory-budget` is in your binary's help (AI-MEM).
For separate configurations use separate output paths so summaries stay clear.

## What each number includes

1. **Samples/s:** synthetic, deterministic raw bytes; no image decoding or GPU
   work. All backends read both `.bin` and `.json`, and compare full-content
   fingerprints, byte count and component count. Fixtures are made with
   `ratarmount shard`; grouping and per-sample frames are enabled. With torch,
   the library uses `RatarIterableDataset` and an eight-worker DataLoader;
   otherwise eight threads call `ratarmount_rs.webdataset.samples` with disjoint
   shard partitions. Worker/archive startup is timed; module imports are outside timing. Library
   readers explicitly use `index="sidecar"` to reuse the indexes built by the
   shard command. `--library-index temp` includes index rebuilding instead. Extracted/FUSE/squashfs use eight
   Python reader threads. The optional `webdataset` package reads the logically
   identical **uncompressed TAR** shards with eight thread readers; its row
   identifies that codec difference. Run `--codec none` for matched storage.
   At least eight shards avoids idle shard-partition workers. Squashfs uses its
   default compressor and records no inferred equivalence to zstd.
2. **Attempts:** all attempts meet a barrier before teardown, ensuring 64 live
   attempts, with separate concurrent CLI/client requests. Value is mean
   setup+teardown latency excluding barrier wait; `seconds` is whole-batch wall
   time, not the mean. Shared repo clone and daemon/base initialization are
   excluded. Docker times create + copy + remove (no container startup), resolves the local
   image tag to an immutable image ID before timing, and records that ID. Git
   worktrees share their cached object store; Docker copies the checkout plus
   its `.git`; ratarmount mounts the same base tree. These are practical setup
   alternatives with different metadata costs. A failed setup aborts the barrier
   and cleans up other attempts.
3. **Build/test:** all configure/build/test work is timed; worktree or overlay
   creation/teardown is excluded. Each run starts from a fresh tree. It uses
   zlib v1.3.1, commit `51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf`, cloned over
   HTTPS into `.cache/zlib`. Only `git`, `cc`, `make` and a shell are required.
   The repo is a few MiB rather than a giant SWE checkout; report that scale.
4. **Cold index:** `open-*` rows use one fresh CLI `--no-mount` process; `mount-*`
   rows start one union mount of all shards and wait for readiness, excluding
   teardown. Indexes are published via `--publish-index --publish-index-to` into
   a local directory, then discovered through an isolated `--index-folders` directory. Published
   copies survive while original sidecars are removed. Each scan gets a fresh
   SQLite index directory. Creation/publication is outside timing. Targeted
   `posix_fadvise(DONTNEED)` is advisory; no claim of physically cold storage or
   network sidecar discovery. New processes reset userspace state. Scale
   `--gib 8 --shard-size 1G` for 8 GiB or `--gib 1024 --shard-size 1G`
   for 1 TiB, allowing several times that
   free disk space for loose fixtures and archives. `--shard-size` is encoded
   size; random input prevents unrealistic compression wins.
5. **Memory:** sum of `/proc/<pid>/status` VmRSS after every foreground mount
   reads one sample, then settles. Measures mount processes only; shared pages
   count once per process. This is steady RSS, not PSS, peak RSS, kernel cache
   or total machine memory. Python ratarmount and Rust read identical plain
   TAR content; squashfuse reads a squashfs image. Requires Linux, including on
   Apple silicon (run inside a Linux VM and label the result).
6. **Model:** `hf download` with an empty private Hub cache, then parse the
   safetensors header and hash every tensor payload byte. The second local
   load reuses that file. HF mount reads use another private cache, mount the
   pinned repo tree (without recursive mounting), and read the same file first
   and second time through one mount. Mount startup/metadata discovery is
   excluded from the read-only rows; `hf-mount-setup-and-first-load` includes
   startup and the first read for comparison with download-and-load. Every measured load validates bytes, not
   just file existence or header metadata. The default revision is
   `f171d7baecaf37b5da5a3616d8833b9969753535` of
   `hf-internal-testing/tiny-random-bert`. Offline/HEAD failures skip; set
   `AI_OFFLINE=1` to skip explicitly. This measures I/O plus SHA-256, not model
   initialization, GPU transfer, inference or llama.cpp. Use a larger public
   safetensors file for hardware runs; pin its revision too.

Every row records hostname, kernel/architecture, load1, run ID, UTC timestamp,
binary path/version and all command-line parameters. Repeat after other builds
finish; record tool versions, filesystem and storage placement externally with
published results. One small laptop run is harness validation, not a performance
claim. Cached reads and Python hashing/worker startup may dominate tiny fixtures.

## Hardware runs and regression checks

[Results and exact laptop commands](../../docs/local-ai/results.md),
[DGX Spark](../../docs/local-ai/dgx-spark.md),
[NVMe placement](../../docs/local-ai/nvme-placement.md),
[Apple silicon](../../docs/local-ai/apple-silicon.md), and
[two-box NFS](../../docs/local-ai/two-box-nfs.md) cover deployment and scaling.
GB10 and M5 cells stay **needs hardware** until measured there.

```bash
python3 -m unittest discover -s benchmarks/ai -p 'test*.py' -v
python3 -m compileall -q benchmarks/ai
# Real NFSv3 server startup/interrupt/cleanup, no mounts or privileges:
AI_TEST_SERVER=1 python3 -m unittest discover -s benchmarks/ai -p test_ai_benchmarks.py -v
# Outside the sandbox, with a working FUSE runtime:
AI_TEST_FUSE=1 python3 -m unittest discover -s benchmarks/ai -p test_ai_benchmarks.py -v
# With mount.nfs + CAP_SYS_ADMIN and a binary containing nfsv4:
sudo env AI_TEST_NFS=1 RATARMOUNT_BIN="$RATARMOUNT_BIN" \
  python3 -m unittest discover -s benchmarks/ai -p test_ai_benchmarks.py -v
# If installed:
shellcheck benchmarks/ai/*.sh
```

The existing `zstd-decode-ahead.sh`, `decode-benchmark.py`, `session-read.rs`
and decode-summary tests remain the focused zstd decode-ahead benchmark. They
have their own CSV schema and must not append to the six-benchmark result file.
