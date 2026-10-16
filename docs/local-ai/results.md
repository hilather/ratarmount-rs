# Local AI laptop smoke results

These are harness smoke measurements from **2026-10-16**, not GB10/M5 claims
or isolated performance comparisons. Host `brewtop`: Intel Core i7-8750H
(6 cores / 12 threads), 62 GiB RAM, Linux `7.2.5-3-omarchy`, x86_64. Other
workers were building on this shared laptop: recorded one-minute load ranged
roughly **25–65** during the successful measurements. The CSV includes per-row
load, fixture parameters, timestamps and run IDs. Hashing, process/worker startup
and page cache can dominate these small fixtures.

Raw data: [brewtop-2026-10-16.csv](../../benchmarks/ai/results/brewtop-2026-10-16.csv).
Exploratory repetitions are retained; the cold-index numbers below select the
final **one-process / one-union-mount** harness (`5f8a20d760e4`), rather than the
earlier per-shard process implementation. The binary-dependent runs initially
used the integration worktree's existing **debug** `ratarmount 0.1.34` at
`/home/brewerm/git/local-ai-worktrees/integration/target/debug/ratarmount` while
the worker's Rust gates built their dependencies. This is not a release-build
speed claim. The final cold-index and sample runs used this worktree's newly
built `target/debug/ratarmount`; the library sample reader used this branch's
newly built `ratarmount-python` extension. The final sample run is
`6e0e80f02569`. Its library case uses zstd, while `webdataset` reads plain TAR;
the script supports `--codec none` for a matched-format comparison. The final
library run explicitly reuses shard sidecars (`--library-index sidecar`). The
earlier `26937f05a46d` run used Python's temporary-index default and is retained
only as an exploratory result. The model/native/git/local-read baselines do
not execute ratarmount during timing.

| Benchmark / case | Laptop result | Dell GB10 / DGX Spark | M5 Apple silicon |
|---|---|---|---|
| Samples, extracted, 8 workers, 256 × 64 KiB + JSON | 2,760.703 samples/s | needs hardware | needs hardware |
| Samples, `webdataset` TAR, 8 threads | 662.010 samples/s | needs hardware | needs hardware |
| Samples, library, 8 threads, zstd | 488.443 samples/s | needs hardware | needs hardware |
| Samples, FUSE | skip: `/dev/fuse` absent | needs hardware | needs hardware |
| Samples, squashfs | skip: mksquashfs/squashfuse absent | needs hardware | needs hardware |
| 64 parallel git worktree attempts | 15.430 s mean setup+teardown per attempt | needs hardware | needs hardware |
| 64 parallel ratarmount sandbox attempts | skip: `/dev/fuse` absent | needs hardware | needs hardware |
| 64 parallel Docker copy attempts | 48.751 s mean setup+teardown per attempt | needs hardware | needs hardware |
| Native zlib configure + build + tests, 2 jobs | 20.621 s | needs hardware | needs hardware |
| Sandbox zlib configure + build + tests | skip: `/dev/fuse` absent | needs hardware | needs hardware |
| Cold open scan, 16 MiB, 3 zstd shards, no FUSE | 1.023449 s | needs hardware | needs hardware |
| Cold open published indexes, same shards, no FUSE | 0.072408 s | needs hardware | needs hardware |
| Cold FUSE union mount, published / scan | skip: `/dev/fuse` absent | needs hardware | needs hardware |
| RSS, 32 concurrent mounts | skip: FUSE absent; Python ratarmount/squashfuse absent | needs hardware | needs hardware (Linux VM `/proc`) |
| Tiny model `hf download` + read all tensor bytes | 3.979174 s | needs hardware | needs hardware |
| Same downloaded model, second tensor read | 0.012596 s | needs hardware | needs hardware |
| `hf://` mount, first / second tensor read | skip: `/dev/fuse` absent | needs hardware | needs hardware |
| Local 16 MiB read + SHA-256, NFS comparison baseline | 134.316 MB/s | needs hardware | needs hardware |
| Kernel NFS loopback | skip: `mount.nfs` absent (also needs CAP_SYS_ADMIN) | needs hardware | needs hardware (Linux VM) |
| Two Dell ConnectX-7 NFSv4.1 link | needs hardware | needs hardware | needs hardware |

The final 64-attempt run is `d8d5bc087a9c`: git batch wall time was
17.220728 s and Docker batch wall time was 60.769883 s. The Alpine image was
pulled before timing; its immutable ID is recorded in the Docker row. The
earlier image-missing skip is retained in the raw data.

The zlib repo has 257 tracked files and is about 6.5 MiB including `.git` at the
pinned commit. That meets the quick real-project fixture goal; it does not model
a large SWE-bench checkout. The 64-attempt value excludes barrier hold time;
batch makespan is recorded separately in `seconds`. A shared Git object store,
a Docker checkout copy and a sandbox base have different metadata costs.
The tiny model has 509,452 tensor payload bytes (the loader reads and hashes all
tensors, rather than just its header). This is storage I/O, not inference.

Commands run from the worktree root (the benchmark venv adds `webdataset` and
`huggingface_hub`; torch was absent). Python was 3.14.7, the system Hub
package was 1.30.0, and the optional `webdataset` reader was 1.0.2:

```bash
python3 benchmarks/ai/build-test.py --jobs 2
python3 benchmarks/ai/model-load.py
./benchmarks/ai/two-box-nfs.sh loopback --mib 16
export RATARMOUNT_BIN=/home/brewerm/git/local-ai-worktrees/integration/target/debug/ratarmount
docker pull alpine:3.20  # outside timing; scripts never pull images
python3 benchmarks/ai/sandbox-attempts.py --attempts 64
python3 benchmarks/ai/mount-memory.py --mounts 32
export RATARMOUNT_BIN="$PWD/target/debug/ratarmount"
python3 benchmarks/ai/cold-index.py --gib 0.015625
cargo build -p ratarmount-python --features extension-module
# A local test import, keeping all artifacts in the ignored benchmark cache:
mkdir -p benchmarks/ai/.cache/binding
cp -r ratarmount-python/python/ratarmount_rs benchmarks/ai/.cache/binding/
cp target/debug/lib_native.so benchmarks/ai/.cache/binding/ratarmount_rs/_native.abi3.so
PYTHONPATH="$PWD/benchmarks/ai/.cache/binding" \
  benchmarks/ai/.cache/venv/bin/python benchmarks/ai/samples.py \
  --samples 256 --sample-bytes 65536 --workers 8
```

Samples include full-content fingerprints. Cold opens use advisory per-file
`DONTNEED`, fresh processes and fresh scan index directories; backing storage
coldness is not guaranteed. Published copies are made locally through
`--publish-index` and discovered via `--index-folders`; no remote publication
or discovery claim follows. The model download used a fresh private Hub cache;
the second read reused its OS-cached file. No global caches were flushed.

A real NFSv3 server startup/interrupt/closed-listener regression also passed
using `AI_TEST_SERVER=1` and the worker binary, without mounting anything.

Validation: `cargo fmt --all`, `cargo fmt --all -- --check`,
`cargo clippy -p ratarmount --all-targets -- -D warnings`,
`cargo test -p ratarmount --no-run`, and `cargo test -p ratarmount` passed.
The benchmark regression suite (including the real unprivileged NFS server
check) ran 36 tests: 33 passed, with three privileged tests skipped. `python3 -m compileall -q benchmarks/ai` and `bash -n benchmarks/ai/*.sh` passed. Shellcheck was not
installed. These Rust results do not substitute for real FUSE mounts.

The [suite README](../../benchmarks/ai/README.md) defines each timing boundary.
To finish the comparison, the orchestrator must run all six defaults outside
the sandbox using a release binary and installed binding, plus optional
squashfs, Python ratarmount, `webdataset`, torch and a preloaded Docker image.
Run `AI_TEST_FUSE=1` for the sample/sandbox/build/index/RSS smoke tests and `AI_TEST_NFS=1` with
privileges and `mount.nfs` for the NFS checksum test. Use the
[DGX guide](dgx-spark.md), [Apple notes](apple-silicon.md), and
[two-box procedure](two-box-nfs.md) for hardware runs. Confirm the AI-MEM flag
is present before trying the documented memory-budget configuration; this
worker snapshot predates it.
