# Two Dells over ConnectX-7

Store shards once on Dell A and export them to Dell B using NFSv4.1. Benchmark
against a local copy on B before deciding whether to keep a second dataset.
These commands are prepared for the two GB10 Dells; the actual link was not
available for validation. A ConnectX-7 connection's nominal line rate is not a
measured filesystem throughput claim. This export uses TCP, not NFS-over-RDMA.

Use NVIDIA's [multi-Spark networking procedure](https://github.com/NVIDIA/dgx-spark-playbooks/blob/main/nvidia/playbook-connect-multiple-sparks/README.md)
to establish the private link. Record NIC/IP selection, negotiated link speed,
MTU, kernel, storage layout and background load. Check IP reachability and
optionally `iperf3` first; no benchmark script changes network settings.
Use the ConnectX private IP explicitly so traffic does not take ordinary Ethernet.

Build ratarmount with `--features nfsv4`. Choose a large shard member and record
its checksum and size. On box A, serving an archive or directory:

```bash
export RATARMOUNT_BIN="$PWD/target/release/ratarmount"
./benchmarks/ai/two-box-nfs.sh serve --source /srv/datasets/train.tar.zst \
  --bind 192.168.50.1 --version 4 --port 20490
```

On box B install `nfs-common` if needed. Put an identical member on B's NVMe,
then run as root with the path to the binary preserved:

```bash
sudo env RATARMOUNT_BIN="$PWD/target/release/ratarmount" \
  ./benchmarks/ai/two-box-nfs.sh read --host 192.168.50.1 \
  --member samples/00000000.bin --version 4 --port 20490 \
  --local-file /srv/local-comparison/00000000.bin --runs 3
```

`--local-file` hashes the local bytes and requires every NFS read to match them.
Alternatively pass `--sha256 <hash-from-A>`. The first NFS read uses a fresh
client mount, while subsequent reads reuse it and may hit the client page cache;
the server/OS cache is uncontrolled. All throughputs include SHA-256 work and
use decimal MB/s. The local row uses advisory file eviction where supported.
Run separate fresh invocations to study cold clients. Do not flush global caches
on a shared box. A single reader plus hashing can be CPU-bound long before it
fills the link; these numbers do not establish multi-worker training throughput.

The script owns and unmounts only its temporary client mount. Ctrl-C in the
server terminal stops the server it started. No SSH or remote configuration is
performed. The private bind is intentional: AUTH_SYS NFS is not an encrypted or
strongly authenticated public-network service.

For a small loopback check on Linux, outside the worker sandbox:

```bash
sudo env RATARMOUNT_BIN="$PWD/target/release/ratarmount" \
  ./benchmarks/ai/two-box-nfs.sh loopback --mib 16 --version 4
# A build without nfsv4 can exercise the v3 path:
sudo env RATARMOUNT_BIN="$PWD/target/release/ratarmount" \
  ./benchmarks/ai/two-box-nfs.sh loopback --mib 16 --version 3
```

Loopback needs `mount.nfs` and `CAP_SYS_ADMIN`, but no `/dev/fuse`. When those
are missing it still measures the local read and records the NFS skip in CSV.
The server lifecycle alone can be tested without privileges using
`AI_TEST_SERVER=1 python3 -m unittest discover -s benchmarks/ai -p test_ai_benchmarks.py`.
Run `AI_TEST_NFS=1 python3 -m unittest discover -s benchmarks/ai -p test_ai_benchmarks.py`
with those privileges for the checksum/cleanup smoke test. All script modes
append the common `results/<host>-<UTC-date>.csv` and print a table.
