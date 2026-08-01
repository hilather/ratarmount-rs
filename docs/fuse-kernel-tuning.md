# FUSE kernel & mount tuning for ratarmount-rs

**Audience:** operators who want faster **sequential** or **parallel** reads through a ratarmount FUSE mount.  
**Policy:** Prefer **application knobs** (`--readahead`, codec spacing) first; use kernel/sysfs tuning for **concurrency**.  
**Harness:** [`benchmarks/compare-fuse-kernel-tuning.sh`](../benchmarks/compare-fuse-kernel-tuning.sh) (fair disk O_DIRECT + FUSE config A/B).  
**Results (local, gitignored):** `benchmarks/fuse-kernel-results/{results.csv,results.md}` after you run the script.

## What “fast” means here

| Layer | What you measure | Fair baseline |
|-------|------------------|---------------|
| **Disk** | O_DIRECT sequential read/write of a probe file on the **same filesystem** as the archive | Media thruput (bypasses page cache) |
| **Page cache** | Buffered re-read after warm | **RAM** — not disk; multi‑GB/s is normal |
| **FUSE seq** | `cat` of an uncompressed member through the mount | Uncompressed MiB/s (same as other ratarmount benches) |
| **FUSE parallel** | N concurrent **1 MiB** window reads at different offsets | Aggregate MiB/s; stresses `max_background` without N full-file decompresses |

FUSE cannot make decompressing mounts “as cheap as raw `read()` of a hot file.” Kernel tuning mainly reduces **request queue stalls** and **metadata chatter**; it does **not** remove inflate cost.

## Recommended defaults (optimal starting point)

Use this unless a re-run of the harness says otherwise on your machine:

```bash
# Read-only archive, sequential-friendly gzip/tar.gz:
ratarmount -o noatime --readahead 1M archive.tar.gz /mnt

# Bulk sequential scan (more RAM per open handle):
ratarmount -o noatime --readahead 4M archive.tar.gz /mnt

# Random-heavy FUSE into large gzip (codec side, not kernel):
ratarmount -o noatime --readahead 1M -gs 4 archive.tar.gz /mnt
```

Then, **if many parallel readers** (build tools, multi-threaded apps, `xargs -P`, etc.), raise the connection queues (see below).

| Knob | Suggested | Why |
|------|-----------|-----|
| **`-o noatime`** | **on** | Fewer atime updates / metadata ops on read-heavy mounts |
| **`--readahead`** | **1 MiB** default (auto on gzip); **4 MiB** for bulk seq | Amortizes short FUSE reads into decompressors |
| **`--readahead 0`** | only if measuring pure per-read cost | Usually **hurts** sequential thruput |
| **`max_background`** | **64** (busy parallel); kernel default often **~12** | More outstanding FUSE requests before congestion |
| **`congestion_threshold`** | **~75% of max_background** (e.g. **48** with 64) | When the kernel starts throttling |
| **`direct_io`** | **avoid** for archives | Bypasses page cache → usually worse re-reads |
| **`sync` / `dirsync`** | **avoid** | Forces slow path |

Application-side (already in ratarmount-rs):

| Knob | Suggested |
|------|-----------|
| G3 default gzip | keep default unless you need Tier D rapidgzip |
| `-gs` / `--gzip-seek-point-spacing` | **16** general; **1–4** random-heavy |
| Release binary | always for benches / production mounts |

## Per-connection sysfs (after mount)

On Linux, each FUSE mount has a connection under `/sys/fs/fuse/connections/<minor>/`.  
The **minor** is the second half of `findmnt -n -o MAJ:MIN /mnt` (e.g. `0:64` → connection `64`).  
Files are typically **owned by the mounting user** (no root required for your own mounts).

```bash
MP=/mnt
MIN=$(findmnt -n -o MAJ:MIN --target "$MP" | cut -d: -f2)
CONN=/sys/fs/fuse/connections/$MIN

# Inspect
echo "max_background=$(cat $CONN/max_background)"
echo "congestion_threshold=$(cat $CONN/congestion_threshold)"
echo "waiting=$(cat $CONN/waiting)"

# Parallel-friendly (example)
echo 64 > "$CONN/max_background"
echo 48 > "$CONN/congestion_threshold"
```

| File | Meaning |
|------|---------|
| `max_background` | Cap on background/outstanding FUSE requests |
| `congestion_threshold` | Soft throttle threshold (must be ≤ max_background) |
| `waiting` | Requests waiting (non-zero under load is normal; stuck high may mean userspace is slow) |

**Reset:** unmount/remount (defaults return).

**When it helps:** many concurrent readers/writers on one mount.  
**When it barely matters:** single-threaded sequential `cat` of one gzip member (CPU/readahead dominate).

## Module parameters (`fuse`)

```bash
ls /sys/module/fuse/parameters/
# typical:
#   max_user_bgreq
#   max_user_congthresh
#   enable_uring
```

| Parameter | Guidance |
|-----------|----------|
| `max_user_bgreq` / `max_user_congthresh` | Global caps across mounts; modern kernels already set large values (tens of thousands). Only raise if many mounts hit global limits. |
| `enable_uring` | Experimental FUSE io_uring on newer kernels; leave **off** unless you are deliberately testing; ratarmount does not require it. |

Boot-time example (rarely needed):

```bash
# /etc/modprobe.d/fuse.conf
options fuse max_user_bgreq=65536 max_user_congthresh=65536
```

## Mount options reference (`-o` / `--fuse`)

Passed through ratarmount’s option parser (known tokens + `CUSTOM` for libfuse/kernel):

| Option | Recommendation |
|--------|----------------|
| `noatime` | **Yes** for RO archive mounts |
| `ro` | Default without write overlay |
| `async` | Default; do not force `sync` |
| `auto_unmount` | Convenience only |
| `allow_other` | Permission model, not thruput |
| `direct_io` | **No** for normal archive serving |
| `default_permissions` | Security/consistency; neutral thruput |

## Fair disk comparison (do this before claiming wins)

```bash
# Full harness (disk O_DIRECT + FUSE matrix)
./benchmarks/compare-fuse-kernel-tuning.sh
# → benchmarks/fuse-kernel-results/{results.csv,results.md}

# Disk only / FUSE only / larger corpus
SKIP_FUSE=1 SIZE_MIB=512 ./benchmarks/compare-fuse-kernel-tuning.sh
SKIP_DISK=1 SIZE_MIB=64 PARALLEL=8 ./benchmarks/compare-fuse-kernel-tuning.sh

# True cold disk read (needs root for drop_caches)
DROP_CACHES=1 SIZE_MIB=512 ./benchmarks/compare-fuse-kernel-tuning.sh
```

**Rules of fairness:**

1. Probe file and archive on the **same block filesystem** (not a RAM tmpfs if you can avoid it).
2. Quote **O_DIRECT** for “disk speed,” not hot page-cache numbers.
3. Quote FUSE as **uncompressed MiB/s** and say so.
4. Do not claim FUSE “beats disk” when page-cache re-reads are multi‑GB/s and O_DIRECT is ~1 GB/s.

### Example interpretation (order of magnitude on a modern NVMe laptop)

These are **illustrative** of what the harness is designed to surface; re-run locally for authoritative numbers:

| Path | Typical order |
|------|----------------|
| NVMe O_DIRECT seq | ~1–3 GB/s |
| Hot page cache | ~5–15 GB/s |
| G3 FUSE gzip seq (64 MiB corpus) | often ~0.5–1.5 GB/s uncompressed |
| Raising `max_background` | small seq change; larger **parallel** aggregate gains |
| `--readahead 0` → `1M`/`4M` | often clear sequential win |

## Optimal recipe checklist

1. **Release** binary; warm index (`--index-file`) for remounts.  
2. **`-o noatime`**.  
3. **`--readahead 1M`** (or rely on gzip auto 1 MiB); **`4M`** for bulk sequential.  
4. For **parallel** clients: set **`max_background=64`**, **`congestion_threshold=48`**.  
5. For **random** gzip: denser **`-gs 1..4`**, keep moderate readahead.  
6. Re-run [`compare-fuse-kernel-tuning.sh`](../benchmarks/compare-fuse-kernel-tuning.sh) after changes; keep results under `benchmarks/fuse-kernel-results/` (gitignored).  
7. If still slow: profile **CPU (inflate)** and **FUSE waiting**, not only disk.

## What not to do

- Raise `max_background` to thousands without measuring (more memory / worse latency under some loads).  
- Use `direct_io` “for fairness” on FUSE archives (changes the product path).  
- Compare FUSE uncompressed MiB/s to O_DIRECT of the **compressed** file without stating units.  
- Expect kernel tuning alone to match Python rapidgzip or raw NVMe on decompress-bound streams.

## Related

- Mount options parity: [`docs/mount-options-parity.md`](mount-options-parity.md) (`--readahead`, `-o`)  
- Gzip G3 polish / spacing: [`docs/gzip-binding-decision.md`](gzip-binding-decision.md), [`docs/tasks/g3-polish-batch.md`](tasks/g3-polish-batch.md)  
- General benches: [`benchmarks/README.md`](../benchmarks/README.md)
