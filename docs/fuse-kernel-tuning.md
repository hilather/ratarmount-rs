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

## Linux FUSE passthrough

`--passthrough auto|on|off` defaults to `auto`. Linux 6.9 or later and
`FUSE_PASSTHROUGH` (ABI 7.40) are required. `auto` negotiates only when the
process has effective `CAP_SYS_ADMIN` in the **initial user namespace** and the
mount has an eligible source type: a read-only folder, uncompressed local TAR,
or read-only overlay. Unknown privileges, compressed-only sources and writable
overlay mounts keep daemon I/O. Negotiation sets maximum stack depth to 1;
avoiding it for unprivileged mounts preserves their ability to support stacked
filesystems above ratarmount.

`on` forces negotiation and probes regular-file backing registration before
serving requests. A denied probe fails the mount with an error naming
`CAP_SYS_ADMIN`; other probe failures also reject startup. `off` retains the
existing read and page-cache behavior. macOS always uses daemon I/O and rejects
`on`; Linux passthrough init calls are excluded from non-Linux builds.

Use `-d 2` to see `FUSE I/O mode:` logs. The init line distinguishes negotiation
from actual registration; the first successful file registration reports
passthrough. An `EPERM` registration failure logs one warning and permanently
disables preparation of new backings for that mount. `ELOOP`/`EXDEV` failures
are remembered per backing filesystem (`st_dev`). Existing registrations remain
pinned until their last release. Other per-open registration errors log at
`-d 3` and keep daemon reads. See the
[kernel passthrough documentation](https://docs.kernel.org/filesystems/fuse/fuse-passthrough.html).

| Source | Eligibility |
|--------|-------------|
| Plain files in a folder mount | Read-only regular files; their fd covers the whole file |
| Stored members of a local, uncompressed TAR | Regular, contiguous, non-sparse, non-generated, top-level members; reflink preparation or explicitly allowed copying |
| Compressed TAR, sparse members, reader-backed/nested archives | Daemon reads |
| Overlay files on an explicitly read-only mount (`-w overlay -o ro`) | Read-only whole-file fds, including when an overlay policy is installed |
| Writable overlay mounts | Daemon I/O for all opens, preserving write policy, quota accounting, and live-commit behavior |
| Future completed caches | Implement `supports_backing_extents` and supply a whole-file `backing_extent`; partial caches must return `None` |
| Empty file handles | Always daemon reads, even if the host file subsequently grows |

The kernel backing-file interface has **no offset**. Passing a TAR archive fd
would expose its header as the first member byte. Instead, ratarmount prepares
a private per-member file with byte zero at the member's first byte. It tries
`FICLONERANGE` for the aligned prefix and copies only the final partial block.
The source and destination offsets must be congruent modulo the filesystem
block size. Since the backing starts at byte zero, the member's **data offset
must be block-aligned**. Its length need not be aligned, but a clone needs at
least one full block. For 4 KiB blocks, only roughly one in eight possible
512-byte TAR offsets is eligible. The upcoming shard tool will offer
block-aligned member placement.

Reflinks require a supporting filesystem (such as btrfs or reflink-enabled
XFS). Ratarmount first creates an `O_TMPFILE` beside the archive, so source and
target share a filesystem. If that directory is not writable, it tries the
cache directory and temporary directory only when their `st_dev` matches the
archive. Without a writable matching location it skips cloning. On filesystems
without `O_TMPFILE`, it uses a private `0700` directory and an immediately
unlinked file. Clone `ELOOP`/`EXDEV` failures are cached per source filesystem;
opt-in bounded copying can still use another filesystem.

Full copies use `$XDG_CACHE_HOME` (or `$HOME/.cache`). Prepared fds last until
the last concurrent open is released; they are not a persistent member cache.
Failure to create or clone a backing keeps daemon reads unless copying is
explicitly allowed:

```bash
# Clone eligible aligned members, otherwise read through the daemon:
ratarmount --passthrough auto stored.tar /mnt

# Permit copying individual members up to 64 MiB, including unaligned members:
ratarmount --passthrough on --passthrough-copy --passthrough-copy-max 64M \
  --passthrough-copy-total-max 1G stored.tar /mnt

# Compare the original daemon path:
ratarmount --passthrough off stored.tar /mnt
```

Full-member copying requires **both** `--passthrough-copy` and a positive
`--passthrough-copy-max`; the default cap is `0` (off). The cap is per member,
and `--passthrough-copy-total-max` separately limits copied bytes retained by
all concurrently open backings (default **1 GiB**). It includes copied clone
tails; whole-file fds and cloned blocks consume no copy budget. Budget exhaustion
uses daemon reads. Reservations are released on preparation/registration failure
or the last release of a registered inode; concurrent opens share a reservation.
A total cap of `0` disables all copying, including clone tails.

Copies complete before the open reply on the serial request worker, so they
can increase first-open latency and disk usage. Clone/copy failures always fall
back; partial files are never published.

All concurrent opens of an inode reuse one registration. If its first open
falls back, subsequent opens keep daemon I/O until its last release. Linux
rejects mixing cached daemon opens with passthrough opens on the same inode,
and rejects `FOPEN_KEEP_CACHE` on passthrough replies. Daemon replies retain
their existing flags; passthrough uses the backing file's page cache.

This kernel restriction also explains the conservative overlay rule: allowing
a read-only passthrough open on a writable overlay inode would prevent a later
policy-enforcing daemon writer from opening that inode. Writable overlay
mounts therefore retain daemon I/O, even without a policy. Read-only overlay
passthrough assumes the overlay is not concurrently committed or mutated by
another frontend. Use `--passthrough off` if sharing it with writable exports.

Kernel regression checks (outside the Codex sandbox):

```bash
cargo test -p ratarmount --test fuse_passthrough
# Require actual backing registration, on a host with the necessary privilege:
RATARMOUNT_TEST_REQUIRE_PASSTHROUGH=1 cargo test -p ratarmount --test fuse_passthrough
```

The privileged integration tests require initial-namespace `CAP_SYS_ADMIN` and
check bytes plus the startup registration probe. The opt-in environment variable
also requires actual registrations for the folder and copied TAR cases. A
separate unprivileged test checks `auto` daemon mode and forced-on startup denial. Unit tests
exercise negotiation and registration failure over a socket without `/dev/fuse`,
copy limits, alignment, tmpfs fallback, and reflinks on btrfs/XFS. Set
`RATARMOUNT_TEST_REFLINK_DIR` to choose the filesystem for the real clone test.

## One-pass reads with `--direct-io`

`ratarmount --direct-io --parallelization 4 --readahead 16M data.tar.zst mnt/`
sets `FOPEN_DIRECT_IO` on source-member opens, including reopened detached archive
inodes. Overlay-file opens keep their existing cached behavior. This bypasses
the FUSE page cache and kernel readahead for ordinary reads; the daemon's
`--readahead` window and zstd decode-ahead still work. Repeated reads may therefore
cost more CPU. This is a FUSE policy, not `O_DIRECT` on the archive: no aligned
user buffers are required.

Direct I/O disables passthrough for the mount, including an explicit
`--passthrough on`, so daemon reads can apply the eviction policy. Passthrough's
backing-file cache would otherwise keep pages outside this policy. Normal mounts
retain their existing passthrough negotiation.

On Linux, consumed local zstd compressed frames and available plain-file/stored
TAR backing extents receive best-effort `POSIX_FADV_DONTNEED`. This does not evict
pages in use elsewhere or guarantee a cold cache. Other codecs, full-decode
fallbacks and remote/nested compressed streams do not currently expose the
backing ranges needed for this advice. Non-Linux builds omit `posix_fadvise`.

The [kernel FUSE I/O documentation](https://docs.kernel.org/filesystems/fuse/fuse-io.html)
describes the mmap distinction: shared mmap is disabled by default with direct
I/O. fuser 0.18 exposes `FUSE_DIRECT_IO_ALLOW_MMAP`; ratarmount requests it when
the Linux kernel advertises support (introduced in Linux 6.6). On older kernels,
shared mmap of direct-I/O members fails. Private mappings are not covered by
that shared-mmap restriction. Allowing mmap does not make mapped pages bypass
the page cache, so use `read`/`cat` for one-pass cache-avoidance workloads.
[Passthrough](https://docs.kernel.org/filesystems/fuse/fuse-passthrough.html)
also delegates mmap to its backing file; it is disabled here along with reads.


## Sequential request sizes and diagnosis

On Linux kernels advertising `FUSE_MAX_PAGES` (Linux 4.20+), ratarmount raises
the request limit to 256 pages (1 MiB with 4 KiB pages). Older kernels retain
the AI-0a 32-page limit. macOS keeps fuser's platform defaults. fuser 0.18 has
no public `set_max_pages`: it derives the field from the larger of
`set_max_write` and `set_max_readahead`; readahead stays within the kernel's
offered cap. Background/congestion limits remain 12/9. The negotiated values
are logged as `fuse-io-limits` at `-d 2`.

This is a ceiling, not a promise that each read becomes 1 MiB. Cached sequential
reads can use kernel readahead. Direct I/O disables kernel readahead, so a
128 KiB `cat` read remains a synchronous round trip even with a 1 MiB ceiling.
A larger caller such as `dd bs=1M` can use larger direct requests. The daemon
still has one request worker; decode workers parallelize only frame decoding.
The application `--readahead 16M` window is filled synchronously on misses;
codec decode-ahead can overlap frames within that fill, but it cannot overlap
FUSE request handling. Sequential requests that grow across a daemon-window
boundary retain the cached tail and continue forward; they do not rewind and
cancel codec prefetch. A small daemon CPU percentage therefore does not by
itself establish that decoding failed to engage.

The harness compares both FUSE cache modes with `cat` and `dd`, plus Session
and zstd CLI baselines:

```bash
SIZE_MIB=256 THREADS=4 WORK_DIR=$PWD/target/ai-perf-data benchmarks/ai/zstd-decode-ahead.sh
```
 Set `CACHE=warm` to compare against
a warm **backing archive**; the default `cold` uses best-effort per-file
`DONTNEED`, never global `drop_caches`. See
[zstd-random-access.md](zstd-random-access.md#sequential-decode-ahead) for the
CSV counters. At unmount `fuse-read-summary` reports `requests`,
`requested_bytes`, `max_request`, and `service_ns` (wall time including reader
waits and replies). Compare handler time with end-to-end time and the library
baseline to distinguish decoder, backing I/O, and request round-trip costs.
