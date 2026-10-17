# Zstd random access (seekable / multi-frame)

How **ratarmount-rs** mounts plain `.zst` and compressed TAR (`.tar.zst` / `.tzst`)
with random read, and how producers should compress large files so seeks stay cheap.

Upstream context: [mxmlnkn/ratarmount#196](https://github.com/mxmlnkn/ratarmount/issues/196)
(multi-frame / chunked zstd examples). Implementation lives in
`ratarmount-compress` (`zstd_seek.rs`).

---

## Open priority (what happens when you mount)

On open, the codec classifies the stream in this order:

| Priority | Path | When it applies | Random-access cost |
|----------|------|-----------------|--------------------|
| **1. Seek table** | Official [zstd seekable format](https://github.com/facebook/zstd/blob/dev/contrib/seekable_format/zstd_seekable_compression_format.md) footer (skippable frame, magic `0x8F92EAB1`) | Producer wrote a seek table | Jump to frame; decompress only that frame (best) |
| **2. Multi-frame scan** | Concatenated independent zstd frames (no footer) | Chunked / multi-frame producers | One pass builds a frame map; seeks restore only the covering frame |
| **3. Full decode** | Single large frame, no seek table | Default `zstd file -o out.zst` on big inputs | Whole stream decoded to RAM (≤ ~256 MiB) or a temp spool |

**Python `zstdblocks` maps** (SQLite index side table / `indexed_zstd` pairs) can also
be imported. That skips seek-table and multi-frame rescan and uses the stored
`(compressed_offset, uncompressed_offset)` pairs (EOF sentinel last). Export is
available from the compress crate for tooling interop.

Nested mounts (e.g. `.tar.zst` inside ZIP/7z with `-r`) use the same seekable
body path when the outer member is `Read + Seek` — see
[embedded-nested-archives.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/embedded-nested-archives.md).

---

## Recommendation for producers

For **large** plain `.zst` or `.tar.zst` that will be mounted and randomly read
(index build, FUSE `pread`, nested open):

1. **Prefer the official seekable format** (seek table at EOF) when you control
   the compressor and have a seekable-format tool or library. Fastest map build
   (no frame walk) and clear frame sizes without decompressing during open.
2. **Otherwise use multi-frame / chunked zstd** — independently compressed frames
   concatenated into one file. Standard `zstd` is enough; no special footer.
   Frame size is a trade-off: smaller frames → cheaper seeks / more map entries;
   larger frames → better ratio, worse worst-case seek.
3. **Avoid a single giant frame** for multi‑GiB payloads if you care about
   cold open or random access. Default one-shot compression falls through to
   **full decode** (memory or temp), which works but is not ideal for huge files.

Small files (well under the ~256 MiB in-memory decode cap) are fine as a single
frame; the full-decode path is simple and fast enough.

---

## One-shot producer

`ratarmount --repack-seekable INPUT OUTPUT` rewrites a file and exits. It does
not mount and is not combined with `--commit-overlay` (or a non-zero
`--commit-overlay-interval` / `--commit-overlay-on-exit`). `--yes` overwrites.
`--repack-frame-size BYTES` defaults to 8 MiB when omitted (`1M` = 1 048 576)
and only affects a recompress.

```bash
ratarmount --repack-seekable in.tar.gz out.tar.zst
```

| Output suffix | Product |
|---------------|---------|
| `.zst`, `.tzst`, `.zstd`, `.tar.zst`, `.tar.zstd` | Multi-frame zstd plus a seek-table footer |
| `.gz`, `.tgz`, `.gzip`, `.tar.gz` | Byte copy of a gzip input, plus `{output}.rgzi` (or `--repack-gzip-index gzidx` / `both`) |
| anything else | Error, exit 2 |

Zstd destination — copy versus recompress:

| Input | Action |
|-------|--------|
| At least two frames and a seek-table footer | **Copy**. Output bytes match the input. |
| At least two frames, no footer, packed from offset 0 with no gaps, every size fits `u32` | **Append** a seek-table footer. Prefix frames stay byte-identical. |
| At least two frames, no footer, and a size does not fit `u32` **or** a skippable frame sits before or between data frames | **Copy**. No footer. A footer would hide the gap: the loader places frame *i* at the sum of compressed sizes from 0. |
| Single zstd frame, with or without a one-row seek table | **Recompress** into `frame_size` chunks, then one footer. |
| gzip or uncompressed bytes | **Recompress** the same way. |
| bzip2, xz, lz4, 7z, zip | Error. v1 reads gzip, zstd, or uncompressed bytes. |

Gzip output is copy-only: a second deflate does not create seek points, so the
index is the sidecar. A non-gzip input named `.gz` is an error. The default
sidecar is `.rgzi` only. `--yes` removes the sidecar that was not selected
after a successful publish (a previous `.rgzi` does not survive `gzidx`, and
the reverse), unless that sidecar is the input: the command then refuses
before publish and does not unlink it. A failed publish leaves the previous
archive and both sidecars.
TAR member order stays input byte order; names are not sorted.

---

## How to produce multi-frame zstd

Both patterns create **concatenated independent frames**. Standard `zstd` is
sufficient. Inspired by upstream [#196](https://github.com/mxmlnkn/ratarmount/issues/196).

### 1. Chunked file list → multiple compressed TAR frames

Groups files into batches; each batch becomes its own TAR+zstd frame; frames are
appended:

```bash
find /path/to/data -type f \
  | xargs -n 40 tar -c -I 'zstd -10' \
  >> /path/to/archive_40.tar.zst
```

- `xargs -n 40` — files per frame (tune for size vs seek granularity)
- `-I 'zstd -10'` — compress each TAR independently
- `>>` — append frames into one multi-frame stream

**Mount note:** each frame is a complete TAR. Use **`-i` / `--ignore-zeros`** so
the TAR indexer continues past end-of-archive zeros between frames:

```bash
ratarmount -i archive_40.tar.zst mnt/
```

### 2. Single TAR stream → fixed-size compressed chunks

One logical TAR, split into fixed-size pieces, each piece compressed as its own
frame:

```bash
tar -c -C /path/to/data . \
  | split -b 8M --filter='zstd -10 -q >> /path/to/archive_8M.tar.zst'
```

- `split -b 8M` — uncompressed chunk size before each `zstd` invocation
- Each filter run emits one frame; `>>` concatenates them

For a continuous single TAR across frames, `-i` is usually only needed when you
**append** more frames later. For cold mounts of a one-shot build, try without
`-i` first; add it if the index stops early.

### 3. Append more data later

Re-run the same pipeline with `>>` to append new frames. Multi-frame maps pick
up the new frames on the next open (or after index rebuild). Prefer
`--ignore-zeros` when mixing multiple TAR EOFs.

### 4. Official seekable format (when available)

If you use a **seekable-format** compressor (zstd contrib / library that writes
the seek-table skippable footer), ratarmount-rs prefers that map on open
(`kind` diagnostic: `zstd-seek-table`). You do not need multi-frame hacks; keep
frames reasonably small for good seek latency.

Plain multi-frame without a footer still works well (`kind`: multi-frame scan).

---

## What ratarmount-rs does at runtime

| Stage | Behavior |
|-------|----------|
| **Open / classify** | Seek table → else multi-frame walk → else full decode |
| **Mapped read** | Locate frame covering the uncompressed offset; decompress that frame (cached per reader); serve the range |
| **Full decode** | Stream-decompress once into RAM or temp; then seek in the decoded body |
| **Threads (`-P` / backend hint)** | Multi-frame maps already isolate frames; full multi-frame materialization can decode frames in parallel when threads > 1 |
| **Index side tables** | Python-compatible `zstdblocks` import/export for cross-tool maps. After a last-frame splice, F-2 rewrites `zstdblocks` from a **fresh** frame scan of the new file inside the sidecar patch transaction (pre-splice maps are not imported). |
| **Incremental reindex (F-2)** | Persist patches the on-disk sidecar from the rewrite window; remount does **not** rescan prefix frames. Persist still **copies** the compressed prefix. `:memory:` / discarded sidecar / single-frame `.tar.zst` still full-rebuild. ZIP commit is still a full rebuild. |
| **Nested / Shared** | From-reader path shares the compressed stream under a mutex; each open tracks a **private compressed offset** so concurrent FUSE readers cannot interleave `seek`+`read` |

Plain `.zst` (non-TAR payload) uses the same seekable body under a single-file
mount — no full payload spool just to present one file.

### Single-frame residual

Default `zstd -o big.zst` emits **one frame**. That path still works (full decode
to RAM ≤ ~256 MiB or a temp spool) but cold open and random access cost scale with
the whole uncompressed size. Prefer a seek table or multi-frame producers (above)
for multi‑GiB mounts.

---

## Quick checks

```bash
# Multi-frame or seek-table .tar.zst
ratarmount -i large.tar.zst mnt/
ls mnt/ | head
dd if=mnt/some/file bs=4k count=1 skip=1000 status=none | wc -c

# Plain multi-frame .zst
ratarmount big.zst mnt/
# → mnt/<basename without .zst>
```

If open is slow or RSS jumps on a multi‑GiB `.zst`, the stream is likely a
**single frame** (full decode). Recompress with multi-frame chunks or a seek
table using the recipes above.

---

## Live overlay commit

`--commit-overlay-on-exit` and `--commit-overlay-interval` accept a **single**
host file that is an uncompressed TAR or `.tar.zst` / `.tzst` / `.tar.zstd`
(or zstd magic + TAR body), with durable `-w` (not `:temp:`). A missing
`.tar.zst` is created as **one empty zstd frame** (1024-byte POSIX TAR EOF,
no seek table) when `-w` is set. One existing `s3://`, `gs://`, or `az://` `.tar` or `.tar.zst`
uses the same live queue: the object is spooled outside the overlay, spliced,
and uploaded (object, then index blob, then pointer). Live ticks still
**reject** prefix-frame mutate (append-only + last-window, no upload).
Offline `--commit-overlay` **is** the
escape hatch for earlier-frame delete/replace: splice from the affected frame
through EOF (prefix frames byte-identical). Classification of that splice
always walks past per-frame TAR EOF (the `xargs tar -c | zstd >>` shape),
so a later-frame delete applies even when the commit command omits `-i`.
Live interval / on-exit classification uses the same full-frame walk: a
tombstone created with `-i` still persists after remount without `-i`
(the mounted `current_base()` would otherwise treat that name as overlay-only
and forget the delete). A missing `.tar.zst` on the
offline path still exits 2 without creating a file (create-if-missing is
uncompressed `.tar` only). Interval `DURATION` is a **per-file settle time**:
only overlay files whose host mtime is at least that old **and** that have no
open write fd are written into the archive; recently modified or still-open
files stay in the overlay until they go idle. On-exit still flushes everything.
See
[mount-options-parity.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/mount-options-parity.md)
and [nfs-export.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/nfs-export.md).

Producer recipes above stay valid. Persist **rewrites only the last zstd frame**
(does not recompress the prefix). Prefix frames stay byte-identical, including
complete-TAR frames (`xargs tar -c | zstd >>`) and split-suffix frames
(`split -b … | zstd >>`). Official seek-table footers are rebuilt when present
and dropped when a frame size exceeds the seekable-format `u32` limit.

**Cost model residual (not “O(last frame)” end-to-end):**

| Step | Cost |
|------|------|
| Last-frame rewrite | Decode + encode the last N frames only (no prefix recompress) |
| Persist (`copy`, default) | Reflink / kernel range copy when available, otherwise a byte copy to a sibling tmp |
| Persist (`append` / eligible `auto`) | Journal and replace only the suffix in place |
| Remount / interval reopen | F-2 patches a durable sidecar from the changed suffix; without a sidecar, full indexing |

With `copy`, plan **2× compressed size** disk headroom on filesystems without reflinks (tmp + original until `persist`
unlinks the old inode). Single-frame `tar \| zstd` is a full last-frame rewrite
(same recompress class as offline gzip TAR commit). **Never refuse on size** —
startup warns when the last-frame uncompressed size exceeds **64 MiB** (a
brand-new one-frame empty archive does **not** warn), then spills
decoded/encoded suffix above 256 MiB.

`--commit-overlay-mode copy|append|auto` also applies to uncompressed TAR and
local offline `--commit-overlay`. The default, `copy`, preserves the existing
copy/rename semantics. `append` journals and overwrites the old EOF/suffix only
for adds-only plans (and `.tar.zst` must have a seek table); replacements/deletes
use copy. `auto` chooses append only when that plan is eligible and the archive
has one hard link. `append` explicitly permits changing hard-linked archives.

```bash
ratarmount -w ov --commit-overlay-mode auto --commit-overlay-interval 15m data.tar.zst mnt
ratarmount --commit-overlay --commit-overlay-mode append --yes -w ov data.tar
```

Append preserves the inode and needs space for the old and new suffixes plus
new data. It changes bytes in place: readers in other processes/mounts, and
reads overlapping the commit on this mount, can observe an incomplete suffix.
Use `copy` for snapshot-like reader isolation. Successful live commits reopen
the source and refresh its generation as before. The journal
`<archive>.ratarmount-commit-journal` is fsynced before mutation and recovered
before every archive open (including read-only CLI and `Session::open`) or
commit. The archive inode carries a journal-locator xattr so aliases also find
pending recovery. Recovery refuses mismatching content or insufficient write
access with the journal path and resolution instructions. Keep the journal with
its archive after a crash. Append requires writable user xattrs; `auto` falls
back to copy if unavailable. Recoverable live append errors roll back immediately
and remain eligible for the next interval. A failed recovery/reopen requires
remount and refuses base reads. For old/new suffix sizes O/N, staging plus the
journal can occupy O + 2N + 100 bytes, including leftovers after process death.
See the [crash protocol](tasks/tar-zst-live-commit-design.md#crash-protocol).

**Not supported (live v1):**

- Gzip / bzip2 / xz live splice — rejected with a message that **names gzip**
  (or the other codec). G3 inflate checkpoints are not deflate cut points.
- Live delete/replace of a name that still has a version in an earlier frame
  (append-only + last-window mutate). Use offline `--commit-overlay` (PR 7
  shipped: rewrite from the affected frame through EOF).
- Offline create-if-missing of a missing `.tar.zst` (uncompressed `.tar` only).
- Plain `.zst` that is not a TAR body.

---

## Related

| Doc / code | Role |
|------------|------|
| [gzip-binding-decision.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/gzip-binding-decision.md) | Gzip checkpoints (analogous idea for deflate) |
| [embedded-nested-archives.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/embedded-nested-archives.md) | Nested `.tar.zst` / plain `.zst` without `/tmp` |
| [parity-todo.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/parity-todo.md) | Codec parity checklist |
| `ratarmount-compress/src/zstd_seek.rs` | Implementation + unit tests |
| Upstream [#196](https://github.com/mxmlnkn/ratarmount/issues/196) | Multi-frame / chunked zstd examples |

## Sequential decode-ahead

Mapped multi-frame and seek-table readers can decode upcoming frames concurrently.
The CLI defaults `--parallelization` to `min(available CPUs, 4)`; `-P 1` keeps
serial decoding. Library openers and Session's default `ParallelizationSpec`
remain at one thread. Explicit `0` still means all available CPUs.

After 128 KiB of uninterrupted forward progress, each reader schedules upcoming
frames on a shared process-wide pool. The pool grows to the largest requested
thread count; readers queue at most `min(threads, 16)` frames. Results are consumed
in frame order. A position-changing seek drops queued results immediately,
without waiting for running decodes. A speculative error is retried synchronously
when that frame is actually requested; later corrupt frames cannot fail an
earlier read. Random reads retain the single-frame cache path.

`--readahead BYTES` also sets the speculative decoded-byte budget for local zstd
openers (64 MiB maximum). When omitted, zstd uses 16 MiB, independently of the
FUSE read window. Explicit `--readahead 0` disables decode-ahead. Equal-size frames
therefore occupy at most `min(threads, 16, budget / frame_size)` slots. A frame
larger than the budget is decoded synchronously: the byte limit takes precedence
over a minimum speculative slot. Variable-size frames reserve their individual
uncompressed lengths before submission. Cancelled running jobs retain their
reservation until they finish. The current synchronous frame, decoder working
memory and FUSE's separate read window are additional memory costs; this is not
a process-wide RSS limit. Input is streamed, without a full compressed-frame copy. Consumed frame buffers
are handed back to workers for reuse when they fit the next reservation, avoiding
per-frame allocation/zero-fill and cross-thread frees on the steady-state path.

Path-backed reads use Linux `POSIX_FADV_SEQUENTIAL` during decode-ahead.
Before dispatch, a bounded contiguous `POSIX_FADV_WILLNEED` hint queues backing
reads in frame order, avoiding dependence on worker scheduling for disk readahead. With
`--direct-io`, successfully decoded compressed ranges also receive
`POSIX_FADV_DONTNEED`. Advice is best effort and may retain partial pages. Reader
backends such as HTTP and nested archive streams have no local descriptor to
advise. Single-frame full-decode fallback does not use this pool or these hints.
The CLI's explicit byte budget and direct-I/O advice currently reach top-level
local zstd openers; nested/remote zstd retains its thread setting and the library
16 MiB window. No temporary spool is added by decode-ahead.

Run `SIZE_MIB=256 THREADS=4 benchmarks/ai/zstd-decode-ahead.sh` for a smaller
smoke run (default member size: 1 GiB). The CSV compares:

- Session reads of the same member with 128 KiB buffers, at `-P 1` and `-P N`;
- `zstd -d` of the entire TAR to `/dev/null` (its byte count includes TAR framing);
- fresh FUSE mounts with direct I/O **off and on**, each at `-P 1` and `-P N`,
  using both `cat` and `dd bs=1M` to distinguish caller request-size limits.

Mount/index time is excluded. CPU percent is the daemon's CPU for FUSE, the
Session process's CPU for library reads, and the zstd child's CPU for the CLI
(100% = one CPU). `CACHE=cold` (default) advises eviction of only the compressed
fixture before each run; `CACHE=warm` reads it into cache first. Eviction is
best effort, and does not produce cold disk reads on tmpfs. Every FUSE row uses
a new mount, so it never measures a hot FUSE member re-read. Use
`WORK_DIR=$PWD/target/ai-perf-data` to keep the fixture/logs on the archive's
filesystem and reuse them between runs. By default the scratch fixture lives below the workspace
`target/` directory, avoiding the common tmpfs `/tmp` default. Check
`findmnt -T "$WORK_DIR"` before drawing disk conclusions: a custom directory
or workspace can still be RAM-backed.
`NO_FUSE=1` runs the baselines without a mount; missing `/dev/fuse` also skips
only FUSE. `SKIP_BUILD=1` reuses existing release binaries. `READAHEAD=1M`
overrides the harness's 16 MiB FUSE/codec window. Missing `zstd` skips its CLI
row with a message; Session still runs.

At log level `-d 2`, each mapped reader emits `zstd-read-summary` on close:
`prefetched` counts submitted frames, `ready` counts results available when
requested, `waited` counts results that required waiting, and `synchronous`
counts foreground decodes (including error retries). `reused` counts consumed
buffers passed back to workers. `wait_ns` measures time
blocked on worker results. A submitted frame may be cancelled without being
consumed. `prefetched > 0` proves the decode-ahead path engaged; the counters do
not infer it from the configured thread count. The benchmark excludes startup
reader logs and includes these counters in its CSV. Library users can take a
difference of `zstd_decode_stats()` after dropping their readers; these aggregate
completed readers across the process, including any concurrent workloads.
FUSE also logs actual request counts, the largest request, and request-handler
wall time at unmount. Neither a larger request limit nor decode-ahead guarantees
NVMe saturation: inspect ready/wait counters and compare the Session baseline
before attributing a slow FUSE read to decompression.

A local diagnostic run (2026-10-16, i7-8750H, Linux 7.2.5, Btrfs fixture,
release build) used a 256 MiB member in 257 one-MiB-or-smaller frames, with
128 KiB Session reads. Medians of 15 randomized serial/parallel pairs were:

| Backing cache | `-P 1` MB/s / CPU% | `-P 4` MB/s / CPU% | Parallel ready / waited frames |
|---|---:|---:|---:|
| Warm | 4771 / 99.5 | 5946 / 324.3 | 254 / 2 |
| Per-file eviction advice | 2422 / 74.5 | 2735 / 191.5 | 207 / 49 |

Every parallel read submitted 256 frames, reused 251 consumed buffers, and
decoded one frame synchronously. Warm worker wait time was a median 2.1 ms;
after eviction advice it was 59.2 ms. These are library measurements, not FUSE
or raw-NVMe measurements. Other builds were active on the host; earlier short
samples sometimes favored serial. Neither these medians nor a ready-frame
counter guarantees every parallel run will outperform serial. The host FUSE
matrix remains necessary to measure the request-size change.
