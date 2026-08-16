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
[embedded-nested-archives.md](embedded-nested-archives.md).

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
| **Index side tables** | Python-compatible `zstdblocks` import/export for cross-tool maps |
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
(or zstd magic + TAR body), with durable `-w` (not `:temp:`). See
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
| Persist | Still **copies** the compressed file to a sibling tmp |
| Remount / interval reopen | Still **reindexes the whole TAR** (sequential decode + parse) |

Plan **2× compressed size** disk headroom (tmp + original until `persist`
unlinks the old inode). Single-frame `tar \| zstd` is a full last-frame rewrite
(same recompress class as offline gzip TAR commit). **Never refuse on size** —
startup warns when `frames.len() == 1` or the last-frame uncompressed size
exceeds **64 MiB**, then spills decoded/encoded suffix above 256 MiB.

**Not supported (v1):**

- Gzip / bzip2 / xz live splice — rejected with a message that **names gzip**
  (or the other codec). G3 inflate checkpoints are not deflate cut points.
- Offline `--commit-overlay` for `.tar.zst` — **not an escape hatch yet**.
- Plain `.zst` that is not a TAR body.
- Delete/replace of a name that still has a version in an earlier frame
  (append-only + last-window mutate).

---

## Related

| Doc / code | Role |
|------------|------|
| [gzip-binding-decision.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/gzip-binding-decision.md) | Gzip checkpoints (analogous idea for deflate) |
| [embedded-nested-archives.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/embedded-nested-archives.md) | Nested `.tar.zst` / plain `.zst` without `/tmp` |
| [parity-todo.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/parity-todo.md) | Codec parity checklist |
| `ratarmount-compress/src/zstd_seek.rs` | Implementation + unit tests |
| Upstream [#196](https://github.com/mxmlnkn/ratarmount/issues/196) | Multi-frame / chunked zstd examples |
