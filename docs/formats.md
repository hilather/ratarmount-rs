# Supported formats

What ratarmount-rs can open, how well random reads work in each format, which
formats open inside other archives without a temporary copy, which can be
written to, and where the edges are. Measured mount and read numbers for each
format are at the end.

**How to read the tables.** *Random access* describes what a read of one
member costs once the archive is indexed. "Direct" means the bytes are read
from their offset like a local file. "Block" or "frame" means the covering
compressed unit is decoded first. *Nested* says whether the format opens from a
parent archive's byte stream (`-r`) without spooling to `/tmp`. *Write* says
whether an overlay can be committed back into that format; every format can be
mounted writable with an overlay regardless.

## Archives

| Format | Random access | Nested | Write | Notes |
|---|---|---|---|---|
| **TAR** (ustar, PAX, GNU) | Direct | Yes | Offline and live commits | GNU and PAX sparse members, GNU incremental dumps, PAX `size` for 8 GiB+ members, duplicate member names under `.versions/`, PAX extended attributes. Uncompressed TAR is the fastest container there is for random access |
| **Compressed TAR** (`.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, `.tar.lz4`, …) | Block or frame, see [codecs](#compressed-streams) | Yes | gzip, bzip2, xz offline; `.tar.zst` offline and live | The seek map is stored in the index, so the cost is paid once |
| **ZIP** | Stored members direct; deflate members inflated once, then seekable (kept in RAM up to 64 MiB, then a temporary file) | Yes | Offline, full rebuild | Passwords, multi-part `.z01` joins, multi-disk end records. Encrypted and multi-part ZIPs cannot be committed |
| **7z** | Stored direct; LZMA2 (plain or AES) progressive with resume at reset points; BCJ/Delta+LZMA2 sequential with a window cache; BCJ2, multi-pack, Deflate and BZip2 solids decode the whole folder | Yes | No | Header-only and full AES encryption, `--password` / `--password-file`. Large solid archives are slow for the first read of a late member; pack with `-mx0` or small solid blocks when you can |
| **CPIO** (newc, crc, odc, binary) | Direct | Yes | No | |
| **AR** (`.a`, `.deb` payloads) | Direct | Yes | No | `.deb` files are AR containing TARs; `-r` opens both levels |
| **XAR** | Stored direct; gzip and zlib heaps inflate to RAM | Yes | No | |
| **CAB** | Stored direct; MSZIP folders decompress in RAM | Yes (store, MSZIP) | No | LZX folders fall back to libarchive with a temporary copy |
| **ASAR** | Direct | Yes | No | |
| **WARC** | Direct to each record's payload | Yes | No | Records are files; response bodies read straight into text pipelines, see the [Common Crawl recipe](recipes/common-crawl-warc.md) |
| **SQLAR** | Whole database loaded in RAM | Yes (unencrypted) | No | Encrypted SQLAR needs the optional sqlcipher feature |
| **Split archives** (`.001`, `.002`, …) | As the joined archive | Yes | No | Decimal, hex and alphabetic part numbering |
| **lrzip** | Decompressed once | No | No | Uses `lrzip`/`lrunzip` if installed, otherwise libarchive |
| **RAR, LHA and the long tail** | Sequential through libarchive | Spools | No | Anything libarchive reads; RAR nested inside another archive is copied to a temporary file first |

## Compressed streams

Each codec below is seekable: the index records checkpoints so a read decodes
only the unit that covers it. A single compressed file (not a TAR) mounts as a
directory holding the decompressed file.

| Codec | Seek unit | Notes |
|---|---|---|
| **gzip** | Checkpoint every few MiB, built on first mount | Imports and exports RGZI and GZIDX seek indexes. Throughput is below Python's rapidgzip on small `.tar.gz` files; an opt-in `gzip-rapidgzip` build feature closes part of the gap. If you own the file, `--repack-seekable` converts it to multi-frame zstd or writes a sidecar seek index |
| **bzip2** | 900 KiB block | Block map stored in the index; multi-stream files supported |
| **xz** | Block | Multi-block and multi-stream files (`xz --block-size`, `pixz`) seek cheaply. A single-block file larger than about 256 MiB is decoded in full and spilled to a temporary file |
| **zstd** | Frame | Multi-frame files and files with the official seek table are random access; `ratarmount shard` and `--repack-seekable` produce both. A single-frame file is decoded in full. Sequential reads decode ahead on up to four threads |
| **lz4** | Independent block | `lz4 -B7` style independent blocks seek cheaply |
| **lzip**, **lzo**, **compress (`.Z`)**, **lzma**, **zlib** | Stream or member | Seekable bodies with the same checkpoint approach |
| Concatenated streams | Partial | `--ignore-zeros` for TAR; concatenated zstd frames are the normal multi-frame case |

**If you produce archives**: write uncompressed TAR when the data is already
compressed (images, audio, Parquet), or multi-frame zstd with a frame of a few
MiB when it is not. `ratarmount shard` does this for you and can put each
sample in its own frame. See [Zstd random access](zstd-random-access.md).

## Disk images and filesystems

| Format | Random access | Nested | Notes |
|---|---|---|---|
| **ISO 9660** | Direct | Yes | Rock Ridge names, POSIX modes, symlinks, modification times and relocated directories; Joliet Unicode names when an image has no Rock Ridge; plain upper-case 8.3 names only for images with neither. Extents are read in place, no image copy |
| **UDF** | Direct | Yes | NSR02 and NSR03; probed before ISO so mixed discs show the UDF view. UDF 2.50 metadata partitions are not supported |
| **SquashFS** | Block, in process | Yes | gzip, zstd, lz4, lzo, xz and uncompressed images, including AppImage payloads and `.snap`. Classic LZMA images fall back to `unsquashfs` with a temporary copy |
| **EXT2/3/4** | Direct | Yes | Pure Rust reader; `debugfs` fallback for images it cannot parse |
| **FAT12/16/32** | Direct | Yes | Superfloppy images and partitions |
| **exFAT** | Direct | Yes | |
| **NTFS** | Direct | Yes | Read-only. Compressed (LZNT1) and encrypted (EFS) files report an error instead of wrong bytes |
| **GPT and MBR disk images** | Direct | Yes | Each partition appears as `p1/`, `p2/`, … and is opened with the FAT, exFAT, NTFS or EXT4 reader. LVM, RAID and Btrfs volumes are not interpreted |
| **DMG** (UDIF) | Direct through the chunk table | Yes | Inner FAT, ISO, exFAT, NTFS, EXT4 or partitioned images. HFS+, APFS, encrypted, LZFSE and LZMA chunks are not supported |
| **WIM** | Direct, uncompressed and XPRESS | Yes | First image only. LZX and LZMS resources, WIMBoot and delta images are not supported |
| **QCOW2** (v2, v3) | Cluster map | Yes | zlib-compressed clusters and local backing files; zstd clusters and network backing are not supported |
| **VHD / VHDX** | Block allocation table | Yes | Fixed and dynamic VHD, fixed and dynamic (sparse) VHDX. Differencing disks and VHDX log replay are not supported |
| **VMDK** | Grain map | Yes | Hosted sparse (KDMV) images. Compressed `streamOptimized` and ESXi formats are not supported |

Disk images are read-only. A partitioned image inside a TAR inside a ZIP still
opens without a temporary copy.

### ISO 9660 file types and Joliet fallback

The file type comes from the ISO 9660 directory record (the directory flag),
not from the Rock Ridge PX `S_IFMT` field. PX contributes permission bits only
(`mode & 0o7777`: rwx, setuid, setgid, and sticky). A missing PX entry leaves a
directory at `0o755` and any other record at `0o644`.

Rock Ridge character devices, block devices, FIFOs, and sockets are shown as
regular files that keep those permission bits. `FileInfo` has no device
numbers, so a device type would require FUSE to create a kernel device node.
The ISO data length is kept. A `PN` entry is not turned into major and minor
numbers. A directory flag still wins when PX claims a device type.

`SL` is a symlink only on a non-directory record. A directory that also carries
`SL` stays a directory (empty link name, size 0) and its children stay in the
tree, including when Joliet omitted that directory. PX `S_IFLNK` with no `SL`
is a regular file.

Joliet names are used when that tree parses and no Rock Ridge `NM` exists. A
damaged Joliet tree (extent past the image, a directory loop, or a truncated
record) logs one warning and the index keeps the ISO 9660 directory.

## AI model and dataset formats

| Format | What you get | Notes |
|---|---|---|
| **safetensors** | A directory per model: `model/layers/12/mlp/down_proj/weight` is a file holding that tensor's bytes, with a `.json` sidecar describing dtype, shape and offsets, plus `__metadata__.json` and `__header__.json` at the root | One shard file per mount; `model.safetensors.index.json` is not merged. Opens inside TARs and from `hf://` without copying. [Details](formats-tensors.md) |
| **GGUF** (v2, v3, little-endian) | Same layout; quantized tensors stay quantized | Every metadata key lands in `__metadata__.json` |
| **WebDataset shards** | Ordinary TAR; samples grouped by key when read through the Python library | Produce them with `ratarmount shard`; publish indexes with `--publish-index`. [Shards](shards.md) |
| **Parquet, JSONL, images, audio** | Lazy files from any remote; read inside archives with the `ratar://` fsspec protocol | [Python guide](python.md#fsspec) |

## Code, containers and backups

| Source | What you get | Notes |
|---|---|---|
| **Git repositories** | A commit's tree as files, any revision, optionally a history-free `.git` with one synthetic commit | Bare repositories and `.git` directories are detected; `--git` forces it for working trees. [Git mounts](git-mounts.md) |
| **OCI, Docker and GHCR images** | The merged root filesystem, whiteouts applied | Layers are read from the registry with range requests; a published index can travel as an OCI referrer |
| **restic repositories** | `snapshots/<id>/`, `latest/` and `ids/` trees from a local repository | Encrypted packs are read on demand; the `restic` binary is needed only to create snapshots. [restic](restic.md) |

## Documents

| Format | What you get |
|---|---|
| **PDF** | File attachments at their original paths, and page images under `images/pageN-imgM.<ext>` (JPEG, JPEG 2000, Flate as PNG; CMYK, indexed and ICC colour). Separation and Lab colour spaces are not converted |
| **OGG** | Each logical stream (by serial number) as a file of raw Ogg pages |
| **HTML** | Every `data:` URL embedded in the page, decoded into a file |

## Indexes

Every mount is backed by a SQLite index, by default `archive.index.sqlite`
next to the archive (or in `$XDG_CACHE_HOME/ratarmount` when that directory
is read-only). It is the same 0.7.x schema Python ratarmount uses for TAR, ZIP
and 7z, so the two tools share indexes. The index also carries the codec seek
maps and, with `--hashes sha256`, member hashes that turn on the payload cache.

Indexes can be published so that nobody else has to scan:

```bash
ratarmount --publish-index archive.tar                 # writes archive.tar.index.ptr + archive.tar.index.<sha256>.sqlite
ratarmount --publish-index hf://datasets/org/name@main/shards/00001.tar   # same, into the Hub repository
ratarmount --index-id <sha256> archive.tar mnt/        # bind a mount to one published snapshot
ratarmount export-index shards/shards.json --format parquet -o members.parquet
```

On HTTP, S3, GCS, Azure, the Hub and inside torrents, a mount looks for
`{url}.index.ptr`, then the immutable `{url}.index.<sha256>.sqlite` blob it
names, then a `Link: rel="describedby"` header on the archive, then the
well-known `{url}.index.sqlite` (also `.gz`, `.zst`, `.xz`, `.bz2`). OCI images
look up a referrer with media type `application/vnd.ratarmount.index.v1+sqlite`.
Every candidate is validated against the archive's size and content
fingerprint before use. Ordinary mounts can rebuild stale indexes;
`--no-recreate-index` refuses detected preparation failures instead.

## Nested archives

`-r` opens archives inside archives. For every format marked *Yes* above the
inner archive is read through the parent's stream, so a TAR of ZIPs of
safetensors files costs nothing extra to open and nothing on `/tmp`. Inner
indexes are stored in the outer index, so a warm remount of a nested tree is
as fast as a flat one. The canonical matrix, including what each stack costs
for a random read, is [Nested archives and temp files](embedded-nested-archives.md).

## Measured

<!-- FORMAT-SWEEP: filled from benchmarks/format-results.md -->

One corpus, every format: 1,000 files of 32 KiB in ten folders plus a 64 MiB
incompressible blob, packed by `benchmarks/compare-formats.sh` into each
container the local tools could produce, then indexed, mounted and read with
the same binary. Run on 2026-10-17 with `ratarmount 0.1.34` on a i7-8750H @ 2.20GHz laptop
(one-minute load before/after 3.27 / 2.57). Every fixture the script knows
was built; the producer tools were 7-Zip, squashfs-tools, mtools and
libguestfs for the last four rows.

Columns: cold index is `--no-mount -c`; cold and warm mount are the time until
a foreground mount answers its first listing; peak RSS is `VmHWM` of the warm
mount at readiness; random cat is the median of 15 `cat`s of 32 KiB members
(64 KiB tensors for the model files); 64 KiB pread is the median of 15 random
reads inside the 64 MiB blob (the 8 MiB tensor for models); sequential is a
full `cat` of that member; find walks the whole tree.

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

What the table says: every container with a real table of contents (TAR, ZIP,
CPIO, AR, ISO, 7z, the filesystem images, safetensors, GGUF) indexes in tens
of milliseconds and serves random reads of stored data in about a millisecond.
The compressed TARs pay for their seek map once at indexing time (bzip2 by far
the most, because every 100 KiB block is decoded once) and then differ in how
large a unit must be decoded per read: lz4 blocks and zstd frames cost a
millisecond or two, gzip and bzip2 a few milliseconds, xz blocks tens of
milliseconds, and a default 7z archive about 90 ms because its solid LZMA2
block is decoded from the start for each random member. Filesystem images
stream at 0.6–3 GiB/s rather than the page-cache speeds of the archive
containers, because reads follow the image's cluster map (FAT is the slowest,
EXT4 and SquashFS the fastest). Sequential
numbers through FUSE are page-cache speeds for a file that fits in RAM, not
disk speeds. Full methodology, CSV and caveats:
[benchmarks/format-results.md](../benchmarks/format-results.md).

## Known limits

The complete status against the Python original is in the
[parity checklist](parity-todo.md). The practical limits by area:

1. **Gzip throughput.** Default gzip seeking is a checkpoint scheme, not
   rapidgzip's parallel decoder, so small `.tar.gz` reads are slower than in
   Python. The opt-in `gzip-rapidgzip` build feature is a partial answer; the
   complete one is to repack archives you own with `--repack-seekable`. Exotic
   xz filters and single-frame zstd larger than RAM decode in full.
2. **Formats that are partial.** Classic SquashFS LZMA (spools through
   `unsquashfs`), pure RAR (libarchive only), encrypted SQLAR without
   sqlcipher, PDF Separation and Lab colour, LVM/RAID/Btrfs inside disk images,
   HFS+/APFS/encrypted DMG, WIM LZX/LZMS/WIMBoot and later images, QCOW2 zstd
   clusters and network backing, differencing VHD/VHDX, compressed and ESXi
   VMDK, NTFS LZNT1 and EFS.
3. **7z solids.** AES+LZMA2 and BCJ/Delta+LZMA2 solids are progressive with a
   window cache but have no dictionary-reset resume; BCJ2 and multi-pack
   folders still decompress whole. The first read of a late member in a
   multi-GB solid archive is slow.
4. **Writes.** ZIP commits rebuild the archive and cannot handle encrypted or
   multi-part ZIPs. Live commits cover uncompressed TAR and `.tar.zst` only
   and refuse to touch members in earlier zstd frames; the offline commit is
   the escape hatch. Gzip, bzip2 and xz TARs commit offline through GNU tar.
   Create-if-missing offline is uncompressed `.tar` only. Details in
   [Writing into archives](write-overlay.md#known-limits).
5. **Platforms.** Linux and macOS on Apple silicon. No Intel macOS package (no
   CI runner), no Windows CLI. The library crates compile on Windows.
6. **Mount point inside its own folder.** The refusal (exit 2) is a point-in-time
   check: a bind created later, mount propagation from another namespace or an ancestor
   rename after mounting are not caught, mount propagation flags are not read (a private
   bind is refused too), and `--corpus` members are not checked.

Remote, export and platform limits are listed with their own guides:
[Remote inputs](phase10-remote.md#not-yet) · [NFS](nfs-export.md) · [other exports](export.md) · [macOS](macos.md).

### Shared prepared indexes

For concurrent writable workers, prepare the local base/index once, then treat
both as immutable until every worker has stopped. `--no-recreate-index` opens
self-contained prepared SQLite artifacts immutably: a pending rollback journal
or nonempty WAL is refused instead of recovered or checkpointed. A zero-length
WAL and leftover SHM can be ignored without touching them. Native archive
catalogs require schema validation and matching backend/tarstats identity;
compression-only shells use matching tarstats and validated codec seek state
without requiring native `backendName` metadata. These checks detect specific
preparation failures; they do not validate every possible catalog defect (for
example, every required `files` column).

Required gzip/zstd/bzip2 seek state must be present and usable. Missing,
damaged or wrong-codec state fails closed. Imported maps require initial
coverage; zstd/bzip2 also check a genuine terminal boundary against the source.
Valid zstd seek-table and
skippable-frame tails and bzip2 padded multistream/trailing-data tails remain
supported. Strict G3 gzip uses nonempty prepared RGZI checkpoints with initial
coverage; it refuses GZIDX to avoid its internal repair fallback. The optional
rapidgzip importer can use compatible prepared data; prepare and consume with
compatible selected backends.

Single-block bzip2 cannot currently persist the block map required by strict
workers: preparation refuses with `single-block bzip2 cannot be prepared for
read-only workers`. Use multi-block bzip2 or another supported prepared format.
Compressed non-TAR readers that always build a file table also remain a limit:
`base.zip.gz` can prepare normally, but a strict worker refuses its required
reader rebuild. This adds no warm-reader support for those formats. Unindexed
sources and ordinary-file binds need no external SQLite sidecar. Private nested
computation is allowed; writes to the shared outer index remain disabled.

See the [prepare-once, N-worker recipe](sandbox.md#prepare-once-n-writable-workers).
