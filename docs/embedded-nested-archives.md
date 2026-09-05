# Embedded / nested archives: random access and temp files

How **recursive automount** (`-r` / `-l`) opens archives *inside* other archives, when **`/tmp` is used**, and which stacks support **true random member reads** without spooling the nested body to disk.

This is the user-facing guide. Implementation / remaining work lives in [`tasks/embedded-nested-random-access.md`](tasks/embedded-nested-random-access.md).

> **Maintainers / agents:** This document is the **canonical format × nested × temp matrix**.  
> Update it in the **same change** as any nested open, materialize, or temp-spool behavior.  
> See root [`AGENTS.md`](../AGENTS.md) and skill [`.grok/skills/format-support-matrices/SKILL.md`](../.grok/skills/format-support-matrices/SKILL.md).

---

## Short answers

| Question | Answer |
|----------|--------|
| **Does `.tar` inside a ZIP use `/tmp`?** | **No**, when AutoMount uses the nested *reader* path (default with `-r`). Outer ZIP `open()` yields a seekable member stream; nested TAR uses a **compact-only** in-process file table (no SQLite `files` store). |
| **Does `.tar.gz` inside a 7z use `/tmp`?** | **No** for the nested body (gzip seek + TAR compact index from the member stream). Same for ZIP / TAR / 7z outers that can open the member as `Read+Seek`. |
| **When *is* `/tmp` used?** | Nested fallback when stream open fails/unsupported; residual path-only top-level backends (classic SquashFS lzma/`unsquashfs`, lrzip CLI, CAB LZX, encrypted SQLAR, …). **Plain** `.gz`/`.bz2`/`.zst`/… single-file mounts use seekable bodies — **not** full payload spool. Nested SquashFS (gzip/zstd/xz/…) uses `open_from_reader` without spool. |
| **Is “no `/tmp`” the same as free I/O?** | No. Store/stencil is cheap; deflate/gzip still decompress; solid 7z can be expensive. |
| **Large recursive trees (`-r` on huge `.deb`s)?** | Prefer **`-l` / `--lazy`** (and optional **`--recursion-depth`**). Eager `-r` can use multi‑GB RAM and minutes; not a correctness bug ([#179](https://github.com/mxmlnkn/ratarmount/issues/179)). |

---

## Large recursive trees (RAM / time)

Upstream [#179](https://github.com/mxmlnkn/ratarmount/issues/179): recursive mount of a large package (e.g. `linux-source-*.deb` with many nested `tar.zst` / `tar.bz2`) can cost multi‑GB RAM and minutes when every nested archive is opened up front. Manual nested mounts of only the layers you need stay lighter.

| Flag | Behavior on nested archives |
|------|-----------------------------|
| **`-r` / `--recursive`** | Eager automount of nested archives (costly on huge trees). |
| **`-l` / `--lazy`** | Mount nested archives **on first access** — prefer for large recursive trees. |
| **`--recursion-depth N`** | Cap how deep automount descends (optional extra control). |

```bash
# Prefer for large packages / deep nested trees
ratarmount -r -l package.deb mnt/
ratarmount -r -l --recursion-depth 2 package.deb mnt/
```

Light nested fixtures are covered by normal tests. Full `linux-source-*.deb` stress is **optional benchmarking**, not a correctness requirement. Extreme cases can still use multi-step manual mounts (outer first, then individual nested paths).

---

## How embedded open works

With **recursive automount** (`-r`), when a path looks like a nested archive:

```text
1. Lookup the nested file in the parent mount (TAR/ZIP/7z/…).
2. parent.open(member)  →  seekable Read+Seek stream of the member bytes
3. Prefer nested *reader* open (no host path):
      open_nested_reader_fn(stream, label, NestedOpenContext)
         sniff magic → 7z | ZIP | TAR | CPIO | AR | gzip|zstd|bz2|xz → TAR | …
         ZIP/TAR/7z/CPIO/AR: try load durable nestedindexes from outer index (fingerprint match)
         else build compact-only file table (no SQLite files); mount as MountSource
         on success + writable outer index: export nestedindexes blob
4. On Unsupported / error → *temp spool* fallback:
      copy member → NamedTempFile under TMPDIR (/tmp) → open_nested_fn(path)
```

```text
┌──────────────── parent archive ─────────────────┐
│  member: inner.tar  /  inner.tar.gz  /  inner.zip │
│  open() → seekable body (stencil, inflate, …)    │
└───────────────────────┬─────────────────────────┘
                        │  no archive-body /tmp
                        ▼
              nested reader open (magic)
          ┌─────────────┼──────────────┐
          ▼             ▼              ▼
        TAR           ZIP/7z     gzip→tar (etc.)
   compact-only    compact-only  seek index + TAR
   file table      file table    compact-only TAR
```

### Nested index memory model

Nested indexes are **not** written next to a virtual label. By default the nested reader path uses a **compact-only** file table:

| Piece | Behavior |
|-------|----------|
| **File table (live)** | In-process **compact** projection: string pool, path **segments**, SoA rows, optional dir **shards** — **no** SQLite `files` table |
| **Top-level contrast** | Path mounts still use on-disk / `:memory:` SQLite for warm remount and Python interop |
| **Fat `FileInfo`** | Materialized only at `list()` / `lookup` / getattr / open; readdir uses cheap `list_dirents` (name/mode/size + cookie) from the string pool + SoA. Compositing wrappers on the FUSE path (Prefix / Union default / AutoMount / Overlay / Control / Folder / Transform / FileVersionLayer) forward that cheap path; Union `--union-resolve-symlinks` still projects fat `list()` so advertised type matches `lookup`. |
| **ZIP sidecars** | Member names interned into the same string pool during index build |
| **Residual** | Parent may still hold a large inflated member body; solid 7z open cost is separate |

Explicit top-level `--index-file :memory:` still uses SQLite in process for that mount; nested AutoMount does **not** force a nested SQLite `files` store as the live nested table.

### Durable nested indexes (warm remount of embedded ZIP/TAR)

When the **outer** archive has a **writable on-disk** SQLite index, a successful nested open of **uncompressed ZIP** or **uncompressed TAR** can **export** the compact nested file table into the outer index side table `nestedindexes`. The next open of the same nested member (same remount or new process) **imports** that blob after a fingerprint check, so nested list/lookup does not rebuild the nested file table from the member stream.

| Piece | Behavior |
|-------|----------|
| **Storage** | Outer SQLite table `nestedindexes` (Rust-only extension): `member_key`, body size, prefix/suffix/mid SHA-256, format tag, **versioned binary/columnar** blob of compact rows (+ ZIP / 7z sidecars). Magic `RNIB` prefix; schema v2. Legacy JSON v1 still imports. Decode errors (corrupt, truncated, unsupported version) **fail closed** so the nested open cold-rebuilds. JSON debug dump (`to_json_debug`) is optional for triage — not the default `to_bytes` encoding |
| **Identity** | Nested member path + optional parent `offsetheader` + body size |
| **Fingerprint** | Store/stencil bodies: head / mid / tail SHA-256 (4 KiB). Progressive/compressed parent members (large pure-LZMA2 7z): **head + size only** — mid/tail seeks would fully decompress the member. Residual: same-size edits outside sampled windows are not full-content hashed |
| **Live mount after import** | Still **compact-only** MemIndex — durable storage is export/import, not nested SQLite `files` as the hot path |
| **Formats (warm)** | Nested **ZIP**, uncompressed **TAR**, **7z** (file table **+ structure** sidecars — no header re-parse), **CPIO**, **AR** via outer `nestedindexes` |
| **Formats still cold** | Nested compressed streams (`.tar.gz`/zstd/bz2/xz file table after codec), ISO/WARC/ASAR/XAR/CAB/SQLAR/FAT/SquashFS/EXT4 (residual — not yet durable-wired) |
| **7z warm details** | Blob stores compact file rows **and** folder/pack/member open cookies; warm open attaches seekable body + imports graph (logs: `imported 7z file table + structure … no header re-parse`). Solid folder decompress CPU/RAM still applies on member open |
| **Policy** | No nested durable write when `write_index=false`, outer index is `:memory:`, read-only index mode, or no on-disk outer index path |
| **Logs** | `nested durable index: stored …` / `loaded …` / `imported … file table` |

```text
outer.sqlite
  ├── files / tarstats / …     (outer warm remount — existing)
  └── nestedindexes            (nested ZIP/TAR compact blobs)
         │
         └── import → compact-only MemIndex (live nested mount)
```

Residuals: fingerprint is not a full-content hash (store: head/mid/tail; progressive parent: head+size); nested **7z** warm still pays solid-folder decompress on member open (structure + file table only); a nested 7z header-at-end parse of a large non-solid LZMA2 parent member is one linear decode (prefix retained — not a second restart); deep `-r` can grow the outer index with one blob per nested archive opened; Python does not need to understand `nestedindexes` for outer warm remount.

Enable logs to see which path ran:

```bash
RUST_LOG=debug,ratarmount=debug,ratarmount_compositing=debug ratarmount -r -d 2 outer.zip mnt/
# look for: "mounted … via nested reader" vs "falling back to temp spool" / "spooled …"
```

---

## Nested reader: formats that open **without** `/tmp`

These are recognized from the **member byte stream** by `open_nested_reader_fn` (factory):

| Nested member | Detection | How it is mounted | Nested member random read |
|---------------|-----------|-------------------|---------------------------|
| **Uncompressed TAR** | ustar magic or `.tar` name | `SqliteIndexedTar::open_from_reader` | **Yes** — stencil on stream offsets |
| **ZIP** | `PK` magic | `ZipMountSource::open_from_reader` | Store: true random; deflate: inflate whole member then seek in RAM |
| **7z** | 7z signature | `SevenZipMountSource::open_from_reader` | Store: true random; pure LZMA2 / AES+LZMA2 / native BCJ/Delta+LZMA2 large solids: progressive; BCJ2 / multi-pack / Deflate / BZip2 solid: full-folder residual |
| **`.tar.gz` / `.tgz`** | gzip magic + TAR body/name | Seekable gzip + `create_index_gzip` | **Yes** — gzip checkpoints + TAR stencil |
| **Plain `.gz` / `.zst` / `.bz2` / `.xz` (non-TAR)** | compress magic | Seekable body + `SingleFileMountSource::from_seekable_body` (or nested archive if payload is ZIP/7z/…) | **Yes** — no nested member spool |
| **`.tar.zst`** | zstd magic + TAR | Seekable zstd + TAR body | Yes (frame/map dependent) |
| **`.tar.bz2`** | `BZh` + TAR | Seekable bzip2 + TAR | Yes (block map) |
| **`.tar.xz`** | xz magic + TAR | Seekable xz + TAR | Index map (multi-block / multi-stream preferred); large single-block spills |
| **CPIO** (newc/odc/bin) | `070701` / `070702` / `070707` / binary magic / `.cpio` | `CpioMountSource::open_from_reader` | **Yes** — stencil |
| **AR** | `!<arch>\n` / `.ar` / `.a` | `ArMountSource::open_from_reader` | **Yes** — stencil |
| **ISO 9660** | PVD `CD001` @ sector 16 / `.iso` | `Iso9660MountSource::open_from_reader` | **Yes** — extent stencils (no full-image RAM load) |
| **WARC** | `WARC/` / `.warc` | `WarcMountSource::open_from_reader` | **Yes** — payload stencils |
| **ASAR** | `.asar` name | `AsarMountSource::open_from_reader` | **Yes** — data-offset stencils |
| **XAR** | `xar!` / `.xar` | `XarMountSource::open_from_reader` | Store: stencil; gzip/zlib heap: inflate to RAM |
| **CAB** (store/MSZIP) | `MSCF` / `.cab` | `CabMountSource::open_from_reader` | Store stencil / MSZIP folder decompress in RAM |
| **SQLAR** (unencrypted) | SQLite magic / `.sqlar` | `SqlarMountSource::open_from_reader` | Full DB in RAM (`sqlite3_deserialize`); no `/tmp` |
| **FAT** | boot probe / `.fat*` | `FatMountSource::open_from_reader` (superfloppy offset 0); partitioned images use `open_from_reader_with_offset` | Shared seek body (no full-image copy); nested no-tmp at offset 0 unchanged |
| **GPT/MBR disk image** | `EFI PART` @ LBA 1 / protective MBR `0xEE` / MBR `0x55AA` + partitions starting after LBA 0 | `BlockMountSource::open_from_reader` → `/p1/`… via FAT/EXT4 `open_*_with_offset` | Shared seek body (no full-image copy). Superfloppy FAT/EXT4 at offset 0 stays in those crates. **Residual:** LVM, RAID, Btrfs; exFAT/NTFS when those crates exist. Factory wiring is a later orchestrator PR |
| **UDIF DMG** | `koly` trailer @ EOF-512 | `DmgMountSource::open_from_reader` → inner FAT/ISO/exFAT/NTFS/EXT4/GPT-MBR | Shared seek body + last-chunk cache (no full-image copy). **Residual:** HFS+, APFS, encrypted DMG, LZFSE/LZMA. Factory wiring is a later orchestrator PR |
| **WIM** | `MSWIM\0\0\0` / `.wim` | `WimMountSource::open_from_reader` | Shared seek body (no image spool). First image; uncompressed + XPRESS. **Residual:** LZX/LZMS `open` errors (not raw bytes); WIMBoot/delta/later images; 64 MiB resource cap; factory nested wire later |
| **QCOW2** | `QFI\xfb` + version 2/3 | `Qcow2MountSource::open_from_reader` → guest map then block/FAT/EXT4 | Shared seek body (no full-image copy). Relative backing needs a real parent path. **Residual:** zstd clusters; HTTP/NBD backing. Factory wiring is a later orchestrator PR |
| **SquashFS** (none/gzip/zstd/lz4/lzo/xz) | `hsqs`/`sqsh` magic (or AppImage scan) / `.squashfs`/`.sqfs`/`.snap` | `SquashFsMountSource::open_from_reader` | **Yes** — in-process backhand; **no** `/tmp` |
| **SquashFS classic LZMA** | same magic | open_from_reader **errors** | **Temp spool** → path `open` / `unsquashfs` residual |
| **EXT2/3/4** | superblock `0xEF53` @ 1024+0x38 / `.ext2`/`.ext3`/`.ext4` | `Ext4MountSource::open_from_reader` | **Yes** — pure ext4-view shared stream; pure fail → temp spool + path/`debugfs` |

Anything else (CAB **LZX**, classic SquashFS **LZMA**, pure-fail EXT4, RAR/libarchive-only, encrypted SQLAR, …) **falls back to temp spool** for the nested open today.

---

## Parent → nested: common stacks (no-tmp when both sides support it)

Outer archive must expose a **seekable** `open()` for the nested file. Then the nested reader path above applies.

| Outer (parent) | Nested member | Uses `/tmp` for nested body? | Notes |
|----------------|---------------|------------------------------|--------|
| **ZIP (store)** | `.tar` | **No** | Parent: byte region; nested: TAR from_reader |
| **ZIP (deflate)** | `.tar` | **No** | Parent inflates member into RAM (`Cursor`); nested TAR from that buffer — **no disk spool** |
| **ZIP** | `.tar.gz` | **No** | Parent open + nested gzip→tar |
| **ZIP** | `.zip` / `.7z` | **No** | Nested magic open |
| **TAR** (plain) | `.tar` | **No** (often no AutoMount) | Flattened nested TAR paths in outer index when small / `-r`; else reader path |
| **TAR** | `.tar.gz` / `.zip` / `.7z` | **No** | Stencil outer member + nested reader |
| **`.tar.gz` / `.tgz`** | `.tar` / `.zip` / `.7z` / `.tar.gz` | **No** | Outer is seekable gzip; member open is stencil over gzip |
| **7z (store/copy)** | `.tar` / `.tar.gz` / `.zip` / `.7z` | **No** | Preferred outer packing for nested random I/O |
| **7z (solid LZMA2 / AES+LZMA2 / native BCJ/Delta+LZMA2)** | same | **No disk**, may be **CPU-heavy** | Progressive prefix decode (BCJ/Delta sequential-from-0 + LRU; no dict-reset resume); not free for large solids |
| **7z solid other** | same | No disk if open succeeds | Full-folder decompress residual for **BCJ2 / multi-pack / Deflate / BZip2** |
| **CPIO / AR / ISO / WARC / ASAR / XAR / CAB store·MSZIP / FAT / SquashFS (non-LZMA) / EXT4 (pure) / GPT·MBR (FAT/EXT4 `pN/`) / WIM (uncompressed·XPRESS crate)** | nested in ZIP/TAR/7z | **No** | Stream `open_from_reader` when magic/name matches. GPT/MBR and WIM crate paths are no-tmp; factory nested wire is later. WIM LZX/LZMS `open` errors |
| **CPIO / AR / ISO / WARC / ASAR / XAR / CAB store·MSZIP / FAT / SquashFS (non-LZMA) / EXT4 (pure) / GPT·MBR (FAT/EXT4 `pN/`) / QCOW2** | nested in ZIP/TAR/7z | **No** | Stream `open_from_reader` when magic/name matches. GPT/MBR and QCOW2 crate paths are no-tmp; factory nested wire is later |
| **SQLAR** unencrypted nested | nested | **No** (full image RAM) | deserialize; encrypted still path residual |
| **CAB LZX / classic SquashFS LZMA / RAR** | nested | **Often yes (tmp)** | LZX → libarchive path; classic LZMA → unsquashfs path |

### Explicit: ZIP + embedded TAR

```text
outer.zip
  └── inner.tar          # store or deflate inside ZIP
        └── hi.txt
```

```bash
ratarmount -r outer.zip mnt/
cat mnt/inner.tar/hi.txt   # no copy of inner.tar to /tmp
```

- **Store** ZIP member: nested TAR reads stencil into the ZIP file (best).
- **Deflate** ZIP member: `inner.tar` is inflated once into memory, then TAR is indexed/read from that buffer — still **not** written under `/tmp`.

Same for `outer.zip` → `inner.tar.gz`.

---

## When `/tmp` (or `TMPDIR`) **is** used

### Nested automount fallback

1. Nested magic not in the table above (e.g. nested `.rar` / LHA via libarchive-only; classic SquashFS **LZMA**).
2. Nested open from stream fails (corrupt, password, unsupported codec).
3. Split multi-part join that materializes a joined temp file.
4. Logs: `falling back to temp spool` / `spooled … for path open`.

Temp files are held for the life of that nested mount and removed when the nested mount is dropped (best-effort).

### Top-level open (not nested)

| Case | Temp / materialize? |
|------|---------------------|
| **`.tar.gz` / `.tar.zst` / multi-frame codecs** | **No** — seekable body + TAR/index |
| **Plain single-file** `.gz` / `.bz2` / `.zst` / `.xz` / lz4 / … | **No** — seekable body + `SingleFileMountSource::from_seekable_body` (or `open_from_reader` if payload is an archive) |
| Residual: classic SquashFS lzma / some EXT4 / RAR / CAB LZX | May materialize or keep a path |
| lrzip | CLI or libarchive materialize when needed |
| Remote URL outside live Range codecs | Download / materialize |
| Write overlay `:temp:` | Explicit temp overlay root (user-requested) |
| Codec internal `DecodedBody` spill | Bodies larger than ~256 MiB may use an internal temp under the codec (not nested AutoMount spool) |

---

## Random-read quality (no-tmp stacks)

| Mechanism | Cost of random `cat` of a nested file |
|-----------|----------------------------------------|
| TAR stencil / ZIP store / 7z store | ~disk `pread` (best) |
| gzip / zstd / bzip2 seek + TAR | Jump to checkpoint/frame + local decompress |
| ZIP deflate member (as nested *or* as parent open of nested TAR) | Inflate whole member once (cached); then free seeks in RAM |
| 7z pure LZMA2 / AES+LZMA2 (solid or large non-solid) | Live sequential cursor (linear `cat`); random reads resume at independent LZMA2 reset chunks. Window LRU helps locality. Non-solid folders retain the 0..N prefix after a header-at-end walk |
| 7z native BCJ/Delta+LZMA2 (large solid) | Sequential-from-0 + LRU; **no** dict-reset resume (BCJ IP is decoder-relative) |
| 7z BCJ2 / multi-pack / Deflate / BZip2 solid | Full-folder decompress residual |
| Temp spool path | One disk write of nested body, then normal path open |

**Recommendation:** For nested archives you care about, pack the **outer** with **store/copy** (ZIP store, 7z `-mx0`, uncompressed TAR) so the nested open is a pure stencil.

---

## TAR-specific: flatten vs AutoMount

Uncompressed **TAR-in-TAR** may never hit AutoMount:

- At index time, small nested TARs (default ≤ 64 MiB without deep recursion) get **flattened** path rows (`/outer/inner.tar/file`) with absolute outer offsets.
- Opens use the outer stencil only — **no second mount, no `/tmp`**.
- Larger nested TARs with `-r` still use AutoMount reader open (also no `/tmp`).

---

## Debugging checklist

| Symptom | Likely cause |
|---------|----------------|
| Nested works but `/tmp/…` appears | Fallback path; check `RUST_LOG` for unsupported magic |
| List OK, read fails with EACCES | Encrypted 7z metadata-only; need password (inner password for nested encrypted 7z) |
| Nested `.tar.gz` slow cold open | Building gzip seek checkpoints on the member stream (once per nested mount) |
| Nested inside solid 7z slow | Solid prefix cost — re-pack outer non-solid if possible |
| Nested classic SquashFS LZMA / RAR needs tmp | Expected residual (in-process SquashFS non-LZMA is no-tmp) |

---

## Related code

| Piece | Role |
|-------|------|
| `ratarmount/src/factory.rs` → `open_nested_reader_fn` | Magic sniff + nested open without path |
| `ratarmount/src/factory.rs` → `open_nested_fn` | Path open after temp spool |
| `ratarmount-compositing` → `AutoMountLayer::try_mount_file` | Prefer reader, then spool |
| `ratarmount-formats-tar` | TAR from_reader, gzip backend, nested flatten |
| `ratarmount-formats-zip` | Store region / deflate buffer; `open_from_reader` |
| `ratarmount-formats-sevenzip` | Shared pack IO; store / progressive LZMA2 |

---

## Summary table (cheat sheet)

| Nested format | No `/tmp`? | Random read? |
|---------------|:----------:|:------------:|
| `.tar` in ZIP/TAR/7z/`.tar.gz` | yes | yes |
| `.tar.gz` in ZIP/TAR/7z | yes | yes (gzip seek) |
| `.zip` / `.7z` in ZIP/TAR/7z | yes | yes* |
| `.tar.zst` / `.tar.bz2` / `.tar.xz` nested | yes (if TAR body) | yes* |
| Nested CPIO / AR / ISO / WARC / ASAR / XAR / CAB store·MSZIP / FAT / GPT·MBR (`pN/`) | yes | yes\* |
| Nested SquashFS (none/gzip/zstd/lz4/lzo/xz) | yes | yes (backhand) |
| Nested EXT2/3/4 (pure ext4-view) | yes | yes |
| Nested unencrypted SQLAR | yes (no `/tmp`) | yes after full DB load in RAM |
| Nested plain `.gz` / `.zst` / … (single file) | yes | yes (seekable body) |
| Nested CAB LZX / classic SquashFS LZMA / RAR | usually **tmp** | depends on path open |
| Solid multi-GB 7z outer | no tmp | often costly |

\* Inner ZIP deflate / solid 7z have the usual decompress costs. **xz residual:** open/size is cheap with a Stream Index (footer-first range reads); any byte access still decompresses the covering **block**. Prefer `xz --block-size=…` / pixz for multi‑GiB random access. Default single-block maps stay seekable only when the unit is ≤ the ~256 MiB RAM cap; larger single-block falls through to full decode + temp spill (same cap as other codecs). Nested temp files are still avoided when the reader path succeeds.
