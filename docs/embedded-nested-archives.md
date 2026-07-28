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
| **Does `.tar` inside a ZIP use `/tmp`?** | **No**, when AutoMount uses the nested *reader* path (default with `-r`). Outer ZIP `open()` yields a seekable member stream; nested TAR is indexed from that stream in memory. |
| **Does `.tar.gz` inside a 7z use `/tmp`?** | **No** for the nested body (gzip seek + TAR index from the member stream). Same for ZIP / TAR / 7z outers that can open the member as `Read+Seek`. |
| **When *is* `/tmp` used?** | Nested fallback when stream open fails/unsupported; residual path-only top-level backends (SquashFS tools, lrzip CLI, CAB LZX, encrypted SQLAR, …). **Plain** `.gz`/`.bz2`/`.zst`/… single-file mounts use seekable bodies — **not** full payload spool. |
| **Is “no `/tmp`” the same as free I/O?** | No. Store/stencil is cheap; deflate/gzip still decompress; solid 7z can be expensive. |

---

## How embedded open works

With **recursive automount** (`-r`), when a path looks like a nested archive:

```text
1. Lookup the nested file in the parent mount (TAR/ZIP/7z/…).
2. parent.open(member)  →  seekable Read+Seek stream of the member bytes
3. Prefer nested *reader* open (no host path):
      open_nested_reader_fn(stream, label)
         sniff magic → 7z | ZIP | TAR | gzip|zstd|bz2|xz → TAR
         build in-memory index; mount as another MountSource
4. On Unsupported / error → *temp spool* fallback:
      copy member → NamedTempFile under TMPDIR (/tmp) → open_nested_fn(path)
```

```text
┌──────────────── parent archive ─────────────────┐
│  member: inner.tar  /  inner.tar.gz  /  inner.zip │
│  open() → seekable body (stencil, inflate, …)    │
└───────────────────────┬─────────────────────────┘
                        │  no /tmp
                        ▼
              nested reader open (magic)
          ┌─────────────┼──────────────┐
          ▼             ▼              ▼
        TAR           ZIP/7z     gzip→tar (etc.)
     in-memory      in-memory    seek index + TAR
        index          index      in-memory index
```

Nested indexes are **in-memory** (`:memory:` SQLite); they are not written next to a virtual label.

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
| **7z** | 7z signature | `SevenZipMountSource::open_from_reader` | Store: true random; pure LZMA2 solid: progressive; other solid: full-folder residual |
| **`.tar.gz` / `.tgz`** | gzip magic + TAR body/name | Seekable gzip + `create_index_gzip` | **Yes** — gzip checkpoints + TAR stencil |
| **Plain `.gz` / `.zst` / `.bz2` / `.xz` (non-TAR)** | compress magic | Seekable body + `SingleFileMountSource::from_seekable_body` (or nested archive if payload is ZIP/7z/…) | **Yes** — no nested member spool |
| **`.tar.zst`** | zstd magic + TAR | Seekable zstd + TAR body | Yes (frame/map dependent) |
| **`.tar.bz2`** | `BZh` + TAR | Seekable bzip2 + TAR | Yes (block map) |
| **`.tar.xz`** | xz magic + TAR | Seekable xz + TAR | Multi-block better; single-stream weaker |
| **CPIO** (newc/odc/bin) | `070701` / `070702` / `070707` / binary magic / `.cpio` | `CpioMountSource::open_from_reader` | **Yes** — stencil |
| **AR** | `!<arch>\n` / `.ar` / `.a` | `ArMountSource::open_from_reader` | **Yes** — stencil |
| **ISO 9660** | PVD `CD001` @ sector 16 / `.iso` | `Iso9660MountSource::open_from_reader` | **Yes** — extent stencils (no full-image RAM load) |
| **WARC** | `WARC/` / `.warc` | `WarcMountSource::open_from_reader` | **Yes** — payload stencils |
| **ASAR** | `.asar` name | `AsarMountSource::open_from_reader` | **Yes** — data-offset stencils |
| **XAR** | `xar!` / `.xar` | `XarMountSource::open_from_reader` | Store: stencil; gzip/zlib heap: inflate to RAM |
| **CAB** (store/MSZIP) | `MSCF` / `.cab` | `CabMountSource::open_from_reader` | Store stencil / MSZIP folder decompress in RAM |
| **SQLAR** (unencrypted) | SQLite magic / `.sqlar` | `SqlarMountSource::open_from_reader` | Full DB in RAM (`sqlite3_deserialize`); no `/tmp` |
| **FAT** | boot probe / `.fat*` | `FatMountSource::open_from_reader` | Shared seek body (no full-image copy) |

Anything else (CAB **LZX**, SquashFS, RAR/libarchive-only, encrypted SQLAR, plain non-TAR `.gz`, …) **falls back to temp spool** for the nested open today.

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
| **7z (solid LZMA2)** | same | **No disk**, may be **CPU-heavy** | Progressive prefix decode; not recommended for large solids |
| **7z solid other** | same | No disk if open succeeds | Full-folder decompress residual for BCJ/AES/etc. |
| **CPIO / AR / ISO / WARC / ASAR / XAR / CAB store·MSZIP / FAT** | nested in ZIP/TAR/7z | **No** | Stream `open_from_reader` when magic/name matches |
| **SQLAR** unencrypted nested | nested | **No** (full image RAM) | deserialize; encrypted still path residual |
| **CAB LZX / SquashFS / RAR** | nested | **Often yes (tmp)** | LZX → libarchive path; SquashFS often needs path |

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

1. Nested magic not in the table above (e.g. nested `.iso`, `.sqfs`, `.rar` via libarchive-only).
2. Nested open from stream fails (corrupt, password, unsupported codec).
3. Split multi-part join that materializes a joined temp file.
4. Logs: `falling back to temp spool` / `spooled … for path open`.

Temp files are held for the life of that nested mount and removed when the nested mount is dropped (best-effort).

### Top-level open (not nested)

| Case | Temp / materialize? |
|------|---------------------|
| **`.tar.gz` / `.tar.zst` / multi-frame codecs** | **No** — seekable body + TAR/index |
| **Plain single-file** `.gz` / `.bz2` / `.zst` / `.xz` / lz4 / … | **No** — seekable body + `SingleFileMountSource::from_seekable_body` (or `open_from_reader` if payload is an archive) |
| Residual: SquashFS tools / some EXT4 / RAR / CAB LZX | May materialize or keep a path |
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
| 7z pure LZMA2 solid | Prefix decompress to offset (can be large); window cache helps locality |
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
| Nested SquashFS/RAR/XAR needs tmp | Expected until those backends gain stream open |

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
| Nested CPIO / AR / ISO / WARC / ASAR / XAR / CAB store·MSZIP / FAT | yes | yes\* |
| Nested unencrypted SQLAR | yes (no `/tmp`) | yes after full DB load in RAM |
| Nested plain `.gz` / `.zst` / … (single file) | yes | yes (seekable body) |
| Nested CAB LZX / SquashFS / RAR | usually **tmp** | depends on path open |
| Solid multi-GB 7z outer | no tmp | often costly |

\* Inner ZIP deflate / solid 7z / single-stream xz have the usual decompress costs; they still avoid nested temp files when the reader path succeeds.
