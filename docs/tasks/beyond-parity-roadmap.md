# Beyond-parity roadmap (protocols, features, product bets)

**Date:** 2026-08-23 (leftover close-out 2026-08-24)  
**Status:** living checklist — not Python parity. Prefer implementing here when it multiplies `MountSource` + SQLite 0.7.x + FUSE/NFS.  
**Legend:** `todo` · `partial` · `done` · `defer`

Parity leftovers stay in [`parity-todo.md`](../parity-todo.md) and [`upstream-feature-requests.md`](upstream-feature-requests.md). This file is **new surface**: more ways in, more ways out, and making the index do more than open a mount.

Protocol inbound/outbound batch (**P-1–P-10**, **F-1**, **F-4**, **G-1** booleans) landed 2026-08-23 (factory/CLI in PR-12; living tables in PR-14). Leftover close-out 2026-08-24: **P-6** / **P-10** `done`; **P-2** stays `partial` (signing shipped; encrypt / 3.1.1 / Finder residual); inbound HMAC / FTP LIST / `rclone+` residuals dropped. Remaining first bets after F-2 / F-3 / G-2: F-5..F-10, G-3..G-5. gzip/rapidgzip thruput and Phase 12 announce stay residual / ops — not this table.

---

## Protocols

Inbound = fetch archives / trees. Outbound = serve the same `MountSource` tree (NFS already proved this adapter).

| ID | Work | Dir | Status | Effort | Ownership |
|----|------|-----|--------|--------|-----------|
| P-1 | **OCI / registry** (`oci://`, `docker://`, `ghcr://`) | in | `done` | L | remote fetch + factory layer open + compositing overlayfs |
| P-2 | **SMB/CIFS server** (`--smb`, reverse of the client) | out | `partial` | L | `ratarmount-smb` (encrypt / 3.1.1 / Finder residual) |
| P-3 | **GCS `gs://` + Azure Blob `az://`** | in | `done` | M | `ratarmount-remote` (clone S3 Range; GOOG1 HMAC) |
| P-4 | **FTP / FTPS** | in | `done` | S | `ratarmount-remote` (implicit FTPS :990 residual) |
| P-5 | **HTTP Range export** (`--http`) | out | `done` | M | `ratarmount-http` GET/HEAD |
| P-6 | **WebDAV server** | out | `done` | M | `ratarmount-http` (mux residual) |
| P-7 | **9P2000.L / virtio-9p** | out | `done` | M | `ratarmount-9p` TCP (virtio residual) |
| P-8 | **IPFS / IPNS** | in | `done` | M | `ratarmount-remote` (gateway + optional API) |
| P-9 | **rclone remote** (`rclone://` or `rclone.conf`) | in | `done` | S–M | `ratarmount-remote` (argv `cat`/`lsjson`; `rclone+`) |
| P-10 | **SFTP server** (`--sftp`) | out | `done` | M | `ratarmount-sftp` (`sftp-russh` MSRV 1.85 feature note) |

Python already has FTP, IPFS, GitHub; it does **not** have in-process NFS, SMB/HTTP/9P/SFTP export, or OCI lazy pull. R2/MinIO already work via `AWS_ENDPOINT_URL` — P-3 is native IAM/listing, not S3-compat.

User-facing: [`docs/phase10-remote.md`](../phase10-remote.md) (inbound) · [`docs/export.md`](../export.md) (outbound besides NFS) · [`docs/nfs-export.md`](../nfs-export.md).

### P-1 — OCI / registry (`oci://`, `docker://`, `ghcr://`) — `done`

Container layers **are** gzip/zstd tarballs. We already index TAR, speak HTTP Range, and union-mount. This is SOCI / eStargz / nydus territory with the SQLite index as the zTOC.

| Piece | Notes |
|-------|-------|
| Manifest + layer fetch | OCI distribution API; bearer/anonymous; `OciBlobRangeFile` Range GET with Bearer (not `HttpRangeFile`) |
| Layer union | `OciImageMountSource` overlayfs whiteouts + opaque dirs (does **not** wrap `UnionMountSource`) |
| Index as zTOC | reuse 0.7.x via `resolve_index_location(Path::new("oci:{digest}"))`; optional push-back as OCI referrer (see G-2) |
| CLI | `ratarmount oci://ghcr.io/org/img:tag mnt/` · `docker://ubuntu:24.04` (scheme-prefix; WHATWG-invalid) |

Factory (PR-12) opens each layer with `open_from_live_range(layer.open_blob(), reopen = open_blob)` then `OciImageMountSource::new`. Product surface is **F-4**.

**Residual:** eStargz / SOCI / nydus; config JSON at `/.oci/config`; parallel layer index; referrer push (G-2). Cold index of every layer on first mount is v1-OK; warm remount by digest is required.

### P-2 — SMB/CIFS server export — `partial`

`--nfs` for Windows shops. Finder/Explorer speak SMB; they do not speak our NFSv3 high-port export. Userspace SMB 2.0.2 subset (not kernel `ksmbd`). `-w` overlay writes map to SMB create/write/delete like NFS. Default bind `127.0.0.1:20445`, share `ratarmount`. Guest `smbclient -N` `ls`/`get` on localhost is the **unsigned** v1 bar. When `RATARMOUNT_SMB_PASSWORD` is set, NTLMv2 NT proof is verified and SMB 2.0.2 HMAC-SHA256 signing is required (guest `-N` is off on that listener).

**Residual vs v1:** encryption, SMB 3.1.1 preauth, macOS Finder / Windows Explorer (leases, create contexts). Packet tests stand in for auth+signing. Localhost-first like NFS. See [`docs/export.md`](../export.md).

### P-3 — GCS `gs://` + Azure Blob `az://` — `done`

Copy `open_s3_range` / `S3RangeFile`. File Range + prefix listing (`GcsListing` / `AzureListing` on F-1 `RemoteListing`). GCS ADC (token / service-account JWT / IMDS / anonymous) plus GOOG1 HMAC (`GOOGLE_HMAC_KEY` / `GOOGLE_HMAC_SECRET`) on XML GET (Range unsigned) and XML ListBucket (STS `/{bucket}` only). Azure SAS / SharedKey / MSI / anonymous. Factory folder probe in PR-12.

**Residual:** GOOG4-HMAC-SHA256 only if live keys reject V2. R2/MinIO stay S3 (`AWS_ENDPOINT_URL`). Not `wasb://`.

### P-4 — FTP / FTPS — `done`

Python parity (`ftp://` / `ftps://`). REST/SIZE when the server supports it, else materialize like non-Range HTTP. Directory mounts via F-1 `RemoteListing` (MLSD preferred, Unix LIST fallback). Auth: URL userinfo, `RATARMOUNT_FTP_*`, else anonymous `anonymous`/`ratarmount@`. FTPS is explicit AUTH TLS via `suppaftp` rustls (no `native-tls`).

**Residual:** implicit FTPS (port 990). Prefer `ftps://` over cleartext.

### P-5 — HTTP Range export — `done`

Reverse of the HTTP client. Serve the indexed tree with `Accept-Ranges` so another ratarmount, curl, a browser, or an OCI snapshotter can Range-GET members. Bind default `127.0.0.1:20491`. GET/HEAD only. Overlay writes are out of v1 (unless P-6 on `--webdav`). Boolean `--http`; `--http --no-mount` exits 2. Fill-loop mandatory (gzip short `Read::read` ≠ HTTP EOF).

### P-6 — WebDAV server — `done`

Reverse of the existing client. macOS Finder, Windows Explorer, Nextcloud. PROPFIND Depth 0/1 + GET/HEAD; PUT/DELETE/MKCOL/MOVE/COPY only with `-w` (else 403). Depth infinity → 403. Separate port `127.0.0.1:20492` (not muxed with `--http`). OPTIONS `DAV: 1,2`. Exclusive write LOCK/UNLOCK (in-memory). PROPPATCH 207. Basic from `RATARMOUNT_WEBDAV_USER` / `RATARMOUNT_WEBDAV_PASSWORD` when the user env is set; none-auth on localhost otherwise.

**Residual:** same-port HTTP+WebDAV mux; Finder/Explorer not in CI.

### P-7 — 9P2000.L / virtio-9p — `done`

QEMU, Firecracker, WSL, gVisor guests with **no FUSE in the guest**. TCP listener `--ninep` / `--ninep-bind` (canonical; **not** `--9p`). Default `127.0.0.1:20493`. Guest: `mount -t 9p -o trans=tcp,port=20493,version=9p2000.L 127.0.0.1 /mnt`. Overlay writes (`Tlcreate`/`Twrite`/…) need `-w` else `EROFS`.

**Residual:** virtio-9p / vhost-user-9p (needs a QEMU device, not a second VFS).

### P-8 — IPFS / IPNS — `done`

Python `ipfs://` / `ipns://`. Local daemon or `IPFS_GATEWAY` (default `http://127.0.0.1:8080`) Range GET. UnixFS directory listing via `IPFS_API` (`/api/v0/ls`). File GET via gateway still works if the API is down; directory mount fails with a clear error. Do not embed a full IPFS node.

### P-9 — rclone remote — `done`

One backend unlocks Drive, OneDrive, B2, Swift, HDFS, and the rest of rclone's long tail. URL `rclone://remote:path` (custom parser — WHATWG-invalid colon form) plus slash alias and `rclone+remote:path` / `rclone+remote://path` (no `://` required). argv `rclone cat --offset --count` + `lsjson` (one process per `open` / listing cache miss; never `sh -c`). Config stays in rclone (`RCLONE_CONFIG` / `rclone.conf`). Missing binary is a clear error.

**Residual:** RC `--rc-serve` HTTP GET.

### P-10 — SFTP server — `done`

`sshfs` in reverse. `--sftp` / `--sftp-bind` default `127.0.0.1:20222` (well-known port 22 is `--sftp-bind 22`). Overlay writes map to SFTP open/write/close. Auth: `RATARMOUNT_SFTP_AUTHORIZED_KEYS` (default `~/.ssh/authorized_keys` **only on loopback**) and/or `RATARMOUNT_SFTP_USER` / `RATARMOUNT_SFTP_PASSWORD`. Non-loopback needs an explicit keys file **or** password env (else exit 2). Host key: `RATARMOUNT_SFTP_HOST_KEY` or ephemeral ed25519. `--sftp-subsystem` is stdio SFTP v3 (OpenSSH `Subsystem sftp`; no SSH-2).

**Feature gate:** russh MSRV **1.85** > workspace **1.74**, so SSH-2 is optional `sftp-russh` (same pattern as `nfsv4`). Default `cargo test` does **not** compile russh; `--sftp` / `--sftp-subsystem` exit 2 with a rebuild hint. Linux/macOS packages enable the feature. No from-scratch SSH-2. That is a **feature note**, not a protocol leftover.

### Not doing (protocols)

| Item | Why |
|------|-----|
| TFTP / gRPC-as-FS / WebSocket | Wrong shape |
| iSCSI | Needs block images (F-8) first |
| Kerberos NFSv4 | Hardening NFS, not a new protocol |
| Native B2 / R2 schemes | R2/MinIO already via S3 endpoint; B2 via P-9 or S3-compat |
| `github://` as a first-class scheme | HTTP Range + GitHub tarball/raw URLs cover MVP; revisit if F-1 directory mounts want repo trees |

---

## Features

| ID | Work | Status | Effort | Ownership |
|----|------|--------|--------|-----------|
| F-1 | **Remote directory mounts** (S3 prefix / SSH dir / WebDAV PROPFIND / HTTP index) | `done` | M | remote `RemoteFolderMountSource` + factory folder probe |
| F-2 | **Incremental reindex** after `.tar.zst` splice / append-only TAR | `done` | L | index + formats-tar + compositing |
| F-3 | **SQLite FTS5 / locate** over the index | `done` | M | index + CLI + control plane |
| F-4 | **OCI image mount** (layer union; product on P-1) | `done` | L | compositing `OciImageMountSource` + remote fetch + factory |
| F-5 | **Windows (WinFsp) + Homebrew + macOS Intel** | `partial` | L | fuse + packaging |
| F-6 | **Pure-Rust SMB client** + recursive SMB/WebDAV folders | `todo` | M | `ratarmount-remote` smb.rs |
| F-7 | **Write-through / commit-to-remote** | `todo` | L | compositing + remote S3/HTTP |
| F-8 | **Block/disk images:** QCOW2, VMDK, VHD/X, DMG, WIM, exFAT, NTFS, UDF | `partial` | L | GPT/MBR + FAT offset + exFAT/NTFS + UDIF DMG crates; remaining image crates + factory |
| F-8 | **Block/disk images:** QCOW2, VMDK, VHD/X, DMG, WIM, exFAT, NTFS, UDF | `partial` | L | GPT/MBR crate + FAT offset + exFAT/NTFS + WIM crates; remaining image crates + factory |
| F-9 | **Producer: `--repack-seekable`** | `done` | M | compress engine + CLI; ZIP/7z/bzip2/xz residual |
| F-10 | **Library / FFI / `ratar://` replacement** | `todo` | L | core + PyO3 cdylib; crates.io policy already exists |

### F-1 — Remote directory mounts — `done`

Today HTTP/S3/WebDAV/SSH mostly fetched **one archive**. Python fsspec mounts whole trees. Shipped: S3 `ListObjectsV2` prefixes (continuation loop, 100k cap), HTTP nginx/apache autoindex, WebDAV Depth-1 `PROPFIND`, SSH `readdir` as `RemoteFolderMountSource`s that AutoMount nested archives. Cheap `list_dirents` carry real sizes. Listing TTL 30s (`RATARMOUNT_REMOTE_LIST_TTL_SECS`).

`try_open_remote_folder` is those four backends only. GCS/Azure/rclone/IPFS/FTP folders export `open_*_folder` from their modules (wired in factory PR-12 / CLI folder arm). Dropbox stays on its own type.

WebDAV recursive directory mount is no longer out of scope in [`phase10-remote.md`](../phase10-remote.md) for Depth-1 collections.

**Residual:** SPA HTML indexes; WebDAV Depth-infinity listing; user-facing S3 pagination UI; forcing Dropbox onto the trait.

### F-2 — Incremental reindex — `done`

Last-frame `.tar.zst` splice and uncompressed GNU `tar --append` **patch the on-disk 0.7.x sidecar as a persist post-step** (interval, on-exit, offline splice). Prefix frames are not rescanned. Interval reopen uses `open_with_existing_index_body`; on-exit does not reopen in-process — the next remount is warm because tarstats were bumped during persist.

Acceptance: remount after last-frame splice does **not** rescan prefix frames; patched `files` equals a full `create_index_body`; `check_tarstats` still detects a replaced archive.

**Residual:** mid-member opaque prefix with no valid header (persist fail-closed); GNU incremental dumpdir across the window; prefix global PAX `g`; single-frame `.tar.zst` = full rebuild; `:memory:` / discarded sidecar → full rebuild (no `copy_prefix_from`); persist still **copies** the compressed prefix; ZIP incremental commit still full rebuild. Live interval vs on-exit splices are coalesced (V-4 `enqueue_commit`; second interval tick `Coalesced`; on-exit waits for inflight then one `commit_atomic` of remaining files; timeout does not splice while interval is still inflight). Live prefix-frame mutate stays fail-closed; offline `--commit-overlay` remains the prefix-rewrite escape hatch (not a live-queue job). F-7 write-through should reuse that live queue.

### F-3 — SQLite FTS5 / locate — `done`

The 0.7.x catalog is the locate index. Shipped:

- `ratarmount find '*.fits' archive.tar` (no FUSE; TSV `path\tsize\tmtime`; exit 0 with matches, 1 if none)
- `--fts` is **find-argv only** (not a mount flag). Optional FTS5 on path + `--hashes` payload (`ensure_fts5` is not called on a normal mount)
- Read-only `/.ratarmount-control/search/<pattern>` (quote globs: `cat '/mnt/.ratarmount-control/search/*.fits'`) plus Unix socket `search <pattern>` (TSV + `count N`)

Upstream Python wishlist is locate/Tracker for disconnected media. Do not invent a new storage engine.

**Residual:** overlay last-wins is live control/socket only (V-1); CLI `find` stays sidecar-only and still rejects `-w`. Folder live glob is a host-tree `read_dir` (no fat `list()`). Union catalog merge is path+`offsetheader` (later source wins that key; `None` if any source is `None`). OCI overlayfs locate is per-layer `search_cheap` (whiteouts / opaque; never `.wh.*` / `layers[0]`; `None` if any layer is `None`). `--prefix` / `--transform` + `-w` last-wins is not guaranteed. No Tracker/D-Bus; no mount `--index-fts`; no FUSE write-then-read `echo pat > search`; rusqlite `fts5` is always compiled in (Cargo unification; workspace rusqlite 0.32 has no `fts5` feature, bundled sqlite still enables `SQLITE_ENABLE_FTS5`).

### F-4 — OCI image mount — `done`

`ratarmount oci://ghcr.io/org/img:tag mnt/` fetches the manifest, unions layer tars, Range-GETs file blobs, and reuses the SQLite index as a SOCI-style zTOC. Whiteouts + opaque dirs for a correct rootfs. Live locate (`search_cheap`) is the same overlayfs walk (not `layers[0]`; never emits `.wh.*`). P-1 is the scheme; this is the union. Factory wired in PR-12.

**Residual:** same as P-1 (eStargz/SOCI/nydus, config JSON, referrer).

### F-5 — Windows (WinFsp) + Homebrew + macOS Intel — `partial`

Homebrew **tap cask** shipped: unpacks the signed `macos-arm64` GitHub Release tarball ([`packaging/homebrew/Casks/ratarmount.rb`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/homebrew/Casks/ratarmount.rb)) with caveats for macFUSE/FUSE-T and runtime `libarchive`. Not a source formula; no `PKG_CONFIG_PATH`; Homebrew-core is out of v1. Audit: [`packaging/test-homebrew-cask.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/test-homebrew-cask.sh).

**Residual:** WinFsp product FUSE; Intel tarball (no GHA Intel runner — do not re-add `macos-13`); Homebrew-core merge. `done` only if WinFsp + Intel also ship.

### F-6 — Pure-Rust SMB client

`smbclient` CLI is a packaging and Windows-host tax. A Range reader plus directory list makes SMB first-class like S3, not a temp-file download. Recursive share listings are F-1 on this backend.

### F-7 — Write-through / commit-to-remote

Overlay commit currently mutates a **local** tar/zip. `s3://bucket/a.tar.zst` + `-w` + interval commit should multipart-upload the spliced object (or a sidecar delta). Depends on F-2 unless we accept full-object PUT of the sibling tmp (works, expensive). Reuse the V-4 live commit queue (`enqueue_commit` IntervalIdle/OnExit); do not put offline `commit_overlay()` on that executor.

S3 **PUT primitive** is in `ratarmount-remote` (`put_s3_file`, multipart abort-on-error, `s3_create_and_abort_multipart_upload` write probe, `publish_index_to_s3` blob-then-pointer). Live overlay spool / `open_live_remote` / CLI `--publish-index` S3 path are still this item.

### F-8 — Block and disk-image family

We already do EXT4 + FAT + ISO + SquashFS. Next users: mount this VM disk / Windows `install.wim` / macOS dmg without qemu-nbd. Guestfish/libguestfs is the competitor.

Suggested order inside the family: exFAT, then NTFS (read-only), then UDF, then DMG, then WIM, then QCOW2/VHD/VMDK (block layer then partition + existing FAT/EXT4).

**Landed:** `ratarmount-formats-block` parses GPT + MBR and mounts FAT/EXT4 partitions as `/p1/`… via `open_*_with_offset` (nested `open_from_reader` is no-tmp). Superfloppy FAT at offset 0 stays in the FAT crate. `ratarmount-formats-dmg` parses UDIF `koly` + raw/ADC/zlib/bzip2 chunks and mounts inner FAT/ISO/exFAT/NTFS/EXT4/GPT-MBR via those crates’ public APIs (nested `open_from_reader` is no-tmp). **Residual:** HFS+, APFS, encrypted DMG, LZFSE/LZMA; LVM, RAID, Btrfs; UDF/WIM/QCOW2/VHD/VMDK crates; factory `FormatBackend::Dmg` / `Block` (orchestrator PR). Do not claim HFS+ via an existing path.
**Landed:** `ratarmount-formats-block` parses GPT + MBR and mounts FAT/EXT4 partitions as `/p1/`… via `open_*_with_offset` (nested `open_from_reader` is no-tmp). Superfloppy FAT at offset 0 stays in the FAT crate. `ratarmount-formats-wim` mounts the first image (uncompressed + XPRESS; nested `open_from_reader` is no-tmp). **Residual:** LVM, RAID, Btrfs; UDF/DMG/QCOW2/VHD/VMDK crates; WIM LZX/LZMS, WIMBoot, delta, later images; factory `FormatBackend::Block` / `Wim` (orchestrator PR).

### F-9 — Producer: make archives seekable — `done`

CLI: `ratarmount --repack-seekable IN OUT` (`num_args = 2`; exclusive with export / `-w` / a FUSE mountpoint; **local files only**). Engine: `ratarmount_compress::repack_seekable` writes multi-frame zstd + official seek table (magic `0x8F92EAB1`, default 8 MiB frames). Already-seekable inputs are copied (`DidNothing` in-place). Multi-frame without a table gets a footer appended when every frame fits `u32`; overflow copies frames and omits the table (`CopiedWithoutSeekTable`). Gzip sidecar is `*.rgzi` via `SeekableGzip::export_seek_index_blob` (`--repack-keep-gzip`; optional `--repack-gzidx`). `--repack-force` is the only recompress-into-smaller-frames path. TAR member offset order is preserved (V-5). Guide: [`zstd-random-access.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/zstd-random-access.md).

**Residual:** ZIP / 7z / bzip2 / xz / lz4 rewrite. Parallel `zstdmt` encode. In-place Windows rename quirks. Remote PUT is F-7.

### F-10 — Library / FFI / `ratar://` replacement

Python still wins on fsspec. A `cdylib` + PyO3 `ratarmountcore` that registers `ratar://` lets the ecosystem keep Python and drop the RAM bill. Dual-run docs: [`phase12-dual-run.md`](../phase12-dual-run.md). crates.io is **not** required: [`crates-io-policy.md`](../crates-io-policy.md).

### Close-the-residual (do not let these eat this roadmap)

Tracked elsewhere; listed so agents do not rediscover them as new work:

- rapidgzip-class gzip throughput — [`rapidgzip-residual-batch.md`](rapidgzip-residual-batch.md)
- pure RAR / pure lrzip — FR-15
- ssh `ProxyCommand` / `Match` — [`phase10-remote.md`](../phase10-remote.md)
- browser cookie jar / Set-Cookie — FR-2 residual
- encrypted SQLAR without sqlcipher
- Kerberos NFS / LAN / Windows NFS READDIR
- ZIP incremental commit (full rebuild today)
- 7z solid dict-reset resume
- SMB encryption / 3.1.1 / Finder (P-2 stays `partial`)
- WebDAV same-port HTTP mux; Finder/Explorer not in CI (P-6 `done`)
- implicit FTPS :990 (P-4)
- rclone RC `--rc-serve` (P-9)
- eStargz / SOCI / nydus (P-1); virtio-9p / vhost-user (P-7)
- Phase 12 dual-run announce — docs ready, **ops-pending** [`phase12-dual-run.md`](../phase12-dual-run.md)

---

## Product bets (top 5)

Larger than a protocol or a feature; still concrete enough to implement. Items 6-10 from the brainstorm (forensic mode, SQL-over-archive, WASM browser, encrypted overlay, dual-run announce) are **not** in this file on purpose.

| ID | Work | Status | Effort | Depends |
|----|------|--------|--------|---------|
| G-1 | **`ratarmount serve`** — one binary, several exports on the same tree | `done` | L | P-2 / P-5 / P-6 (NFS already); **booleans**, no `serve` subcommand |
| G-2 | **Index as a portable artifact** (sidecar + OCI referrer / HTTP `Link:`) | `done` | M | index; pairs with P-1 |
| G-3 | **Content-addressed member cache** (hash to decompressed chunk) | `done` | L | `--hashes` (partial today) |
| G-4 | **Snapshot browser:** restic / borg / kopia / ZFS send | `todo` | L | new MountSources |
| G-5 | **Kubernetes CSI + systemd `.mount` + autofs** | `partial` | L | packaging; F-1 makes volumes useful |

### G-1 — `ratarmount serve` — `done` (booleans)

`--nfs --http --webdav --smb --ninep --sftp` on the same tree (FUSE remains “mountpoint present”; there is **no** `--fuse` flag). Boolean flags + required-value binds (`num_args = 1`) on the existing mount CLI. Combine in one process (`ratarmount --nfs --http archive.tar.gz`). Export-only is allowed without a FUSE mountpoint. SIGINT/SIGTERM stops every export.

A `ratarmount serve` **subcommand was not shipped** (clap positionals steal the archive path). Booleans are the product. Residual: control-plane redesign, IP allowlists.

### G-2 — Index as a portable artifact — `done`

Media type `application/vnd.ratarmount.index.v1+sqlite` names this SQLite **blob family** (`v1`). Inner `INDEX_VERSION` stays `0.7.0` (`files` schema). Not SOCI / eStargz / nydus zTOC.

Discovery (fail-open): explicit `--index-file` (CLI `--index-id HEX` pre-resolves to this path) → local folder candidates (`resolve_index_location`, including `oci:{digest}` cache) → GET `{url}.index.ptr` then `{url}.index.{id}.sqlite` → HTTP `Link: rel="describedby"` on HEAD of the **archive** URL → http(s) well-known sibling GET → S3/GCS/Azure well-known sibling GET → OCI 1.1 referrer **on local miss**. Pointer/blob/tarstats failure continues (additional candidate, not terminal). After a remote fetch, `check_tarstats_matches_remote` (size + edge hashes); mismatch → warn + cold index. Object-store sibling **GET** of pointer then blob then well-known is in. S3 **PUT** of blob then pointer is the remote primitive (`put_s3_file` / `publish_index_to_s3`; never pointer-first; leftover blob on pointer failure). CLI `--publish-index` and live overlay commit remain F-7. GCS/Azure PUT residual.

Publish: `--publish-index` copies the sidecar next to the archive; `--publish-index-to PATH` is a required value. Both always write `{archive}.index.ptr` (`ratarmount.index.pointer.v1`; `index_id` = sha256 of the blob, 64 hex), including dest==sidecar. Keep-last-K=2 local snapshots (`{archive}.index.{old_id}.sqlite`) when a pointer is written. HTTP export `GET /.ratarmount-control/index.sqlite` is HTTP-only (not a FUSE control file) with that Content-Type. `--http` still serves the **indexed tree**, not host archive bytes. Inbound clients consume `Link` on the archive HEAD, not on `--http` tree export.

**Residual:** SOCI / eStargz / nydus zTOC converter; CLI `--publish-index` / live overlay S3 PUT (F-7; library primitive landed); GCS/Azure PUT; FUSE/NFS exposure of the SQLite blob; Docker Hub Referrers matrix; tag-convention fallback.

### G-3 — Content-addressed member cache — `done`

Hash members (`--hashes sha256` on TAR/ZIP/7z). Cache decompressed **member bodies** by sha256 across mounts (`payload-v1/{hh}/{sha256}`). Nested Debian sources, OCI layers, and unioned backup tars share identical members. Default-on when `user.hash.sha256` exists; do not hash on cold `open`. Skip `:memory:` indexes, overlay writes, members > 64 MiB (`RATARMOUNT_PAYLOAD_CACHE_MEMBER_MAX`), and `RATARMOUNT_PAYLOAD_CACHE_BYTES=0`. LRU cap default 4 GiB.

`payload-v1/` is a **sibling** of `local-index-v1/` under [`platform_cache_root()`](https://github.com/hilather/ratarmount-rs/blob/main/ratarmount-index/src/local_cache.rs) (macOS `~/Library/Caches/ratarmount/`, Linux XDG, Windows `%LOCALAPPDATA%\ratarmount\`). Distinct from V-3 (`$XDG_CACHE_HOME/ratarmount/meta-v3/`), which caches whole **sidecar downloads** (SQLite blobs ≤ 64 MiB) and is **not** migrated to Library/Caches.

**Residual:** CDC / nydus-like chunking of members larger than 64 MiB (would need a chunk table; do not put it in SQLite `files`).

### G-4 — Snapshot browser

restic / borg / kopia / ZFS send already store trees of archives or content-addressed packs. A MountSource that walks a restic pack index or a ZFS snapshot send-stream gives browse-the-backup-without-restore. Adjacent users, same random-access problem. Start with **restic** (documented index JSON) before borg/kopia/ZFS.

### G-5 — Kubernetes CSI / systemd / autofs — `partial`

v1 shipped: `packaging/mount.fuse.ratarmount` (`Type=fuse.ratarmount`, installed as `/usr/sbin/mount.fuse.ratarmount` in `.deb`/`.rpm`), example systemd `.mount` + autofs map, operator docs ([`systemd-mount.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/systemd-mount.md)). Helper argv has **no** secrets (env / `EnvironmentFile=` only). CSI is **spec-only** ([`csi.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/csi.md)); the driver is a **separate repo** that execs the packaged binary — **no kube crate** in this workspace. Residual: CSI node plugin implementation, `-w` overlay StorageClass (needs F-7), SELinux / AppArmor, Windows CSI.

---

## Suggested implementation order (agents)

Protocol batch is in. Parallel-safe splits use the ownership column. Orchestrator owns `ratarmount/src/factory.rs` and CLI flag wiring unless a task says otherwise.

1. ~~**F-1** remote directory mounts~~ — done (S3/SSH/WebDAV/HTTP + GCS/Azure/rclone/IPFS/FTP folders).
2. ~~**P-4** FTP~~ — done (file REST + LIST/MLSD folders; implicit :990 residual).
3. ~~**F-2** incremental reindex~~ — done (sidecar patch; prefix not rescanned; residuals above).
4. ~~**P-5** HTTP Range export~~ / ~~**P-6** WebDAV~~ — HTTP `done`; WebDAV `done` (mux residual). SMB **P-2** stays `partial` (encrypt / 3.1.1 / Finder).
5. ~~**P-1 + F-4** OCI~~, ~~**P-3** GCS/Azure~~, ~~**P-9** rclone~~, ~~**P-10** SFTP~~ — done (`sftp-russh` is a feature note).
6. ~~**F-3** FTS5/locate~~ — done (`ratarmount find`, read-only `search/<pattern>`, socket `search`; FTS5 table only via `ensure_fts5`).
7. ~~**F-9** `--repack-seekable`~~ — done (engine + CLI; ZIP/7z/bzip2/xz residual).
8. ~~**G-1** booleans~~ — done (`--http --nfs ARCHIVE`; no `serve` subcommand).
9. ~~**G-2** portable index~~ — done (`Link` / sibling / OCI referrer on miss; `--publish-index` + `{archive}.index.ptr` / `--index-id`; HTTP + S3/GCS/Azure sibling GET of pointer then blob then well-known). Residual SOCI / CLI+live S3 PUT (F-7; `publish_index_to_s3` primitive landed) / GCS/Azure PUT / FUSE blob / Hub referrers.
10. Everything else as capacity allows: F-5 packaging, F-6 SMB client, F-8 images, F-10 FFI, ~~G-3 cache~~, G-4 snapshots, G-5 CSI; P-2 Finder/encrypt, HTTP+WebDAV mux, implicit FTPS :990, rclone RC, eStargz, virtio.
9. ~~**G-2** portable index~~ — done (`Link` / sibling / OCI referrer on miss; `--publish-index` + `{archive}.index.ptr` / `--index-id`; HTTP + S3/GCS/Azure sibling GET of pointer then blob then well-known). Residual SOCI / object-store PUT (F-7) / FUSE blob / Hub referrers.
10. Everything else as capacity allows: F-5 packaging, F-6 SMB client, F-8 images, F-10 FFI, G-3 cache, G-4 snapshots, G-5 CSI driver (systemd/autofs helper shipped); P-2 Finder/encrypt, HTTP+WebDAV mux, implicit FTPS :990, rclone RC, eStargz, virtio.

---

## Tracking

Update this file when status changes. User-visible landings also update [`README.md`](../../README.md) feature tables, [`parity-todo.md`](../parity-todo.md) if it is also a Python gap, [`phase10-remote.md`](../phase10-remote.md) for remotes, [`export.md`](../export.md) for HTTP/SMB/WebDAV/9P/SFTP, and [`nfs-export.md`](../nfs-export.md) for NFS.
