# Beyond-parity roadmap (protocols, features, product bets)

**Date:** 2026-08-23  
**Status:** living checklist — not Python parity. Prefer implementing here when it multiplies `MountSource` + SQLite 0.7.x + FUSE/NFS.  
**Legend:** `todo` · `partial` · `done` · `defer`

Parity leftovers stay in [`parity-todo.md`](../parity-todo.md) and [`upstream-feature-requests.md`](upstream-feature-requests.md). This file is **new surface**: more ways in, more ways out, and making the index do more than open a mount.

Suggested first three: **F-1** remote directory mounts → **F-2** incremental reindex → one of **P-1/F-4** OCI, **P-2** SMB export, or **P-5** HTTP export. Cheap wins around those: **P-4** FTP, **P-9** rclone.

---

## Protocols

Inbound = fetch archives / trees. Outbound = serve the same `MountSource` tree (NFS already proved this adapter).

| ID | Work | Dir | Status | Effort | Ownership |
|----|------|-----|--------|--------|-----------|
| P-1 | **OCI / registry** (`oci://`, `docker://`, `ghcr://`) | in | `todo` | L | remote + formats-tar + compositing |
| P-2 | **SMB/CIFS server** (`--smb`, reverse of the client) | out | `todo` | L | new `ratarmount-smb` or nfs-sibling |
| P-3 | **GCS `gs://` + Azure Blob `az://`** | in | `todo` | M | `ratarmount-remote` (clone S3 Range) |
| P-4 | **FTP / FTPS** | in | `todo` | S | `ratarmount-remote` |
| P-5 | **HTTP Range export** (`--http`) | out | `todo` | M | new export crate / nfs-sibling |
| P-6 | **WebDAV server** | out | `todo` | M | export crate |
| P-7 | **9P2000.L / virtio-9p** | out | `todo` | M | export crate |
| P-8 | **IPFS / IPNS** | in | `todo` | M | `ratarmount-remote` |
| P-9 | **rclone remote** (`rclone://` or `rclone.conf`) | in | `todo` | S–M | `ratarmount-remote` |
| P-10 | **SFTP server** (`sftp-server` / `--sftp`) | out | `todo` | M | export crate |

Python already has FTP, IPFS, GitHub; it does **not** have in-process NFS, SMB/HTTP/9P/SFTP export, or OCI lazy pull. R2/MinIO already work via `AWS_ENDPOINT_URL` — P-3 is native IAM/listing, not S3-compat.

### P-1 — OCI / registry (`oci://`, `docker://`, `ghcr://`)

Container layers **are** gzip/zstd tarballs. We already index TAR, speak HTTP Range, and union-mount. This is SOCI / eStargz / nydus territory with the SQLite index as the zTOC.

| Piece | Notes |
|-------|-------|
| Manifest + layer fetch | OCI distribution API; bearer/anonymous; Range GET layer blobs |
| Layer union | existing union MountSource; overlayfs-style whiteouts later |
| Index as zTOC | reuse 0.7.x; optional push-back as OCI referrer (see G-2) |
| CLI | `ratarmount oci://ghcr.io/org/img:tag mnt/` |

Product surface is **F-4**. Do not ship a scheme without a layer-union mount.

### P-2 — SMB/CIFS server export

`--nfs` for Windows shops. Finder/Explorer speak SMB; they do not speak our NFSv3 high-port export. Userspace server (not kernel `ksmbd`). `-w` overlay writes map to SMB create/write/delete like NFS.

Residual vs v1: signing, guest vs user, macOS Finder quirks. Localhost-first like NFS.

### P-3 — GCS `gs://` + Azure Blob `az://`

Copy `open_s3_range` / `S3RangeFile`. IMDS/Workload Identity (GCS) + Azure IMDS. Anonymous GET. List is **F-1**, not this ticket — single-object Range is the MVP.

### P-4 — FTP / FTPS

Python parity (`ftp://`). REST/SIZE when the server supports it, else materialize like non-Range HTTP. Debian mirrors and HPC tape robots still live here. Keep credentials out of logs (same redaction as HTTP Basic).

### P-5 — HTTP Range export

Reverse of the HTTP client. Serve the indexed tree with `Accept-Ranges` so another ratarmount, curl, a browser, or an OCI snapshotter can Range-GET members. Bind default `127.0.0.1` high port (NFS pattern). Overlay writes are out of v1 (GET/HEAD only) unless P-6 lands first.

### P-6 — WebDAV server

Reverse of the existing client. macOS Finder, Windows Explorer, Nextcloud. Overlay writes become save-from-Word into the archive. PROPFIND + GET first; PUT/DELETE only with `-w`.

### P-7 — 9P2000.L / virtio-9p

QEMU, Firecracker, WSL, gVisor guests with **no FUSE in the guest**. Same tree already handed to `nfsserve`. One extra adapter. Attach via virtio-9p or a TCP 9P listener.

### P-8 — IPFS / IPNS

Python `ipfs://` / `ipns://`. Local daemon or `IPFS_GATEWAY`. UnixFS directory listing + block Range. WARC/TAR datasets (Common Crawl-adjacent). Do not embed a full IPFS node in v1 — gateway + optional Unix socket to `ipfs`.

### P-9 — rclone remote

One backend unlocks Drive, OneDrive, B2, Swift, HDFS, and the rest of rclone's long tail. Exec `rclone cat --offset` / RC API; read `rclone.conf`. Ugly, but wins the long tail the way libarchive wins formats. Do **not** reimplement OAuth.

### P-10 — SFTP server

`sshfs` in reverse. Admins already allow SFTP through firewalls that block NFS. Internal `sftp-server` subsystem or `--sftp-bind`. Overlay writes map to SFTP open/write/close. Auth: reuse SSH keys / `authorized_keys` subset; localhost-first.

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
| F-1 | **Remote directory mounts** (S3 prefix / SSH dir / WebDAV PROPFIND / HTTP index) | `todo` | M | remote + compositing FolderMountSource |
| F-2 | **Incremental reindex** after `.tar.zst` splice / append-only TAR | `todo` | L | index + formats-tar + compositing |
| F-3 | **SQLite FTS5 / locate** over the index | `todo` | M | index + CLI + control plane |
| F-4 | **OCI image mount** (layer union; product on P-1) | `todo` | L | compositing + remote + tar |
| F-5 | **Windows (WinFsp) + Homebrew + macOS Intel** | `todo` | L | fuse + packaging |
| F-6 | **Pure-Rust SMB client** + recursive SMB/WebDAV folders | `todo` | M | `ratarmount-remote` smb.rs |
| F-7 | **Write-through / commit-to-remote** | `todo` | L | compositing + remote S3/HTTP |
| F-8 | **Block/disk images:** QCOW2, VMDK, VHD/X, DMG, WIM, exFAT, NTFS, UDF | `todo` | L | new `formats-*` crates |
| F-9 | **Producer: `--repack-seekable`** | `todo` | M | compress + formats-tar + CLI |
| F-10 | **Library / FFI / `ratar://` replacement** | `todo` | L | core + PyO3 cdylib; crates.io policy already exists |

### F-1 — Remote directory mounts

Today HTTP/S3/WebDAV/SSH mostly fetch **one archive**. Python fsspec mounts whole trees. S3 `ListObjectsV2` prefixes, HTTP directory indexes, WebDAV `PROPFIND`, SSH `readdir` should become `FolderMountSource`s that AutoMount nested archives. This is the difference between a tool for a tarball and sshfs that understands tar.

WebDAV recursive directory mount is explicitly out of scope in [`phase10-remote.md`](../phase10-remote.md) — this ticket lifts that.

Depends: none. Unlocks P-3 listing, P-8 UnixFS dirs, P-9 folder remotes.

### F-2 — Incremental reindex

Live `.tar.zst` splice still **reindexes the whole TAR on remount**. That tax will kill the write path. Append-only TAR / last-frame zstd should patch the SQLite index (insert/delete rows, bump tarstats checksum) instead of rebuilding.

Acceptance: remount after last-frame splice does **not** rescan prefix frames; index row count matches GNU tar listing; `check_tarstats` still detects a replaced archive.

### F-3 — SQLite FTS5 / locate

The 0.7.x catalog already exists. Expose:

- `ratarmount find '*.fits' archive.tar` (no FUSE)
- `/.ratarmount-control/search` and the Unix socket
- optional FTS5 on path + `--hashes` payload

Upstream Python wishlist is locate/Tracker for disconnected media. Do not invent a new storage engine.

### F-4 — OCI image mount

`ratarmount oci://ghcr.io/org/img:tag mnt/` fetches the manifest, unions layer tars, Range-GETs file blobs, and reuses the SQLite index as a SOCI-style zTOC. Whiteouts + opaque dirs for a correct rootfs. P-1 is the scheme; this is the union + snapshotter-shaped UX.

### F-5 — Windows (WinFsp) + Homebrew + macOS Intel

One static binary is the Rust story. Without WinFsp/WinGet, NFS-on-Windows residuals stay theoretical. Homebrew is how macOS people install this. Intel macOS is smaller (no GHA Intel runner today) but the first-class Apple Silicon claim currently has a hole.

Split if needed: Homebrew formula first (S), WinFsp (L), Intel tarball when a runner exists.

### F-6 — Pure-Rust SMB client

`smbclient` CLI is a packaging and Windows-host tax. A Range reader plus directory list makes SMB first-class like S3, not a temp-file download. Recursive share listings are F-1 on this backend.

### F-7 — Write-through / commit-to-remote

Overlay commit currently mutates a **local** tar/zip. `s3://bucket/a.tar.zst` + `-w` + interval commit should multipart-upload the spliced object (or a sidecar delta). Depends on F-2 unless we accept full-object PUT of the sibling tmp (works, expensive).

### F-8 — Block and disk-image family

We already do EXT4 + FAT + ISO + SquashFS. Next users: mount this VM disk / Windows `install.wim` / macOS dmg without qemu-nbd. Guestfish/libguestfs is the competitor.

Suggested order inside the family: exFAT, then NTFS (read-only), then UDF, then DMG, then WIM, then QCOW2/VHD/VMDK (block layer then partition + existing FAT/EXT4).

### F-9 — Producer: make archives seekable

`ratarmount --repack-seekable in.tar.gz out.tar.zst` (zstd seek table and/or gzip index sidecar). Random access is only as good as the producer. [`zstd-random-access.md`](../zstd-random-access.md) recipes help; a one-shot rewriter makes every subsequent mount instant.

Do not recompress if the input is already multi-frame + seek-table; just copy + emit index.

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

---

## Product bets (top 5)

Larger than a protocol or a feature; still concrete enough to implement. Items 6-10 from the brainstorm (forensic mode, SQL-over-archive, WASM browser, encrypted overlay, dual-run announce) are **not** in this file on purpose.

| ID | Work | Status | Effort | Depends |
|----|------|--------|--------|---------|
| G-1 | **`ratarmount serve`** — one binary, several exports on the same tree | `todo` | L | P-2 / P-5 / P-6 (NFS already) |
| G-2 | **Index as a portable artifact** (sidecar + OCI referrer / HTTP `Link:`) | `todo` | M | index; pairs with P-1 |
| G-3 | **Content-addressed member cache** (hash to decompressed chunk) | `todo` | L | `--hashes` (partial today) |
| G-4 | **Snapshot browser:** restic / borg / kopia / ZFS send | `todo` | L | new MountSources |
| G-5 | **Kubernetes CSI + systemd `.mount` + autofs** | `todo` | L | packaging; F-1 makes volumes useful |

### G-1 — `ratarmount serve`

`--fuse --nfs --http --webdav --smb` on the same tree. Become the minio of archives: point it at a tarball (or an S3 prefix of tarballs) and every client language gets a filesystem. The control socket already looks like this product. CLI shape is the work; adapters are P-2/P-5/P-6/P-10.

### G-2 — Index as a portable artifact

Publish `.index.sqlite` (or a SOCI-compatible zTOC) next to the archive. HTTP/S3 already download compressed indexes. Standardize a content-addressed index media type and a `Link:` / OCI referrer so **any** tool can lazy-open the archive. Interop with 0.7.x is the constraint — do not fork the schema without a version bump plan.

### G-3 — Content-addressed member cache

Hash members (`--hashes` exists for TAR/ZIP/7z). Cache decompressed chunks by hash across mounts. Nested Debian sources, OCI layers, and unioned backup tars share gzip/zstd windows. This is nydus chunk-dedup without a new format. Cache dir: XDG cache, size cap, skip on `:memory:` indexes.

### G-4 — Snapshot browser

restic / borg / kopia / ZFS send already store trees of archives or content-addressed packs. A MountSource that walks a restic pack index or a ZFS snapshot send-stream gives browse-the-backup-without-restore. Adjacent users, same random-access problem. Start with **restic** (documented index JSON) before borg/kopia/ZFS.

### G-5 — Kubernetes CSI / systemd / autofs

`ratarmount-csi` presents `s3://bucket/dataset.tar.zst` as ReadOnlyMany. systemd `What=s3://...` + autofs for `/mnt/archives/...`. HPC already uses Python ratarmount this way; a static binary + CSI is how this gets into clusters. RO-only v1; `-w` overlay is a later StorageClass.

---

## Suggested implementation order (agents)

Parallel-safe splits use the ownership column. Orchestrator owns `ratarmount/src/factory.rs` and CLI flag wiring unless a task says otherwise.

1. **F-1** remote directory mounts (S3 prefix + SSH dir; WebDAV PROPFIND). Unlocks every inbound protocol.
2. **P-4** FTP — small, Python parity, same fetch path as F-1.
3. **F-2** incremental reindex — unblocks honest live commit and F-7.
4. Pick **one** outbound story: **P-5** HTTP Range export (smallest) or **P-2** SMB (Windows).
5. Pick **one** inbound bet: **P-1 + F-4** OCI, or **P-3** GCS/Azure, or **P-9** rclone (widest, least elegant).
6. **F-3** FTS5/locate — independent, good control-plane demo.
7. **F-9** `--repack-seekable` — independent producer.
8. **G-1** `serve` once two exports exist besides FUSE/NFS.
9. **G-2** portable index alongside P-1/F-4 if OCI is chosen.
10. Everything else as capacity allows: F-5 packaging, F-6 SMB client, F-8 images, F-10 FFI, G-3 cache, G-4 snapshots, G-5 CSI, P-6/P-7/P-8/P-10.

---

## Tracking

Update this file when status changes. User-visible landings also update [`README.md`](../../README.md) feature tables, [`parity-todo.md`](../parity-todo.md) if it is also a Python gap, [`phase10-remote.md`](../phase10-remote.md) for remotes, and [`nfs-export.md`](../nfs-export.md) if an export lands next to NFS.
