# Beyond-parity roadmap (protocols, features, product bets)

**Date:** 2026-08-23 (Local AI status refresh 2026-10-16)
**Status:** living checklist — not Python parity. Prefer implementing here when it multiplies `MountSource` + SQLite 0.7.x + FUSE/NFS.  
**Legend:** `todo` · `partial` · `done` · `defer`

The [Local AI roadmap](plans/local-ai-roadmap.md) tracks current implementation work that updates this checklist.

Parity leftovers stay in [`parity-todo.md`](../parity-todo.md) and [`upstream-feature-requests.md`](upstream-feature-requests.md). This file is **new surface**: more ways in, more ways out, and making the index do more than open a mount.

Protocol inbound/outbound batch (**P-1–P-10**, **F-1**, **F-4**, **G-1** booleans) landed 2026-08-23 (factory/CLI in PR-12; living tables in PR-14). Leftover close-out 2026-08-24: **P-6** / **P-10** `done`; **P-2** `done` (signing + 3.1.1 preauth/optional encrypt + leases/create contexts; Finder not CI). Inbound HMAC / FTP LIST / `rclone+` residuals dropped. Local AI additions and remaining publication/validation work are summarized below; partial rows retain their named residuals. gzip/rapidgzip thruput and Phase 12 announce stay residual / ops — not this table.

---

## Protocols

Inbound = fetch archives / trees. Outbound = serve the same `MountSource` tree (NFS already proved this adapter).

| ID | Work | Dir | Status | Effort | Ownership |
|----|------|-----|--------|--------|-----------|
| P-1 | **OCI / registry** (`oci://`, `docker://`, `ghcr://`) | in | `done` | L | remote fetch + factory layer open + compositing overlayfs |
| P-2 | **SMB/CIFS server** (`--smb`, reverse of the client) | out | `done` | L | `ratarmount-smb` (leases + 3.1.1 preauth/encrypt; Finder not CI; Kerberos/guest encrypt/WAN residual) |
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

### P-2 — SMB/CIFS server export — `done`

`--nfs` for Windows shops. Finder/Explorer speak SMB; they do not speak our NFSv3 high-port export. Userspace SMB 2.0.2 / 3.1.1 subset (not kernel `ksmbd`). `-w` overlay writes map to SMB create/write/delete like NFS. Default bind `127.0.0.1:20445`, share `ratarmount`. Guest `smbclient -N` `ls`/`get` on localhost is the **unsigned** v1 bar. Guest picks SMB 2.1 when offered so `CAP_LEASING` is advertised (2.0.2-only clients stay 2.0.2, no leases). When `RATARMOUNT_SMB_PASSWORD` is set, NTLMv2 NT proof is verified and signing is required (HMAC-SHA256 on 2.0.2, AES-CMAC on 3.1.1). A 3.1.1-only client gets SHA-512 preauth; AES-128-GCM/CCM encryption is used when that client also offers an encryption context. Guest `-N` is off on a password listener. CREATE contexts grant R / RH / WH leases (`SMB2_CREATE_REQUEST_LEASE` / v2 if parsed) and durable-handle-v1 (`DHnQ` grant / `DHnC` reconnect); a conflicting open or overlay write sends `LEASE_BREAK` (ACK path included). Packet tests stand in for leases + preauth+encrypt.

**Residual vs v1:** Kerberos; guest encryption; WAN; durable v2 / persistent handles. Finder/Explorer are not a CI bar. Localhost-first like NFS. See [docs/export.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/export.md).

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

**Feature gate:** SSH-2 is optional `sftp-russh` because default CI does not compile russh (same pattern as `nfsv4`). Workspace MSRV is **1.90**. Default `cargo test` does **not** compile russh; `--sftp` / `--sftp-subsystem` exit 2 with a rebuild hint. Linux/macOS packages enable the feature. No from-scratch SSH-2. That is a **feature note**, not a protocol leftover.

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
| F-6 | **Pure-Rust SMB client** + recursive SMB/WebDAV folders | `partial` | M | In-tree SMB 2.0.2 codec, Range + folders wired; file dialect still falls back to `smbclient`; SMB 3.x/Kerberos/DFS residual |
| F-7 | **Write-through / commit-to-remote** | `partial` | L | Live `-w` commit to S3/GCS/Azure and Hugging Face; remote index publication; offline remote commit unsupported |
| F-8 | **Block/disk images:** QCOW2, VMDK, VHD/X, DMG, WIM, exFAT, NTFS, UDF | `partial` | L | Factory and crates cover listed formats; HFS+/APFS, codec/features, differencing and advanced volume residuals remain |
| F-9 | **Producer: `--repack-seekable`** | `done` | M | compress engine + CLI; ZIP/7z/bzip2/xz residual |
| F-10 | **Library / FFI / `ratar://` replacement** | `partial` | L | Session + PyO3 Python package, fsspec/torch/WebDataset, mount/publish APIs landed; PyPI and crates.io publication pending |

### F-1 — Remote directory mounts — `done`

Today HTTP/S3/WebDAV/SSH mostly fetched **one archive**. Python fsspec mounts whole trees. Shipped: S3 `ListObjectsV2` prefixes (continuation loop, 100k cap), HTTP nginx/apache autoindex, WebDAV Depth-1 `PROPFIND`, SSH `readdir` as `RemoteFolderMountSource`s that AutoMount nested archives. Cheap `list_dirents` carry real sizes. Listing TTL 30s (`RATARMOUNT_REMOTE_LIST_TTL_SECS`).

`try_open_remote_folder` is those four backends only. GCS/Azure/rclone/IPFS/FTP/SMB folders export `open_*_folder` from their modules (wired in session `remote_open`; factory PR-12 / CLI folder arm for the earlier schemes). Dropbox stays on its own type.

WebDAV recursive directory mount is no longer out of scope in [`phase10-remote.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/phase10-remote.md) for Depth-1 collections.

**Residual:** SPA HTML indexes; WebDAV Depth-infinity listing; user-facing S3 pagination UI; forcing Dropbox onto the trait.

### F-2 — Incremental reindex — `done`

Last-frame `.tar.zst` splice and uncompressed GNU `tar --append` **patch the on-disk 0.7.x sidecar as a persist post-step** (interval, on-exit, offline splice). Prefix frames are not rescanned. Interval reopen uses `open_with_existing_index_body`; on-exit does not reopen in-process — the next remount is warm because tarstats were bumped during persist.

Acceptance: remount after last-frame splice does **not** rescan prefix frames; patched `files` equals a full `create_index_body`; `check_tarstats` still detects a replaced archive.

**Residual:** mid-member opaque prefix with no valid header (persist fail-closed); GNU incremental dumpdir across the window; prefix global PAX `g`; single-frame `.tar.zst` = full rebuild; `:memory:` / discarded sidecar → full rebuild (no `copy_prefix_from`); default copy mode accelerates prefix copying with reflink / `copy_file_range`; eligible add-only commits can use journaled append; ZIP incremental commit still full rebuild. Live interval vs on-exit splices are coalesced (V-4 `enqueue_commit`; second interval tick `Coalesced`; on-exit waits for inflight then one `commit_atomic` of remaining files; timeout does not splice while interval is still inflight). Live prefix-frame mutate stays fail-closed; offline `--commit-overlay` remains the prefix-rewrite escape hatch (not a live-queue job). F-7 write-through should reuse that live queue.

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

Homebrew **tap cask** shipped: unpacks the signed `macos-arm64` GitHub Release tarball ([`packaging/homebrew/Casks/ratarmount.rb`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/homebrew/Casks/ratarmount.rb)) with caveats for macFUSE/FUSE-T and runtime `libarchive`. Not a source formula; no `PKG_CONFIG_PATH`; A Linux Homebrew core formula draft is prepared but unpublished; AUR, Nix and conda drafts are also in-tree ([packaging](../packaging.md#additional-package-drafts)). Audit: [`packaging/test-homebrew-cask.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/test-homebrew-cask.sh).

**Residual:** WinFsp product FUSE; Intel tarball (no GHA Intel runner — do not re-add `macos-13`); Homebrew-core merge. `done` only if WinFsp + Intel also ship.

### F-6 — Pure-Rust SMB client — `partial`

`smbclient` CLI is a packaging and Windows-host tax. A Range reader plus directory list makes SMB first-class like S3, not a temp-file download. Recursive share listings are F-1 on this backend.

**Landed:** in-tree blocking SMB 2.0.2 Direct-TCP packet codec (`ratarmount-remote/src/smb2_client.rs`): NEGOTIATE, SESSION_SETUP (guest + NTLMv2), TREE_CONNECT, CREATE, READ at offset, QUERY_DIRECTORY, QUERY_INFO, CLOSE. Live Range (`open_smb_range` / `SmbRangeFile`). Share listing (`open_smb_folder` / `SmbListing` QUERY_DIRECTORY Depth-1 on F-1 `RemoteFolderMountSource`; listing TTL `RATARMOUNT_REMOTE_LIST_TTL_SECS`). Session `open_remote_input` wires `smb://` through `open_s3_like` (Range) and `try_open_remote_folder_url` (folders). Fake-server tests; default stays on the in-tree codec. Crate-disjoint from `ratarmount-smb`. File dialect residual still falls back to `smbclient` download-to-temp.

**Residual:** file dialects that require `smbclient` download-to-temp; SMB 3.x encryption, Kerberos, DFS, SMB1.

### F-7 — Write-through / commit-to-remote — `partial`

Live `-w` commits upload archives and index siblings to S3, GCS (`gs://`) and Azure (`az://`) through the V-4 queue. Hugging Face write-back now supports existing TAR / `.tar.zst` files on branches: archive, fresh index blob and pointer publish in one atomic Hub commit guarded by the previous SHA. Successful intervals reopen the new commit; conflicts stop publication and retain the overlay. Hub write-back currently spools the archive and rebuilds its full index each interval. Native Xet uploads remain unsupported (LFS-compatible upload required). CLI `--publish-index` supports local paths and `hf://`, `s3://`, `gs://`, `az://`; offline remote `--commit-overlay` exits 2. See [Hub read/write guide](../remote-hf.md).

**Residual:** offline `s3://` commit; create-if-missing on remote URLs (K16 Unchanged).

### F-8 — Block and disk-image family

We already do EXT4 + FAT + ISO + SquashFS. Next users: mount this VM disk / Windows `install.wim` / macOS dmg without qemu-nbd. Guestfish/libguestfs is the competitor.

Suggested order inside the family: exFAT, then NTFS (read-only), then UDF, then DMG, then WIM, then QCOW2/VHD/VMDK (block layer then partition + existing FAT/EXT4).

**Landed:** Session factory `FormatBackend` + `formats-all` (K7b): `Udf` immediately before `Iso`; `Exfat`/`Ntfs`/`Dmg`/`Wim`/`Block`/`Qcow2`/`Vhd`/`Vmdk` after `Fat`; nested `open_from_reader` in `open_nested_reader_fn` and `try_open_formats_from_seekable_body`. Crates: GPT/MBR `p1/`… (FAT/EXT4 offset), exFAT, NTFS, UDF, UDIF DMG (inner FAT/ISO/exFAT/NTFS/EXT4/GPT-MBR), WIM (first image, uncompressed + XPRESS), QCOW2 v2/v3 zlib + local backing, VHD/VHDX (no parent, including qemu-img 11 packed metadata), VMDK KDMV sparse.

**Residual:** HFS+, APFS, encrypted DMG, LZFSE/LZMA; WIM LZX/LZMS, WIMBoot, delta, later images; LVM, RAID, Btrfs; QCOW2 zstd clusters and HTTP/NBD backing; VHD/VHDX differencing / encrypted / log replay; compressed VMDK `streamOptimized` / ESXi COWD·VMFSSPARSE·SESparse / delta `parentCID`; NTFS LZNT1/EFS; UDF 2.50 metadata partition. Do not claim HFS+ via an existing path.

### F-9 — Producer: make archives seekable — `done`

CLI: `ratarmount --repack-seekable IN OUT` (`num_args = 2`; exclusive with export / `-w` / a FUSE mountpoint; **local files only**). Engine: `ratarmount_compress::repack_seekable` writes multi-frame zstd + official seek table (magic `0x8F92EAB1`, default 8 MiB frames). Already-seekable inputs are copied (`DidNothing` in-place). Multi-frame without a table gets a footer appended when every frame fits `u32`; overflow copies frames and omits the table (`CopiedWithoutSeekTable`). Gzip sidecar is `*.rgzi` via `SeekableGzip::export_seek_index_blob` (`--repack-keep-gzip`; optional `--repack-gzidx`). `--repack-force` is the only recompress-into-smaller-frames path. TAR member offset order is preserved (V-5). Guide: [`zstd-random-access.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/zstd-random-access.md).

**Residual:** ZIP / 7z / bzip2 / xz / lz4 rewrite. Parallel `zstdmt` encode. In-place Windows rename quirks. Remote PUT is F-7.

### F-10 — Library / FFI / `ratar://` replacement — `partial`

`ratarmount-session` G0–G7 is the embedder API (no FUSE). crates.io first-publish is **Q5=(a) dry-run only**: [`packaging/test-crates-io-dry-run.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/test-crates-io-dry-run.sh) runs `cargo publish -p ratarmount-core --dry-run` (and index). No live upload. L3.5 session stays path-depend until a freeze review. Dual-run does **not** wait: [`phase12-dual-run.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/phase12-dual-run.md). Policy: [`crates-io-policy.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/crates-io-policy.md). G7.3 keep-green: `cargo test -p ratarmount-session --lib index_job_sidecar_python_07` · [`test-harness/run-indexjob-python-interop.sh`](https://github.com/hilather/ratarmount-rs/blob/main/test-harness/run-indexjob-python-interop.sh).

The optional PyO3/maturin distribution **`ratarmount-rs`** imports as `ratarmount_rs`: library reads, stored-member mmap, paged iteration, fsspec `ratar`/chained URLs, torch Dataset, WebDataset iterator, supervised `mount()` and `index.publish()` are implemented. Wheel CI builds artifacts; **PyPI publication remains pending**. The Python crate stays outside default workspace members and Session dependencies. See [Python guide](../python.md). The crates.io dry-run now checks the workspace MSRV (1.90), including normalized package metadata.

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
- SMB Kerberos / guest encrypt / WAN (P-2 `done`; leases + 3.1.1 preauth/encrypt shipped; Finder not CI)
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
| G-1 | **`ratarmount serve`** — one binary, several exports on the same tree | `done` | L | P-2 / P-5 / P-6 (NFS already); export booleans + optional `serve` sugar |
| G-2 | **Index as a portable artifact** (sidecar + OCI referrer / HTTP `Link:`) | `done` | M | index; pairs with P-1 |
| G-3 | **Content-addressed member cache** (hash to decompressed member) | `partial` | L | `payload-v1/` + HTTP `range-v1/` share a cap; optional Hub cache sharing and offline snapshots; CDC residual |
| G-4 | **Snapshot browser:** restic / borg / kopia / ZFS send | `partial` | L | restic reader exists; borg, kopia and ZFS send readers absent |
| G-5 | **Kubernetes CSI + systemd `.mount` + autofs** | `partial` | L | systemd/autofs + in-tree CSI node driver and Docker/Podman plugin; privileged kind/csi-sanity validation pending |

### G-1 — `ratarmount serve` — `done`

`--nfs --http --webdav --smb --ninep --sftp` on the same tree (FUSE remains “mountpoint present”; there is **no** `--fuse` flag). Boolean flags + required-value binds (`num_args = 1`) on the existing mount CLI. Combine in one process (`ratarmount --nfs --http archive.tar.gz`). Export-only is allowed without a FUSE mountpoint. SIGINT/SIGTERM stops every export.

Optional `ratarmount serve --nfs --http ARCHIVE` sugar now dispatches to these booleans, requires at least one export, and rejects `--no-mount`. Residual: control-plane redesign, IP allowlists.

### G-2 — Index as a portable artifact — `done`

Media type `application/vnd.ratarmount.index.v1+sqlite` names this SQLite **blob family** (`v1`). Inner `INDEX_VERSION` stays `0.7.0` (`files` schema). Not SOCI / eStargz / nydus zTOC.

Discovery (fail-open): explicit `--index-file` (CLI `--index-id HEX` pre-resolves to this path) → local folder candidates (`resolve_index_location`, including `oci:{digest}` cache) → GET `{url}.index.ptr` then `{url}.index.{id}.sqlite` → HTTP `Link: rel="describedby"` on HEAD of the **archive** URL → http(s) well-known sibling GET → S3/GCS/Azure well-known sibling GET → OCI 1.1 referrer **on local miss**. Pointer/blob/tarstats failure continues (additional candidate, not terminal). After a remote fetch, `check_tarstats_matches_remote` (size + edge hashes); mismatch → warn + cold index. Object-store sibling **GET** of pointer then blob then well-known is in. CLI `--publish-index` now publishes index blobs and pointers to `hf://`, `s3://`, `gs://`, and `az://`, as well as local paths. Hub publication uses an atomic commit; object stores upload the blob before the pointer.

Publish: `--publish-index` publishes next to the archive; `--publish-index-to PATH_OR_URL` takes a required destination value. Both always write `{archive}.index.ptr` (`ratarmount.index.pointer.v1`; `index_id` = sha256 of the blob, 64 hex), including dest==sidecar. Keep-last-K=2 local snapshots (`{archive}.index.{old_id}.sqlite`) when a pointer is written. HTTP export `GET /.ratarmount-control/index.sqlite` is HTTP-only (not a FUSE control file) with that Content-Type. `--http` still serves the **indexed tree**, not host archive bytes. Inbound clients consume `Link` on the archive HEAD, not on `--http` tree export.

**Residual:** SOCI / eStargz / nydus zTOC converter; offline `s3://` `--commit-overlay`; FUSE/NFS exposure of the SQLite blob; Docker Hub Referrers matrix; tag-convention fallback.

### G-3 — Content-addressed member cache — `partial`

Hash members (`--hashes sha256` on TAR/ZIP/7z). Cache decompressed **member bodies** by sha256 across mounts (`payload-v1/{hh}/{sha256}`). Nested Debian sources, OCI layers, and unioned backup tars share identical members. Default-on when `user.hash.sha256` exists; do not hash on cold `open`. Skip `:memory:` indexes, overlay writes, members > 64 MiB (`RATARMOUNT_PAYLOAD_CACHE_MEMBER_MAX`), and `RATARMOUNT_PAYLOAD_CACHE_BYTES=0`. LRU cap default 4 GiB, shared with the remote range cache (`range-v1/`); `=0` disables both.

`payload-v1/` is a **sibling** of `local-index-v1/` under [`platform_cache_root()`](https://github.com/hilather/ratarmount-rs/blob/main/ratarmount-index/src/local_cache.rs) (macOS `~/Library/Caches/ratarmount/`, Linux XDG, Windows `%LOCALAPPDATA%\ratarmount\`). Distinct from V-3 (`$XDG_CACHE_HOME/ratarmount/meta-v3/`), which caches whole **sidecar downloads** (SQLite blobs ≤ 64 MiB) and is **not** migrated to Library/Caches.

**Remote ranges (AI-RC):** HTTP foreground/prefetch reads now cache aligned 4 MiB chunks under `range-v1/`, keyed by verified content tokens. A strong resource-scoped ETag plus size enables plain HTTP caching; backends can supply a pinned Hub commit/path or SHA-256. LRU eviction spans both body caches, with periodic reconciliation rather than a directory scan on every install. Completed files are assembled contiguously on consumer request for passthrough/Hub-cache use; multi-chunk reads do not trigger a copy. Range data stays inside the payload cache root, at `payload-v1/range-v1/`. See [remote cache configuration](../phase10-remote.md#persistent-remote-range-cache-ai-rc).

**Hub cache sharing (AI-HF3):** configured sharing checks existing `huggingface_hub` blobs before network reads and atomically installs only completed, verified files in the standard blobs/snapshots/refs layout. `hf-cache://` mounts local snapshots without networking. The external Hub cache has its own lifecycle; the ratarmount payload/range cap does not bound it. See [cache settings and offline mounts](../remote-hf.md#offline-snapshots-hf-cache).

**Residual:** CDC / nydus-like chunking of decompressed members larger than 64 MiB (would need a chunk table; do not put it in SQLite `files`); object-store transports need separate wiring to the shared range cache.

### G-4 — Snapshot browser — `partial` (restic done; borg / kopia / ZFS residual)

restic / borg / kopia / ZFS send already store trees of archives or content-addressed packs. A MountSource that walks a restic pack index or a ZFS snapshot send-stream gives browse-the-backup-without-restore.

**restic (done):** `restic:/abs/path` (scheme-prefix, not WHATWG) opens `ResticMountSource` via session `open_remote_input` only — not `open_path` / factory FormatBackend. Presentation: `/snapshots/<short-id>/…`, `/latest` symlink, `/ids/<full-id>/`. Password: `RESTIC_PASSWORD` / `RESTIC_PASSWORD_FILE` (never logged). Local `data/` pack `Read+Seek`; restic v1/v2 JSON indexes. Guide: [`docs/restic.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/restic.md).

`ratarmount snapshot add|list` also wraps the external restic CLI for creating and listing task snapshots ([recipe](../recipes/dedup-snapshots.md)).

**Residual:** S3 restic repos (`restic://s3://…` errors; use a local cache copy); borg; kopia; ZFS send.

### G-5 — Kubernetes CSI / systemd / autofs — `partial`

The systemd/autofs helper (`Type=fuse.ratarmount`) and operator examples remain available ([systemd guide](../systemd-mount.md)); credentials use env / `EnvironmentFile=`.

**Implemented:** in-tree `ratarmount-csi` gRPC Identity + Node plugin, supervised mount children, persisted lifecycle journal, secrets via environment, per-pod overlays and deployment manifests. It is a separate binary outside default packages. `ratarmount-volume-plugin` implements Docker/Podman volume API v1 with supervised mounts and per-volume overlays. See [CSI guide](../csi.md) and [Docker/Podman plugin](../docker-volume-plugin.md).

**Residual:** privileged kind / csi-sanity and real container-runtime validation are pending on a capable host; SELinux/AppArmor and Windows CSI remain open.

---

## Local AI

Implemented surfaces below use the stable AI task IDs from the
[Local AI plan](plans/local-ai-roadmap.md); P/F/G columns link them to this
roadmap without allocating duplicate IDs. User recipes start at the
[Local AI guide](../local-ai/index.md).

| Area | Implemented additions | Limits / next validation |
|---|---|---|
| Protocols / F-1 / F-7 (AI-HF1/HF2/HF3/HFW, AI-0b) | Commit-pinned `hf://`, paginated trees, token rules, Xet Range reads, offline `hf-cache://`, pooled HTTP/Bearer/prefetch, remote index publishing and Hub live write-back — [Hub](../remote-hf.md) | Native Xet upload and offline remote commit unsupported |
| Features (AI-GIT, AI-UN, AI-SB1–SB4) | Git refs/prefix/synthetic head, corpus, per-source binds, overlay policy/quotas, diff/stats, ownership mapping, tmpfs and supervisor + Python client — [Git](../git-mounts.md) · [sandbox](../sandbox.md) | Supervisor is Linux; FUSE fleet validation needs `/dev/fuse` |
| Agent grading (SBX-META/LAYER/UTF8/RULES/DIFF/LOWER/SEAL/GIT/IMPORT/OPLOG/PACK/RUN/UPPER) | Identity and ordered lower stacks, sealed layers, fsck, canonical change hashes, patch/upperdir import, journals/marks, bundles, Git snapshots and `sandbox run` — [guide](../sandbox.md) | UTF-8 paths; layered commit unsupported; offline macOS commands still require macFUSE libraries; `serve-sandboxes` design only. Kernel overlayfs FUSE-lowerdir build/import comparison passed on Linux 7.2.5 (2026-10-17); runtime/FUSE tests need a host with `/dev/fuse` |
| Features (AI-ST, AI-SH) | safetensors/GGUF byte-range plugin; reproducible shards and Parquet/JSONL/CSV export — [tensors](../formats-tensors.md) · [shards](../shards.md) | GGUF little-endian v2–v3; Parquet via default `export-parquet` feature |
| F-2 / F-9 (AI-CM1/CM2, AI-PV) | Reflink/kernel-copy commit acceleration, journaled append, rolling series, `user.*` provenance and opt-in manifests — [zstd](../zstd-random-access.md) · [rolling](../rolling-archives.md) · [provenance](../provenance.md) | Append only for eligible adds; manifests are separate atomic replacements |
| F-10 / G-3 (AI-PY1–PY3, AI-RC) | Python library/integrations/mount/publish, shared payload/range budget and Hub cache reuse — [Python](../python.md) · [cache](../phase10-remote.md#persistent-remote-range-cache-ai-rc) | PyPI publication and non-HTTP range-cache wiring pending |
| Performance (AI-PT, AI-PERF, AI-MEM) | Negotiated FUSE passthrough, 1 MiB request ceiling on 4 KiB pages, zstd decode-ahead, direct I/O, managed memory budget — [tuning](../fuse-kernel-tuning.md) · [budget](../memory-budget.md) | Passthrough needs kernel support + initial-namespace CAP_SYS_ADMIN; kernel pages excluded from RAM cap |
| G-4 / G-5 (AI-SNAP, AI-DK, AI-CSI) | restic snapshot wrapper, Docker/Podman plugin, in-tree CSI node driver | External restic required; privileged container/CSI validation pending |
| Packaging / recipes (AI-PKG, AI-BENCH, AI-DOCS) | AUR/Nix/conda/Homebrew-core drafts, portable vendored OpenSSL, AI recipes/benchmark scripts — [packaging](../packaging.md) · [recipes](../local-ai/index.md) | Registry submissions/publication pending; GB10/M5/two-box measurements need hardware |

**Correctness fixes:** concurrent file-backed TAR member reads now use independent positional I/O (AI-FIX-NESTPAR); the VHDX parser accepts qemu-img 11 packed metadata and the logical-sector GUID (AI-FIX-VHDX); crates.io dry-run MSRV checks match the workspace's Rust 1.90 declaration.

---

## Suggested implementation order (agents)

Protocol batch is in. Parallel-safe splits use the ownership column. Orchestrator owns `ratarmount/src/factory.rs` and CLI flag wiring unless a task says otherwise.

1. ~~**F-1** remote directory mounts~~ — done (S3/SSH/WebDAV/HTTP + GCS/Azure/rclone/IPFS/FTP folders).
2. ~~**P-4** FTP~~ — done (file REST + LIST/MLSD folders; implicit :990 residual).
3. ~~**F-2** incremental reindex~~ — done (sidecar patch; prefix not rescanned; residuals above).
4. ~~**P-5** HTTP Range export~~ / ~~**P-6** WebDAV~~ — HTTP `done`; WebDAV `done` (mux residual). SMB **P-2** `done` (Finder not CI; Kerberos/guest encrypt/WAN residual).
5. ~~**P-1 + F-4** OCI~~, ~~**P-3** GCS/Azure~~, ~~**P-9** rclone~~, ~~**P-10** SFTP~~ — done (`sftp-russh` is a feature note).
6. ~~**F-3** FTS5/locate~~ — done (`ratarmount find`, read-only `search/<pattern>`, socket `search`; FTS5 table only via `ensure_fts5`).
7. ~~**F-9** `--repack-seekable`~~ — done (engine + CLI; ZIP/7z/bzip2/xz residual).
8. ~~**G-1** booleans~~ — done (`--http --nfs ARCHIVE`; optional `serve` sugar).
9. ~~**G-2** portable index~~ — done (discovery + local/Hub/S3/GCS/Azure publication). Residual SOCI / offline remote commit / FUSE blob / Hub referrers.
10. Follow the named residuals in F-5–F-10 and G-3–G-5: publication, missing format/protocol features and privileged validation. Local AI implementation is summarized above; Python and CSI are no longer missing implementations.

---

## Tracking

Update this file when status changes. User-visible landings also update [`README.md`](../../README.md) feature tables, [`parity-todo.md`](../parity-todo.md) if it is also a Python gap, [`phase10-remote.md`](../phase10-remote.md) for remotes, [`export.md`](../export.md) for HTTP/SMB/WebDAV/9P/SFTP, and [`nfs-export.md`](../nfs-export.md) for NFS.
