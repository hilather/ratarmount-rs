# Phase 10 — remote inputs

Inbound URL schemes. Outbound servers (`--http` / `--smb` / …) are [`export.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/export.md). Status vs Python: [`parity-todo.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/parity-todo.md) · beyond-parity IDs: [`tasks/beyond-parity-roadmap.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/beyond-parity-roadmap.md).

`is_remote_url` is a **scheme-prefix** check (not `url::Url` first). Forms that fail WHATWG parse still mount: `rclone://gdrive:bucket/path`, `rclone+gdrive:bucket/path`, `docker://ubuntu:24.04`. `restic:/abs/path` has no `://` and is still remote (not a local colon filename).

## Supported

| Scheme | Behavior |
|--------|----------|
| `file://` | Map to local path |
| `http://` / `https://` | Probe for `Accept-Ranges: bytes` + size; sequential Range GETs (4 MiB chunks) when supported, else full GET → temp file; **HTTP Basic** + **Cookie** auth on HEAD/GET/Range; explicit secret **Bearer** auth through the Rust API. Shared keep-alive connections and parallel sequential readahead (`RATARMOUNT_HTTP_PARALLEL`). Trailing `/` or HTML autoindex → **folder** (nginx/apache `<a href>`). Index discovery: GET `{url}.index.ptr` then `{url}.index.{id}.sqlite`, then `Link: rel="describedby"` on archive HEAD, then well-known `{url}.index.sqlite` (+ `.gz`/`.zst`/`.xz`/`.bz2`). Pointer/blob/tarstats failure continues |
| `s3://bucket/key` | Live Range (`open_s3_range` / `S3RangeFile`) when the object supports it; else GetObject → temp. SigV4 env + IMDS/ECS + anonymous. Empty key / trailing `/` / list children → **prefix folder** (`ListObjectsV2`, continuation loop, 100k cap). Index discovery: GET `{url}.index.ptr` then `{url}.index.{id}.sqlite` then well-known `{url}.index.sqlite`. **PUT** (`put_s3_file` / multipart, abort on error; `publish_index_to_s3` blob-then-pointer). Anonymous is GET-only. Live overlay commit (`-w` + `--commit-overlay-interval` / `--on-exit`) for TAR/ZST: write probe, persistent spool, multipart PUT, then blob+pointer; reopen is live Range. Offline `--commit-overlay` + `s3://` exits 2 |
| `gs://bucket/object` | XML path-style Range GET (`storage.googleapis.com/{bucket}/{object}`). Prefix folder via JSON list + `pageToken` (HMAC GOOG1 lists via XML). R2/MinIO stay `s3://` + `AWS_ENDPOINT_URL`. Same sibling pointer/blob/well-known GET as S3 |
| `az://container/blob` | Azure Blob Range (`azure://` alias). Prefix folder via List Blobs + `NextMarker`. Account from env, not URL host. Not `wasb://`. Same sibling pointer/blob/well-known GET as S3 |
| `ftp://` / `ftps://` | REST/SIZE Range or full RETR. `ftps://` = explicit AUTH TLS (`suppaftp` rustls). Trailing `/` or CWD-success → **folder** (MLSD preferred, Unix LIST fallback). Implicit FTPS :990 residual |
| `ssh://` / `sftp://` / `scp://` | SFTP download → temp (`ssh_config` HostName/User/Port/IdentityFile/IdentitiesOnly/ProxyJump/Include). Directory URL → SFTP `readdir` folder |
| `webdav://` / `webdavs://` | Map to `http`/`https`; Depth-0 PROPFIND for size; GET → temp (Basic from URL userinfo). Collection → Depth-1 **folder** |
| `smb://` | Parse `smb://[domain;]user[:pass]@host[:port]/share/path`. Session `open_remote_input` live Range (`open_smb_range` / `SmbRangeFile` via in-tree SMB 2.0.2 `Smb2Client`) + share listing (`open_smb_folder` / `SmbListing` QUERY_DIRECTORY Depth-1 → F-1 `RemoteFolderMountSource`). Dialect `STATUS_NOT_SUPPORTED` / non-2.x (including a non-SMB2 banner) falls back to Samba `smbclient` for **files** when on `PATH`. Folder URLs: QUERY_DIRECTORY unsupported is a clear error (not an empty list; `smbclient` listing is residual). File URLs: dialect miss is `Ok(None)` so Range/smbclient can take over. Missing both names install **or** the dialect residual. Auth and connect-refused do not fall back. Listing TTL: `RATARMOUNT_REMOTE_LIST_TTL_SECS` (default 30) |
| `dropbox://` | Dropbox content API (`DROPBOX_TOKEN`); folder browse via `DropboxMountSource` (list TTL 30s); large opens prefer chunked HTTP Range |
| `oci://` / `docker://` / `ghcr://` | Registry manifest + Bearer blob Range + overlayfs layer union (`OciImageMountSource`). Custom parser (WHATWG-invalid `docker://ubuntu:24.04`). Index: local `oci:{digest}` cache first, then OCI 1.1 referrers (`artifactType=application/vnd.ratarmount.index.v1+sqlite`) on miss; fail-open if Referrers API is missing (not SOCI; no tag-convention fallback) |
| `ipfs://` / `ipns://` | Gateway Range GET (`IPFS_GATEWAY`, default `http://127.0.0.1:8080`). UnixFS dirs via `IPFS_API` `/api/v0/ls`. No embedded node |
| `rclone://remote:path` | argv `rclone cat --offset --count` + `lsjson` (one process per open). Slash alias `rclone://remote/path`. Plus-form `rclone+remote:path` / `rclone+remote://path` (no `://` required). Config stays in rclone |
| `restic:/abs/path` | Local restic snapshot browser (`ResticMountSource`). Scheme-prefix (not WHATWG): `restic:/var/repo`, extra-slash `restic:///var/repo`. Relative `restic:path` errors. `restic://s3://bucket/repo` / `restic:s3://…` error (`S3 restic repos residual; use a local cache copy`). Password `RESTIC_PASSWORD` / `RESTIC_PASSWORD_FILE` (never logged). Session `open_remote_input` only — not `open_path`. Layout `/snapshots/<id>/`, `/latest`, `/ids/<full-id>/`. Guide: [restic.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/restic.md). borg/kopia residual |
| bare local paths | Unchanged |

`resolve_to_local` / `fetch_http_to_temp_prefer_range` prefer Range materialization (Python fsspec-style) and fall back to a full GET when the server does not support ranges. `HttpRangeFile` provides a seekable Range reader for the same probe; without ranges it buffers a full download.

Factory `open_remote_input` probes `restic:` first (local snapshot browser), then F-1 folders (s3/ssh/webdav/http) then `open_gcs_folder` / `open_azure_folder` / `open_rclone_folder` / `open_ipfs_folder` / `open_ftp_folder` / `open_smb_folder`, then live Range, then materialize. OCI is a layer-union mount, not a single-file download.

### Portable index discovery (G-2)

Order: explicit `--index-file` (including `--index-id HEX` already resolved to that path) → local folder candidates (`resolve_index_location`, including `oci:{digest}` cache) → GET `{url}.index.ptr` then immutable `{url}.index.{id}.sqlite` → HTTP `Link: rel="describedby"` on HEAD of the **archive** URL → http(s) well-known `{url}.index.sqlite` (+ compressed suffixes) → S3/GCS/Azure well-known sibling GET → OCI 1.1 referrer **on local miss**. Fail-open. Pointer/blob/tarstats failure **continues** the chain (pointer is an additional candidate, not terminal). Remote sidecar is checked with `check_tarstats_matches_remote` (size + edge hashes); mismatch → warn + cold index. Media type `application/vnd.ratarmount.index.v1+sqlite` is the blob family; `INDEX_VERSION` `0.7.0` is the `files` schema — not SOCI. Publish with `--publish-index` / `--publish-index-to PATH` (local copy + `{archive}.index.ptr` JSON pointer, schema `ratarmount.index.pointer.v1`, `index_id` = sha256 of the blob). Object-store **GET** of pointer/blob/well-known is supported. S3 **PUT** of the immutable blob then the pointer is [`publish_index_to_s3`](https://github.com/hilather/ratarmount-rs/blob/main/ratarmount-remote/src/index_sibling.rs) (never pointer-first; pointer PUT failure after blob PUT does not claim success — leftover blob is not deleted). CLI `--publish-index` PUTs that blob-then-pointer for `s3://` archives. GCS/Azure PUT is residual. Local `--index-id HEX` remounts `{archive}.index.{id}.sqlite` (keep-last-K=2 when a pointer is written).

Whole sidecar GETs ≤ 64 MiB are stored in `$XDG_CACHE_HOME/ratarmount/meta-v3/` (V-3; cap `RATARMOUNT_META_CACHE_BYTES`, default 256 MiB, `=0` disables). Lookup is URL-first so a remount without `.ptr` still hits. Not archive `HttpRangeFile` paging and not G-3 member bodies. `file://` / `:memory:` / a nonempty local folder candidate skip the download. HPC home-quota: set `XDG_CACHE_HOME` to scratch.

### HTTP transport and sequential readahead (AI-0b)

HTTP(S), HTTP folder listing, WebDAV, Dropbox, OCI and IPFS share one blocking
`ureq::Agent` per process. Connections return to its keep-alive pool after the
response body is consumed. The shared agent keeps ureq's existing defaults:
30-second connect timeout and no socket read/write or overall request timeout.
Existing per-request timeouts still apply, including across redirects.
S3/GCS/Azure retain their existing transports.

`HttpRangeFile` caches the final redirect URL from HEAD or the first ranged GET.
Subsequent requests go directly to that URL. Authorization and Cookie headers
are sent only to the origin and removed on every redirect, including redirects
to another path on the same host. A cached target returning 401, 403, 404 or 410
triggers one origin re-resolution and retry; concurrent failures share that
refresh. Every 206 must have a matching `Content-Range`, including the object
length when known. Servers returning a full 200 response retain the existing
skip-to-offset fallback.

| Env | Behavior |
|-----|----------|
| `RATARMOUNT_HTTP_PARALLEL` | Maximum sequential range requests per reader, default **8**. **1** disables readahead and keeps reads on the calling thread. Values are clamped to 1–64; invalid values use 8. Read at reader creation. |
| `RATARMOUNT_HTTP_PREFETCH_LIMIT` | Process-wide background chunk/worker cap, default **64** (**256 MiB** of chunk payloads). Values are clamped to 1–1024; invalid values use 64. Read once when prefetch first starts. |

Readahead starts after at least **1 MiB** of contiguous progress, or after a
read of at least **64 KiB** followed by an adjacent read. Two small archive-header
reads do not start prefetch. The window ramps through **1, 2, 4, 8** chunks,
up to the reader's configured maximum, as chunks are consumed. Each chunk is
**4 MiB**, and results are delivered in byte order. Both running workers and
completed, unconsumed chunks count against the process-wide cap, shared by all
open files. Cancelled workers retain their slots until they exit. At capacity,
new prefetch is skipped and the foreground reads on the calling thread.
Uncached, unverified sources read directly into the caller's buffer; verified
cache misses fetch an aligned chunk for reuse. Payload storage is reserved only
after the first body bytes arrive. The payload cap excludes caller-owned
buffers, transport buffers and thread stacks.

A random read is capped at 4 MiB; callers continue filling after a short read.
With a verified cache identity, misses fetch aligned 4 MiB chunks (a read
straddling a boundary may need two requests). Seeking to a different position or dropping the reader cancels
and detaches background work immediately, without waiting for network progress.
Cancellation is checked while skipping an ignored-Range 200 prefix as well as
while receiving chunk data. Background requests have a **60-second overall
per-request deadline**, covering redirects and body reads; an expired target's
origin refresh is a separate attempt with the same deadline. This deadline
applies only to prefetch, so slow IPFS gateways and foreground/full downloads
retain their existing timeout behavior. A failed prefetch is discarded, and
the next read at that offset retries synchronously. This is an in-memory
window; the persistent disk cache below is shared with foreground reads.

Rust callers can pass `HttpAuthOptions { bearer_token: Some(SecretString::new(token)) }`
to `HttpRangeFile::open_with_auth`, `HttpRangeFile::range_backed_with_auth`, or
`fetch_http_bytes_capped_with_auth`. Bearer takes precedence over URL/env Basic
credentials, combines with the configured Cookie header at the origin, and is
redacted from Debug output. There is no new CLI token option or HF-specific
handling in this transport layer.

### HTTP(S) Basic authentication (FR-2 / [#157](https://github.com/mxmlnkn/ratarmount/issues/157))

`Authorization: Basic …` is sent on HEAD, full GET, and Range GETs when credentials are available.

| Source | Behavior |
|--------|----------|
| URL userinfo | `https://user:pass@host/path` — credentials stripped from the wire URL |
| Env | `RATARMOUNT_HTTP_USER` + optional `RATARMOUNT_HTTP_PASSWORD` when the URL has no username |
| URL user + env password | Username in URL, password from `RATARMOUNT_HTTP_PASSWORD` if omitted in the URL |

URL userinfo wins over env username. **401 Unauthorized** returns a clear error naming these credential sources.

### HTTP(S) Cookie authentication (FR-2 residual / [#157](https://github.com/mxmlnkn/ratarmount/issues/157))

A `Cookie` header is sent on HEAD, full GET, and Range GETs when configured. Combines with Basic when both are set.

| Source | Behavior |
|--------|----------|
| `RATARMOUNT_HTTP_COOKIE` | Raw `Cookie` header value (e.g. `session=abc; token=xyz`). Wins over file when both set. |
| `RATARMOUNT_HTTP_COOKIE_FILE` | Path to Netscape jar lines and/or simple `name=value` lines (joined with `"; "`) |

**Residual:** no browser-style jar, no `Set-Cookie` persistence, no per-domain store. Values are redacted in debug logs.

```bash
ratarmount -f 'https://user:pass@example.com/archives/a.tar' mnt/
RATARMOUNT_HTTP_USER=user RATARMOUNT_HTTP_PASSWORD=pass \
  ratarmount -f https://example.com/archives/a.tar mnt/
RATARMOUNT_HTTP_COOKIE='session=abc; token=xyz' \
  ratarmount -f https://example.com/archives/a.tar mnt/
```

`webdav://` / `webdavs://` use `fetch_webdav_to_temp` for files; **Depth-1 collections** mount as folders (F-1). Plain `http(s)://` DAV endpoints that need no special scheme continue to use the HTTP path; put credentials in the URL when using the WebDAV schemes.

### S3 credentials / endpoint

| Env | Purpose |
|-----|---------|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Required for PUT / live overlay commit (anonymous is GET-only) |
| `AWS_SESSION_TOKEN` | Optional STS |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Default `us-east-1` |
| `AWS_ENDPOINT_URL` / `S3_ENDPOINT_URL` | MinIO / LocalStack (path-style) |
| `RATARMOUNT_S3_ANONYMOUS` / `AWS_ANONYMOUS` | Unsigned GET; live overlay commit exits 2 |
| `RATARMOUNT_COMMIT_SPOOL_DIR` | Persistent F-7 live-commit mirror (default `$TMPDIR`) |

`s3://bucket/prefix/` (trailing slash **or** no object at key + ListObjectsV2 children) mounts as a directory. `list_dirents` returns common prefixes as dirs and objects as files with sizes. Opening a `.tar` child uses `S3RangeFile` (no full-bucket download). Continuation tokens loop until empty; more than 100 000 keys is an error (not a silent truncate). Listing TTL: `RATARMOUNT_REMOTE_LIST_TTL_SECS` (default 30).

### S3 PUT (F-7 primitive)

Live overlay `s3://… -w --commit-overlay-interval` / `--commit-overlay-on-exit` (uncompressed TAR or `.tar.zst`) GETs a persistent spool under `$RATARMOUNT_COMMIT_SPOOL_DIR` or `$TMPDIR/ratarmount-f7-{pid}/`, splices locally, multipart-PUTs the spool, then PUTs the patched sqlite blob and `{url}.index.ptr`. Startup write probe is `CreateMultipartUpload` + `AbortMultipartUpload` (fail-closed on 403/404; no leftover object). `RATARMOUNT_S3_ANONYMOUS=1` / missing keys exit 2. Reopen is live Range (`open_live_remote`). Offline `--commit-overlay` + `s3://` exits 2. CLI `--publish-index` PUTs blob-then-pointer for `s3://`.

| API | Behavior |
|-----|----------|
| `put_s3_file` | Single **PutObject** if size ≤ 8 MiB; else multipart (`CreateMultipartUpload` → 8 MiB `UploadPart` → `CompleteMultipartUpload`). Body is a file path (never a `Vec` of the archive). **Abort** the MPU on any error. |
| `s3_create_and_abort_multipart_upload` | F-7 startup write probe: Create + immediate Abort. Fail-closed on 403/404. Does not leave a `.ratarmount-write-probe` object. |
| `publish_index_to_s3` | PUT `{url}.index.{id}.sqlite` **then** `{url}.index.ptr` (schema `ratarmount.index.pointer.v1`). Pointer PUT failure after blob PUT returns `Err` and names the leftover blob. |

PUT requires non-anonymous AWS credentials (`AWS_ACCESS_KEY_ID` / IMDS/ECS). `AWS_ANONYMOUS=1` / `RATARMOUNT_S3_ANONYMOUS=1` is GET-only. Residual: GCS `gs://` / Azure `az://` PUT.

### GCS (`gs://`)

XML file GET; JSON list API (Bearer/ADC/IMDS). HMAC GOOG1 uses XML ListBucket (query params unsigned on the wire; STS is `/{bucket}` only). Range is sent unsigned.

| Env | Purpose |
|-----|---------|
| `CLOUDSDK_AUTH_ACCESS_TOKEN` / `GOOGLE_OAUTH_ACCESS_TOKEN` | Bearer (tried first) |
| `GOOGLE_HMAC_KEY` / `GOOGLE_HMAC_SECRET` | GOOG1 HMAC (both non-empty; selected **before** the ADC/IMDS token cache) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Service-account JSON (RS256 JWT → oauth2; cached until expiry−120s) |
| GCE/GKE IMDS | `Metadata-Flavor: Google` (override `RATARMOUNT_GCS_IMDS_BASE` for tests) |
| `RATARMOUNT_GCS_ANONYMOUS` / `CLOUDSDK_ANONYMOUS` | Anonymous GET |
| `RATARMOUNT_GCS_ENDPOINT` | XML/JSON API base override |

### Azure Blob (`az://` / `azure://`)

| Env | Purpose |
|-----|---------|
| `AZURE_STORAGE_ACCOUNT` | Required for non-anonymous (host is `{account}.blob.core.windows.net`) |
| `AZURE_STORAGE_SAS_TOKEN` | Query append (redacted in logs) |
| `AZURE_STORAGE_KEY` | SharedKey HMAC-SHA256 |
| IMDS MSI | `Metadata: true`, resource `https://storage.azure.com/` (`RATARMOUNT_AZURE_IMDS_BASE` for tests) |
| `RATARMOUNT_AZURE_ANONYMOUS` | Anonymous |
| `AZURE_STORAGE_ENDPOINT` | Azurite / private endpoint |

### FTP / FTPS

| Env | Purpose |
|-----|---------|
| `RATARMOUNT_FTP_USER` / `RATARMOUNT_FTP_PASSWORD` | When URL has no userinfo; else anonymous `anonymous`/`ratarmount@` |
| `RATARMOUNT_FTP_CA_FILE` | PEM CA bundle for `ftps://` |

URL userinfo is redacted in logs (`ftp://user:***@host/…`). Prefer `ftps://`. Directory URLs (trailing `/`, or CWD when SIZE fails) mount as F-1 folders. Implicit FTPS (port 990) is residual.

### SSH authentication

Tried in order: password from URL (`ssh://user:pass@host/…`), SSH agent, `~/.ssh/id_ed25519|id_rsa|id_ecdsa`, then `RATARMOUNT_SSH_PASSWORD`.

Config path: `RATARMOUNT_SSH_CONFIG` or `~/.ssh/config`. URL User/Port override the **destination** only (not ProxyJump hops).

| `ssh_config` keyword | Status |
|----------------------|--------|
| `Host` / `HostName` / `User` / `Port` | **Done** |
| `IdentityFile` / `IdentitiesOnly` | **Done** |
| `ProxyJump` (comma-separated hops via libssh2 `direct-tcpip`) | **Done** |
| `Include` (tilde / relative to the config file; trailing `*` via `read_dir`; depth 16; 1 MiB cap) | **Done** |
| `ProxyCommand` (shell) | **Residual** (injection / no pty) |
| `Match` exec/host | **Residual** (ignored) |
| Live hop handshake | Unit tests cover parse + hop resolution + cycles; live `direct-tcpip` is skip-without-`sshd` |

Path rules (fsspec-like):

- `ssh://host/rel/path` → relative `rel/path`
- `ssh://host//abs/path` → absolute `/abs/path`
- `ssh://host//path/dir/` → SFTP `readdir` folder when `stat` says directory

### SMB inbound

In-tree SMB 2.0.2 Direct-TCP codec (`Smb2Client`: NEGOTIATE / SESSION_SETUP guest+NTLMv2 / TREE_CONNECT / CREATE / READ-at-offset / QUERY_DIRECTORY / QUERY_INFO / CLOSE) plus live Range reader (`open_smb_range` / `SmbRangeFile`) and share listing (`open_smb_folder` / `SmbListing` → F-1 `RemoteFolderMountSource`). Auth: URL userinfo, then `RATARMOUNT_SMB_USER` / `RATARMOUNT_SMB_PASSWORD`, else guest. Session `open_remote_input` opens live Range (`open_s3_like` / `open_smb_range`) and F-1 folders (`open_smb_folder`); dialect residual still materializes via `resolve_to_local` / `smbclient`. Dialect `STATUS_NOT_SUPPORTED` / non-2.x (SMB1 or non-SMB2 banner) falls back to Samba `smbclient` on `PATH` for **files** (`apt install smbclient` / `dnf install samba-client`). Folder URLs: QUERY_DIRECTORY unsupported fails with an install/dialect message (not a silent empty list; `smbclient` listing is residual). File URLs: dialect miss returns `Ok(None)` so [`open_smb_range`](https://github.com/hilather/ratarmount-rs/blob/main/ratarmount-remote/src/smb.rs) / smbclient can take over. Missing both names the install hint **or** the dialect residual. Logon failure and connect-refused do not fall back. Listing TTL: `RATARMOUNT_REMOTE_LIST_TTL_SECS` (default 30). Outbound `--smb` is [export.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/export.md).

| Env | Purpose |
|-----|---------|
| `RATARMOUNT_SMB_PASSWORD` | Password when URL has no userinfo (pairs with `RATARMOUNT_SMB_USER` or `$USER`) |
| `RATARMOUNT_SMB_USER` | Username when using `RATARMOUNT_SMB_PASSWORD` |

URL path: first segment is the **share**, remainder is the file path inside the share. Domain may appear as `DOMAIN;user` or `DOMAIN%5Cuser` in userinfo.

```bash
ratarmount -f 'smb://user:pass@fileserver/backups/archives/a.tar' mnt/
```

### OCI / Docker / GHCR

Custom parsers — **not** `url::Url`. `docker://ubuntu:24.04` is invalid as a WHATWG URL and is still accepted.

| Env | Purpose |
|-----|---------|
| `RATARMOUNT_OCI_USER` / `RATARMOUNT_OCI_PASSWORD` | Registry user/token |
| `GITHUB_TOKEN` | GHCR password (`USERNAME` or `x-access-token`) |
| `RATARMOUNT_DOCKER_CONFIG` | Path to docker `config.json` (`auths` / `credHelpers`) |

Layers are overlayfs-unioned (file whiteout `.wh.<name>`, opaque dir `.wh..wh..opq`; `.wh.*` names are never listed). Index key `oci:{digest}` for warm remount. First mount may cold-index every layer tar. Residual: eStargz / SOCI / nydus; `/.oci/config`.

```bash
ratarmount docker://ubuntu:24.04 mnt/
ratarmount oci://ghcr.io/org/img:tag mnt/
```

### IPFS / IPNS

Do **not** embed an IPFS node.

| Env | Purpose |
|-----|---------|
| `IPFS_GATEWAY` | Range GET base (default `http://127.0.0.1:8080`) |
| `IPFS_API` | Kubo `/api/v0/ls` (default `http://127.0.0.1:5001`; Unix socket / multiaddr ok) |

File CIDs work via the gateway if the API is down. A **directory** CID without API is a clear error naming `IPFS_API`.

### rclone

Unlocks Drive / OneDrive / B2 / Swift / HDFS without reimplementing OAuth. Config: `RCLONE_CONFIG` or `~/.config/rclone/rclone.conf`.

| Env | Purpose |
|-----|---------|
| `RATARMOUNT_RCLONE` | Absolute path to the `rclone` binary (otherwise `PATH`) |

Primary URL **`rclone://remote:path`** (colon after remote name). Alias **`rclone://remote/path`**. Plus-form **`rclone+remote:path`** / **`rclone+remote://path`** (no `://` required; otherwise treated as a local path). Missing binary: `rclone not found on PATH; install rclone or use a native scheme`. One process per `open` / listing cache miss (materialize at open). Residual: `rclone rcd` `--rc-serve` HTTP GET.

## Not yet

- SMB 3.x encryption, Kerberos, DFS, SMB1; `smbclient` directory listing (file dialect residual still falls back to `smbclient`) — F-6
- SPA HTML indexes; WebDAV Depth-infinity listing
- Implicit FTPS (port 990)
- GCS GOOG4-HMAC-SHA256 (only if live keys reject GOOG1 / V2)
- Full browser cookie jar / `Set-Cookie` persistence (env Cookie + Netscape file **are** shipped)
- ssh_config **ProxyCommand** / **Match** (ProxyJump + Include **are** shipped)
- S3 credential **refresh after open** (anonymous + IMDS/ECS snapshot at open **are** shipped; live Range is the default path, not GetObject→temp)
- rclone RC `--rc-serve` HTTP GET (`rclone+remote:path` **is** shipped)
- OCI eStargz / SOCI / nydus / config JSON
- Offline `--commit-overlay` on remote URLs (exits 2); create-if-missing on remote URLs. Live TAR/`.tar.zst` interval/on-exit commits and index publishing **are** shipped for `s3://`, `gs://`, `az://` and `hf://` (F-7)

## Usage

```bash
ratarmount -f http://127.0.0.1:8000/archive.tar mnt/
ratarmount -f 'https://user:pass@example.com/archive.tar' mnt/
ratarmount -f file:///path/to/archive.tar mnt/
ratarmount -f s3://my-bucket/path/archive.tar mnt/
ratarmount -f s3://my-bucket/prefix/ mnt/          # F-1 prefix folder
ratarmount -f gs://my-bucket/obj.tar mnt/
ratarmount -f az://container/blob.tar mnt/
ratarmount -f 'ftp://mirror.example/debian/a.tar' mnt/
ratarmount -f 'ftp://mirror.example/debian/' mnt/   # F-1 LIST/MLSD folder
ratarmount -f 'ssh://user@host//home/user/archive.tar' mnt/
ratarmount -f 'webdav://user:pass@dav.example.com/archives/a.tar' mnt/
ratarmount -f 'webdavs://dav.example.com/archives/a.tar' mnt/
ratarmount -f 'smb://user:pass@fileserver/share/path/archive.tar' mnt/
ratarmount -f 'smb://user:pass@fileserver/share/' mnt/   # F-1 QUERY_DIRECTORY folder
ratarmount -f 'rclone://gdrive:bucket/path.tar' mnt/
ratarmount -f 'rclone+gdrive:bucket/path.tar' mnt/
ratarmount -f docker://ubuntu:24.04 mnt/
ratarmount -f ipfs://bafyhash/path.tar mnt/
```

## Tests

```bash
./test-harness/run-phase10-http.sh
./test-harness/run-phase10-remote.sh
# Crate / factory (WHATWG-invalid URLs, folders, Range mocks):
#   cargo test -p ratarmount-remote --lib
#   cargo test -p ratarmount-session --lib remote_smb
#   cargo test -p ratarmount-session --lib try_open_remote_folder_url
#   cargo test -p ratarmount --bin ratarmount docker_ubuntu
#   cargo test -p ratarmount-formats-restic --lib
#   cargo test -p ratarmount-remote --lib restic
#   cargo test -p ratarmount-session --lib restic
# Optional live:
# RATARMOUNT_TEST_S3_URL=s3://bucket/key.tar AWS_… ./test-harness/run-phase10-remote.sh
# RATARMOUNT_TEST_SSH_URL=ssh://user@host//path/a.tar ./test-harness/run-phase10-remote.sh
# RATARMOUNT_TEST_OCI_URL=oci://ghcr.io/org/img:tag
```

### Persistent remote range cache (AI-RC)

HTTP range readers and their prefetch workers store verified bytes under
`platform_cache_root()/payload-v1/range-v1/`. The root follows the same platform
rules as `payload-v1/`: Linux XDG, macOS `~/Library/Caches/ratarmount/`, and Windows
`%LOCALAPPDATA%/ratarmount/`. Put the cache on local NVMe/scratch by setting
`XDG_CACHE_HOME` or choosing a dedicated parent with the override below.

| Env | Behavior |
|-----|----------|
| `RATARMOUNT_PAYLOAD_CACHE_BYTES` | **Shared** disk body budget for `payload-v1/` and `range-v1/`, default **4 GiB**. **0** disables both reads and writes. Invalid/empty values use the default. Metadata sidecars remain under the separate `RATARMOUNT_META_CACHE_BYTES` cap. |
| `RATARMOUNT_PAYLOAD_CACHE_DIR` | Exact payload cache directory override. Remote ranges stay **inside it**, at `$RATARMOUNT_PAYLOAD_CACHE_DIR/range-v1/`; for example `/nvme/ratarmount/payload-v1/range-v1`. |
| `RATARMOUNT_PAYLOAD_CACHE_MEMBER_MAX` | Whole decompressed member limit, default **64 MiB**; it does not limit remote file sizes or range chunks. |

Chunks are aligned **4 MiB** windows, with a shorter final chunk. Keys include
an immutable content token, file size, chunk size and chunk number. Plain HTTP
uses a **strong ETag scoped to the origin resource URL plus size**, captured
from HEAD or a validated ranged response. The URL alone, weak ETags and missing
ETags never enable caching. A reopened reader still probes metadata (normally
HEAD); once its token is known, rereading cached bytes issues **zero GETs**.
A changed ETag on a new open selects new data. If ETags differ within an open
(including HEAD versus GET, or CDN edges), caching is disabled for that source;
network reads continue. Explicit tokens pin the first strong response ETag too.
Invalid `Content-Range`, short bodies and extra body bytes still fail the read;
ignored-Range 200 responses and ranges without the expected ETag are never persisted.
Servers that reject HEAD require a one-byte GET metadata probe on reopen.

Small random foreground misses (**less than 256 KiB**) request only the bytes
needed, avoiding 4 MiB downloads for individual archive headers. They are not
stored unless they cover an entire chunk/small file. Sequential and prefetch
reads fill aligned chunks; cached windows are skipped while scheduling later
misses within the bounded readahead window. An unprobed first partial read does
not trigger a second aligned download.

A syntactically strong ETag is a server promise, not necessarily a content hash.
Some servers (including common nginx configurations) derive ETags from mtime
and size: replacing a file within the same second with the same size can reuse
the ETag and therefore reuse stale cached bytes. Prefer a verified SHA-256 or
immutable commit token where available; `RATARMOUNT_PAYLOAD_CACHE_BYTES=0`
disables body caching when a server's validators cannot be trusted. No ETag
format heuristic or weak-ETag trust override is applied.

Backends with verified metadata can use
`HttpRangeFile::with_content_token(ContentToken)` or
`HttpRangeSource::with_content_token(ContentToken)`. Tokens support SHA-256,
resolved Hub commit + endpoint/repo/path, strong ETag + resource/size, and
object-store version/generation + resource/size. Supplying a token asserts that
the backend has verified its binding to the remote bytes; revision names and
untrusted URL parameters are insufficient. The Hub backend attaches a pinned
commit/path on every reader and adds `X-Linked-Etag` or tree `lfs.oid` SHA-256
when available. Redirect headers retain the Hub's first linked digest.
Object-store readers have a token API available; their own transports are not
wired to this HTTP hook.

`RangeCache::get` / `put` expose chunks. Once every chunk is present and the
whole file fits the cap, an explicit `complete_file` request assembles one
contiguous `.complete` file, with one assembly per token at a time. Foreground
reads and prefetch workers never assemble multi-chunk files. Publication removes
the separate chunks, counting stored body bytes once. Single-chunk files are
written directly as complete files without an extra copy. Known SHA-256 values
check the whole digest before publishing that completed file.
`RangeCache::complete_file` and
`HttpRangeFile::complete_file` return its path for passthrough/Hub-cache callers;
open it promptly because later eviction may unlink it. Files larger than the
cap retain only their recently used chunks and cannot become complete.

LRU eviction spans both stores. In-process accounting uses an ordered LRU and
reconciles disk changes at most once per **60 seconds**, on installation.
There is no interprocess lock: concurrent processes can temporarily exceed the
cap and have approximate cross-process recency until reconciliation. Directory
scans and eviction unlinks run outside the short bookkeeping lock. Hot page hits
never wait for that lock: repeated hits on the newest entry are throttled and
header timestamps persist in batches during later maintenance (at most once
per five seconds). Unreadable directories are skipped and logged once; failed
evictions are logged once, excluded from active accounting, and do not stop
other evictions. Such inaccessible files can consume space beyond the active
budget until their permissions are repaired. Payload `lookup`/`get_or_fill`
return owned read fds, so eviction cannot race a caller opening a returned path.
Already open Unix readers retain unlinked bytes; caches remain best effort on
platforms that refuse to unlink an open file. The cap counts published body bytes;
headers,
active temporary files and transient completion copies use additional space.

Directories are private (0700 on Unix). Reads verify that the cache root and
fanout directories belong to the effective uid and are not group/world-writable.
Cache roots/fanout directories and entries reject symlinks; Unix file opens also
use `O_NOFOLLOW`. Both whole-chunk and slice reads verify chunk SHA-256; bounded
Unix fingerprint/header memos avoid rehashing unchanged chunks on every page
read. Data and headers
use unique temporary files, sync, then atomic rename, as in payload-v1.
Temporary files are ignored by readers and reclaimed after **one hour** during
reconciliation; truncated chunks/completed files are misses. Cache hits are
read on the calling thread and do not take HTTP prefetch worker permits.
