# Phase 10 — remote inputs

Inbound URL schemes. Outbound servers (`--http` / `--smb` / …) are [`export.md`](export.md). Status vs Python: [`parity-todo.md`](parity-todo.md) · beyond-parity IDs: [`tasks/beyond-parity-roadmap.md`](tasks/beyond-parity-roadmap.md).

`is_remote_url` is a **scheme-prefix** check (not `url::Url` first). Forms that fail WHATWG parse still mount: `rclone://gdrive:bucket/path`, `rclone+gdrive:bucket/path`, `docker://ubuntu:24.04`.

## Supported

| Scheme | Behavior |
|--------|----------|
| `file://` | Map to local path |
| `http://` / `https://` | Probe for `Accept-Ranges: bytes` + size; sequential Range GETs (4 MiB chunks) when supported, else full GET → temp file; **HTTP Basic** + **Cookie** auth on HEAD/GET/Range. Trailing `/` or HTML autoindex → **folder** (nginx/apache `<a href>`). Index discovery: GET `{url}.index.ptr` then `{url}.index.{id}.sqlite`, then `Link: rel="describedby"` on archive HEAD, then well-known `{url}.index.sqlite` (+ `.gz`/`.zst`/`.xz`/`.bz2`). Pointer/blob/tarstats failure continues |
| `s3://bucket/key` | Live Range (`open_s3_range` / `S3RangeFile`) when the object supports it; else GetObject → temp. SigV4 env + IMDS/ECS + anonymous. Empty key / trailing `/` / list children → **prefix folder** (`ListObjectsV2`, continuation loop, 100k cap). Index discovery: GET `{url}.index.ptr` then `{url}.index.{id}.sqlite` then well-known `{url}.index.sqlite`. Live commit PUTs the archive object, then the pointer blob, then `{url}.index.ptr`. Well-known `{url}.index.sqlite` stays GET-only |
| `gs://bucket/object` | XML path-style Range GET (`storage.googleapis.com/{bucket}/{object}`). Prefix folder via JSON list + `pageToken` (HMAC GOOG1 lists via XML). R2/MinIO stay `s3://` + `AWS_ENDPOINT_URL`. Sibling pointer/blob/well-known GET as S3. Live commit: one PUT of the archive (GOOG1 or bearer; no multipart), then `{url}.index.{id}.sqlite`, then `{url}.index.ptr`. Well-known stays GET-only. Anonymous PUT is an error |
| `az://container/blob` | Azure Blob Range (`azure://` alias). Prefix folder via List Blobs + `NextMarker`. Account from env, not URL host. Not `wasb://`. Same sibling pointer/blob/well-known GET as S3 |
| `ftp://` / `ftps://` | REST/SIZE Range or full RETR. `ftps://` = explicit AUTH TLS (`suppaftp` rustls). Trailing `/` or CWD-success → **folder** (MLSD preferred, Unix LIST fallback). Implicit FTPS :990 residual |
| `ssh://` / `sftp://` / `scp://` | SFTP download → temp (`ssh_config` HostName/User/Port/IdentityFile/IdentitiesOnly/ProxyJump/Include). Directory URL → SFTP `readdir` folder |
| `webdav://` / `webdavs://` | Map to `http`/`https`; Depth-0 PROPFIND for size; GET → temp (Basic from URL userinfo). Collection → Depth-1 **folder** |
| `smb://` | SMB 2.0.2 read/list (`SmbRangeFile` / one-share folder). `smbclient` temp file only if `RATARMOUNT_SMB_USE_SMBCLIENT=1` |
| `dropbox://` | Dropbox content API (`DROPBOX_TOKEN`); folder browse via `DropboxMountSource` (list TTL 30s); large opens prefer chunked HTTP Range |
| `oci://` / `docker://` / `ghcr://` | Registry manifest + Bearer blob Range + overlayfs layer union (`OciImageMountSource`). Custom parser (WHATWG-invalid `docker://ubuntu:24.04`). Index: local `oci:{digest}` cache first, then OCI 1.1 referrers (`artifactType=application/vnd.ratarmount.index.v1+sqlite`) on miss; fail-open if Referrers API is missing (not SOCI; no tag-convention fallback) |
| `ipfs://` / `ipns://` | Gateway Range GET (`IPFS_GATEWAY`, default `http://127.0.0.1:8080`). UnixFS dirs via `IPFS_API` `/api/v0/ls`. No embedded node |
| `rclone://remote:path` | argv `rclone cat --offset --count` + `lsjson` (one process per open). Slash alias `rclone://remote/path`. Plus-form `rclone+remote:path` / `rclone+remote://path` (no `://` required). Config stays in rclone |
| bare local paths | Unchanged |

`resolve_to_local` / `fetch_http_to_temp_prefer_range` prefer Range materialization (Python fsspec-style) and fall back to a full GET when the server does not support ranges. `HttpRangeFile` provides a seekable Range reader for the same probe; without ranges it buffers a full download.

Factory `open_remote_input` probes F-1 folders (s3/ssh/webdav/http) then `open_gcs_folder` / `open_azure_folder` / `open_rclone_folder` / `open_ipfs_folder` / `open_ftp_folder`, then live Range, then materialize. `smb://` is its own arm (not `open_s3_like`): `try_open_smb_folder` or `open_smb_range`, and it does not materialize unless `RATARMOUNT_SMB_USE_SMBCLIENT=1`. OCI is a layer-union mount, not a single-file download.

### Portable index discovery (G-2)

Order: explicit `--index-file` (including `--index-id HEX` already resolved to that path) → local folder candidates (`resolve_index_location`, including `oci:{digest}` cache) → GET `{url}.index.ptr` then immutable `{url}.index.{id}.sqlite` → HTTP `Link: rel="describedby"` on HEAD of the **archive** URL → http(s) well-known `{url}.index.sqlite` (+ compressed suffixes) → S3/GCS/Azure well-known sibling GET → OCI 1.1 referrer **on local miss**. Fail-open. Pointer/blob/tarstats failure **continues** the chain (pointer is an additional candidate, not terminal). Remote sidecar is checked with `check_tarstats_matches_remote` (size + edge hashes); mismatch → warn + cold index. Media type `application/vnd.ratarmount.index.v1+sqlite` is the blob family; `INDEX_VERSION` `0.7.0` is the `files` schema — not SOCI. Publish with `--publish-index` / `--publish-index-to PATH` (local copy + `{archive}.index.ptr` JSON pointer, schema `ratarmount.index.pointer.v1`, `index_id` = sha256 of the blob). Object-store **GET** of pointer/blob/well-known is supported. S3 and GCS live commit **PUT** the archive object, then the pointer blob, then `{url}.index.ptr` (well-known stays GET-only; GCS is a single PUT). Azure PUT is still F-7. Local `--index-id HEX` remounts `{archive}.index.{id}.sqlite` (keep-last-K=2 when a pointer is written).

Whole sidecar GETs ≤ 64 MiB are stored in `$XDG_CACHE_HOME/ratarmount/meta-v3/` (V-3; cap `RATARMOUNT_META_CACHE_BYTES`, default 256 MiB, `=0` disables). Lookup is URL-first so a remount without `.ptr` still hits. Not archive `HttpRangeFile` paging and not G-3 member bodies. `file://` / `:memory:` / a nonempty local folder candidate skip the download. HPC home-quota: set `XDG_CACHE_HOME` to scratch.

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
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Required |
| `AWS_SESSION_TOKEN` | Optional STS |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Default `us-east-1` |
| `AWS_ENDPOINT_URL` / `S3_ENDPOINT_URL` | MinIO / LocalStack (path-style) |

`s3://bucket/prefix/` (trailing slash **or** no object at key + ListObjectsV2 children) mounts as a directory. `list_dirents` returns common prefixes as dirs and objects as files with sizes. Opening a `.tar` child uses `S3RangeFile` (no full-bucket download). Continuation tokens loop until empty; more than 100 000 keys is an error (not a silent truncate). Listing TTL: `RATARMOUNT_REMOTE_LIST_TTL_SECS` (default 30).

### GCS (`gs://`)

XML file GET; JSON list API (Bearer/ADC/IMDS). HMAC GOOG1 uses XML ListBucket (query params unsigned on the wire; STS is `/{bucket}` only). Range is sent unsigned.

| Env | Purpose |
|-----|---------|
| `CLOUDSDK_AUTH_ACCESS_TOKEN` / `GOOGLE_OAUTH_ACCESS_TOKEN` | Bearer (tried first) |
| `GOOGLE_HMAC_KEY` / `GOOGLE_HMAC_SECRET` | GOOG1 HMAC (both non-empty; selected **before** the ADC/IMDS token cache) |
| `GOOGLE_APPLICATION_CREDENTIALS` | Service-account JSON (RS256 JWT → oauth2; cached until expiry−120s) |
| GCE/GKE IMDS | `Metadata-Flavor: Google` (override `RATARMOUNT_GCS_IMDS_BASE` for tests) |
| `RATARMOUNT_GCS_ANONYMOUS` / `CLOUDSDK_ANONYMOUS` | Anonymous GET (PUT is an error before any request) |
| `RATARMOUNT_GCS_ENDPOINT` | XML/JSON API base override |

Live commit (`--commit-overlay-interval` / `--commit-overlay-on-exit`) on one existing `gs://` `.tar` or `.tar.zst` spools with ranged GET when the object is large, splices locally, then sends one PUT. GOOG1 signs verb, Content-MD5, Content-Type, Date, and resource. Bearer sends `Authorization: Bearer` plus Content-MD5 and does not use that signer. Content-Type is `application/octet-stream` for the archive, `application/vnd.ratarmount.index.v1+sqlite` for the blob, and `application/json` for the pointer. No multipart and no well-known key. Offline `--commit-overlay` does not upload.

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

### SMB (SMB 2.0.2) inbound

File URLs are a live Range reader (dialect **0x0202** only). The scheme match is ASCII-case-insensitive (`SMB://` / `Smb://` use the same arm). A share root (`smb://host/share`), a trailing slash, or QUERY_INFO that says directory is an F-1 folder (`try_open_smb_folder` / `RemoteFolderMountSource`). `smbclient` downloads to a temp file only when `RATARMOUNT_SMB_USE_SMBCLIENT=1`. With that hatch unset, a failed open returns the error and does not spawn `smbclient` or call `fetch_smb_to_temp`. The live reader opens ustar TAR, ZIP, gzip, bzip2, xz, and zstd only. 7z, ISO, SquashFS, and pre-ustar tar are not read on this path; set `RATARMOUNT_SMB_USE_SMBCLIENT=1` to fetch those with `smbclient`. Outbound `--smb` is [`export.md`](export.md).

Short non-zero `STATUS_SUCCESS` READ replies are not EOF. The fill stops when the caller buffer is full, `offset` is at least the QUERY_INFO size, status is `STATUS_END_OF_FILE` (`0xC0000011`), or status is `STATUS_SUCCESS` and `DataLength == 0`. `0x80000002` (`STATUS_DATATYPE_MISALIGNMENT`) is an error, not EOF. Chunk size is the server `MaxReadSize`, capped at 1 MiB.

Directory list is `QUERY_DIRECTORY` / `FileIdBothDirectoryInformation`, pattern `*`, ended on `STATUS_NO_MORE_FILES` (`0x80000006`). An empty directory is `STATUS_NO_SUCH_FILE`. Caps are 100_000 entries and 10_000 pages; hitting a cap is an error, not a silent truncate. Listing TTL is `RATARMOUNT_REMOTE_LIST_TTL_SECS` (default 30). No WRITE, SET_INFO, or DELETE. Encryption and any dialect other than `0x0202` fail closed.

`RATARMOUNT_SMB_PASSWORD` and `RATARMOUNT_SMB_USER` are **export-only** (the `--smb` server). The inbound client does not read them. URL userinfo wins over the client env.

| Env | Purpose |
|-----|---------|
| `RATARMOUNT_SMB_CLIENT_USER` | Username when the URL has no user |
| `RATARMOUNT_SMB_CLIENT_PASSWORD` | NTLMv2 password |
| `RATARMOUNT_SMB_CLIENT_DOMAIN` | Domain when the URL has none |
| `RATARMOUNT_SMB_USE_SMBCLIENT` | Set to `1` to force the `smbclient` temp-file hatch |

No URL user and no client password is a guest session (still two SESSION_SETUP legs). If the server requires signing and no client password is set, the open fails. It does not retry unsigned and it does not fall back to `RATARMOUNT_SMB_PASSWORD`.

```bash
ratarmount -f 'smb://user:pass@fileserver/backups/archives/a.tar' mnt/
ratarmount -f 'smb://fileserver/backups/' mnt/
RATARMOUNT_SMB_USE_SMBCLIENT=1 ratarmount -f 'smb://fileserver/share/a.tar' mnt/
```

URL path: first segment is the **share**, remainder is the path inside the share. Domain may appear as `DOMAIN;user` or `DOMAIN%5Cuser` in userinfo. `smb://host` with no share is a parse error. The hatch still needs `smbclient` on `PATH` (`apt install smbclient` / `dnf install samba-client`).

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

- SMB 3.1.1 / encryption on the inbound client (v1 is dialect `0x0202` only; no WRITE). `smbclient` remains the `RATARMOUNT_SMB_USE_SMBCLIENT=1` hatch
- SPA HTML indexes; WebDAV Depth-infinity listing
- Implicit FTPS (port 990)
- GCS GOOG4-HMAC-SHA256 (only if live keys reject GOOG1 / V2)
- Full browser cookie jar / `Set-Cookie` persistence (env Cookie + Netscape file **are** shipped)
- ssh_config **ProxyCommand** / **Match** (ProxyJump + Include **are** shipped)
- S3 credential **refresh after open** (anonymous + IMDS/ECS snapshot at open **are** shipped; live Range is the default path, not GetObject→temp)
- rclone RC `--rc-serve` HTTP GET (`rclone+remote:path` **is** shipped)
- OCI eStargz / SOCI / nydus / config JSON
- S3 and GCS write-through landed; Azure follows

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
#   cargo test -p ratarmount --bin ratarmount docker_ubuntu
# Optional live:
# RATARMOUNT_TEST_S3_URL=s3://bucket/key.tar AWS_… ./test-harness/run-phase10-remote.sh
# RATARMOUNT_TEST_SSH_URL=ssh://user@host//path/a.tar ./test-harness/run-phase10-remote.sh
# RATARMOUNT_TEST_OCI_URL=oci://ghcr.io/org/img:tag
```
