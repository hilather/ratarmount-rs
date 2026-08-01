# Phase 10 — remote inputs

## Supported

| Scheme | Behavior |
|--------|----------|
| `file://` | Map to local path |
| `http://` / `https://` | Probe for `Accept-Ranges: bytes` + size; sequential Range GETs (4 MiB chunks) when supported, else full GET → temp file; **HTTP Basic** + **Cookie** auth on HEAD/GET/Range |
| `s3://bucket/key` | AWS SigV4 GetObject → temp file |
| `ssh://` / `sftp://` / `scp://` | SFTP download → temp file |
| `webdav://` / `webdavs://` | Map to `http`/`https`; optional Depth-0 PROPFIND for size; GET → temp (Basic auth from URL userinfo) |
| `smb://` | Parse `smb://[domain;]user[:pass]@host[:port]/share/path`; download via Samba `smbclient` CLI when on `PATH` |
| bare local paths | Unchanged |

`resolve_to_local` / `fetch_http_to_temp_prefer_range` prefer Range materialization (Python fsspec-style) and fall back to a full GET when the server does not support ranges. `HttpRangeFile` provides a seekable Range reader for the same probe; without ranges it buffers a full download.

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

`webdav://` / `webdavs://` use `fetch_webdav_to_temp` (plain file GET is enough for mounting; recursive directory mount is out of scope). Plain `http(s)://` DAV endpoints that need no special scheme continue to use the HTTP path; put credentials in the URL when using the WebDAV schemes.

### S3 credentials / endpoint

| Env | Purpose |
|-----|---------|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Required |
| `AWS_SESSION_TOKEN` | Optional STS |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Default `us-east-1` |
| `AWS_ENDPOINT_URL` / `S3_ENDPOINT_URL` | MinIO / LocalStack (path-style) |

### SSH authentication

Tried in order: password from URL (`ssh://user:pass@host/…`), SSH agent, `~/.ssh/id_ed25519|id_rsa|id_ecdsa`, then `RATARMOUNT_SSH_PASSWORD`.

Path rules (fsspec-like):

- `ssh://host/rel/path` → relative `rel/path`
- `ssh://host//abs/path` → absolute `/abs/path`

### SMB (`smbclient`)

Requires the Samba client binary on `PATH` (`apt install smbclient` / `dnf install samba-client`). Without it, `resolve_to_local` returns a clear install hint.

| Env | Purpose |
|-----|---------|
| `RATARMOUNT_SMB_PASSWORD` | Password when URL has no userinfo (pairs with `RATARMOUNT_SMB_USER` or `$USER`) |
| `RATARMOUNT_SMB_USER` | Username when using `RATARMOUNT_SMB_PASSWORD` |

URL path: first segment is the **share**, remainder is the file path inside the share. Domain may appear as `DOMAIN;user` or `DOMAIN%5Cuser` in userinfo.

```bash
ratarmount -f 'smb://user:pass@fileserver/backups/archives/a.tar' mnt/
```

## Not yet

- Pure-Rust SMB (no `smbclient` dependency)
- Git
- Recursive WebDAV directory mount as a folder (single-file GET only)
- Streaming open without full download for multi-GB archives (Range-backed format readers)
- S3 anonymous / instance-profile auto-refresh beyond static env keys

## Usage

```bash
ratarmount -f http://127.0.0.1:8000/archive.tar mnt/
ratarmount -f 'https://user:pass@example.com/archive.tar' mnt/
ratarmount -f file:///path/to/archive.tar mnt/
ratarmount -f s3://my-bucket/path/archive.tar mnt/
ratarmount -f 'ssh://user@host//home/user/archive.tar' mnt/
ratarmount -f 'webdav://user:pass@dav.example.com/archives/a.tar' mnt/
ratarmount -f 'webdavs://dav.example.com/archives/a.tar' mnt/
ratarmount -f 'smb://user:pass@fileserver/share/path/archive.tar' mnt/
```

## Tests

```bash
./test-harness/run-phase10-http.sh
./test-harness/run-phase10-remote.sh
# Optional live:
# RATARMOUNT_TEST_S3_URL=s3://bucket/key.tar AWS_… ./test-harness/run-phase10-remote.sh
# RATARMOUNT_TEST_SSH_URL=ssh://user@host//path/a.tar ./test-harness/run-phase10-remote.sh
```
