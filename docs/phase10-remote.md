# Phase 10 — remote inputs

## Supported

| Scheme | Behavior |
|--------|----------|
| `file://` | Map to local path |
| `http://` / `https://` | Probe for `Accept-Ranges: bytes` + size; sequential Range GETs (4 MiB chunks) when supported, else full GET → temp file |
| `s3://bucket/key` | AWS SigV4 GetObject → temp file |
| `ssh://` / `sftp://` / `scp://` | SFTP download → temp file |
| bare local paths | Unchanged |

`resolve_to_local` / `fetch_http_to_temp_prefer_range` prefer Range materialization (Python fsspec-style) and fall back to a full GET when the server does not support ranges. `HttpRangeFile` provides a seekable Range reader for the same probe; without ranges it buffers a full download.

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

## Not yet

- `smb://`, WebDAV, Git
- Streaming open without full download for multi-GB archives (Range-backed format readers)
- S3 anonymous / instance-profile auto-refresh beyond static env keys

## Usage

```bash
ratarmount -f http://127.0.0.1:8000/archive.tar mnt/
ratarmount -f file:///path/to/archive.tar mnt/
ratarmount -f s3://my-bucket/path/archive.tar mnt/
ratarmount -f 'ssh://user@host//home/user/archive.tar' mnt/
```

## Tests

```bash
./test-harness/run-phase10-http.sh
./test-harness/run-phase10-remote.sh
# Optional live:
# RATARMOUNT_TEST_S3_URL=s3://bucket/key.tar AWS_… ./test-harness/run-phase10-remote.sh
# RATARMOUNT_TEST_SSH_URL=ssh://user@host//path/a.tar ./test-harness/run-phase10-remote.sh
```
