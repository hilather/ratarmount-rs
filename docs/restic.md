# restic repository snapshot browser (G-4)

Mount a **local** restic repository as a read-only tree of snapshots. Pack blobs are decrypted on demand from `data/` (no restore to disk). This is **not** a FormatBackend and is **not** nested via `open_path` / factory probes — session opens it only through `open_remote_input`.

Living roadmap: [beyond-parity G-4](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/beyond-parity-roadmap.md). Remote schemes: [phase10-remote.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/phase10-remote.md).

## Usage

```bash
export RESTIC_PASSWORD='…'          # or RESTIC_PASSWORD_FILE=/path/to/file
ratarmount restic:/var/backup/repo mnt/
ls mnt/snapshots/
cat mnt/latest/hello.bin            # /latest → snapshots/<newest-id>
```

Password is never logged. `Debug` of `ResticMountSource` prints `password: "<redacted>"`.

| Input | Result |
|-------|--------|
| `restic:/var/backup/repo` | local repo `/var/backup/repo` |
| `restic:///var/backup/repo` | extra slash tolerated |
| `restic:relative/path` | error (absolute path required) |
| `restic://s3://bucket/repo` | error (`S3 restic repos residual; use a local cache copy`) |
| `restic:s3://bucket/repo` | same S3 residual |

`restic:` is a **scheme-prefix** (not WHATWG `Url::parse`). `restic:/path` is not treated as a local filename with a colon.

## Tree layout

```text
/snapshots/<short-id>/…restic tree…
/latest -> snapshots/<latest-id>     # symlink to the newest snapshot
/ids/<full-id>/                      # alias using the 64-hex snapshot id
```

Short ids are unique prefixes (8 hex when unique). File open looks up blob IDs in `index/*` and `Read+Seek`s the matching range in local `data/` pack files (restic v1 uncompressed and v2 zstd blobs).

## Residuals

- **S3 / remote restic backends** (`s3://`, SFTP, REST, …) — copy or cache the repo locally first.
- **borg / kopia / ZFS send** — G-4 remains `partial` until those MountSources exist.
- Write / fuse overlay commit into a restic repo is out of scope (RO).

## Tests

```bash
cargo test -p ratarmount-formats-restic --lib
cargo test -p ratarmount-remote --lib restic
cargo test -p ratarmount-session --lib restic
# live restic init + backup (eprintln skip when `restic` is missing):
cargo test -p ratarmount-formats-restic --lib restic_init
```
