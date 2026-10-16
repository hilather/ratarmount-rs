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

## Create and list snapshots

`ratarmount snapshot` wraps an installed `restic` executable. Writes are performed
by restic; the ratarmount reader remains read-only. Only local repository paths
are accepted (relative paths are resolved from the invocation directory).

```bash
export RESTIC_PASSWORD_FILE=/secure/restic-password
ratarmount snapshot add /data/tree --repo /var/backup/repo --init \
    --tag task=42 --tag split=train --host corpus-builder
ratarmount snapshot list --repo /var/backup/repo
# A history-free tree at a commit, tagged with repo=... and commit=<full SHA>:
ratarmount snapshot add --git /src/project@0123456789abcdef \
    --repo /var/backup/repo --tag task=42
```

`--init` is required to initialize a missing repository. Without it, missing
repositories fail before backup. Existing repositories are never reinitialized.
`--restic-bin /path/to/restic` overrides PATH lookup on either verb. `--tag` is
repeatable and `--host` is optional. `add` takes either a directory or `--git`,
not both. Git mode temporarily materializes one committed tree, preserving
symlinks and executable bits, with no working-tree changes or history.

Use `--password-file F` on either verb to override inherited credentials; its
absolute path is passed through `RESTIC_PASSWORD_FILE`. Otherwise
`RESTIC_PASSWORD` / `RESTIC_PASSWORD_FILE` are inherited by restic. Relative
password-file paths resolve from the invocation directory, including the env
variable form. Password contents never appear on argv. Set the same environment variable when mounting;
the wrapper's `--password-file` applies to that invocation only.

Successful backups print the snapshot id, `data_added`, file counts, logical
bytes processed, the `restic:/absolute/repo` mount source, and a snapshot path.
The wrapper backs up `.` from inside the input directory, giving each snapshot
its contents directly at the root. List prints tab-separated id/time/tags/paths
with tags and paths encoded as JSON arrays. Child exit codes are preserved,
including partial backups (restic exit 3); wrapper/JSON errors exit 1 and CLI
usage errors exit 2. A failed backup may still have created a partial snapshot:
inspect `snapshot list` and restic's stderr before retrying.

Mount the printed source and select `/ids/<full-id>/` inside it, or
`/snapshots/<unique-id-prefix>/` when using a short id. There is no tag selector
or single-snapshot mount URL; use list to map tags to ids. See the
[deduplicated task corpus recipe](recipes/dedup-snapshots.md) for a commit loop,
per-task overlays, and measured deduplication.

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
# wrapper unit tests and live dedup + Session readback (no FUSE):
cargo test -p ratarmount --bin ratarmount snapshot::
```
