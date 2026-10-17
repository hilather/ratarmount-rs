# Deduplicated repository snapshots for task corpora

Use a local restic repository to store trees from many commits, then mount it
with a separate writable overlay for each task. Restic performs content-defined
chunk deduplication across snapshots; ratarmount reads encrypted pack blobs on
demand. You need the `restic` executable on PATH (or `--restic-bin /path/to/restic`)
to create snapshots, but not to read them. See [restic support](../restic.md).

## Build a corpus of N commits

Use a password file outside the source trees. Keep the repository and password
file when moving the corpus to another machine. `--init` creates a missing
repository and leaves an existing one intact.

```bash
export RESTIC_PASSWORD_FILE=/secure/corpus-password
repo=/data/corpus-restic
source_repo=/src/project
mkdir -p manifests

# commits.txt contains one full commit SHA per task, in the desired order.
# For example: git -C "$source_repo" rev-list --max-count=100 HEAD > commits.txt
while IFS= read -r sha; do
    ratarmount snapshot add --git "$source_repo@$sha" \
        --repo "$repo" --init --host corpus-builder --tag "task=$sha" \
        > "manifests/$sha.txt" || exit "$?"
done < commits.txt

ratarmount snapshot list --repo "$repo"
```

`--git` exports only the requested committed tree through `GitMountSource` into
a temporary directory. Working-tree edits and Git history are absent. Executable
bits and symlinks are preserved. Each snapshot also receives `repo=<absolute
source path>` and `commit=<resolved full SHA>` tags. The temporary tree is removed
after the backup, including on failure. Budget disk space for one expanded tree;
this convenience is not a zero-copy export. Submodules and LFS objects are not
fetched or expanded; Git tree entries must be readable by the existing Git reader.

For an existing directory instead, use:

```bash
ratarmount snapshot add /data/task-tree --repo "$repo" --init \
    --tag task=example --tag split=train
```

Directory mode includes all files that restic normally backs up, including a
`.git` directory if present. Both modes back up `.` from inside the input tree,
so files appear directly at each mounted snapshot's root. `snapshot_id=...`,
`data_added=...`, `mount_source=...`, and `snapshot_path=...` are printed after
success. `data_added` counts newly added blob bytes, not total repository disk
usage; encryption, compression, indexes, and snapshots contribute other overhead.

## Mount a task with a private overlay

```bash
task_id=task-0001
sha=$(head -n 1 commits.txt)
id=$(sed -n 's/^snapshot_id=//p' "manifests/$sha.txt")
mkdir -p /mnt/task
ratarmount "restic:$repo" /mnt/task -w "/data/task-overlays/$task_id"
cd "/mnt/task/ids/$id"
# Run the task here. Writes go to this task's overlay.
```

The mount exposes all snapshots; `/ids/<full-id>/` chooses a task tree. Use
`/snapshots/<unique-id-prefix>/` for a short id. `/latest` points to the newest
snapshot and is unsuitable for pinning a task. Tags are shown by `snapshot list`;
the reader has no tag-filter URL or single-snapshot mount URL. Record the id per
task instead of relying on tag ordering or `latest`.

Use one overlay directory per task. Mounting requires FUSE and its usual host
permissions. The restic base remains read-only: overlay changes are not committed
back into restic. Create a new snapshot from a resulting directory when needed.
Since `--git` omits `.git`, initialize a task-local Git repository if tooling
requires one; the original commit SHA remains available in the snapshot tags.

## Measured small example

Measured on 2026-10-16 with restic 0.19.1, default repository format/compression:
two different input directories each held the same 4,194,304-byte deterministic
pseudorandom file plus `changed.txt` (`before` versus `after`).

| Backup | Logical file bytes | `data_added` |
|--------|-------------------:|-------------:|
| First | 4,194,310 | 4,195,341 |
| Second | 4,194,309 | 1,036 |

The two trees contain about 8 MiB of logical file data and add about 4 MiB of
blob data in total. The second adds under 0.025% of its logical size. This is a
small measurement, not a promise that any 10,000-task corpus fits in a few GB:
results depend on shared content, generated files, binaries, and edits.

Reproduce it with the wrapper:

```bash
example=$(mktemp -d)
export RESTIC_PASSWORD_FILE="$example/password"
printf '%s\n' example-only-password > "$RESTIC_PASSWORD_FILE"
chmod 600 "$RESTIC_PASSWORD_FILE"
python3 - "$example" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
seed = 123456789
payload = bytearray()
mask = (1 << 64) - 1
for _ in range(4 * 1024 * 1024):
    seed ^= (seed << 13) & mask
    seed ^= seed >> 7
    seed ^= (seed << 17) & mask
    payload.append(seed & 255)
for name, changed in [('one', b'before'), ('two', b'after')]:
    directory = root / name
    directory.mkdir()
    (directory / 'shared.bin').write_bytes(payload)
    (directory / 'changed.txt').write_bytes(changed)
PY
ratarmount snapshot add "$example/one" --repo "$example/repo" --init --tag one
ratarmount snapshot add "$example/two" --repo "$example/repo" --tag two
ratarmount snapshot list --repo "$example/repo"
```

Timestamps, restic versions, and metadata can change the precise byte counts.
The automated `regression_snapshot_restic_dedup_roundtrip` test checks a small
second addition and reads both snapshots through `Session::open(restic:...)`
without FUSE; it reports an explicit skip when restic is absent.
