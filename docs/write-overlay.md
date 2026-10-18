# Writing into archives

An archive mount is read-only. `-w DIR` adds a write overlay: new and changed
files go into `DIR`, deletions are recorded there, and the mount shows the
union. The archive itself is never touched until you ask for a commit. This is
how ratarmount serves as a sandbox for agents, as a checkpoint directory for
training, and as an editor for archives you cannot or do not want to extract.

```bash
ratarmount -w ./changes archive.tar mnt/          # durable overlay in ./changes
ratarmount -w :temp: archive.tar mnt/             # throwaway overlay in a temporary directory
ratarmount --overlay-tmpfs=2G archive.tar mnt/    # Linux: private RAM overlay with a size cap
ratarmount --sandbox repo.git mnt/                # Linux preset: RAM overlay, container-friendly ownership, allow_other, noatime
```

Writable mounts honour `chmod` and time changes without copying the member's
payload into the overlay, executables inside the archive run, and `-o
uid=,gid=,umask=` presents the tree with different ownership. Ownership
changes themselves are refused. Policies that protect paths or cap writes
(`--overlay-readonly`, `--overlay-quota`, `--overlay-quota-files`) are
described in [Sandboxes](sandbox.md).

## What is in the overlay directory

Besides your files, the overlay holds a SQLite database,
`.ratarmount.overlay.sqlite`, with deletions ("tombstones"), metadata-only
changes and provenance attributes, and a marker file,
`.ratarmount-overlay.used`. Both names are hidden inside the mount and cannot
be created, deleted or renamed through it at any depth, ignoring ASCII case;
an archive member with one of those names is hidden too.
Copy-on-write stages each copy in a `.ratarmount.overlay.cow-*` temp next to
its destination, hidden the same way (ASCII case ignored); `--commit-overlay`
never picks a temp up, an archive member with that prefix is hidden but stays in
the archive unchanged, and the next open removes leftover temps it can reach.

The marker is a safety device. A marked overlay whose database is missing, is
a directory, or lacks its `files` table is refused for mounting and for
`--commit-overlay` rather than silently recreated, because recreating it would
resurrect every file you deleted. If you really want to discard the recorded
deletions, remove the marker; the error message names every marker present.
Overlays from older builds get the marker on first open (the older marker
name `.ratarmount.overlay.sqlite.used` is still honoured and then removed).

Inspect an overlay without mounting:

```bash
ratarmount overlay-stats ./changes --json
ratarmount diff ./changes --base archive.tar          # what changed, as a listing
ratarmount diff ./changes --base repo.git@<sha> --git # as a Git patch
```

## Layered overlays

Internally, `ReadOnlyOverlayLayer` wraps a base `MountSource` and one existing
overlay directory. `compose_stack` applies directories from bottom to top;
each layer merges directory entries, hides tombstoned names, and serves its own
host files before consulting the inner view. A later layer can recreate a
deleted path. Wrapping the result in `WriteOverlay::new(stack, top)` makes
copy-up read the composed lower bytes, including files created by a lower layer.

The read-only view uses the same host metadata, metadata-only chmod/utime
overrides, and xattr replacement/removal rules as a writable overlay. Database,
marker, and staging names stay hidden. Host symlinks remain symlink entries and
are never opened as their targets.

Construction snapshots database rows in memory without schema changes or
repairs. `Immutability::Immutable` opens SQLite with `mode=ro&immutable=1` for
caller-guaranteed sealed layers; `Shared` uses ordinary read-only access and
reports a busy writer. Shared rows do not refresh automatically, and host files
are read directly, so this mode does not promise a consistent live snapshot.
`serving_layer` reports `base` or `lower:N` (1-based, bottom to top); an entry
with metadata-only or xattr changes belongs to the layer making those changes.
Seal checks and mount flags are handled by the caller.

## Committing offline

```bash
ratarmount --commit-overlay -w ./changes archive.tar            # prompts; --yes skips the prompt
ratarmount --commit-overlay --yes -w ./changes --commit-manifest archive.tar.zst
```

| Archive | Offline commit |
|---|---|
| Uncompressed `.tar` | Rewritten; a missing `.tar` is created as an empty base when `-w` is set |
| `.tar.gz`, `.tar.bz2`, `.tar.xz` | Rewritten through GNU tar |
| `.tar.zst` (multi-frame or seek table) | Spliced from the first affected frame to the end, including deletes in earlier frames |
| `.zip` | Fully rebuilt (encrypted and multi-part ZIPs are not supported) |
| Remote URLs (`s3://`, `hf://`, ...) | Not offline; exits 2. Use the live commits below |

`--commit-overlay-mode copy|append|auto` chooses between the safe copy
(default), a journaled in-place append for eligible add-only commits to TAR
and seek-table zstd, and letting ratarmount pick. `--commit-manifest` writes a
JSONL manifest of the commit; `user.*` extended attributes set on a mounted
file are stored in TAR PAX headers. Both are explained in
[Provenance](provenance.md).

## Committing while the mount is live

```bash
ratarmount -w ./ov --commit-overlay-on-exit data.tar.zst mnt/        # on unmount, SIGINT or SIGTERM
ratarmount -w ./ov --commit-overlay-interval 15m data.tar mnt/       # every 15 minutes, files idle for 15 minutes
ratarmount -w ./ov --commit-overlay-interval 2s new.tar.zst mnt/     # creates new.tar.zst if it does not exist
ratarmount --nfs -w ./ov --commit-overlay-interval 15m data.tar      # works for exports too
```

Live commits support **uncompressed TAR and `.tar.zst`** only, locally and on
`s3://`, `gs://`, `az://` and `hf://` branches. Gzip, bzip2, xz and ZIP are
rejected rather than silently rewritten. What happens on each commit:

- Only the **last zstd frame** is rewritten; earlier frames are copied as they
  are, with reflink or `copy_file_range` where the filesystem supports it and a
  streaming copy otherwise. The copy fallback needs twice the compressed size
  free on disk.
- The on-disk index is patched, so the next mount does not rescan the prefix.
  A `:memory:` index still rebuilds fully.
- An interval commit takes only files that have not been modified for the
  interval. Files still being written, including open write handles, stay in
  the overlay until they settle. The on-exit commit takes everything.
- A delete or replace of a member that lives in an earlier zstd frame is
  refused on a live tick; run the offline `--commit-overlay` for that.
- Commits never refuse on size, but warn when the last frame is larger than
  64 MiB uncompressed, because that frame is rewritten on every commit.
- Eligible add-only commits can use the journaled append mode.
- RAM overlays (`--overlay-tmpfs`) need `--overlay-tmpfs-allow-commit`.
- `--roll-every 1d` or `--roll-every 20G` turns the target into a numbered
  series of archives presented as one union; see [Rolling archives](rolling-archives.md).

On the Hub, each commit uploads the archive, its immutable index blob and the
index pointer in one atomic Hub commit, so readers never see a mismatched
pair; `--create-pr` sends them to a pull request instead of the branch. See
[Writing archive changes back to the Hub](remote-hf.md#writing-archive-changes-back-to-the-hub).

## Concurrent readers and renames

Renaming over a file that another process has open keeps the old bytes
readable through the open handle until it is closed, and the new name is
never observed as missing in between. Hundreds of concurrently held archive
members survive a commit that moves their offsets. These guarantees are
tested on every change; see the regression catalog in `AGENTS.md`.

## Known limits

- File names must be UTF-8 on writable FUSE mounts; invalid names are refused with `EILSEQ`.

- ZIP commits rebuild the whole archive; encrypted and multi-part ZIPs cannot be committed.
- Gzip, bzip2 and xz TARs commit offline only, through GNU tar, and are rewritten in full.
- A live commit cannot delete or replace members in earlier zstd frames.
- Create-if-missing offline is for uncompressed `.tar` only; a missing `.tar.zst` is created by the live modes.
- Whole-repository `hf://` mounts and non-TAR formats on the Hub have no write-back.
- Overlay data is not deduplicated; each attempt's overlay holds full copies of the files it changed.
