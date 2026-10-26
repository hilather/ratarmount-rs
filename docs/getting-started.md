# Getting started

A tour of the command line, one job at a time. Every example works with a
release package; a few features need a build with extra Cargo features and say
so. Run `ratarmount --print-features` to see what your binary includes and
`ratarmount --help` for every flag.

## Mount and unmount

```bash
ratarmount archive.tar.gz mnt/     # mount; the process daemonizes once the mount is usable
ratarmount -f archive.tar mnt/     # stay in the foreground (logs on stderr, Ctrl-C unmounts)
ratarmount archive.tar             # no mountpoint: mounts at ./archive/
ratarmount folder                  # a folder mounts at ./folder.mounted/
ratarmount -u mnt/                 # unmount
```

The first mount of an archive scans it and writes a SQLite index next to it
(`archive.tar.gz.index.sqlite`), or into your user cache when the directory is
not writable. Later mounts load the index and come up in tens of milliseconds.

A mount point may not be, lie inside, or be an ancestor of a folder being mounted
(a positional folder or a `--bind` source) or of the `-w` overlay directory. This also
holds through symlinks, bind mounts (of the whole folder or a subdirectory, a bind hidden
under a later mount, and a bind mounted *inside* the folder, into which a FUSE mount
would propagate) and case or Unicode aliases. The single-threaded daemon would `stat` its
own mount point and hang, so ratarmount refuses with exit code 2 **before the overlay
database and marker are created, before any daemon is forked and before the FUSE mount**.
It does not create the mount point itself when it refuses, unless that path lies under a
directory that indexing creates (for example `--index-folders`). Two layouts are only
visible to a second check that runs after the archives are opened and the `-w` directory
is created: a `-w` directory and a mount point that did not exist yet and differ only by
letter case or Unicode form on a case-insensitive filesystem, and an input directory that
did not exist until another input's index was written into it (`--index-folders`). As with
any later failure, index folders and sidecars written while opening the inputs, and an
empty `-w` directory (no database, no marker), can remain after a refusal.
`<folder>.mounted` is the default mount point when the usual default would be the folder
itself (`folder` becomes `folder.mounted`; `folder.d` becomes `folder`; `x.tar.gz` becomes
`x`). The check is point-in-time and does not read mount propagation flags (a private bind
is refused too); `--corpus` members are not checked.

```bash
ratarmount -c archive.tar mnt/                     # rebuild the index
ratarmount --no-mount -c archive.tar               # only build the index, no FUSE
ratarmount --index-file /nvme/idx/a.sqlite a.tar mnt/   # choose where the index lives
ratarmount --index-file :memory: a.tar mnt/        # never touch the disk
ratarmount --no-recreate-index a.tar mnt/          # require a prepared index; fail instead of scanning
```

`--no-recreate-index` requires a complete prepared index for an indexed source:
missing state and detected schema, backend, fingerprint or seek-map failures
produce an error instead of a scan, rebuild or repair. It also refuses archive
commits and explicit index writes. For independent writable attempts, prepare
once and give each process its own overlay and mountpoint; see the
[N-worker recipe](sandbox.md#prepare-once-n-writable-workers) and its format limits.

Indexes use the same schema as Python ratarmount, so either tool can open the
other's. If you want to bind a mount to one exact index snapshot, publish it
with `--publish-index` and later mount with `--index-id <sha256>`; see
[Supported formats](formats.md#indexes) for how pointers work.

## Compressed archives

`.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, `.tar.lz4` and friends mount
like plain TARs. The index also stores a seek map for the compressed stream,
so reading a member decodes only the block or frame that covers it. A single
compressed file such as `big.csv.gz` mounts as a directory holding `big.csv`.

Random reads are cheapest in formats that were written with independent
blocks: multi-frame zstd, lz4 with independent blocks, bzip2, and xz with a
block size. A single-frame zstd file or a plain gzip stream still works but
costs more. If you own the archive, repack it once:

```bash
ratarmount --repack-seekable big.tar.gz big.tar.zst     # multi-frame zstd with an official seek table
ratarmount --repack-seekable in.gz out.gz   # keep gzip, write an out.gz.rgzi seek index instead
```

`--repack-seekable IN OUT` takes exactly two paths, works on local files only,
and cannot be combined with a mountpoint, `-w` or an export flag. The default
frame is 8 MiB. Details and the frame-size trade-offs are in
[Zstd random access](zstd-random-access.md).

Gzip archives get a 1 MiB sequential readahead window automatically;
`--readahead BYTES` sets it explicitly (up to 64 MiB) and `--readahead 0`
turns it off.

## Nested archives

```bash
ratarmount -r archive.zip mnt/                    # inner .tar, .tar.gz, .zip, .7z ... open as folders
ratarmount -r -l huge.deb mnt/                    # lazy: open each nested archive on first access
ratarmount -r --recursion-depth 2 package.deb mnt/
ratarmount -r -s archive.tar mnt/                 # mount inner foo.tar at foo/ instead of foo.tar/
```

Nested archives open from the parent's byte stream. For almost every format
that means no copy of the inner archive to `/tmp`, and a nested read costs
about the same as a top-level one. The exceptions (CAB LZX, classic SquashFS
LZMA, RAR) spool once. Prefer `-l` on huge trees so the mount comes up before
every inner archive has been indexed. The complete matrix is
[Nested archives and temp files](embedded-nested-archives.md).

Several sources mount as one union, the later ones on top:

```bash
ratarmount base.tar.zst patches.zip extra-dir/ mnt/
ratarmount -p data archive.tar mnt/               # everything under mnt/data/
ratarmount --no-file-versions archive.tar mnt/    # hide the <path>.versions/ folders for duplicate members
```

## Find files without mounting

```bash
ratarmount find '*.fits' archive.tar                # TSV: path, size, mtime
ratarmount find --fts fits archive.tar.gz           # full-text search over paths
ratarmount find --offset-order '*.fits' archive.tar # results in archive order, best for sequential extraction
ratarmount find --xattr train_ok=false traces.tar.zst   # by provenance attribute
```

A mounted archive answers the same question through its control interface:

```bash
ratarmount --control-interface archive.tar mnt/
cat 'mnt/.ratarmount-control/search/*.fits'       # quote the glob
```

## Remote archives and folders

Anything that accepts a path accepts a URL. Only the ranges you read are
fetched, and a published index next to the archive is picked up automatically.

```bash
ratarmount https://host/data.tar mnt/
ratarmount s3://bucket/key.tar.zst mnt/             # AWS_* environment, IMDS or anonymous
ratarmount gs://bucket/object.tar mnt/
ratarmount az://container/blob.tar mnt/
ratarmount 'ssh://user@host//abs/path/a.tar' mnt/   # ssh_config is honoured, including ProxyJump
ratarmount 'rclone+gdrive:bucket/path.tar' mnt/     # anything rclone can reach
ratarmount docker://ubuntu:24.04 mnt/               # OCI image, layers unioned
ratarmount -r hf://datasets/org/name@main mnt/      # Hugging Face repository, shards as folders
ratarmount dataset.torrent mnt/                     # BitTorrent: web seeds only by default; --torrent-swarm auto allows peers
export RESTIC_PASSWORD='…'
ratarmount restic:/var/backup/repo mnt/             # restic snapshots
ratarmount --password secret encrypted.7z mnt/      # or --password-file
```

Credentials come from the environment and the tools' own config files, never
from the command line: `HF_TOKEN`, `AWS_*`, `DROPBOX_TOKEN`, `RESTIC_PASSWORD`,
`RATARMOUNT_HTTP_*` for Basic and Cookie auth. Every scheme and its options:
[Remote inputs](phase10-remote.md) · [Hugging Face](remote-hf.md) ·
[BitTorrent](remote-bittorrent.md).

## Write on top, commit back

```bash
ratarmount -w ./changes archive.tar mnt/            # writes go to ./changes, the archive is untouched
ratarmount -w :temp: archive.tar mnt/               # throwaway overlay
ratarmount --commit-overlay -w ./changes archive.tar          # fold the changes into the archive
ratarmount -w ./ov --commit-overlay-on-exit data.tar.zst mnt/ # commit when the mount ends
ratarmount -w ./ov --commit-overlay-interval 2s new.tar.zst mnt/  # commit settled files while serving; creates new.tar.zst if missing
```

Offline commits support uncompressed, gzip, bzip2 and xz TAR, `.tar.zst` and
ZIP. Live commits (on exit or on an interval) support uncompressed TAR and
`.tar.zst`, rewriting only the last zstd frame. Everything about overlays,
including the safety rules and what happens on a crash, is in
[Writing into archives](write-overlay.md). Policies for untrusted writers
(`--overlay-readonly`, `--overlay-quota`, `--sandbox`) are in
[Sandboxes](sandbox.md).

### Agent attempts and grading

For a fleet sharing one immutable base/index, the Linux supervisor prepares it
once at `create-base` and starts independent strict workers at `new --count N`.
The [prepare-once recipe](sandbox.md#prepare-once-n-writable-workers) also shows
direct CLI mounts and a remount without preparation.

A committed Git tree can become a portable base; sealed preparation layers can
then be shared across independent writable attempts:

```sh
ratarmount snapshot repo@HEAD base.tar.zst --with-index --json
ratarmount overlay import --no-seal prepared.patch prepared base.tar.zst
ratarmount overlay seal prepared
ratarmount --lower prepared -w attempt base.tar.zst mnt/
# Run the agent and its edits through mnt/ before unmounting.
ratarmount -u mnt/
ratarmount overlay fsck attempt --repair
ratarmount overlay seal attempt
ratarmount overlay info attempt --json
ratarmount overlay verify attempt
ratarmount diff attempt --hash --normalize strict --json
ratarmount diff attempt --manifest
ratarmount diff attempt --git -o attempt.patch  # exit 1 means changes
ratarmount overlay import --lower prepared attempt.patch replay base.tar.zst
ratarmount overlay pack attempt attempt.tar.zst --include-index
ratarmount overlay unpack attempt.tar.zst restored
ratarmount overlay verify restored
```

`overlay unseal restored --i-know` explicitly makes a sealed copy writable again.
For a stopped kernel overlayfs upperdir, use
`ratarmount overlay import-upperdir --lower prepared upperdir imported base.tar.zst`.
The [interop reference](sandbox.md#kernel-overlayfs-interop) describes whiteouts
and opacity.

Use a fresh top for each attempt. BASE and lowers default to recorded metadata
in offline inspection commands. Renames are delete + add unless patch rendering
opts into `--detect-renames`; canonical hashes always use delete + add.

```sh
ratarmount sandbox run --base base.tar.zst --lower prepared --top next-attempt \
  --image busybox --network none --timeout 120 --journal --seal --json \
  -- sh -c 'printf "candidate\n" > answer.txt'
ratarmount journal summarize next-attempt.journal.jsonl --json
```

The runner needs Linux FUSE and a local Docker/Podman runtime. Its own exit 0
means the pipeline completed; inspect JSON `exit_code` for the container result.
For turn boundaries during a journaled mount, use
`ratarmount journal mark mnt 'turn 1'`. See the
[offline worked example and reference](sandbox.md) for scratch-fixture setup,
metadata, normalization, limits, branching and the supervisor API.

## Serve over the network

```bash
ratarmount --nfs archive.tar.gz                    # NFSv3 on 127.0.0.1:20490, no FUSE mountpoint needed
sudo mount -t nfs -o vers=3,tcp,nolock,port=20490,mountport=20490 127.0.0.1:/ mnt
ratarmount --nfs --nfs-vers 4 archive.tar.gz       # NFSv4.1 (release packages compile it)
sudo mount -t nfs -o vers=4.1,tcp,port=20490,sec=sys 127.0.0.1:/ mnt

ratarmount --http archive.tar.gz                   # GET/HEAD with ranges on :20491
ratarmount --webdav --smb --ninep archive.tar      # several exports from one process
ratarmount --sftp archive.tar                      # SFTP on :20222 (release packages compile it)
ratarmount --nfs --http -w ./ov archive.tar        # exports honour the write overlay too
```

Exports bind to localhost on high ports by default; `--nfs-bind`, `--http-bind`
and the other `*-bind` flags change that. For fstab, systemd and autofs there
is a `mount.fuse.ratarmount` helper, for Kubernetes an in-tree CSI node driver,
and for Docker and Podman a volume plugin.
[NFS](nfs-export.md) · [other exports](export.md) · [systemd](systemd-mount.md) · [CSI](csi.md) · [volume plugin](docker-volume-plugin.md)

## Tune it

```bash
ratarmount --memory-budget 512M data.tar.zst mnt/  # cap the daemon's own buffers and caches
ratarmount --direct-io data.tar.zst mnt/           # one-pass training reads bypass the page cache
ratarmount --readahead 8M data.tar.gz mnt/         # bigger sequential window
ratarmount -P 4 data.tar.zst mnt/                  # decode threads where the codec allows it
sudo ratarmount --passthrough on -o allow_other data.tar mnt/   # Linux 6.9+: kernel serves eligible files directly
```

`--memory-budget` limits ratarmount's pools (decode-ahead, HTTP prefetch,
readahead, codec and SQLite caches) and falls back to synchronous paths
instead of failing reads; it does not limit the kernel page cache. FUSE
passthrough needs `CAP_SYS_ADMIN` in the initial namespace and an eligible
source (plain files, stored TAR members, read-only overlays).
[FUSE tuning](fuse-kernel-tuning.md) · [Memory budget](memory-budget.md)

For mounts that other users or containers must see, enable `user_allow_other`
in `/etc/fuse.conf` and mount with `-o allow_other`. `-o uid=,gid=,umask=`
present the tree with different ownership without changing the archive.

## Stopping a mount

`ratarmount -u mnt/` retries `fusermount3 -u` for about a second while the mount
is busy; desktop watchers (gvfsd-trash, gvfs-udisks2-volume-monitor) probe every
new mount and briefly hold it. A foreground or daemonized FUSE mount also
unmounts on a signal. SIGINT (Ctrl-C) retries the same way and never detaches
lazily; if the mount is still busy it warns and keeps serving, and pressing it
again retries. SIGTERM retries for about a second, then detaches lazily
(`fusermount3 -u -z`) and the process exits once open files close; with a file
held open that takes the full retry window. macOS has no lazy unmount.

## When something looks wrong

```bash
ratarmount -f -d 2 -r archive.zip mnt/     # debug logs: "nested reader" vs "temp spool", index decisions, I/O mode
RUST_LOG=debug ratarmount -f archive.tar mnt/
fusermount3 -uz mnt/                       # lazy unmount if a mount is stuck
ratarmount --print-features                # which formats, remotes and exports this build has
```

A mount that is slow to come up is usually a cold index on a compressed
archive; the second mount will be fast. A mount that reads slowly from a
compressed archive is usually single-frame zstd or plain gzip; see
[compressed archives](#compressed-archives) above.
