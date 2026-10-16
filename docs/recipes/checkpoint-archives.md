# Checkpoints, traces, and provenance

Create a `.tar.zst` checkpoint archive and mount it with a durable write
overlay. Training code writes the next checkpoint into the mounted directory;
`--commit-overlay-on-exit` commits changes when the mount exits. Use
`--commit-overlay-mode auto` to select the available append path for eligible
add-only changes, with the normal safe commit behavior for other plans. Keep
the prior archive or a versioned copy when you need immutable historical
checkpoints; a commit updates the archive in place.

For high-volume traces, mount an archive series with `--roll-every 20G` or a
time interval such as `--roll-every 1d`. See the zstd [random access and commit
guide](../zstd-random-access.md) for the commit constraints and recovery
behavior.

On Linux, use `setfattr -n user.teacher -v ...` on a mounted file to attach
metadata, then commit with `--commit-manifest`. The commit stores user xattrs in
TAR PAX headers, and `ratarmount find --xattr teacher=train_ok archive.tar.zst`
filters indexed values. See [provenance xattrs](../provenance.md) for names,
encoding, and format limits. The smoke script exercises archive creation and
skips the overlay commit when FUSE is unavailable.

```sh
docs/recipes/scripts/checkpoint-archives.sh
```
