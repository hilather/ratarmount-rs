# Formats

## ISO 9660

The file type comes from the ISO 9660 directory record (the directory flag),
not from the Rock Ridge PX `S_IFMT` field. PX contributes permission bits only
(`mode & 0o7777`: rwx, setuid, setgid, and sticky). A missing PX entry leaves a
directory at `0o755` and any other record at `0o644`.

Rock Ridge character devices, block devices, FIFOs, and sockets are shown as
regular files that keep those permission bits. `FileInfo` has no device
numbers, so a device type would require FUSE to create a kernel device node.
The ISO data length is kept. A `PN` entry is not turned into major and minor
numbers. A directory flag still wins when PX claims a device type.

`SL` is a symlink only on a non-directory record. A directory that also carries
`SL` stays a directory (empty link name, size 0) and its children stay in the
tree, including when Joliet omitted that directory. PX `S_IFLNK` with no `SL`
is a regular file.

Joliet names are used when that tree parses and no Rock Ridge `NM` exists. A
damaged Joliet tree (extent past the image, a directory loop, or a truncated
record) logs one warning and the index keeps the ISO 9660 directory.
