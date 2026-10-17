# Provenance attributes and commit manifests

On a writable FUSE mount, attach provenance without copying an archive member's
payload into the overlay:

```sh
ratarmount -w edits traces.tar.zst mnt
setfattr -n user.teacher -v glm-5.3-flash mnt/trace.jsonl
setfattr -n user.train_ok -v false mnt/trace.jsonl
getfattr -d mnt/trace.jsonl
fusermount3 -u mnt
ratarmount --commit-overlay --yes -w edits --commit-manifest traces.tar.zst
ratarmount find --xattr train_ok=false traces.tar.zst
```

Only `user.*` attributes on members are writable; the synthetic mount root refuses changes. `XATTR_CREATE` refuses existing names;
`XATTR_REPLACE` and removal refuse missing names. Empty values are supported.
Each value is limited to 64 KiB; names plus values are limited to 256 KiB per
file (including stored removal-mask names). Names must be UTF-8, at most 255 bytes, and contain no NUL, newline or `=`.
Read-only overlay globs apply to attribute changes. The overlay data/file quota
**excludes xattr metadata**; the independent per-file caps apply instead.

The overlay SQLite database stores values and deletion masks separately from
payloads. Existing databases gain the table without dropping existing data;
the missing/corrupt database and marker protections remain in effect. Attributes
inherit from the archive until changed or removed. Rename carries attributes
with the file, and unlink/recreate clears the old attributes.

Commit persistence supports uncompressed TAR and `.tar.zst`. Overlay roots are
canonicalized for both live and offline provenance commits, including paths
beneath macOS's `/var` symlink. Confinement still rejects member paths that
escape the overlay root. Attributes use
`SCHILY.xattr.<name>` PAX records with **raw binary values**, matching GNU tar's
length-prefixed representation; invalid UTF-8, NUL and newlines in values are
preserved. Reindexing and remount read these values back. Metadata-only edits
rewrite the member and stream its payload through a temporary file during the
commit. They do not copy payloads at `setxattr` time. Existing-member changes
force copy mode even when append was requested; new members with attributes
can use journaled append. Other archive commit formats refuse xattr changes.

`find --xattr` accepts `NAME`, `NAME=VALUE`, and `NAME!=VALUE`. `user.` may be
omitted. Multiple predicates are ANDed, and inequality requires the attribute
to exist. Values are compared as UTF-8 bytes supplied on the command line.
The optional path pattern defaults to `*`. Filtering uses index xattrs before
the result limit; older member versions remain searchable like ordinary find.
Control-file/socket search does not yet accept xattr predicates.

`--commit-manifest` is opt-in, for offline and local live/on-exit/interval TAR
commits. Every successful nonempty commit writes `<archive>.manifest.jsonl`.
Each line contains `path`, `size`, `sha256`, `xattrs`, and `commit_id` for a visible
member (including directories). Xattr values are JSON arrays of byte integers,
so no lossy text conversion occurs. Only `user.*` attributes are included.

`--manifest-hashes new|all|none` controls hashing (default `new`):

- `new`: hash new/replaced payloads; reuse a stored `user.hash.sha256` for unchanged
  members when available in PAX metadata or a valid sibling index, otherwise emit `null`. Metadata-only changes count as
  unchanged payloads.
- `all`: read and hash every regular member.
- `none`: emit `null` for every hash.

New/replaced payload hashes are computed while the TAR writer copies their bytes,
excluding TAR headers and padding. `all` also reads unchanged regular members;
hashing is bounded in memory. A commit ID is the UTC microsecond timestamp, advanced past the previous
nonempty manifest's ID if necessary. Empty archives produce an empty manifest.
IDs are monotonic across consecutive nonempty manifests for an archive; deleting
the manifest or an intervening empty manifest loses that counter history.

The manifest is written to a sibling temporary file, fsynced, then renamed and
the parent directory synced. Readers see a complete old or new manifest. The
archive and manifest are **two separate atomic replacements**: a crash between
them can leave an older manifest, and a manifest failure is reported after the
archive has committed. Live mounts refuse further access after that failure
until remounted. The manifest is provenance metadata, not a signature or an
access-control rule; consumers must check `train_ok` themselves.

Remote live commits to s3/gs/az do not upload manifests (`--commit-manifest` has no remote effect). NFS has no xattr API;
9P/SMB/SFTP xattr writes are not implemented by this change. FUSE is the supported
frontend for editing these attributes.
