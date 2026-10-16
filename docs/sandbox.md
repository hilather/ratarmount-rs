# Write-overlay sandbox controls

Protect source paths and bound a sandbox's writable content with a persistent
or temporary write overlay:

```sh
ratarmount -w attempt-overlay --overlay-readonly 't/**,tests/**' \
  --overlay-quota 2G --overlay-quota-files 100000 source.tar mnt/
```

These options require `-w` / `--write-overlay` and conflict with the offline
`--commit-overlay` command, which does not install mount policies. They apply through the shared
overlay to FUSE, NFS, 9P, SFTP, SMB and WebDAV. Reads and read-only opens remain
available. The base archive is unchanged by ordinary overlay writes.

## Read-only path rules

`--overlay-readonly GLOBS` accepts a comma-separated list and can be repeated.
Quote patterns to prevent expansion by your shell. Matching is case-sensitive
and anchored at the mount root: `tests/**` and `/tests/**` are equivalent and
match `tests`, `tests/a`, and `tests/a/b.t`, but not `other/tests/a`.

- `*` matches zero or more characters within one path component.
- `?` matches one Unicode character within one path component.
- `**` must occupy a whole component and matches zero or more components.
  `**/tests/**` protects a `tests` directory at any depth; `a/**/z` also
  matches `a/z`.
- A matching directory protects its entire subtree. A trailing `/` is accepted
  and has the same effect as omitting it. `tests/**` explicitly includes the
  directory node itself, whereas `tests/*` matches children.
- Other characters are literal, including `[`, `]`, `!`, `#` and backslash.
  There are no exclusion/negation rules, brace expansion, escaping, or comments.
  A comma always separates rules. Whitespace around each rule is trimmed.
  Empty rules, empty interior components, `.` and `..` are rejected.

A protected path rejects creation, write opens, writes, truncate, COW copy-up,
unlink, rmdir, mkdir and symlink creation with `EROFS` (read-only filesystem).
Both rename endpoints are checked. Host parent symlinks are resolved as well,
so a symlink alias cannot bypass rules for pre-existing overlay content; unlinking
the alias itself remains allowed. Rename, rmdir and overlay reset also reject
an ancestor of any possible match: with `a/*/test`, renaming `a` is refused even
if no matching child currently exists. This conservative rule prevents moving
protected paths through a parent. While a COW copy is in flight, replacing any
of its parent directories or parent symlink aliases is also temporarily refused
with `EROFS`. This keeps the copy's publication path stable; the restriction is
released when the copy completes or fails. Unprotected directory renames still have
the overlay's existing directory-rename limitations.

## Quota

`--overlay-quota SIZE` accepts a nonnegative integer byte count or a binary
`K`, `M`, `G`, or `T` suffix (1024-based, case-insensitive). `0` permits no
growth. `--overlay-quota-files N` independently limits regular files plus
symlinks; directories do not consume file slots. Either quota can be used alone,
or combined with read-only rules. Protected-path errors take precedence.

Usage starts with a scan of existing overlay content. Quotas count logical file
lengths, including sparse extents, full COW copies, and symlink target lengths.
Internal database/marker files are excluded and symlinks are never followed.
A write or truncate that would grow beyond the byte cap fails with `EDQUOT`;
creating a file beyond the file cap does too. NFSv4 reports `NOSPC`. Overwrites
within the current extent and shrinking remain possible when an existing
overlay starts above its limit. Unlink and truncate release the corresponding
charge. COW reserves bytes and a file slot before copying, so concurrent copies
and writes cannot overrun the cap; competing copies may be refused conservatively.

The accounting covers operations through ratarmount. External edits directly
inside the overlay directory bypass enforcement; use an overlay directory only
the mount owner can modify. This is a logical content quota, not a filesystem
block quota or a complete process isolation boundary. Removal releases the
named file's original extent. Growth through a held, unlinked descriptor stays
charged until its last tracked descriptor closes.

With `--control-interface`, both the socket `status` command and
`/.ratarmount-control/status` append these live fields whenever any sandbox
policy is installed:

```text
overlay_bytes 1234
overlay_quota_bytes 2147483648
overlay_files 3
overlay_quota_files 100000
```

An absent limit is printed as `unlimited`. In-flight COW reservations are
included in live usage; offline statistics describe named content only.

## overlay-stats

```sh
ratarmount overlay-stats attempt-overlay
ratarmount overlay-stats attempt-overlay --json
```

This offline command opens the existing overlay database read-only and scans
the directory without mounting or creating a database. Stop the mount first
for a consistent view: host content and SQLite are separate snapshots. Missing,
malformed, or exclusively locked databases produce an error.

Stable JSON keys (integer counts):

| Key | Meaning |
| --- | --- |
| `bytes_in_overlay` | Logical bytes in regular files and symlink targets |
| `files_present` | Regular files present, combining additions and modifications |
| `files_deleted` | Durable tombstone rows, including removed directories |
| `directories_created` | Host directories in the overlay, including implicit COW parents |
| `symlinks` | Symlinks present, including dangling symlinks |

Database files, SQLite sidecars, staging files using the internal database
prefix, and current/legacy overlay markers are omitted at every depth.
Statistics do not require or compare against the original archive; additions
and modifications are consequently reported together.

## diff

Export an attempt's patch offline, without a mount or a Git executable:

```sh
ratarmount diff --base source.tar attempt-overlay > attempt.diff
ratarmount diff --base repo.git attempt-overlay --git > attempt.patch
ratarmount diff --base source.tar attempt-overlay --name-status
ratarmount diff --base source.tar attempt-overlay --stat
```

`--base SOURCE` is required to generate an accurate patch: the overlay stores
changed content and deletion records, but neither the original content nor its
base location. SOURCE accepts the session factory's archives, committed Git
repositories, folders and remote URLs. A working Git repository compares against
its committed tree, including when its working tree has edits. Use the same base
snapshot used for the attempt. The base and overlay contents remain read-only;
archive indexes are built in memory. Stop writers first for a consistent view.

The default is a deterministic unified diff with three context lines; `-U N`
(`--context N`) changes the context. Additions/deletions use `/dev/null`, symlinks
are compared as link-target text, and missing final newlines are marked.
Binary data (NUL bytes or invalid UTF-8) prints `Binary files a/x and b/x differ`.
New, deleted and changed modes are recorded, including mode-only changes.

`--git` emits a [Git patch](https://git-scm.com/docs/diff-format) accepted by
`git apply --check` / `git apply`: Git headers,
executable modes, symlinks as mode `120000`, exact-content renames with similarity
100%, and forward/reverse `GIT binary patch` literals (zlib + base85). Git modes
record the owner executable bit, not other Unix permission changes. Type changes use
a delete/add pair. Rename detection pairs deleted paths with new paths of the
same type and identical bytes, in deterministic path order; other moves remain
delete/add. Default unified output keeps delete/add records. `--name-status`
prints `A`, `M`, `D`, `T` or `R100` with paths; `--stat` prints per-file line counts
(byte sizes for binary changes) and totals. Both summaries detect exact renames
and replace patch output; they cannot be combined with each other.
Use `git apply --unidiff-zero` when applying a patch generated with `-U 0`.

Internal database, marker and staging names are excluded using the overlay's
shared path filter at every depth. `.git` directories, including synthetic-head
metadata, are omitted by default; `--include-git-dir` includes them. Unchanged
copy-up files are omitted. Git patches do not represent empty directories or
directory permission changes. Unsupported special files and non-UTF-8 filenames
produce an error. Content is held in memory; very large, unrelated text files
may use a full replacement hunk to bound diff traceback storage.

Exit status is **0** for no changes, **1** for changes, and **2** for an error
(including missing/corrupt/locked databases or a missing `--base`). Redirecting
stdout preserves a clean patch; source-opening progress goes to stderr. Harnesses
should accept both 0 and 1 as successful comparisons.

## Image + repository rootfs

`--bind /MOUNTPATH=SOURCE` mounts one input inside the tree before unioning:

```sh
ratarmount docker://ubuntu:24.04 \
  --bind /repo=/srv/repos/project.git@0123456789abcdef0123456789abcdef01234567 \
  --git-synthetic-head -w attempt-overlay mnt
```

Sources accept the same local paths, archives, Git revisions and URLs as
positional inputs. Mount paths must be absolute within the mount, with no `.`
or `..` components; `/` is allowed. The first `=` separates the path from the
source, so URL query parameters containing `=` remain intact. Positional inputs
come first at `/`; repeated binds follow in flag order, even when flags are
interspersed with positionals. Supply an explicit mountpoint when using only
binds, or use `serve` for an export-only tree. With binds, a lone local
positional that is not an existing file is interpreted as the mountpoint;
supply both source and mountpoint when adding a positional directory/repo.
Export flags keep a lone positional as the source.

Directories merge; later sources win for conflicting files. The existing union
policy favors real directories over conflicting symlinks/files. OCI whiteouts
are evaluated within the image's own layers and cannot delete a separately
bound repository. Image content already under `/repo` remains visible unless
replaced by repository entries. Use an image with an empty `/repo` when a clean
Git worktree is required.

Explicit binds retain their requested paths under `--disable-union-mount`;
that option gives only positional inputs inferred basename prefixes. Global
`-p` still wraps the completed union. `--git-synthetic-head` requires exactly
one Git source and exposes `.git` under its bind path. Git selectors apply to
that Git source alongside non-Git image/archive inputs; multiple Git sources
remain an error in synthetic mode. A write overlay wraps the complete union.

See the [rootfs recipe](recipes/sandbox-rootfs.md) for bubblewrap,
systemd-nspawn, and microVM exports. This assembles filesystem content; the
sandbox runtime supplies process isolation.
