# Git trees and history-free sandboxes

Mount a committed tree, optionally selecting a revision and subdirectory:

```sh
ratarmount --git-ref HEAD~1 /path/to/repo mnt
ratarmount '/path/to/repo.git@v1.0' mnt
ratarmount 'git:///path/to/repo.git#v1.0' mnt
ratarmount --git --git-prefix src /path/to/repo mnt
ratarmount --git-ref <base-sha> --git-synthetic-head -w attempt-overlay /path/to/repo mnt
```

`--git` selects the Git backend for a normal working directory, as does
`RATARMOUNT_FORCE_GIT=1`. The environment override applies only to directories
recognized as repositories; archive files and downloaded inputs remain archive
mounts. An explicit `--git` on a non-directory input is an error. Bare detection
requires `HEAD`, `objects/`, and `refs/`. `--git-ref REV` and the inline `repo@REV` form also
select Git mode. Bare repositories and `.git` directories select it automatically.
A normal working directory without these selectors remains a live folder mount,
including its original `.git`. `--git-synthetic-head` and `--git-prefix` require
Git mode; they do not silently convert ordinary folders. Synthetic mode requires
exactly one Git source. Non-Git images or archives can share the union; use
`--bind /repo=repo.git@REV` to expose synthetic metadata at `/repo/.git`.
Multiple Git sources remain rejected.

Revisions use libgit2's revision syntax (commit IDs, branches, tags, `HEAD~1`,
etc.). Quote expressions containing shell metacharacters. An existing literal
path takes precedence over inline parsing, allowing repository names with `@`.
Use `--git-ref` for ambiguous paths. Combining an inline revision and
`--git-ref` is an error. Explicit invalid revisions fail; they never fall back
to HEAD. Resolution happens once at open, so subsequent source branch changes
do not change the mount. The source commit ID is logged at info level and
available as `user.ratarmount.git.commit` on ordinary Git mounts. Synthetic
mounts expose no such xattr on any path, including `.git/*`. Keep daemon logs
outside the agent sandbox: the info log still records the resolved source ID.

The local URL form `git:///absolute/path#REV` also selects Git mode. It accepts
bare repositories, working directories, and `.git` directories. Omit `#REV` to
select HEAD. The path is percent-decoded (`%20` for a space, `%23` for a literal
`#`); `@` in this path is always a directory-name character. A URL fragment and
`--git-ref` cannot both select a revision. URLs with a host, including
`git://localhost/...`, fail with “network git URLs are not supported; clone
locally”. The same alias works in mount positionals, diff bases, overlay
commands, and sandbox daemon `create-base` sources.

Git source metadata preserves committed permissions: regular files are 0644 or
0755, directories 0755, and symlinks 0777. The source remains read-only until
wrapped in a write overlay. Ordinary Git sources skip submodules (gitlinks) with
a warning; synthetic HEAD continues to reject them.

`--git-prefix SUBDIR` selects a directory within that commit; missing prefixes
and file prefixes are errors. Synthetic HEAD then refers to that subtree,
with paths relative to it.

## Portable Git snapshots

```sh
ratarmount snapshot 'git:///srv/repos/project.git#v1.0' project.tar.zst --with-index
ratarmount snapshot '/srv/repos/project.git@v1.0' project.tar.zst --frame-size 1M --json
```

This exports the committed tree without a checkout, `.git`, or synthetic HEAD.
Entries are sorted by path, ownership is uid/gid 0, mtimes use the commit's
committer time, and file modes and symlink targets match the Git base. Empty
directories are preserved and list as empty on both bases. Submodules are skipped
with a stderr warning. Working-tree changes and later commits are
excluded. Identical input trees, commit times, and frame sizes produce identical
archive bytes. Existing output archives are refused.

The archive uses independent zstd frames with an official seek table. Frame size
is configurable (default 1 MiB, positive and at most 2³²−1 bytes). `--with-index`
writes `project.tar.zst.index.sqlite` alongside the archive. Ship both files in
the same directory to let mounts reuse the index without building it.

Text output contains two lines, `sha256:<archive hash>` and `git-tree:<tree id>`.
`--json` emits an object with `archive_digest` and `base_digest` containing those
strings. The Git tree ID is the base digest used for Git bases; the archive hash
identifies the exported bytes. Existing `snapshot add` and `snapshot list`
commands retain their restic behavior. Use `./add` or `./list` if a local Git
repository has one of those reserved command names.

## Synthetic repository guarantees

`--git-synthetic-head` adds ordinary source files under top-level `.git`, backed
by a separate cached repository. Its initial object database contains exactly
the selected tree, all recursively reachable trees and blobs, and one new
parentless commit. No source commits, tags, remote configuration, packed refs,
reflogs, hooks, alternates, or shared object directory are copied. Objects use
Git's loose-object format. `git cat-file --batch-all-objects --batch-check`
therefore cannot enumerate source history or a later fix's unique objects.

HEAD points to `refs/heads/sandbox`, the only initial ref. The commit message is
`Synthetic sandbox HEAD`; author and committer are both
`ratarmount <sandbox@ratarmount.invalid>`. Their date is the source commit's
committer timestamp, with UTC offset zero. The commit is deterministic for a
given selected tree and source timestamp. Source names and messages are absent.
`git log` initially shows one commit; blame cannot traverse source parents.

The index records the mounted paths, Git modes, sizes, and source commit time.
`core.checkStat=minimal` and `core.trustctime=false` let Git ignore the mount's
device/inode and other irrelevant stat differences. No assume-unchanged or
skip-worktree bits are set. Git's canonical index modes are 100644/100755 and
120000; synthetic source files have matching permissions and symlink sizes.
See the [Git stat configuration](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corecheckStat)
and [index format](https://git-scm.com/docs/gitformat-index) for these rules.
Pristine status is clean; ordinary files need no content refresh when their
stat data match. Materialized copies, symlinks, racy timestamps, and timestamps
outside the index API's signed 32-bit range can still require Git to verify
content. Index timestamps are clamped to `[0, 2147483647]` seconds; the mounted
mtime and synthetic commit retain the source timestamp. This avoids integer
wraparound without hiding edits or making pristine status dirty.

## Writes and cache

With `-w OVERLAY`, `.git` participates in the same copy-on-write overlay as the
working tree: index locks, index replacement, staging, refs, stash objects and
edits are private to that overlay. `git add`, `git diff`, and `git stash` work
without modifying the source or cache. New commits/stashes created by the agent
naturally add new objects; the exact initial object-set guarantee applies before
those writes. Use a fresh overlay for each independent attempt. The initial
config sets `gc.auto=0`, `maintenance.auto=false`, and `core.fsmonitor=false`,
so ordinary commits do not automatically collect/repack objects or start a
filesystem monitor. No hooks directory is present and no `core.hooksPath` is
configured. Explicit maintenance and changes to overlay configuration remain
possible.

Without `-w`, the mount is read-only. `git status`, `git diff`, and `git log`
can read it; use `git --no-optional-locks status` to suppress optional index
refresh writes. Commands needing index/ref/object writes require an overlay.

The cache is always `git-synthetic-v1/` under the platform cache root:
`${XDG_CACHE_HOME:-$HOME/.cache}/ratarmount/` on Linux and
`~/Library/Caches/ratarmount/` on macOS (XDG overrides it). `--index-file`
does not change this location, and Git mounts do not create a SQLite index.
Missing or relative platform cache roots fail with an error; there is no
fallback to the current directory. Synthetic mode currently requires Unix
no-follow filesystem access; it fails closed on other platforms.

The root and new entry directories are created with mode 0700. The root must
belong to ratarmount's effective uid and must not be group/world-writable.
Symlinked cache paths are refused. The directory key includes the canonical
repository location, resolved source commit, and selected tree. A lock on the
cache root directory serializes builders; a complete staging directory is
renamed into place atomically. Reopens reuse object files, but validate every
entry: exact allowed paths, HEAD/config/ref/index contents, and loose-object
headers, sizes, and hashes. Extra refs, hooks, alternates, packed refs, links,
foreign ownership, or altered contents cause an error. Reads use pinned
directory descriptors and no-follow file opens, rejecting files changed since
validation. Treat the cache as immutable and keep it inaccessible to agents.

On the next build, abandoned `.building-*` directories older than 30 minutes
are reclaimed under the root lock, only when owned by us and safe to traverse.
Old, unheld legacy `.lock` files are also removed; current builders lock the
root directory itself and create no lock files. Completed entries are never
automatically evicted. After unmounting and stopping builders, manually remove
unused or rejected entry directories (or the whole `git-synthetic-v1/` cache)
to rebuild on the next mount. Do not run older cache-writing versions alongside
this implementation.

Mounted ownership currently uses ratarmount's effective uid/gid. Git run by an
agent under a different uid may refuse the mount with “dubious ownership”.
Until AI-SB3 provides uid/gid mapping, run the daemon and agent under the same
uid, or have the agent explicitly trust this exact mount path in its protected
configuration, for example:

```sh
git config --global --add safe.directory /absolute/path/to/mnt
```

Do not use a wildcard trust exception. Setting `safe.directory` inside the
repository's own config is ineffective; see [Git's ownership and protected
configuration rules](https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory).

## Limits

Synthetic mode currently rejects submodules (gitlinks), non-UTF-8 tree names,
symlink targets containing non-UTF-8 bytes or NUL, and names unsafe to expose
as Git worktree paths. It does not fetch Git LFS
payloads. Blob reads retain the backend's existing whole-blob allocation.
SHA-256 repositories are limited by the bundled libgit2 support.

The guarantee covers objects reachable through this synthetic `.git`, not
arbitrary access to the host or network. Source symlink targets and committed
file contents are preserved, including any secrets already in that tree.
Use process/container isolation to deny the agent access to the source repo,
host cache, external Git configuration/object-store environment variables,
other mounted sources, and network fetches. Other union sources can expose additional content and metadata; inspect
the assembled tree when choosing an image. A control interface can still add untracked files; the clean-status
guarantee is for the selected Git tree with its synthetic metadata.


## Pinned code corpora

`ratarmount corpus LIST-FILE MOUNTPOINT [options]` mounts many committed trees
read-only, with no checkout and no synthetic `.git`:

```text
# corpus.txt: repository paths are relative to this list file
repos/org/project.git@0123456789abcdef0123456789abcdef01234567
repos/other/tool.git@89abcdef0123456789abcdef0123456789abcdef tools/tool
```

```sh
ratarmount corpus corpus.txt corpus-mnt --corpus-cache-size 64
```

Each nonblank line is `REPO@SHA [MOUNT/PATH]`. A SHA must be the full 40-digit
hexadecimal commit ID. Floating branches/tags and abbreviated IDs are rejected.
The optional path may start with `/`; it cannot contain `.` or `..` components
or designate the root. The default is the repository's final parent/name pair,
with `.git` removed (`repos/org/project.git` becomes `/org/project`); a path
without a parent uses just its name. Blank lines and `#` comments (including
trailing comments) are accepted. Fields are whitespace-separated; repository
and mount names containing whitespace or `#` cannot be represented.

The namespace is built without opening repositories. Listing `/`, its synthetic
ancestor directories, or looking up a mount directory opens none. Listing a
repository's contents or looking up a file inside it opens that repository on
first access. Up to `--corpus-cache-size N` idle sources are retained (default
64, minimum 1); the least recently used is dropped on a cache miss. Metadata
cookies reopen the exact pinned commit after eviction. Active operations and
open file readers can retain their data beyond this idle-cache limit, and the
namespace/list entries themselves scale with the number of repositories. The
limit bounds retained repository sources, not total process RSS or blob sizes.

Repos must remain available and retain their pinned objects while mounted.
Missing/corrupt repositories or missing commits are reported on access in the
daemon log, with missing entries to readers; file opens report an I/O error.
The parser validates the list at startup but deliberately does not validate
all repository contents. Revisions are checked against their requested commit
ID on every reopen. Later list entries win for conflicting files and directories
merge with the ordinary union policy. Listing all files recursively opens repos
as it visits them. `-r` archive recursion implicitly uses lazy mode so it does
not open the corpus during startup. Corpus mode rejects `-w`, `--bind`, Git selectors and
`--no-mount`; use normal binds for writable rootfs attempts. Standard foreground,
prefix, and export flags can be used with the required mountpoint.
