# Write-overlay sandbox controls

Run untrusted or automated writers on top of a read-only base. Each attempt
gets its own overlay, chosen paths stay read-only, the amount an attempt may
write is capped, ownership is mapped for containers, and a supervisor creates
and destroys hundreds of attempts and exports each one's patch. The
[SWE-bench recipe](recipes/swe-bench-sandboxes.md) is the worked example; this
page is the reference.


Protect source paths and bound a sandbox's writable content with a persistent
or temporary write overlay:

```sh
ratarmount -w attempt-overlay --overlay-readonly 't/**,tests/**' \
  --overlay-quota 2G --overlay-quota-files 100000 source.tar mnt/
```

These options require an overlay from `-w` / `--write-overlay`,
`--overlay-tmpfs`, or `--sandbox`, and conflict with the offline
`--commit-overlay` command, which does not install mount policies. They apply through the shared
overlay to FUSE, NFS, 9P, SFTP, SMB and WebDAV. Reads and read-only opens remain
available. The base archive is unchanged by ordinary overlay writes.

## Git-ref bases and portable snapshots

Use a committed Git tree directly as an attempt's base:

```sh
ratarmount -w attempt-overlay 'git:///srv/repos/project.git#v1.0' mnt
ratarmount sandbox create-base --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock" \
  task 'git:///srv/repos/project.git#v1.0'
```

`git:///absolute/path#REV` accepts bare repositories, working directories, and
`.git` directories. It forces Git mode; an omitted revision selects HEAD. Paths
are percent-decoded and may contain literal `@`. Network Git URLs are refused:
clone locally first. `repo@REV` and `--git-ref` remain supported. Pin a commit ID
for reproducible attempts. Git base digests use `git-tree:<selected tree id>`.

To distribute the same tree as an archive, export it with its mount index:

```sh
ratarmount snapshot 'git:///srv/repos/project.git#v1.0' base.tar.zst --with-index --json
```

Ship `base.tar.zst` and `base.tar.zst.index.sqlite` together. Mounts discover the
sidecar alongside the archive and reuse it. The archive is deterministic for the
selected tree, commit time, and frame size: sorted paths, uid/gid 0, committed
file permissions, directories 0755, preserved symlinks, and commit-time mtimes.
There is no `.git` or synthetic HEAD; submodules are skipped with a stderr
warning. Independent zstd frames and a seek table support random access;
`--frame-size SIZE` changes the default 1 MiB frame size. JSON output reports
`archive_digest` (`sha256:…`) and `base_digest` (`git-tree:…`); text output prints
those values on two lines. Existing restic `snapshot add|list` commands are
unchanged. See [Git mounts](git-mounts.md) for selectors and synthetic HEAD.

## Executables and file metadata

Writable FUSE mounts honor chmod and access/modification time updates, including
“now” and omitted timestamps. New files and directories use the requested mode
masked by the FUSE request's umask; the daemon's umask is not applied a second
time. Archive members with execute bits and executables built inside the overlay
can run normally. Mounts default to `exec`; an explicit `-o noexec` still wins.
A configured `-o umask=...` continues to mask the attributes exposed to clients.

Changing an archive member's mode or times records metadata without copying its
payload into the overlay. Reads still come from the archive. The changes survive
reopening the overlay, and a later data write preserves the mode during copy-up.
TAR and compressed-TAR commit preserve executable bits and modification times;
the current TAR writer stores whole-second mtime and does not store atime.
Metadata-only commit uses the same temporary payload staging as provenance
xattrs and is limited to the TAR commit formats. Offline `ratarmount diff`
includes metadata-only mode changes without requiring a payload copy-up.
Time-only changes do not enter its change set.

NFSv3/v4 SETATTR, 9P Tsetattr and SFTP SETSTAT also apply mode and time changes.
SFTP OPEN honors requested creation permissions. The current NFSv3 server dependency
does not forward MKDIR attributes to the filesystem adapter, so newly created
NFSv3 directories initially use mode 0755; SETATTR can change it afterwards.
Ownership changes are refused
with `EPERM` (the corresponding permission status for SFTP); they neither chown
host files nor invent stored owners. Use `-o uid=...,gid=...` for presentation
mapping. chmod on a symlink itself is unsupported. SMB Basic Information has no
Unix mode field; unsupported SET_INFO classes continue to return an error.

## Read-only path rules

`--overlay-readonly GLOBS` and `--overlay-allow GLOBS` accept comma-separated
lists and can be repeated. Both require `-w`, `--overlay-tmpfs` or `--sandbox`;
`--overlay-allow` also requires at least one `--overlay-readonly` rule.
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
  There is no negation syntax, brace expansion, escaping, or comments.
  A comma always separates rules. Whitespace around each rule is trimmed.
  Empty rules, empty interior components, `.` and `..` are rejected.

The matching rule with the most **literal path components** wins: a component
counts as literal only if it contains neither `*` nor `?`. Wildcard components
(including `**`) contribute zero; literal character count and rule order do not
break ties. **Allow wins every specificity tie.** A path with no matching rule
is writable. Every rule applies to its matched root and descendants, including
exceptions: `t/agent/**` permits creating `t/agent` itself.

```sh
ratarmount -w attempt-overlay --overlay-readonly 't/**' \
  --overlay-allow 't/agent/**' source.tar mnt/
```

For these rules:

| Operation | `t/suite` | `t/agent` | `t/agent/leaf` | `outside` |
| --- | --- | --- | --- | --- |
| Create, mkdir, write, truncate, unlink, chmod, setxattr | EROFS | allowed | allowed | allowed |
| Rename endpoint, rmdir, reset | EROFS | EROFS | allowed | allowed |

The second row also checks possible protected descendants. Exception roots inside
protected subtrees stay anchored: renaming `t` or `t/agent` is refused; renaming an allowed leaf within
`t/agent` succeeds. A more specific read-only rule such as
`t/agent/private/**` protects that subtree again and prevents moving its parents.
These are policy decisions; normal filesystem errors and directory-rename
limitations still apply.

A protected path rejects creation, write opens, writes, truncate, COW copy-up,
unlink, rmdir, mkdir, chmod, timestamp updates, setxattr and symlink creation
with `EROFS` (read-only filesystem).
Both rename endpoints are checked. Host parent symlinks are resolved as well,
so a symlink alias cannot bypass rules for pre-existing overlay content; unlinking
the alias itself remains allowed. Rename, rmdir and overlay reset also reject
an ancestor of a possible read-only match that outranks the allow rule at that
ancestor: with `a/*/test`, renaming `a` is refused even if no matching child
currently exists. This conservative rule prevents moving protected paths through
a parent, including when a descendant exception might later override that match.
While a COW copy is in flight, replacing any of its parent directories or parent
symlink aliases is also temporarily refused
with `EROFS`. This keeps the copy's publication path stable; the restriction is
released when the copy completes or fails. Unprotected directory renames still have
the overlay's existing directory-rename limitations.

Every `EROFS` returned by the rule policy increments its live `erofs_denied`
counter once, including temporary COW-parent denials. With `--control-interface`,
the socket `status` reply and `/.ratarmount-control/status` include an
`erofs_denied N` line alongside quota usage, even when no quota is configured.
The counter starts at zero for each policy instance; offline `overlay-stats`
does not include it. An observer hook receives the requested path and policy
operation once per denial for journal integration. Rules are available in input
order as `{"readonly":[...],"allow":[...]}` for metadata integration.

Supervisor protocol version 1 also accepts optional base `options.allow_globs`
(an array of strings), forwarded as `--overlay-allow` to attempt mounts. It
requires base `readonly_globs`; attempts cannot supply new allow exceptions.

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

## Overlay metadata

New write overlays record their base identity in the `meta` table of
`.ratarmount.overlay.sqlite`. Inspect it offline, without mounting or modifying
the overlay:

```bash
ratarmount overlay info ./attempt
ratarmount overlay info ./attempt --json
ratarmount -w ./attempt --base-digest sha256:<64-hex-digits> snapshot.tar mnt/
ratarmount -w ./throwaway --base-digest none snapshot.tar mnt/
```

The JSON object contains every stored metadata key (string values, including
JSON-encoded `lower_layers`), plus the numeric `overlay-stats` fields
`bytes_in_overlay`, `files_present`, `files_deleted`, `directories_created`, and
`symlinks`. It also contains `tombstone_count` and the booleans `legacy`,
`files_dir_writable`, and `db_opens_read_only`. Overlay files live directly in
the overlay directory, so its permissions determine `files_dir_writable`.
Success exits 0. Missing or damaged databases fail without being created or
repaired. A mounted overlay's exclusive database lock is reported as "in use".

| Key | Meaning |
|---|---|
| `format_version` | `2` for new overlays; `1` for migrated legacy overlays |
| `ratarmount_version` | Creator's version |
| `created_at` | Creation time, RFC 3339 UTC |
| `base_url` | Original base positional |
| `base_digest` | `sha256:<hex>`, `git-tree:<sha>`, `weak:<hex>`, or `none` |
| `base_digest_kind` | `strong`, `git-tree`, `weak`, or `none` |
| `base_size`, `base_mtime_ns` | Local archive size and modification time used for cheap remount checks |
| `base_git_tree` | Selected Git tree, also retained when a SHA-256 digest was supplied |
| `base_remote_token` | Available remote validators, or known multi-source inputs |
| `lower_layers` | JSON array, bottom to top, of `{path, layer_digest, sealed_at}` records; empty for an ordinary mount |
| `stack_digest` | SHA-256 of the base digest and ordered lower-layer digests, each followed by a newline |
| `base_mismatch_forced_at` | Last explicit override of a failed base check, RFC 3339 UTC |
| `sealed_at`, `layer_digest` | Reserved for sealing; absent on new writable overlays |
| `journal_path` | Reserved for the last journal file used |
| `fsck_at`, `fsck_result` | Reserved for consistency checks |

A local archive gets a streaming SHA-256 of all file bytes at creation. If an
existing writable archive index is available, a small cache reuses the digest
for the same canonical path, size, nanosecond mtime, and inode. Hashing never
creates an archive index. `--no-recreate-index` and immutable index snapshots
are not modified for this cache.

A directory gets a `strong` digest of a sorted manifest of relative path,
mode, size and content SHA-256. The root and empty directories participate;
directory sizes are zero. Symlinks hash their target bytes without following
them; special files cannot be hashed. Paths are sorted as OS bytes and fields
are length-framed, so names containing delimiters remain distinct. A Git base
gets the selected tree id, including `--git-prefix`, and startup pins the
resolved commit before opening the mount.

For a computed directory digest, keep the overlay outside the base directory.
Otherwise its own SQLite metadata would become part of the input being hashed;
creation refuses that arrangement. A supplied digest or `none` allows it.

Remote bases use a `weak` digest of the URL and cheaply available validators:
HTTP HEAD ETag/Content-Length/Last-Modified or S3 ETag/size. Failed HEADs,
redirects, and other schemes fall back to the known URL. This fallback does
not detect changes behind a mutable URL. Multiple base inputs likewise get a
weak identity of the ordered input names. Supply a known SHA-256 for these
cases when stronger identity is required.

`--base-digest sha256:<hex>` trusts the caller and skips base-content hashing.
`--base-digest none` warns and disables identity checking for new overlays.
Both it and `--force-base-mismatch` require `-w`, `--overlay-tmpfs`, or
`--sandbox`. On remount, only local archive size/mtime and Git tree ids are
checked; directory contents and remote objects are not rehashed. Deliberately
preserving file size and mtime can therefore evade the cheap check. A mismatch
refuses the mount; its message shows the recorded digest and current identity
(stat values for a local archive, without recomputing SHA-256).
`--force-base-mismatch` records the override time while preserving the original
base and stack digests. Use it deliberately after an external base replacement.
Successful local archive commits refresh the recorded size, mtime, base and
stack digests, and record `base_committed_at`. Strong digests are recomputed
and the writable index digest cache is refreshed. Reopening the same overlay
after an offline, interval, on-exit, append, or rolling commit needs no override;
a subsequent external archive change is still refused. Rolling mounts check
the active generation. Legacy overlays remain legacy and digest kinds stay unchanged.

Existing overlays without `meta` remain usable. Opening one with `-w` adds
only `format_version=1`: it stays `legacy: true`, with no retroactively assigned
digest or sealed state. Library callers using `WriteOverlay::new` without
creation context create version 2 metadata with digest kind `none`; callers
that know the base should use `new_with_create_info`.

## Layered overlays

Use repeated `--lower DIR` arguments in bottom-to-top order to share prepared
content across attempts. With `-w TOP`, all writes go to that top; without it,
the composed mount is read-only. Copy-up reads the composed lower view, including
files produced by a prepared layer. The highest layer mentioning a path wins:
a tombstone hides the layers below, and a higher layer can re-create that name.

```sh
ratarmount --lower prepared -w attempt source.tar mnt/
ratarmount --lower prepared --lower attempt source.tar inspect/
ratarmount --lower prepared --overlay-tmpfs=2G source.tar scratch/
```

Lower layers must have `sealed_at` metadata. `--allow-unsealed-lower` also accepts
unsealed and legacy overlays; these open read-only without SQLite's immutable
option and may fail with “in use” if another mount holds the database. They use
a construction-time row snapshot, so stop writers before using them. Sealed
lowers use immutable SQLite and can be shared by concurrent mounts.

A new top records absolute lower paths, their ordered layer digests and seal
timestamps, and `stack_digest`. An unavailable digest or seal timestamp on an
opted-in unsealed lower is recorded as an empty string. Remounting an existing
top compares ordered absolute paths and digests, including an omitted lower
list. A mismatch names both stacks and is refused. `--force-stack-mismatch`
allows it and records `stack_mismatch_forced_at`; it preserves the original
stack identity. A sealed top cannot be opened with `-w`, including when using
`--sandbox`: mount it with `--lower` or unseal it first.

Committing a layered stack is unsupported: `--commit-overlay`, on-exit commit,
a nonzero commit interval, and rolling commits with `--lower` are refused with
“commit of a layered stack is not supported; flatten first”. RAM tops are
supported; the sandbox supervisor API does not yet accept lower stacks.

## fsck

```sh
ratarmount overlay fsck attempt --json
ratarmount overlay fsck attempt --repair
```

Run this after unmounting, especially after a writer was killed before its
pending database rows were saved. The checker makes one directory walk and one
`files` scan. Reports contain `missing_content`, `orphan_content`,
`tombstone_content`, `type_mismatch`, `invalid_path`, `missing_parent`,
`repaired`, and `result`. Category counts describe the state before repair;
`repaired` counts resolved findings. Exit codes are 0 for clean or repaired,
1 for unrepaired inconsistencies, and 2 for an operational error.

Repair removes rows whose content disappeared, inserts orphan entries using
host mode/mtime/uid/gid, corrects type mismatches, removes content under
tombstones, and drops malformed path rows. Missing parents of tombstones are
created where safe. Removal uses directory-relative, no-follow operations;
symlinks are entries, never traversal paths. Repair does not delete an external
file named by a corrupt row. Invalid host UTF-8 names are reported as an error.
Database files, overlay markers, COW/spool staging files and `.ratarmount-sealed`
are excluded. Existing metadata-only chmod/utime rows for inherited content
are valid without a host copy. A `files.path` such as `/lib` is the schema's
mount-relative parent, not a host absolute path.

Unsealed checks record `fsck_at` and `fsck_result` (`ok`, `errors:N`, or
`repaired:N`). Sealed overlays can be checked without modifying any metadata;
`--repair` is refused. A database locked by a mount returns “in use”. Repairs
hold an exclusive SQLite transaction, but host changes and SQLite are not one
atomic transaction: stop direct host writers and rerun after an interrupted
repair. A consistency check does not verify content hashes.

## Seal and verify

```sh
ratarmount overlay seal attempt [--lower prepared] [BASE]
ratarmount overlay verify attempt [--lower prepared] [BASE]
ratarmount diff attempt --strict --hash --include-git-dir
ratarmount overlay unseal attempt --i-know
```

Stop writers and unmount before sealing. BASE defaults to `meta.base_url` and
lower layers default to `meta.lower_layers`; repeated `--lower` values replace
that list in bottom-to-top order. Lowers must themselves be sealed. A legacy
overlay without a recorded base requires explicit BASE. Sealing creates minimal
metadata for such an overlay without inventing a base identity; keep supplying
BASE to verify it.

Seal refuses a database held by another mount (“in use by another ratarmount
process”). It runs fsck without repair under a writer reservation and refuses
inconsistencies with an `overlay fsck --repair` hint. The digest is the canonical
SHA-256 change hash against the composed lower view, with exact bytes, modes,
no excludes, and `.git` included. `--json` prints `layer_digest` and `sealed_at`;
plain output is the digest. Repeating seal prints the recorded digest and exits
0 even if the base is no longer available; use verify to check integrity.

Before chmod, the same transaction records per-path hashes in `seal_rows`,
`sealed_at`, `layer_digest`, and each materialized entry's permission bits in
`overlay_metadata.mode` where no override exists. Thus lookup and directory
listing modes stay unchanged. Seal removes host write bits recursively from
files, directories, and the database, with the overlay root last; it skips
symlinks and never follows them. `.ratarmount-sealed` contains the digest and
is hidden from mounted listings. Sealed layers are accepted by `--lower` and
`diff --strict`; writable mounts with `-w` are refused.

Verify opens the top database immutable and read-only, recomputes the exact
hash and compares both metadata and sentinel. Exit 0 means a match; exit 1
reports differing, added, or removed paths (or a sentinel mismatch); exit 2
means an operational error, including an unsealed overlay. `--json` also returns
`ok`, `recorded`, `computed`, `sentinel_ok`, and `mismatched`. It works on the
read-only tree and detects unindexed host additions as well as changed bytes.

Unseal requires `--i-know` (otherwise exit 2), restores owner write permission
on files and directories, removes the sentinel, clears the seal and per-path
hashes, and records `unsealed_at`. Saved mode overrides stay in place. Host
permissions and SQLite cannot be changed in one transaction: after an interrupted
seal, run unseal, fsck, and seal again. Stop direct host writers during these
commands; chmod is not a security boundary against the owner or root. The seal
covers canonical changes, not timestamps, ownership or xattrs.

## Branching an episode

A harness can fork an attempt at
turn *k* by stopping writers, unmounting, and sealing that attempt. Then each
branch gets its own writable top over the same ordered lower stack:

```sh
fusermount3 -u attempt-mnt
ratarmount overlay fsck attempt-k --repair
ratarmount overlay seal attempt-k
ratarmount --lower prepared --lower attempt-k -w branch-a source.tar branch-a-mnt/
ratarmount --lower prepared --lower attempt-k -w branch-b source.tar branch-b-mnt/
```

The prepared layer must also be sealed. Branches share the saved filesystem
state and copy up only what they modify. Shell state, processes, and runtime
isolation remain the harness's responsibility.

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

Compare an overlay with its composed lower view without mounting it:

```sh
ratarmount diff attempt-overlay source.tar --git -o attempt.patch
ratarmount diff attempt-overlay source.tar --lower prepared --name-status
ratarmount diff attempt-overlay --manifest
ratarmount diff attempt-overlay --hash --normalize strict --json
ratarmount diff attempt-b source.tar --between attempt-a --git
```

The syntax is `ratarmount diff [OPTIONS] OVERLAY_DIR [BASE]`. BASE accepts the
mount factory's archives, committed Git repositories, folders and remote URLs.
A working Git repository compares against its committed tree even when its
working tree is dirty. The old `--base SOURCE` spelling remains a hidden alias;
a positional BASE takes precedence. Without either, `meta.base_url` supplies the
base and a note goes to stderr. Repeat `--lower DIR` in bottom-to-top order, or
omit it to use `meta.lower_layers`. Sealed lowers open immutable; other lowers
open read-only. `--strict` refuses any unsealed top or lower. Without it, unsealed
and legacy overlays produce warnings. Stop writers before comparing: offline
diff refuses a database locked by a mount, and files/SQLite are separate stores.

Choose one output mode (default `--patch`):

| Mode | Output |
|---|---|
| `--patch` | Unified patch, three context lines by default; `-U N` / `--context N` changes that. |
| `--git` | Git headers, blob IDs, executable modes, symlink targets, and forward/reverse literal binary patches. |
| `--manifest` | One JSON object per changed path, byte-sorted. |
| `--hash` | Canonical hash; `--json` includes base/stack identity and comparison options. |
| `--stat` | Per-path insertion/deletion counts, file count and bytes written; supports `--json`. |
| `--name-only` | Changed paths, one per line. |
| `--name-status` | `A`, `M`, `D`, `T` and paths (`written` when added/modified is unknown). |

Manifest, hash and name modes also work without a base. They call present entries
`written` because added versus modified is unknown. Patches, stat and between
comparisons require a base. `-o FILE` writes output to a file. Source-opening
progress and warnings go to stderr. Output is withheld until rendering succeeds,
so a limit failure does not publish a partial patch or truncate an existing output.

The change set comes from `files` and metadata-only `overlay_metadata` mentions,
resolved through the same read-only overlay layers as a mount. Orphan host files
without a database mention do not enter an offline diff. Unchanged copy-ups,
write-then-revert and tombstones of nonexistent lower paths are omitted. Empty
directories appear as `"type":"dir"` in the manifest; Git patches cannot create
empty directories or preserve directory modes. Symlinks are target strings,
never followed. Invalid traversal/NUL rows are corruption errors. The database's
normal absolute **mount-parent** column is allowed; absolute child names are not.

Renames are delete + add by default, including `sandbox diff --git`.
`--detect-renames` opts into deterministic exact-content pairing and `R100` / Git
rename headers. It never changes a manifest or canonical hash. Type changes use
delete + add in patches and `T` in name-status output. Git mode headers preserve
the owner executable bit; other Unix permission changes remain visible in the
manifest. `--ignore-mode` omits mode-only changes and mode fields from canonical
hash rows. Use `git apply --unidiff-zero` for patches generated with `-U 0`.

Patches always preserve exact content bytes. Binary means NUL in the first
8 KiB, so Latin-1 and other non-UTF-8 text remains text. CRLF and missing final
newlines round-trip. Binary unified output says `Binary files … differ`; `--git`
emits literal zlib/base85 sections, never delta sections. Text exceeding
`--max-diff-bytes` per side (default 8 MiB) deliberately uses this binary form.
Large literals stream via a compressed temporary file instead of buffering the
payload. Text hunks retain the existing bounded Myers traceback.

`--exclude GLOB` is repeatable, case-sensitive and applied before content opens
on either side. It supports `*`, `?`, `**`, bracket classes, trailing `/` for a
directory subtree, leading `/` for root anchoring, and slashless patterns at any
depth. Overlay internal names are always excluded; `.git` components are excluded
unless `--include-git-dir` is given. Negated re-inclusion rules are not supported.

`--max-files N` caps changed paths / manifest rows. `--max-patch-bytes N` caps
rendered patch output **and** imposes a conservative per-payload input-work budget:
a mentioned regular file larger than N fails before hashing or compression,
including one that might compress below N or prove unchanged. This extra check
makes an accidental 10 GiB write fail promptly. Manifest/hash modes ignore the
patch budget and stream content hashing with bounded buffers. The change-path
list still takes memory proportional to the number of mentioned paths.

Manifest rows contain `path`, `status`, `type`, and, for present entries, `mode`,
`size`, `hash` (files and symlinks), `target` (symlinks) and `layer:"top"`.
A base-less metadata-only write omits unknown size and content hash.
Existing lower entries contribute `base_hash` and `base_layer` (`base` or
`lower:N`, numbered from one). Deleted rows have no new content hash. Modes are
six-digit octal. A changed mount-root mode uses the empty relative path.
Byte-string JSON writers emit `path_b64` / `target_b64` in place
of non-UTF-8 strings. Overlay paths currently use UTF-8 TEXT and MountSource
strings, so arbitrary byte paths remain unsupported; the base64 writer is tested
with synthetic byte paths. The daemon similarly returns `patch_b64` instead of
`patch` for non-UTF-8 patch bytes; UTF-8 responses retain `{"patch":"…"}`.

Canonical hashing uses `--algo sha256|blake3` (default SHA-256). For every changed
path in byte order after exclusions, hash this row into the final digest:

```text
path NUL status NUL type NUL mode-or-empty NUL content-hash-or-empty NUL
```

Content hashes include the algorithm prefix. A deletion uses the old type/mode
and an empty new-content hash; directories also have no content hash. The base
hash, provenance, timestamps and rendered patch text are excluded. Both content
and row hashing use the chosen algorithm. `Change::row_hash` exposes the same row
encoding for verification tools to identify mismatching paths.

`--normalize exact` hashes bytes as written. `strict` converts CRLF to LF, strips
trailing ASCII whitespace per line and ignores one final newline; it is suitable
for grading. `loose` additionally removes blank lines and warns once on stderr:
it is for analysis only, because blank lines can affect tests. Symlink targets
and binary data always use exact bytes. Normalization applies only to hash and
manifest comparisons; normalized-equivalent edits disappear from those change
sets. Patches always compare exact bytes. SHA-256 hashes supplied by a lower
view's `user.hash.sha256` xattr are preferred for exact SHA-256 comparisons.
Materialized lower payloads are rehashed because their inherited base xattr may
be stale.

The empty change-set SHA-256 constant (SHA-256 of the empty stream) is:

```text
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

`--hash --json` returns `patch`, `base`, `stack`, `files`, `normalize`, `excludes`,
`algo`, and `sealed`. Base and stack are recorded metadata (or null); a missing
stack digest is derived from the recorded base digest and ordered lower digests.
`--between OTHER_DIR` compares OTHER's composed tree to OVERLAY_DIR's tree using
the union of both overlays' mentions. Both must record the same `stack_digest`.
For two legacy overlays, an explicit BASE and `--lower` stack are required and
used for both, with a warning. Identical trees produce the empty constant.

Exit status is **0** for no changes, **1** for changes, **2** for errors and **3**
for size/file limits. Hash and manifest modes always exit **0** on success.
Harnesses consuming patch/name/stat modes should accept both 0 and 1.

## Ownership and container mounts

`-o uid=12345,gid=23456,umask=027` overrides reported Unix ownership and
masks permission bits with `mode & ~umask`, including directories and symlinks.
The options apply to FUSE, NFS v3/v4, 9P and SFTP attributes, including overlay
files. Omit an option to retain its original value. IDs are decimal; umask is
octal (`000` through `777`). These presentation options do not change stored ownership or creation
credentials; chmod and timestamp updates use the overlay metadata behavior above. SMB and WebDAV expose no Unix uid/gid fields.
This mapping can avoid Git's “dubious ownership” check when a container uses a
different user; see [Git mounts](git-mounts.md).

`--sandbox` expands to `-o allow_other,noatime`, caller uid/gid (using
`SUDO_UID` / `SUDO_GID` when present), and a RAM overlay unless `-w` supplies
an explicit overlay. Explicit `-o uid=...,gid=...` overrides the caller IDs.
Passthrough retains its `auto` default; an explicit `--passthrough` is honored.
The effective options, overlay, quota and passthrough mode are logged at info
level (`-d 2`). This preset configures filesystem access; container process and
network isolation still come from the container runtime.

For a non-root FUSE mount with `allow_other`, `/etc/fuse.conf` must contain
this exact uncommented line:

```text
user_allow_other
```

Ratarmount checks this before mounting and explains the required line if it is
missing. `allow_other` lets other local users access the mount; choose the
reported permissions and mountpoint access accordingly.

For example, for a host caller with uid/gid 1000, run the mount in one
terminal, then bind it into a container (adjust IDs for your host and container
user namespace):

```sh
mkdir -p mnt
ratarmount -f --sandbox --overlay-tmpfs=2G \
  -o uid=1000,gid=1000,umask=077 source.tar mnt/
# In another terminal (the image must contain the tools you want):
podman run --rm --userns=keep-id --user 1000:1000 -v "$PWD/mnt:/workspace:rw" \
  -w /workspace docker.io/library/debian:stable-slim sh
# Docker: omit --userns=keep-id; retain --user, -v and -w.
```

## Throwaway RAM overlays

`--overlay-tmpfs[=SIZE]` creates a private mode-0700 directory on Linux
`/dev/shm`. If unavailable, it tries `$XDG_RUNTIME_DIR`, verifying that the
selected filesystem is tmpfs. It fails if neither offers RAM storage. macOS
and other platforms reject this option with a clear error; `-w :temp:` remains
the disk-backed alternative. It conflicts with explicit `-w` and offline
`--commit-overlay`.

Use `--overlay-tmpfs=2G` (with `=`) so the optional size cannot consume the
archive argument. SIZE uses the same units and shared logical-content quota
as `--overlay-quota`; when both are supplied, the smaller cap wins. All
frontends enforce the cap. It does not reserve RAM or limit SQLite metadata,
filesystem overhead, or other processes using the shared tmpfs. Without a
size or an explicit quota, RAM use has no application cap and startup warns.

The directory is removed on unmount, normal exit, SIGINT and SIGTERM, after
serving and overlay shutdown. A daemon parent leaves cleanup to its serving
child. SIGKILL and machine failure cannot run cleanup; remove abandoned
`ratarmount-write-overlay.*` directories from the RAM filesystem after checking
that no mount still uses them.

Changes are discarded by default. `--commit-overlay-on-exit` or
`--commit-overlay-interval` requires the explicit additional
`--overlay-tmpfs-allow-commit` flag with `--overlay-tmpfs`; this deliberately
allows changes to reach the base archive and retains the existing supported
live-commit archive formats. Temporary overlay data is removed after commit.

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

## Sandbox supervisor API

The Linux supervisor manages a fleet of independent attempts without a Python
binding. Each attempt is a foreground ratarmount process mounting the registered
base directly, with its own writable overlay and FUSE request worker. The base
itself is never mounted by the supervisor.

```sh
mkdir -m 700 -p "$HOME/.local/state/ratarmount-sandboxes"
ratarmount sandbox daemon --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock" \
  --state-dir "$HOME/.local/state/ratarmount-sandboxes" --max-attempts 256
# In another terminal:
ratarmount sandbox create-base --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock" \
  task /srv/repos/project.git@0123456789abcdef0123456789abcdef01234567 \
  --options '{"git_synthetic_head":true,"readonly_globs":["tests/**"],"quota":2147483648}'
ratarmount sandbox new --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock" task --count 8
ratarmount sandbox list --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock" --base task
ratarmount sandbox diff --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock" ATTEMPT_ID --git
ratarmount sandbox stats --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock" ATTEMPT_ID
ratarmount sandbox destroy --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock" ATTEMPT_ID
ratarmount sandbox destroy --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock" --base task
ratarmount sandbox shutdown --socket "$XDG_RUNTIME_DIR/ratarmount-sandbox.sock"
```

Client commands print the server's JSON response envelope, including server
errors (exit 1). Local option and transport errors go to stderr.
`new` also accepts `--overlay disk|tmpfs`, `--quota SIZE`, and repeated
`--readonly GLOBS`. `--socket` works before or after the subcommand.
`daemon --timeout SECONDS` sets base-validation and batch-readiness deadlines
(default 120, range 1–3600). The foreground daemon exits on `shutdown`, SIGINT
or SIGTERM after destroying its attempts. Base definitions and warmed indexes
remain available for the next daemon run.

The state directory must be owned by the daemon user, mode 0700, and must not
be a symlink. Its parent must already exist. Exclusive locks protect both the
state directory and socket address. Socket permissions are 0600 from creation;
existing symlinks, regular files, foreign-owned sockets, and active listeners
are refused. An owned stale socket may be replaced. The socket parent must be
owned by the caller and protected against other users replacing entries (a
root-owned sticky directory such as `/tmp` is also accepted). Lock files remain
on disk; flock, not file existence, indicates ownership. Use a local filesystem
for state and locks.

### Protocol version 1

Transport is UTF-8 JSON lines over AF_UNIX/SOCK_STREAM. Every complete request
line receives one response line, in order on its connection. There are no
notifications or unsolicited output. Multiple lines per connection are allowed;
the CLI and Python client use one connection per call. Unknown operations,
unknown fields (including option keys), missing fields, and malformed JSON
are errors. Each request includes integer `version: 1` and an `op` string:

```json
{"version":1,"op":"create_base","name":"task","source":"/srv/base.tar","options":{"quota":2147483648}}
{"version":1,"op":"new","base":"task","count":8,"overlay":"disk"}
{"version":1,"op":"list","base":"task"}
{"version":1,"op":"diff","id":"attempt-ABC123","git":true}
{"version":1,"op":"stats","id":"attempt-ABC123"}
{"version":1,"op":"destroy","id":"attempt-ABC123"}
{"version":1,"op":"destroy","base":"task"}
{"version":1,"op":"shutdown"}
```

| Operation | Fields and result |
| --- | --- |
| `create_base` | Required `name`, `source`; optional `options` object. Validates by opening/indexing without mounting, then durably records and returns `{name,source,options}`. An existing name returns `already_exists`. |
| `new` | Required `base`; `count` defaults to 1, `overlay` to `"disk"`; optional integer `quota` in bytes and `readonly_globs` string array. Returns an array of attempts only after all mounts are ready. |
| `list` | Optional `base` filters the attempt array. Status is `"ready"` or `"crashed"` (`"starting"` is internal to setup). An unknown base is an error. |
| `diff` | Required `id`; boolean `git` defaults to false. Returns `{"patch":"..."}` using the in-process diff renderer and the same composed base, including recursive sources and binds. |
| `stats` | Required `id`. Returns the same integer object as `overlay-stats --json`. |
| `destroy` | Exactly one of `id` or `base`. Returns `{"destroyed":true}`. A base selector destroys its attempts, retaining its registered definition/indexes. Unknown IDs return `not_found`. |
| `shutdown` | No additional fields. Destroys all attempts, returns `{"shutdown":true}`, and stops the daemon. If cleanup fails, returns an error and stays available for retry. |

An attempt is `{id,base,path,overlay_dir,status}`. Paths are absolute host paths;
`path` is the writable merged mount and `overlay_dir` contains changed content
and the overlay database. IDs are unique generated directory names. Base names
start with an ASCII letter or digit, followed by letters, digits, `.`, `_` or
`-`, at most 128 characters. Source strings accept ordinary ratarmount inputs,
including Git `repo.git@REV`, OCI URLs and restic snapshots. Relative local
sources and bind sources resolve against the daemon's working directory at
registration and are stored as absolute paths. Pin Git revisions, container
digests and snapshot IDs: registration does not freeze mutable folders or refs.

`options` accepts these keys (all optional):

| Key | Type / default |
| --- | --- |
| `git_synthetic_head` | boolean, false; history-free synthetic Git metadata |
| `recursive` | boolean, false |
| `uid`, `gid` | unsigned 32-bit integers; default daemon effective IDs |
| `umask` | octal string, e.g. `"027"`; default no mask override |
| `readonly_globs` | array of glob strings, default `[]` |
| `quota` | unsigned integer logical bytes, default unlimited |
| `passthrough` | `"auto"`, `"on"` or `"off"`; default `"auto"` |
| `binds` | array of `/MOUNTPATH=SOURCE` strings, default `[]` |
| `allow_other` | boolean, false; true requires the FUSE configuration described above |

Attempts always use `noatime` and omit file-version virtual directories. New
attempt read-only rules append to base rules; quotas use the smaller of the
base and attempt caps. A request cannot loosen a base policy. Options are typed;
there is no arbitrary shell command or mount-argument passthrough. Remote
credentials come from the daemon's inherited environment/backend configuration.
State and logs may contain source URLs; prefer credential-free URLs.

Response envelopes are:

```json
{"version":1,"ok":true,"result":[{"id":"attempt-ABC123","base":"task","path":"/state/attempts/attempt-ABC123/mnt","overlay_dir":"/state/attempts/attempt-ABC123/overlay","status":"ready"}]}
{"version":1,"ok":false,"error":{"code":"capacity","message":"count must be positive and fit --max-attempts (including crashed attempts)"}}
```

Stable error codes include `invalid_request`, `unsupported_version`,
`not_found`, `already_exists`, `capacity`, `in_use`, `unsafe_path`,
`base_open_failed`, `mount_failed`, `timeout`, `unmount_failed`, `diff_failed`,
`stats_failed`, `response_too_large`, `unsupported`, and `io`. Messages provide
context and may change. Validation logs live in `indexes/BASE/prepare.log`;
attempt diagnostics live in `attempts/ID/mount.log` until destroy. Failed-batch
errors include a bounded excerpt of the failing mount's log when available.

### Lifetime, concurrency and recovery

Registration warms `state-dir/indexes/BASE` with `--no-mount`; subsequent
attempts share that cache, including source-specific indexes for binds. No
per-attempt archive copy or Git worktree is made. Warm setup still includes
process startup, opening the cached index and mounting FUSE; it is not promised
to take zero time. The ignored 64-attempt test reports measured setup/teardown
milliseconds per attempt on the orchestrator's host.

All children in a batch start before readiness is polled. `--max-attempts`
(default 256, maximum 4096) caps total retained attempts across bases, including
crashed attempts, until destroy. Mutating requests and diff/stats execute
serially; separate clients may connect concurrently. Up to 32 connections are
retained. Incomplete/idle connections expire after 30 seconds, request lines
are limited to 1 MiB, response lines to 64 MiB, and stalled response writes to
5 seconds. Diff/source reads use the existing backend timeouts; the batch
readiness timeout does not interrupt an in-process diff. Stop agent writers
before diff/stats for a consistent result: files and SQLite are separate
snapshots, and these calls do not pause applications. Live attempts return
in-memory deletion records over a private child inspection socket, avoiding
the overlay database's exclusive lock (including deletions awaiting SQL retry).
The supervisor renders the patch and scans usage in-process. For a crashed
attempt, diff/stats use its offline database; an unrecoverable database returns
a structured error. State paths must leave room within the platform's Unix
socket path limit for `attempts/ID/inspect.sock`: the full path must be shorter
than 104 bytes on macOS or 108 bytes on Linux. Overlong paths return an error
with the native limit and the offending path. Use a short private state directory
under `$XDG_RUNTIME_DIR` or `/tmp` when the usual state/temp directory is too long;
socket addresses are not relocated automatically.

A failed/timed-out batch rolls back its own children and directories without
affecting previous attempts. If unmount fails, directories and attempt records
are retained, and the error names the IDs for inspection/retry. A crashed mount
is marked `crashed`; siblings and the supervisor continue. Its disk/RAM overlay
is retained for inspection until destroy. Destroy tries normal unmount, then
lazy unmount, and stops/reaps the child if needed. It never deletes backing
content while a mount remains attached. Shutdown and destroy-by-base can
partially succeed if one cleanup fails; `list` reports what remains.

RAM overlays use Linux `/dev/shm`, falling back to verified tmpfs at
`$XDG_RUNTIME_DIR`. The supervisor owns a private directory there and passes
its explicit path to each mount with `-w`, using the same tmpfs verification
and logical quota semantics as `--overlay-tmpfs`. Owning the directory here
keeps `overlay_dir` known and permits cleanup after child SIGKILL. No RAM is
reserved; set a quota. State records the RAM location for restart cleanup.

After daemon restart, registered bases and caches survive; **all abandoned
attempts are unmounted and discarded**, including disk overlays. They are never
re-adopted. Cleanup must succeed before requests are served. Linux children
receive SIGKILL if their supervisor dies (including during startup); restart
then removes disconnected mounts and directories. Persisted process IDs are
never used to kill processes. An exclusive state lock prevents a second daemon
from reconciling an active daemon's attempts. This initial supervisor is Linux
only; other platforms can use ordinary mounts and offline diff/stats.

A lost connection is not cancellation. A mutation may finish after the client
times out; clients must reconcile with `list` before retrying `new`. There is
no request deduplication or automatic retry. Normal shutdown discards attempts;
collect patches first. Registered bases currently have no API to unregister
or evict their index cache; remove those state files only with the daemon
stopped and no attempts left.

### Python client

Add `clients/python` to `PYTHONPATH` or copy
`clients/python/ratarmount_sandbox.py` into the harness. It uses only the Python
standard library (Python 3.9+), with no extension module or runtime dependency:

```python
from ratarmount_sandbox import RatarmountSandbox

with RatarmountSandbox("/run/user/1000/ratarmount-sandbox.sock") as client:
    attempts = client.new("task", count=8, overlay="disk")
    for attempt in attempts:
        print(attempt.path, attempt.overlay_dir)
        # Run and stop the agent before exporting:
        patch = attempt.diff(git=True)
        usage = attempt.stats()
# All attempts created through this client are destroyed, even on exceptions.
```

`create_base(name, source, **options)`, `list(base=None)`,
`destroy(id=... | base=...)`, and `shutdown()` expose the other operations.
An individual `Attempt` is also a context manager; `destroy()` is locally
idempotent. A client context destroys only attempts created through that
client; it does not shut down the shared daemon or destroy attempts returned
by `list`. `SandboxError.code` exposes the structured error code. Transport
errors raise `OSError`/`TimeoutError`; no mutations are retried automatically.
The default client I/O timeout is 3600 seconds, configurable on construction.
See the [SWE-bench recipe](recipes/swe-bench-sandboxes.md).

## Journal

`--journal FILE` appends a JSONL operation journal on FUSE mounts, with or without
`-w`. Put the file outside both the mountpoint and write-overlay directory;
existing symlink aliases into either are rejected. A writable overlay records
the resolved path in its `journal_path` metadata. This operation journal is
separate from the archive append-commit journal.

```sh
ratarmount -w attempt --journal attempt.jsonl \
  --journal-exclude '.git/**' --journal-exclude 'blib/**' source.tar mnt
ratarmount journal mark mnt 'turn 1'
ratarmount journal summarize attempt.jsonl --json
ratarmount journal summarize attempt.jsonl --since-mark 'turn 1' --until-mark 'turn 2'
```

Each mount appends a version-1 header containing `mount`, `base_digest`,
`stack_digest`, `overlay`, UTC RFC 3339 `t0`, and `clock: "monotonic_ns"`.
Subsequent `ts` values are monotonic nanoseconds since that header. Paths are
mount-relative, without a leading slash; the root is `""`. JSON writers use
`path_b64` for invalid UTF-8 bytes, although the FUSE frontend currently rejects
such names. `open` includes access flags (`r`, `w`, `rw`), the request's `pid`,
`uid`, `gid`, best-effort Linux `/proc/PID/comm`, and `layer` (`base`, `lower:N`,
or `top`). The process-name cache is bounded to 1024 PIDs.

Successful creates, mkdirs, unlinks, rmdirs, renames (with `to`), symlinks,
truncates, and chmods are recorded as they happen. The first successful readdir
on each directory handle records its child-entry count (excluding `.` and
`..`). Lookups and getattr/stat are omitted. Failed mutations returning
`EROFS`, `EDQUOT`, or `ENOSPC` produce `denied` records with the attempted `what`
and numeric `errno`; rule observers and callback errors are deduplicated.
Denials from non-FUSE callers of the same rule observer have PID/UID/GID zero.

Reads and writes aggregate per open handle and emit on RELEASE, or at unmount
for outstanding handles. `bytes` counts bytes actually returned or written,
including repeated accesses; `count` counts successful I/O requests, including EOF. `ranges`
merges adjacent and overlapping `[offset, length]` pairs. At most 64 ranges are
retained; additional disjoint ranges set `ranges_truncated: true` while byte
counts remain complete. `--journal-reads first` retains only the first non-empty
read range per handle; byte and request counts still include all reads. The
default is `--journal-reads all`. `first_ts` preserves the first successful I/O timestamp
when handles release out of order. Reads/writes retain the opened path and
layer even after rename or unlink.

`--journal-exclude GLOB` is repeatable and accepts the same comma-separated,
root-anchored patterns as `--overlay-readonly`. It omits matching paths and
renames with a matching endpoint. Status counters still include excluded
activity. Marks are never excluded.

The writer uses a bounded 1024-record queue and flushes buffered output at least
every 100 ms while processing. A full queue blocks request processing until
space is available; records are not dropped to relieve pressure. Unmount joins
the writer and flushes pending records; `--journal-sync` also fsyncs the file.
Write failures appear in the daemon log and `.stats`'s `journal_error`; mark
requests then fail with EIO and unmount reports the failure. Abrupt termination
can lose buffered records. Summaries tolerate an incomplete final record and
an incomplete record immediately before a subsequent mount header.

`summarize` streams the input, keeping a per-path table and mark-to-path sets.
It reports first read/write timestamps, bytes, read request counts, layer and
process-name set; lists `files_read`, `files_read_then_written`, and
`files_written_blind`; and groups `reads_by_mark` by label. The leading `""`
bucket contains reads released before the first mark. Repeated labels combine
into one bucket. `--since-mark` starts after the first matching mark;
`--until-mark` stops before the first match after the start. Missing labels are
errors. Because read records emit at RELEASE, a handle spanning marks is
assigned to its release bucket; close file handles before marking a turn when
exact turn attribution matters. Byte-path fallback keys appear as
`path_b64:BASE64` in the summary. Both `journal` commands exit 0 on success and
2 on argument, input, or I/O errors.

The journal describes operations reaching FUSE. Kernel page-cache hits, mmap
accesses and accesses through other export protocols do not produce read
callbacks. Passthrough is disabled when journaling. Mounts without `-w` permit root control requests at the kernel boundary; file
mutations still return EROFS in the frontend. These mounts consequently report
a writable kernel mount flag even though their data is read-only. Explicit
`-o ro` also prevents control writes (the kernel returns EROFS before the root
control handler, including when journaling is off).

Run `RATARMOUNT=target/release/ratarmount benchmarks/journal-overhead.sh` on a
machine with `/dev/fuse`, Python 3, `fusermount3`, `make`, and a C compiler. It
alternates fresh overlay mounts with and without journaling, runs three
build/test loops per sample, and prints median workload overhead. `RUNS`
(default 6) and `JOBS` (default 4) tune the run. The under-3% target is not a CI
gate; absent tools yield an explicit skip (exit 77).

## Control and status xattrs

The mount root exposes these synthetic read attributes, including on mounts
without a write overlay:

| Xattr | Value |
| --- | --- |
| `user.ratarmount.base_digest` | Recorded base identity, or empty string |
| `user.ratarmount.stack_digest` | Recorded stack identity, or empty string |
| `user.ratarmount.sealed` | `1` when the supplied metadata is sealed, otherwise `0` |
| `user.ratarmount.layers` | JSON `lower_layers`, or `[]` without metadata |
| `user.ratarmount.journal` | Resolved active journal path, or empty string |
| `user.ratarmount.stats` | JSON counters described below |

`stats` contains `bytes_read`, `bytes_written`, `files_touched` (distinct paths
observed), `overlay_bytes` (quota usage, or null without a quota policy), `ops`
(counts by journal operation), `erofs_denied`, and `journal_error` (null or an
error string). Byte counters update during I/O; aggregated read/write operation
counts update on RELEASE. All counters are for this mount's lifetime.

Set `user.ratarmount.mark` on the root to append a UTF-8 label of at most 4096
bytes. `ratarmount journal mark MOUNT LABEL` performs this same xattr call.
Invalid labels return EINVAL. Without `--journal`, marks return ENOTSUP on a
writable mount and EROFS on a read-only one (a read-only mount without
`--journal` stays kernel `ro`). Other
`user.ratarmount.*` root writes and removals return EPERM. These controls are
intercepted before the overlay's xattr implementation. The existing
`user.ratarmount.git.commit` read attribute continues to come from the source.

```sh
getfattr -n user.ratarmount.stats mnt
getfattr -n user.ratarmount.base_digest mnt
python3 -c 'import os; os.setxattr("mnt", "user.ratarmount.mark", b"turn 2")'
```

## Bundles

Pack a sealed overlay into one portable, seekable `.tar.zst` archive:

```bash
ratarmount overlay seal attempt
ratarmount overlay pack attempt attempt.tar.zst \
  --include-journal attempt-journal.jsonl --include-index
ratarmount overlay unpack attempt.tar.zst restored
ratarmount overlay verify restored
```

`pack DIR BUNDLE [--lower LAYER …] [BASE]` uses the recorded base URL and lower
layers unless overridden. It refuses unsealed overlays and existing output
files, publishes the completed bundle atomically, and prints `layer_digest`.
Packing the same layer with the same optional inputs produces identical bytes.
Paths are sorted, archive uid/gid are zero, and layer modes, mtimes and symlink
targets are preserved. File content is streamed; symlinks are never followed.
In-use markers and COW/spool temporary files are excluded.

The ordinary TAR layout is:

```text
layer/                         # overlay content and directories
layer/.ratarmount.overlay.sqlite
layer/.ratarmount-sealed
manifest.jsonl                 # exact changes against the composed stack
meta.json                      # all overlay meta keys, as JSON string values
journal.jsonl                  # with --include-journal FILE
journal-summary.json           # journal summarize output
index/BASE.index.sqlite        # with --include-index, if an adjacent sidecar exists
```

The index is the local base archive's adjacent `BASE.index.sqlite` sidecar;
remote and directory bases do not contribute an index. Unpacking restores only
`layer/`. To use a shipped index on another machine, copy it beside the matching
base archive under its original sidecar name. A bundle carries layer changes,
not the base archive or its lower layers.

`unpack BUNDLE DIR` accepts a nonexistent or empty directory, restores sealed
read-only permissions, checks that the database opens read-only and immutable,
and compares the seal sentinel with the recorded digest. It also recomputes the
seal against the recorded stack when that base and its lowers are reachable.
When they are absent it reports that only the database and sentinel were
checked; run `overlay verify` after restoring the stack to validate content.
Exit codes are 0 for a match, 1 for a digest/content mismatch, and 2 for invalid
input or an operational error. Unsafe archive paths, duplicate entries,
hardlinks, device entries and writes through symlink components are refused.
Extraction uses a private staging directory and publishes the result by rename.

A bundle can be mounted directly as an ordinary archive, or used as a lower:

```bash
ratarmount attempt.tar.zst inspect-mnt
# inspect-mnt contains layer/, manifest.jsonl and meta.json
ratarmount --lower attempt.tar.zst -w next-attempt base.tar.zst work-mnt
```

For `--lower`, the metadata is read through the archive session API, then the
layer is unpacked once into
`$XDG_CACHE_HOME/ratarmount/layers/<layer_digest without sha256:>` (default:
`~/.cache/ratarmount/layers/`). Publication is atomic. Later mounts reuse the
cached sealed directory after checking its immutable database and sentinel;
a damaged cache entry is refused. Directory lowers continue to work normally.

## Overlay import

`ratarmount overlay import` builds a new write overlay from a unified or Git
patch against a base and optional lower overlays. It uses the same write APIs
and creation metadata as a mounted write session; no mount or external patch
program is needed.

```sh
ratarmount diff attempt base.tar.zst --git -o attempt.patch
ratarmount overlay import --mtime 1700000000 attempt.patch replay base.tar.zst
cat attempt.patch | ratarmount overlay import --lower prepared - replay2 base.tar.zst
ratarmount diff replay base.tar.zst --hash --normalize exact
```

The destination must not exist or must be an empty directory. `--lower DIR` is
repeatable, bottom to top; unsealed lower layers require
`--allow-unsealed-lower`. The base positional accepts the same local archive,
folder, committed Git source and remote source forms as other offline overlay
commands. Import pins Git references before opening the source and records the
base identity and lower-layer stack identity.

Accepted patches include `git diff --binary` literal sections (Git base85 plus
zlib), additions, deletions, executable mode changes, symlinks, rename/copy
headers and ordinary unified hunks. Rename means copy the preimage to the new
name, apply its hunks, then delete the old name. Copy keeps the old name.
Reverse binary literals are validated and ignored. Binary delta sections and
`Binary files … differ` without content are errors naming the affected file;
regenerate these as literal patches, for example with `ratarmount diff --git`.
Index object IDs are accepted without verification.

Hunks require exact context bytes. Their location may move; context is never
trimmed to force a match. CRLF, Latin-1 file content and missing final newlines
are preserved. Git C-quoted names are decoded, and header paths have one
leading component removed (`-p1`); plain `diff -u` headers may include a tab
followed by a timestamp. Both old and new names are validated. Absolute paths,
NUL, empty, `.` or `..` components, reserved overlay bookkeeping names, and
symlink parents in either the lower view or the new overlay are refused.
Symlink targets are stored as link data, never followed. Paths and symlink
targets must be UTF-8 because the workspace's mount and overlay APIs use
strings; non-UTF-8 names are refused, rather than changed silently.

If a hunk fails, the default is to abort and remove the partial overlay.
`--reject` keeps that file's original lower content and writes only its failed
hunks to `PATH.rej`, while applying other files. Later sections for an already
rejected file cannot replace its original content. Import exits 0 on success, 1 when hunks
were rejected with `--reject`, and 2 on invalid input or I/O errors. A preexisting
nonempty destination is left intact.

`--mtime now` is the default. An explicit epoch timestamp (including fractional
or negative seconds) is applied after content writes to files, symlinks and
reject files. It does not alter tombstones. Import seals by default after
closing the writer and prints the layer digest. `--no-seal` leaves the overlay
writable. `--json` prints `{ "overlay": "…", "files": N, "rejected": N,
"layer_digest": "…" }`; the digest is null with `--no-seal`. `files` counts
successfully applied distinct paths (both sides of renames), excluding reject
files and rejected originals.

`--max-patch-bytes N` defaults to 268435456 (256 MiB). It bounds input bytes,
the total retained decoded literals, each reverse literal, and each file's
preimage/postimage. Import buffers the bounded patch and one file's text at a
time; increase the limit explicitly for larger patches.

Git/unified patches cannot represent empty directories, directory metadata or
extended attributes. Empty directories therefore do not round-trip, and Git
patches project regular-file permissions to 0644/0755. Exact canonical hashes
round-trip for representable changes with those modes; use manifests or packed
overlays when the full directory/mode/xattr state is needed.
