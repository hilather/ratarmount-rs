# Agent sandboxes and grading

Build a snapshot once, share a sealed prepared layer, and give each attempt its
own writable top. Seal the result, inspect its changes, grade it against the
same stack, and pack the layer for transport. Ordinary overlay writes leave
the base unchanged. The [SWE-bench recipe](recipes/swe-bench-sandboxes.md)
shows a larger harness; the [supervisor API](#sandbox-supervisor-api) manages
fleets of attempts.

## Worked example: snapshot to graded bundle

This small episode runs entirely offline: patch import supplies the edits that
an agent or build would normally make through a writable mount. It needs Git,
Python 3 and a built `ratarmount` on PATH, but no FUSE device or container runtime.
Use a fresh scratch directory; all generated overlays stay outside the Git base.

```sh
mkdir sandbox-example
cd sandbox-example
git init -q repo
printf 'pending\n' > repo/answer.txt
git -C repo add answer.txt
git -C repo -c user.name=Example -c user.email=example@example.invalid commit -qm base

# Snapshot the committed tree and its mount index.
ratarmount snapshot "git://$(pwd)/repo#HEAD" base.tar.zst --with-index --json

# Prepare shared content once, then seal it.
cat > prepared.patch <<'PATCH'
diff --git a/prepared.txt b/prepared.txt
new file mode 100644
--- /dev/null
+++ b/prepared.txt
@@ -0,0 +1 @@
+shared build output
PATCH
ratarmount overlay import --no-seal prepared.patch prepared base.tar.zst
ratarmount overlay seal prepared

# The attempt changes only its answer, inheriting prepared.txt from the lower.
cat > attempt.patch <<'PATCH'
diff --git a/answer.txt b/answer.txt
--- a/answer.txt
+++ b/answer.txt
@@ -1 +1 @@
-pending
+42
PATCH
ratarmount overlay import --no-seal --lower prepared attempt.patch attempt base.tar.zst
ratarmount overlay fsck attempt --repair
ratarmount overlay seal attempt
ratarmount overlay verify attempt

# Inspect exact changes and record a grading cache key (stack + strict patch).
ratarmount diff attempt --manifest > attempt.manifest.jsonl
ratarmount diff attempt --hash --normalize strict --json > grade-key.json

# Grade this toy task against its known answer without materializing the tree.
python3 - <<'GRADE'
import hashlib, json
from pathlib import Path
rows = [json.loads(line) for line in Path('attempt.manifest.jsonl').read_text().splitlines()]
assert len(rows) == 1 and rows[0]['path'] == 'answer.txt'
assert rows[0]['hash'] == 'sha256:' + hashlib.sha256(b'42\n').hexdigest()
print('grade: pass')
GRADE

ratarmount overlay pack attempt attempt.tar.zst --include-index
ratarmount overlay unpack attempt.tar.zst restored
ratarmount overlay verify restored
```

The manifest contains only `answer.txt`; shared preparation does not pollute the
attempt's change set. For real tasks, run the test suite on the composed tree
with [`sandbox run`](#sandbox-run-one-command-in-a-container), or mount
`ratarmount --lower prepared -w attempt base.tar.zst mnt` before sealing.
Use a fresh top for each attempt. Store both `stack` and `patch` from
`grade-key.json` in a grade-cache key, together with the grader/version and its
options; the patch hash alone does not identify the environment.

The remaining sections describe offline commands and mount controls. Mount
examples require FUSE; container examples also require the stated runtime.

## Overlay metadata

New write overlays record their base identity in the `meta` table of
`.ratarmount.overlay.sqlite`. Inspect it offline, without mounting or modifying
the overlay:

```bash
ratarmount overlay info ./attempt
ratarmount overlay info ./attempt --json
ratarmount -w ./attempt --base-digest "$KNOWN_BASE_DIGEST" snapshot.tar mnt/
ratarmount -w ./throwaway --base-digest none snapshot.tar mnt/
```

Set `KNOWN_BASE_DIGEST` to the snapshot's known `sha256:` identity (64 hex
digits) before using the supplied-digest example.

The JSON object contains every stored metadata key (string values, including
JSON-encoded `lower_layers`), plus the numeric `overlay-stats` fields
`bytes_in_overlay`, `files_present`, `files_deleted`, `directories_created`, and
`symlinks`. It also contains `tombstone_count` and the booleans `legacy`,
`files_dir_writable`, and `db_opens_read_only`. Overlay files live directly in
the overlay directory, so its permissions determine `files_dir_writable`.
Success exits 0. Missing or damaged databases fail without being created or
repaired. A mounted overlay's exclusive database lock is reported as "in use"
(a foreground `-f` mount; a daemonized mount holds no lock, #183).

| Key | Meaning |
|---|---|
| `format_version` | `2` for new overlays; `1` for migrated legacy overlays. A value above `2` is refused by every reader (`overlay format_version N is newer than this ratarmount supports (2); upgrade ratarmount`); new keys are additive within version 2 and are accepted |
| `ratarmount_version` | Creator's version |
| `created_at` | Creation time, RFC 3339 UTC |
| `base_url` | Original base positional, with credentials removed: remote URLs lose userinfo, query and fragment (`https://user:pw@h/b.tar?sig=x` is stored as `https://h/b.tar`), a magnet URI keeps only `xt` and `dn`, and local paths and `git:///` URLs are unchanged. A remote base recorded this way cannot be reopened by `seal`, `verify`, `pack` or `diff` from the overlay alone: pass BASE explicitly |
| `base_digest` | `sha256:<hex>`, `git-tree:<sha>`, `weak:<hex>` (also the default for a directory base), or `none`; empty while `pending` |
| `base_digest_kind` | `strong`, `git-tree`, `weak`, `pending`, or `none` |
| `base_digest_source` | `computed` or `supplied` (absent for `none`) |
| `base_weak_digest`, `base_weak_excludes` | Directory bases: the weak manifest digest (also recorded beside a supplied strong digest) and the JSON array of base-relative paths left out of it |
| `base_size`, `base_mtime_ns` | Local archive size and modification time used for cheap remount checks |
| `base_git_tree` | Selected Git tree, also retained when a SHA-256 digest was supplied |
| `base_remote_token` | Available remote validators, or known multi-source inputs (each redacted like `base_url`) |
| `lower_layers` | JSON array, bottom to top, of `{path, layer_digest, sealed_at}` records; empty for an ordinary mount |
| `stack_digest` | SHA-256 of the base digest and ordered lower-layer digests, each followed by a newline |
| `base_mismatch_forced_at` | Last explicit override of a failed base check, RFC 3339 UTC |
| `sealed_at`, `layer_digest` | Seal time and exact canonical change hash against the recorded stack; absent while writable |
| `journal_path` | Last resolved operation-journal path |
| `fsck_at`, `fsck_result` | Last consistency-check time and `ok`, `errors:N`, or `repaired:N` |
| `readonly_rules` | JSON object containing `readonly` and `allow` pattern arrays |
| `stack_mismatch_forced_at` | Last explicit lower-stack override, RFC 3339 UTC |
| `base_committed_at` | Time of the last successful base-archive commit |
| `unsealed_at` | Last explicit unseal time |

Every command below includes an `Exit status:` block and examples in its long
`--help`. Offline command exit codes:

| Command | Exit status |
|---|---|
| `overlay info` | 0 success; 1 operational error; 2 argument error |
| `overlay seal`, `unseal`, `pack`, `import-upperdir` | 0 success; 2 invalid input or operational error |
| `overlay verify`, `unpack` | 0 match; 1 mismatch; 2 invalid input or operational error |
| `overlay fsck` | 0 clean/repaired; 1 unrepaired inconsistencies; 2 operational error |
| `overlay import` | 0 imported; 1 rejected hunks with `--reject`; 2 invalid input or operational error |
| `diff` | 0 unchanged; 1 changed; 2 error; 3 limits; successful hash/manifest output always exits 0 |
| `journal summarize`, `journal mark` | 0 success; 2 invalid arguments, data or I/O error |
| `snapshot` (Git export) | 0 success; 1 operational error; 2 argument error |
| `snapshot add`, `snapshot list` (restic) | 0 success; 1 local operational error; 2 argument error; nonzero restic status forwarded (including 3 for partial backup), or 128 + signal |
| `sandbox run` | 0 completed pipeline (inspect JSON `exit_code`); 2 harness failure |

### Base and stack digests

```text
stack_digest = sha256(base_digest + "\n" + layer_digest_1 + "\n" + … + layer_digest_n + "\n")
```

The input is the UTF-8 digest strings, including their algorithm prefixes, in
bottom-to-top order. With no lowers, hash only the base digest and newline.
The stored result has the `sha256:` prefix.

A local archive gets a streaming SHA-256 of all file bytes, but never on the
mount's critical path. If an existing writable archive index holds the digest
for the same canonical path, size, nanosecond mtime, and inode, creation
records it as `strong` at once. Otherwise creation records
`base_digest_kind = pending` (empty `base_digest`, no `stack_digest`, the
base's size and mtime as usual) and the mount hashes the archive on a
background thread once it is serving, then records `strong`, the digest and
`stack_digest` through the mount's own database connection (a compare-and-set
on `pending` and the recorded stamp, so a supplied digest, a forced reopen or a
commit that moved the archive wins). Until then `overlay info` prints
`base_digest: pending (computing)` (`null` and `"pending"` with `--json`) and
the live `user.ratarmount.base_digest` and `user.ratarmount.stack_digest`
xattrs read as empty. If the process exits first, the next mount of the
overlay (after the usual size/mtime check, which still runs before any
hashing) restarts the hash, and `overlay seal` hashes and records the digest
before sealing, so a sealed layer is never `pending`. A successful archive
commit rehashes the new archive and resolves it too. `--base-digest` removes
the work entirely: no base file is opened for hashing. `--no-mount` creation
never serves, so it stays `pending`. Hashing never creates an archive index.
`--no-recreate-index` and immutable index snapshots are not modified for this
cache. The test-only variable `RATARMOUNT_TEST_HASH_GATE=<path>` holds the
background hash until that path exists; `RATARMOUNT_TEST_HASH_LOG=<path>`
appends one line per full archive hash and `RATARMOUNT_TEST_HASH_DELAY_MS`
slows each hash (both are test seams, compiled only into test builds and the
`test-hooks` feature; a release binary contains no `RATARMOUNT_TEST_*` string,
which `packaging/test-no-test-hooks-in-release.sh` checks). A plain
`cargo test --workspace` enables the feature through the dev-dependencies.

**Deferred = after the mount is serving, and only when the digest is not
cached; computed once per archive and cached in its index.** A mount never
hashes an archive whose digest is already in the index, and the second to Nth
mount of the same archive read the cache. The first hash is serialized per
archive: an in-process entry plus an advisory `flock` on
`<index>.digest-lock` (hidden from a directory base's digest like the other
sidecars), taken before hashing and followed by a second cache read, so N
concurrent first mounts (threads or processes) run SHA-256 once and the rest
read the result. A mount waiting on that lock is already serving and still
unmounts promptly. The cache write waits up to 5 s for a busy index and logs a
warning if it still fails. **Without a writable index cache** (no index,
`--index-file :memory:`, a read-only or hard-linked index, a published
snapshot, a remote/meta-cache index, or an index pointer) the background
hasher does nothing and the digest **stays `pending`**: hashing on every mount
would repeat the work. `overlay seal`, `verify`, `pack`, `diff --hash` and
`sandbox run` still resolve it for the one command that needs it; pass
`--base-digest` or give the base a writable index to resolve it at mount time.
A mount only *peeks* at the cache: it never waits for another mount that is
hashing the same archive. The second mount serves at once with a `pending`
digest and its background hasher waits (cancellably, so unmount is never stuck
behind it) for the first, then reads the cached result: the archive is hashed
once. While a digest is `pending`, `diff --hash --json` and the `sandbox run`
report give `base` and `stack` as `null` and `base_pending: true` (never a
stack derived from an empty digest).

#### Digest states

`base_digest_state` is a stable contract next to `base_digest_kind`
(`strong`, `weak`, `git-tree`, `none`, `pending`). It has three values:

| State | Meaning |
|---|---|
| `present` | A digest is recorded: kind `strong`, `weak` or `git-tree`. |
| `pending` | An archive base has not been hashed yet. `base_digest` and `stack_digest` are empty (`null` in JSON). |
| `none` | No digest: `--base-digest none`, or a legacy overlay that recorded none. |

It appears in `overlay info` (text and `--json`), in the root xattr
`user.ratarmount.base_digest_state` of a mount (it changes from `pending` to
`present` when the background hasher finishes; a read-only `--lower` mount
reports `pending` when the base archive was never hashed), and in the
`diff --hash --json` and `sandbox run` `patch_hash` reports. Those reports keep
the older boolean `base_pending` (true exactly when the state is `pending`) for
compatibility. `pending` means the archive was not hashed yet, so there is no
base identity to compare: a consumer that needs one (for example cpanmine)
must treat `pending` as an error, or resolve it first with `overlay seal`.

When a verb resolves a `pending` digest it hashes the archive through the
index digest cache: with a writable index the digest is written there, and
every later mount or verb reads it (no more hashing). Without one (`:memory:`,
read-only or hard-linked index, none) the digest is recorded in the overlay
database only and the index is not touched. With no writable index there is no
lock to coordinate on, and ratarmount keeps no user-level digest cache, so
hashing is **per verb**: N concurrent `overlay seal` runs over one read-only
archive hash it N times (each records the same correct digest), and every
`overlay verify` rehashes the base, by design, even when the digest is cached.

A directory gets a `weak` digest by default: `weak:<hex>` over a sorted
manifest of relative path, type, size and nanosecond mtime (symlinks include
their target; directories and unreadable subdirectories are typed entries
without size or mtime). The walk only reads directory entries and `lstat`s
them: no file is opened, so a 1 GiB base mounts in milliseconds and FIFOs or
unreadable files cannot break creation. Mode, owner and ctime are excluded.
**A mount never hashes a base it was not asked to.** The consequence: a content
edit that keeps a file's size and mtime is invisible to a weak digest. When a
strong identity is needed, compute it once and supply it:

```bash
digest=$(ratarmount overlay digest-base ./repo --exclude-overlay ./repo/.ov)
ratarmount -w ./repo/.ov --base-digest "$digest" ./repo mnt/
```

`ratarmount overlay digest-base PATH [--json]` (experimental) reads a directory
or archive once and prints `sha256:<hex>` (JSON adds `kind`, and `excluded` for
a directory). It opens no overlay, index or cache and writes nothing. For a
directory it refuses to run while an un-excluded write overlay lives inside
it; pass one `--exclude-overlay PATH` per overlay, journal or lower layer that
is inside the directory. `ratarmount snapshot` prints an `archive_digest` that
`--base-digest` accepts as is. A supplied directory digest is also recorded
with its weak companion (`base_weak_digest`), so remounts still check the base
cheaply. `ratarmount sandbox run --base-digest` passes the value to its mount.

An overlay, `--journal` file or `--lower` layer inside (or beside) a
directory base is left out of the walk: none of them is part of the base. A
FUSE mount point inside a directory base is refused at startup (exit 2): the
daemon would stat its own mount point and hang, so mount outside the base. The excluded paths are
recorded in `base_weak_excludes` (base-relative, append-only). When the
overlay's parent does not exist yet (`-w BASE/new/ov`) the topmost new
component (`new`) is recorded, because creating the overlay adds it. A later
mount may append a journal path that is not in the base yet; one that already
exists is base content and is refused. The same rule holds for the check of a
`--lower` stack against its base, with or without `-w`: an invocation path
(`--journal`) is left out only if it is not in the base yet or is already in a
recorded excluded set (the existing top's, or the bottom lower's). Anything else counts as a change
to the base (`--force-stack-mismatch` to override). A `-w` remount of the same
top keeps its journal inside the base (it was recorded when first created). A
read-only `--lower` mount has nowhere to record anything, so a `--journal` file
that already exists inside the base is refused on the next mount; keep the
journal outside the base. Index and sidecar files that ratarmount
itself writes beside an archive (`X.index.sqlite` and its `-wal`/`-shm`,
`.index.ptr`, pinned `.index.<id>.sqlite`, `.rgzi`, `.gzidx`, commit journals,
manifests, staging temp names) never count. Archives written, replaced or
repacked inside the base (for example `--repack-seekable` writing next to its
input) are base content: the weak digest changes and the next remount of an
older overlay is refused, naming `--force-base-mismatch`. The sidecars such a
repack leaves (`.rgzi`, `.gzidx`, staging names) stay invisible. Keep generated
archives outside the base, or create a fresh overlay.

A Git base gets the selected tree id, including `--git-prefix`, and startup pins
the resolved commit before opening the mount.

### Base kind and place

An overlay records the kind of base (`base_kind`: `git`, `directory` or
`archive`) and where it is (`base_location`: `local:<path>` or
`remote:<redacted URL>`). Both are what the factory actually opened for the
mount or the verb, never a guess from a path or a URL: a bind-only mount, a
composite (its first element), a bare repository, `RATARMOUNT_FORCE_GIT`, a
`file://` URL, an HTTP/S3 archive and a torrent each record what they served.
`seal`, `pack`, `diff`, `overlay verify`, `--lower` and every reopen compare
that kind under every digest kind, `--base-digest none` included: a base of
another kind is refused, naming `--force-base-mismatch`. With digest `none` the
overlay is kind-only: nothing is walked, statted or hashed. A base that moved
between local and remote agrees only when the overlay's record is strong and a
supplied `--base-digest` (or an archive's already cached digest) equals it.
Locations are compared in their redacted form, and a credential in the typed
URL is never stored. The verbs open the base with an in-memory index but read a
cached digest of a local copy from the sidecar a mount would have used (the
sibling sidecar, a `--index-folders` entry; `overlay ... --index-folders` and
`diff --index-folders` pass the folders), read-only: nothing is created,
written or locked, so a read-only (`chmod 444`) index answers too.

Overlays from v0.1.35 or earlier have no base metadata. A plain `-w` remount
keeps working without a flag, and the first open records the kind, place and
URL (no digest). Only an overlay written by an unreleased build (`format_version`
2 with no usable `base_kind`) needs one `--force-base-mismatch`, which records
the base now in use.

### Forced base changes

A forced base-kind change without a supplied digest drops the overlay to
kind-only identity (`base_digest_kind=none`): later runs compare kind, not
content, until you supply `--base-digest`. `--base-digest none` accepts a remote
or local copy of the same archive (location is ignored).

### Commits and the base

A live, interval or on-exit commit, and `--commit-overlay` on an overlay with a
database, check before they write that the archive is still the base the last
create, commit or refresh recorded (a `stat` of its size and mtime; the mount's
`--base-digest` never overrides a changed stamp, and nothing is read under
`none`). A refused commit refuses that commit only: nothing is written, the
mount keeps serving, and `--force-base-mismatch` accepts the new base. A swap of
the base with the same size and mtime cannot be caught without hashing; only
`overlay verify` with a strong digest catches it (`overlay seal` of an
already-strong base compares the stamp and does not rehash).
`--commit-overlay` on a raw directory of files (no overlay database) has no
identity to check and says so. Only a database path with nothing at all
there counts as "no database": a dangling symlink, a directory or any other
entry that is not a readable regular file is an existing but unreadable
database, so the commit is refused (and any journal on the archive is left
alone) instead of committing as a raw directory. A symlink to a regular
database file keeps working. A database path whose target cannot be resolved
(`ENOTDIR`, `EACCES`, `ELOOP`, `EIO`: for example a symlink to
`plain-file/missing.sqlite`) is neither present nor absent: the error is
reported with the path and nothing is recovered, committed or cleared. An
overlay that was used (its marker remains) but whose database is missing,
empty or a dangling symlink is a lost record: the commit exits 2 with the #96
text before any recovery.

The commit check also compares the recorded KIND under every digest kind, `none`
included (a directory overlay does not commit into an archive), and refuses an
Unknown record (written by an unreleased build) without
`--force-base-mismatch`. A mounted base reached through a symlink is the same
file only while the name and its inode still match: a link retargeted to another
archive is refused. `--commit-overlay` classifies what it is rewriting with the
factory's own dispatch questions, without opening it: a local `.torrent` under
`--features bittorrent` is a remote folder, a `file://` URL is the local path, a
bare Git repository (or any repository under `RATARMOUNT_FORCE_GIT`) is Git,
any other directory a folder and a file an archive. The Git question is one
function (`serves_as_git`) that the mount dispatch and this classifier both call;
the remote, torrent and `file://` questions are still asked separately and
pinned by parity tests. It builds no index, reads
and writes no sidecar, and recovers a pending commit journal only after this
check. A commit journal is applied only to the file it was started for: before
EVERY commit, whatever the digest kind (`none` included), whether or not stamp
rows were recorded, for a union member the overlay did not describe, for a
v0.1.35 overlay and for a raw overlay directory, the journal's inode must equal
the archive's (the device number is only a hint; it changes across reboots).
Another file's interrupted-append journal (a copy of the interrupted bytes, a
restored backup) is refused with the archive and journal left untouched, and
`--force-base-mismatch` accepts it. A journal the overlay owns rolls back when
the size and mtime it restores equal the recorded stamp; one in the `complete`
phase that is still on disk rolls FORWARD and re-baselines the recorded stamp
(the files that commit appended are still in the overlay, so the retry appends
them again and the later member wins). A recorded strong digest named the
pre-crash bytes, so the roll-forward marks it `pending` (never clears it);
seal, diff, pack or grading resolve it lazily and mounting stays fast. Once the journal is gone nothing ties a
changed archive to the crash, and that commit is refused as a changed base.
Journals exist on Linux and macOS only; elsewhere there is nothing to check.
A journal touches the overlay's recorded rows only when its target is the
recorded base: a union member's own journal recovers that member alone and
leaves the base stamp as it was. The target is the recorded base when the
record names the archive's path or when the recorded path is another name of
the very same file (same device and inode, e.g. a hard link); it is never
inferred from matching stamps, so a base that left its recorded place (a
renamed directory, a reused name) is recovered without touching the rows and
is left to the gate (`--force-base-mismatch`). Mounting applies the same ownership check
before any recovery (the plain mount, `-w` remounts, sessions and rolling
series): a journal started for another file refuses the open with the archive
and journal untouched, and the archive's own crash still recovers at mount.
Every readable record (the `-w` overlay and each `--lower` directory) votes on a
member's journal before any recovery write: the journal's pre-commit stamp must
be the recorded stamp (or the rows already describe the committed bytes). A
journal a record does not own (another archive renamed over the base, a union
member, a lower that disagrees, a `--lower` bundle whose record is read only
after unpacking, a sealed or unreadable top) waits for the gates: a torn one is
refused with exit 2 and the instruction to recover that file alone first
(`ratarmount --no-mount FILE`), a complete one is recovered after every gate
accepted. The decision is taken again under the archive lock, on the locked
file. A journal whose rows already describe the file recovery will leave (the
committed bytes, or rolled-back bytes whose mtime could not be restored; only
the unlink is owed) is accepted by every gate. Recovery finds a journal through
its inode locator or beside the archive's current name (a directory renamed
with the journal in it). Before the first recovery write (clearing a stale
prepare locator included) every overlay record the recovery answers to (the
mount's top and directory lowers, the offline overlay, the live mount's own
database, which must still be the file it opened) is classified again under
the archive lock; a lost record or one whose database path cannot be resolved
refuses the recovery with the locator, the archive and any journal left as
they were. The offline overlay's database may be a symlink to a regular file,
as the offline gate accepts; a mount's records must be regular files. That
refusal is a refused recovery, also next to a complete journal: a live mount
is not marked as having a base changed by a failed commit, and the next gate
still refuses. The restamp after a roll-forward re-checks the record too, and a
used overlay's database must still have its `files` table, else the journal is
kept. A stale prepare locator without a journal is otherwise cleared
after a directory sync; a complete locator whose journal cannot be found is
refused, never cleared (the commit's hook may not have run), and the error
names the manual escape: verify the archive, then remove its
`user.ratarmount.commit-journal` xattr (`setfattr -x` on Linux, `xattr -d` on
macOS). A done locator (the commit finished; only the journal's unlink was
owed) whose journal is not beside the name recovery was given is kept too: the
journal may sit beside another name of the file (a directory renamed under a
hard link), and dropping the locator would make it look torn. Until it is
removed, every later commit refuses with "pending journal" and the refusal
names the same escape (verify the archive, then `setfattr -x` or `xattr -d`
the xattr). Recovery
restamps the recorded rows from the locked descriptor before it unlinks the
journal, on every path (mount, offline commit, library openers, live and
on-exit commits).

A failed replacement is cleaned up under the archive lock it took, from its own
record of what it published, before any other committer can touch the file:
it never adopts a journal another file left at the name, and it recovers only
the journal file it published. A rollback that cannot restore the mtime (a
non-owner gets `EPERM`) moves the recorded stamp to the restored file only when
the journal was started on the recorded state; a strong digest is kept (the
bytes are the recorded bytes). A commit whose rows could not be updated, or
whose journal is no longer where it was written, keeps its journal and stays
committed but pending (the mount stops committing and needs a remount) until
that file is recovered; it is never reported as a success. A copy fallback
(`--commit-overlay-mode auto`) publishes only over the file the commit gate
accepted, unchanged since the copy read it, and only while no journal is
pending on it. It reads only the gate's own snapshot: when anything wrote the
archive after the gate (another mount's commit, `tar -r`, a touch), the
append is refused and no copy runs; the commit fails and the next one is
judged afresh. The one exception is the append's own rollback, which moved
the archive's ctime under its lock: the copy then needs the exact stamp the
rolled-back file had after that cleanup, read under the lock.
`--commit-overlay-mode copy` reads its source by the same rule. The
lower gate still compares
content: a lower sealed against the pre-commit stamp refuses the rolled-forward
archive, and `--force-stack-mismatch` mounts it anyway; a forced lower mismatch
mounts and is never refused.
`overlay seal` or `pack` against a directory base at another place measures its
weak manifest there (one walk of the directory).

Remote bases use a `weak` digest of the URL and cheaply available validators:
HTTP HEAD ETag/Content-Length/Last-Modified or S3 ETag/size. Failed HEADs,
redirects, and other schemes fall back to the known URL. This fallback does
not detect changes behind a mutable URL. Multiple base inputs likewise get a
weak identity of the ordered input names. Supply a known SHA-256 for these
cases when stronger identity is required.

`--base-digest sha256:<hex>` trusts the caller and skips base-content hashing.
`--base-digest none` warns and disables identity checking for new overlays.
`--base-digest` applies only when an overlay is created: reopening an existing
overlay always compares the base with the identity the overlay recorded (weak
manifest with the recorded exclusions, size/mtime, Git tree, or the strong digest
per its kind), so `none` cannot be used to skip that check or to accept a changed
base without `--force-base-mismatch`. A `sha256:` value given on reopen is still
compared with the recorded digest and refused when it differs.
`--base-digest` also applies to a read-only `--lower` mount; `--force-base-mismatch`
requires `-w`, `--overlay-tmpfs`, or `--sandbox`. On remount, local archive
size/mtime, Git tree ids and the weak manifest of a directory base (re-walked with
the recorded exclusions) are checked; file contents and remote objects are
not rehashed. A directory base edited between sessions is refused, naming
`--force-base-mismatch`. For a copy of a base on another host or filesystem
(mtimes differ), take the strong digest on the source and pass it with `--base-digest`; a read-only `--lower` mount accepts it too when it equals the lower's recorded strong digest (an archive's cached index digest works as well; the mount never hashes). Deliberately
preserving file size and mtime can therefore evade the cheap check. A mismatch
refuses the mount; its message shows the recorded digest and current identity
(stat values for a local archive, without recomputing SHA-256).
`overlay seal`, `overlay pack` and `diff` (any mode) run the same cheap check
before they do anything and refuse a base that is not the recorded one, showing
recorded and current identity and naming `--force-base-mismatch` (experimental),
and `--base-digest sha256:<hex>` when the record is strong: a supplied digest, or
the digest already cached in an archive's index, equal to the recorded one
confirms a copy without hashing. Forced, `seal` records the base actually used
(its kind, place and URL; with `--base-digest`, that digest as strong plus the
directory's weak manifest or the archive's size/mtime; without one, kind-only
`none`; Git: the tree id), recomputes `stack_digest` and
sets `base_mismatch_forced_at`, so `overlay verify` against that base passes;
`pack` writes the same rows into the bundle only (the sealed source layer is
untouched); `diff --hash --json` reports the base actually diffed as `base`,
with `base_forced: true` and `base_recorded`. A forced run over a record with a
digest and without `--base-digest` downgrades to kind-only and says so. Sealing
an already sealed overlay still needs no base (it is finished from its own
record and writes nothing).
`--force-base-mismatch` on reopen records the override time while preserving the original
base and stack digests. Use it deliberately after an external base replacement.
Successful local archive commits refresh the recorded size, mtime, base and
stack digests, and record `base_committed_at`. Strong digests are recomputed
and the writable index digest cache is refreshed. Reopening the same overlay
after an offline, interval, on-exit, append, or rolling commit needs no override;
a subsequent external archive change is still refused. Rolling mounts check
the active generation. Legacy overlays remain legacy and digest kinds stay unchanged.

Existing overlays without `meta` remain usable. Opening one with `-w` adds
`format_version=1` and the base kind, place and URL: it stays `legacy: true`,
with no retroactively assigned digest or sealed state. Library callers open an
overlay with `WriteOverlay::open(&ClassifiedBase, composed, dir, &CreateOptions)`
(experimental): the token comes from `ClassifiedBase::open` over an `OpenBase`
implementation that reports what it served, so the recorded identity is what was
opened.

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
option and may fail with “in use” if another mount holds the database
(a foreground `-f` mount; a daemonized mount holds no lock, #183). They use
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

**The lower must match the mounted base.** A mount (read-only `--lower`, or a
`-w`/`--overlay-tmpfs`/`--sandbox` top over a stack) compares the base it serves
with the identity the bottom lower recorded, using metadata only, never file
content: a directory base is walked (path, size, mtime) with the lower's own
recorded `base_weak_excludes` and compared with its `base_weak_digest`; a local
archive's size and mtime are compared with `base_size`/`base_mtime_ns`; a Git
base's tree id with `base_git_tree`. A difference refuses the mount with
`lower PATH was sealed against a different base than the mounted one; run
`overlay verify PATH BASE` to compare digests, or pass --force-stack-mismatch to
mount anyway`. A lower recorded with `--base-digest none`, or one that predates
these keys, has no identity to compare and is accepted. A same-size edit with a
restored mtime passes at mount; `overlay verify` (which rehashes) catches it.
Offline commands (`overlay verify`, `seal`, `pack`, `diff`, `import`) do not
apply this check.

Committing a layered stack is unsupported: `--commit-overlay`, on-exit commit,
a nonzero commit interval, and rolling commits with `--lower` are refused with
“commit of a layered stack is not supported; flatten first”. RAM tops are
supported; the sandbox supervisor API does not yet accept lower stacks.

## Seal and verify

```sh
ratarmount overlay seal attempt --lower prepared base.tar.zst
ratarmount overlay verify attempt --lower prepared base.tar.zst
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
process”) (a foreground `-f` mount; a daemonized mount holds no lock, #183).
It runs fsck without repair under a writer reservation and refuses
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

Verify also compares the **base** with the digest recorded at creation (mounts
never do; this is where a supplied `--base-digest` is checked). The base is the
BASE argument, else the recorded `base_url`. What is compared depends on the
recorded kind:

| Recorded digest | Check | Cost |
|---|---|---|
| strong: a computed archive digest, or any supplied digest | recomputed from the bytes (directory: file contents and symlink targets, without the recorded `base_weak_excludes` and ratarmount's own sidecars); the index digest cache is never consulted | one full read of the base |
| weak directory digest (the default for a directory base) | the size/mtime/symlink-target manifest is rewalked with the recorded exclusions | a stat walk |
| `none`, `pending`, git tree, remote, unreadable or unhashable (FIFO under a strong directory digest) | skipped, with a warning when hashing failed | none |

A mismatch exits 1 with `base mismatch: recorded X, current Y` (weak digests add
`(weak digest: size/mtime manifest)`). `--json` adds `base_ok` (`true`, `false`,
or `null` when skipped), `base_check` (`strong`, `weak` or `skipped`) and
`base_current`, so a grader can tell what `true` means. A weak digest cannot see
a same-size content edit whose mtime was restored (pass a strong digest from
`overlay digest-base` for that); it does catch size changes, added or removed
entries and a retargeted symlink. `--no-base-check` (experimental) skips the
comparison and never opens the base, for bases too large to rehash.

Unseal requires `--i-know` (otherwise exit 2), restores owner write permission
on files and directories, removes the sentinel, clears the seal and per-path
hashes, and records `unsealed_at`. Saved mode overrides stay in place. Host
permissions and SQLite cannot be changed in one transaction: after an interrupted
seal, run unseal, fsck, and seal again. Stop direct host writers during these
commands; chmod is not a security boundary against the owner or root. The seal
covers canonical changes, not timestamps, ownership or xattrs.

## fsck

```sh
ratarmount overlay fsck attempt --json
ratarmount overlay fsck attempt --repair
```

Run this after unmounting, especially after a writer was killed before its
pending database rows were saved. The checker makes one directory walk and one
`files` scan. Reports contain `missing_content`, `unrowed`, `orphan_content`,
`tombstone_content`, `type_mismatch`, `invalid_path`, `missing_parent`,
`repaired`, and `result`. Category counts describe the state before repair;
`repaired` counts resolved findings. Exit codes are 0 for clean or repaired,
1 for unrepaired inconsistencies, and 2 for an operational error.

Host entries without a `files` row are normal: copy-on-write edits of existing
base or lower-layer files publish host content without inserting a row. Their
count, including implicit parent directories, is informational (`unrowed`);
the compatibility field `orphan_content`
is always 0 and does not contribute to errors. Repair does not invent rows for
these entries.

Repair removes rows whose content disappeared, corrects type mismatches,
removes content under tombstones, and drops malformed path rows. Only present
rows require host parents; tombstones need none, and repair never creates
directories for them. Removal uses directory-relative, no-follow operations;
symlinks are entries, never traversal paths. Repair does not delete an external
file named by a corrupt row. Invalid host UTF-8 names are reported as an error.
Database files, overlay markers, COW/spool staging files and `.ratarmount-sealed`
are excluded. Existing metadata-only chmod/utime rows for inherited content
are valid without a host copy. A `files.path` such as `/lib` is the schema's
mount-relative parent, not a host absolute path.

Unsealed checks record `fsck_at` and `fsck_result` (`ok`, `errors:N`, or
`repaired:N`). Sealed overlays can be checked without modifying any metadata;
`--repair` is refused. A database locked by a mount returns “in use”
(a foreground `-f` mount; a daemonized mount holds no lock, #183). Repairs
hold an exclusive SQLite transaction, but host changes and SQLite are not one
atomic transaction: stop direct host writers and rerun after an interrupted
repair. A consistency check does not verify content hashes.

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
diff refuses a database locked by a mount (a foreground `-f` mount; a
daemonized mount holds no lock, #183), and files/SQLite are separate stores.

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

The change set comes from host entries together with `files` rows and
metadata-only `overlay_metadata` mentions, resolved through the same read-only
overlay layers as a mount. Copy-on-write edits enter diff, manifest, hash and
seal even without a database row. The host walk never follows symlinks and
skips overlay bookkeeping, COW/spool staging files, the seal sentinel and the
in-use marker. Exclusions apply before any content read. Implicit host parent
directories with the same mode as the lower view are unchanged; a host directory
absent from the lower view is added. Unchanged copy-ups,
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

Manifest rows contain `path`, `status`, `type`, and, for present entries, `mode`
(not for symlinks), `size`, `hash` (files and symlinks), `target` (symlinks) and
`layer:"top"`.
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

Content hashes include the algorithm prefix. Symlink rows always have an empty
mode field: Linux reports `120777` and macOS a umask-dependent mode (usually
`120755`), so including it made a hash covering a symlink differ between hosts.
Regular files and directories keep their mode. A deletion uses the old type/mode
and an empty new-content hash; directories also have no content hash. The base
hash, provenance, timestamps and rendered patch text are excluded. Both content
and row hashing use the chosen algorithm. `Change::row_hash` exposes the same row
encoding for verification tools to identify mismatching paths.

[`test-harness/canonical-hash/reference.py`](../test-harness/canonical-hash/reference.py)
is a short, dependency-free reference implementation of the SHA-256 definition,
including normalization. Its `--self-test` (run in CI) and the Rust test
`golden_canonical_hash_fixture` pin the same fixture to the same three digests,
so an external grader can check its own implementation against either.

This definition is **canonical hash format 2**. Format 1, used only by
pre-release builds of the sandbox branch, also hashed symlink modes; any
digest covering a symlink changed when format 2 dropped them, which also changed
the golden digests. Seal records `canonical_hash_format` = `2` in the layer
metadata, and bundles carry it in `meta.json`. Verify, pack, unpack and repeated
seal refuse a layer recorded under another format (missing means 1), because this
build cannot recompute that digest: verify and seal exit 2, pack and unpack exit 1. To move such a layer to format 2,
run `overlay unseal --i-know` and seal it again.

Choosing `--algo`: on a CPU without SHA extensions (i7-8750H), `diff --hash` of
one modified 1 GiB file, which hashes both the base and the overlay copy, took
about 9.5 s with SHA-256 and 0.8 s with BLAKE3 (`--normalize strict` on 1 GiB of
text: 11.4 s against 3.0 s).
Use `blake3` for hashes that stay inside a grading loop, and `sha256` for
published digests such as seals and bundles. With `--hash` or `--manifest` the
cost is hashing only: `--max-diff-bytes` keeps large files out of the diff
algorithm, and memory stays around 20 MiB.

On macOS, a timestamp between −1 s and 0 is reported as `{0 s, negative ns}`,
and rustix 1.1's `stat` panics on it. Fsck, seal, verify, diff and pack therefore
read metadata through `ratarmount_compositing::host_stat`, which calls libc on
Apple platforms and normalizes such timestamps instead of crashing.
As a backstop, every stat call there runs under `catch_unwind`: any other panic
inside it becomes an error `internal error reading file metadata (rustix panic) for
<path>` and the verb exits 2 (the code it already uses for an I/O error), never
an abort with status 101. The default panic hook may still print one line first.

`--normalize exact` hashes bytes as written. `strict` converts CRLF to LF, strips
trailing ASCII whitespace per line (space, tab, CR, LF and form feed; not vertical
tab) and ignores one final newline; it is suitable
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
NUL, empty, `.` or `..` components, reserved overlay bookkeeping names, the
`.ratarmount-control` folder at the root (a `--control-interface` mount serves
a virtual folder there, so imported bytes would be hashed and sealed but
invisible; refused whatever flags the later mount uses), and
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

While it writes, import sets the `import_in_progress` meta row (`<pid>:<epoch seconds>`)
and clears it after the last write. A killed import leaves it: `overlay fsck`
reports `import_incomplete` (exit 1; `--repair` does not clear it, since fsck cannot
know the import finished), `overlay seal` refuses, and a `-w` mount prints a warning
but still opens so the partial result can be inspected. Delete the directory and
import again.

`--max-patch-bytes N` defaults to 268435456 (256 MiB). It bounds input bytes,
the total retained decoded literals, each reverse literal, and each file's
preimage/postimage. Import buffers the bounded patch and one file's text at a
time; increase the limit explicitly for larger patches.

Git/unified patches cannot represent empty directories, directory metadata or
extended attributes. Empty directories therefore do not round-trip, and Git
patches project regular-file permissions to 0644/0755. Exact canonical hashes
round-trip for representable changes with those modes; use manifests or packed
overlays when the full directory/mode/xattr state is needed.

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

| Record | Fields / meaning |
| --- | --- |
| Header | `journal: 1`, `mount`, `base_digest`, `stack_digest`, `overlay`, `t0`, `clock` |
| `open` | Path, access `flags`, caller `pid`/`uid`/`gid`, optional `comm`, source `layer` |
| `read`, `write` | Per-handle `bytes`, `count`, `ranges`, `first_ts`, `layer`; optional `ranges_truncated` |
| `create`, `mkdir`, `unlink`, `rmdir`, `symlink`, `truncate`, `chmod` | Successful path mutation and caller |
| `rename` | Source path and destination `to` |
| `readdir` | First successful directory listing, `entries` count |
| `denied` | Attempted `what`, path and numeric `errno` |
| `mark` | UTF-8 `label` identifying a turn boundary |

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
Write failures appear in the daemon log and `user.ratarmount.stats`'s `journal_error`; mark
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
callbacks. Passthrough is disabled when journaling. With `--journal`, mounts without `-w` permit root control requests at the
kernel boundary; file mutations still return EROFS in the frontend. These
journaled mounts consequently report a writable kernel mount flag even though
their data is read-only. Without `--journal`, read-only mounts stay kernel `ro`. Explicit
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
| `user.ratarmount.base_digest` | Identity of the base actually mounted: the supplied `--base-digest`, the weak manifest of a directory, `git-tree:<id>`, or an archive's cached digest; empty when it is not known without hashing. On a read-only `--lower` mount it is never the lower's recorded value |
| `user.ratarmount.stack_digest` | Recorded stack identity, or empty string (on a read-only `--lower` mount, derived from the mounted base's identity and the lower digests; empty when that base identity is empty) |
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

## Read-only path rules

Protect source paths and cap writable content with a persistent or temporary top:

```sh
ratarmount -w attempt-overlay --overlay-readonly 't/**,tests/**' \
  --overlay-quota 2G --overlay-quota-files 100000 source.tar mnt/
```

These controls require `-w` / `--write-overlay`, `--overlay-tmpfs`, or
`--sandbox`. They conflict with offline `--commit-overlay`, which does not
install mount policies. The shared overlay enforces them through FUSE, NFS,
9P, SFTP, SMB and WebDAV; reads and read-only opens remain available.

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

While a mount serves the control folder (`--control-interface` without
`--control-socket-only`), `/.ratarmount-control` is a reserved name at the mount
root: create, mkdir, symlink, rename into or out of it, writes, truncates,
xattr, chmod and utimens on it fail with EACCES and never reach the overlay.
Read-only opens, `status` and `ls` work. The same name below a subdirectory
(`/sub/.ratarmount-control`) or a longer name (`/.ratarmount-controlx`) is
ordinary, and so is the name on a mount without `--control-interface` or with
`--control-socket-only`.

Every `EROFS` returned by the rule policy increments its live `erofs_denied`
counter once, including temporary COW-parent denials. With `--control-interface`,
the socket `status` reply and `/.ratarmount-control/status` include an
`erofs_denied N` line alongside quota usage, even when no quota is configured.
The counter starts at zero for each policy instance; offline `overlay-stats`
does not include it. An observer hook receives the requested path and policy
operation once per denial for journal integration. Rules are recorded in input
order as `{"readonly":[...],"allow":[...]}` in `meta.readonly_rules`.

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

## Interrupted seals

A seal commits its digest, then writes the `.ratarmount-sealed` sentinel, then
makes the tree read-only. If the process is killed in between, re-run
`ratarmount overlay seal DIR`: it writes a missing sentinel, re-applies the
read-only modes and reports `already_sealed` as before. It never writes the
database, and it refuses (exit 2, file untouched) a sentinel that names a
different digest.

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
In-use markers and COW/spool temporary files are excluded. The database member
and the optional index are copies SQLite writes (`VACUUM INTO`) in a private
staging directory, never the live files read directly (closing such a read
would release this process's SQLite locks on them, #156): their rows are the
layer's and the sidecar's, their bytes need not be, so two packs are
byte-identical only with the same ratarmount build (the SQLite version is part
of the copy). `--include-index` copies an index only when it has no companion
files or both `-wal` and `-shm` (a live writer); any other set (a rollback
`-journal`, a `-wal` without `-shm`), a symlink, a file substituted during the
open, or an index SQLite cannot read fails the pack instead of being shipped
raw. The companion set is checked by name before the open: an index with none
is opened `immutable=1`, so a writer in another process that starts a rollback
journal on it after that check can leave the copy torn (ratarmount's own
indexes use WAL, and connections in the packing process are not affected).

The ordinary TAR layout is:

```text
layer/                         # overlay content and directories
layer/.ratarmount.overlay.sqlite
layer/.ratarmount-sealed
manifest.jsonl                 # exact changes against the composed stack
meta.json                      # all overlay meta keys, as JSON string values
bundle.json                    # {"bundle_format":1}: the bundle layout version
journal.jsonl                  # with --include-journal FILE
journal-summary.json           # journal summarize output
index/BASE.index.sqlite        # with --include-index, if an adjacent sidecar exists
```

`bundle.json` versions the layout of the bundle itself. A bundle without it is
layout 1; `unpack` and the `--lower` cache refuse a layout above 1 with
`bundle layout N is newer than this ratarmount supports (1)`.

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

**Extraction caps (experimental; may change before 1.0).** A bundle that would
extract more than 1,000,000 tar entries or 32 GiB is refused with
`bundle extracts more than N entries` / `more than N bytes`, and the staging
tree is removed, so a decompression bomb cannot fill the disk. Override with
`overlay unpack BUNDLE DIR --max-bytes SIZE --max-entries N` (`SIZE` takes
`K`/`M`/`G`/`T`) or the environment variables `RATARMOUNT_BUNDLE_MAX_BYTES`
and `RATARMOUNT_BUNDLE_MAX_ENTRIES`; a flag beats the variable. `--lower`
bundle fills use the variables or the defaults. The caps are enforced while
the bundle is **streamed** through a size-limited zstd decoder (nothing is
spooled to disk first): the decoder stops with `bundle decodes to more than N
bytes` once the payload cap plus tar framing is exceeded, so even a hostile
single-frame bundle stops early. `meta.json` and `bundle.json` are read
through the same scan, at most 1 MiB each (a sequential pass: it decodes
the bundle up to those members, which a packed bundle writes last).
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

For `--lower`, the bundle is first copied into a private file in the cache
directory while its SHA-256 is computed; everything after that (metadata,
extraction, verification) reads that copy, never the original path. The layer
is then unpacked once into
`$XDG_CACHE_HOME/ratarmount/layers/<sha256 of the bundle file>` (default:
`~/.cache/ratarmount/layers/`), so a bundle with different bytes can never
occupy another bundle's entry (entries named by `layer_digest` by earlier
builds are never looked up again). **Before publication the unpacked layer is
verified against the view it is mounted on** (the base plus the lowers beneath
it); a mismatch refuses the mount, names the offending paths and publishes
nothing. Publication is atomic.

**Staging is removable until the end.** `unpack` and the cache fill extract into
a staging directory (`.ratarmount-unpack-*` beside the destination,
`.ratarmount-layer-*` in the cache) that stays writable throughout; the archived
modes, mtimes and read-only bits are applied in one last step after every check
has passed, just before the publishing rename. A process killed earlier
therefore leaves a tree `rm -rf` can delete. Each stage holds an `flock` on a
sibling `<stage>.lock` file (never inside the layer), and the next `unpack` or
cache fill removes stages of dead processes whose lock it can take; a stage
another process still holds, directories with other names and symlinks are left
alone. Leftover `.ratarmount-copy-*` bundle copies are swept the same way, only
in the `--lower` cache: `overlay unpack` never touches other files in the
destination's parent directory.

This check reads base and lower content only for the paths the layer mentions
(plus the descendants of directories it deletes or replaces), once per cache
fill or marker miss; it never hashes the whole base, and a plain `-w` mount
or a directory lower reads no base content at mount.

A later use of a cached entry checks its immutable database and sentinel, and
either trusts a *verified marker* (`layers/<sha256>.verified/<view key>`) or
verifies again. Markers are written and trusted only when the base is a
**single archive** whose SHA-256 the mount already holds in the index digest
cache (computed, never merely claimed). The marker name also carries the listing
options that change which members the archive shows (`--no-file-versions`,
`--ignore-zeros`, `--gnu-incremental`, `--detect-gnu-incremental`, `--encoding`),
so a check made under one listing is never reused under another; options that
reshape the tree (prefix, transforms, recursion, binds, ...) get no marker and every lower beneath the bundle is a
sealed, immutable layer. A directory base, a union of several inputs, a
supplied `--base-digest` that was not computed, a remote or git base, and any
`--allow-unsealed-lower` directory lower always re-verify, so an edit to the
base or an unsealed lower between two mounts fails closed. Directory lowers continue to
work normally and are not seal-verified at mount (they are trusted like the
base; this is not a boundary against the owner).

`overlay unpack` checks the bundle against its recorded base and lowers when
they are reachable. Without them it proves only that the database and sentinel
agree with each other and prints `content not verified; run \`overlay verify
DIR BASE\` before using it as a lower`; it still exits 0. Verification is not
authenticity: a re-sealed bundle is a different, valid layer.

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

## `sandbox run`: one command in a container

`ratarmount sandbox run` mounts a base and optional sealed lowers, runs an OCI
container, then unmounts and finalizes the writable top. It is independent of the
sandbox daemon and does not require `--socket`.

```bash
ratarmount sandbox run --base source.tar.zst --lower prepared \
  --top attempt --image busybox --network none \
  --readonly 'tests/**' --allow 'tests/agent/**' --quota 1G \
  --timeout 120 --journal --seal --pack attempt.tar.zst --json \
  -- sh -c 'printf "hello\n" > result.txt'
```

Repeat `--lower`, `--readonly`, `--allow`, and `--env K=V` for multiple values.
The default container working directory and bind destination are `/repo`; change
both with `--bind /path`. `--cpus N` and `--memory SIZE` are passed to the runtime.
`--network` accepts `none` (default), `bridge`, or `host`. The command runs as the
calling user's UID/GID. The container is hardened by default:
`--cap-drop ALL`, `--security-opt no-new-privileges` and `--pids-limit 4096`
are always passed. `--pids-limit N` changes the process cap (`0` or `-1`
mean whatever docker/podman define as unlimited) and `--cap-add CAP` (repeatable,
`[A-Za-z0-9_]+`) adds a capability back (experimental, may change); nothing
removes `no-new-privileges`. A credentialed `--base URL` is visible in `ps`
because the mount child's argv carries the URL as given (only what is stored or
printed is redacted, including the runtime's stderr in cleanup warnings and the inline credentials of `rclone`, `restic` and `torrent`/magnet inputs; the covered forms are listed in the module docs of `ratarmount-core/src/redact.rs`); use an unauthenticated URL. Docker is preferred, then Podman, unless `--runtime`
selects one. `RATARMOUNT_SANDBOX_RUNTIME=/absolute/path/to/executable` overrides
that selection, including for the in-tree test stub. The runtime must use the
local host's mount namespace; a remote Docker daemon cannot bind this mount.
Non-root FUSE mounts require `user_allow_other` in `/etc/fuse.conf`; the command
checks this before mounting and reports the existing actionable diagnostic.

A credentialed remote `--base URL` is passed to the mount child on its command line, so
other local users can see it in `ps`. Everything ratarmount itself prints or stores
(mount progress, error text, the JSON report, the overlay metadata, a packed bundle) shows
the URL with credentials removed. Prefer a credential source the remote layer reads from the
environment or a config file over userinfo in the URL.

The mount is made on `<dir>/mnt`, where `<dir>` is a private `ratarmount-run-XXXXXX`
directory (mode 0700, owned by the caller) in the temporary directory. The mount uses
`allow_other`, so without the private parent another local user could enter the mounted
tree through a shared `/tmp`; they cannot traverse a 0700 parent. The same directory is
the mount child's `TMPDIR` and holds its control socket, and it is removed whole at the
end (and by crash recovery, which removes only a caller-owned 0700 `ratarmount-run-*`
parent of a recorded `mnt`).

Stdout contains exactly one JSON object. Container stdout/stderr goes to stderr;
`--json` suppresses harness progress messages. The report contains `exit_code`,
`timed_out`, `interrupted`, `wall_time_s`, `patch_hash`, `manifest_path`,
`journal_summary`, `overlay`, `bundle`, `erofs_denied`, `bytes_written`, and
`fsck_result`. `patch_hash` has the same fields as `diff --hash --json`, using
strict normalization, SHA-256, and no excludes. `bytes_written` is the final
logical overlay payload size, not cumulative I/O. `erofs_denied` comes from the
mount's control status before unmount, read over a private control socket: the
mount child runs with `--control-interface --control-socket-only` (experimental)
and a `TMPDIR` that is a 0700 directory outside the container's bind, so the
in-FS `/.ratarmount-control/` folder (host pid, memory stats, an `unmount` file)
is not visible in the container or the graded mount. Manifest and journal artifacts live next
to the top: `<top>.manifest.jsonl`, `<top>.journal.jsonl`, and
`<top>.journal.summary.json`. The summary report contains its path and counts of
files read, read then written, and written blind. Without `--journal`, it is null;
without `--pack`, `bundle` is null.

The harness returns status **0** when the pipeline completes, even if the command
fails. Inspect `exit_code` for the command result. A timeout kills the container
and reports 124 with `timed_out: true`. SIGINT/SIGTERM kills the container,
unmounts, and finalizes the overlay with `interrupted: true` and exit code
128 + signal. Harness failures return **2** with a JSON error object. A mount
that fails to become ready within 60 seconds reports captured child diagnostics.
Unmount and child termination waits are bounded. After all overlay writers exit,
the command runs `fsck --repair`, optionally seals, optionally packs, and writes
the hash and manifest. `--pack` implies `--seal`.

`--tmpfs` uses the same private, verified tmpfs allocator as `--overlay-tmpfs`
(`/dev/shm`, falling back to `$XDG_RUNTIME_DIR` on Linux). It requires an absent
or empty `--top`. After unmount, the harness copies the RAM overlay, including
its database, file modes, and symlinks, into `--top`, then removes the RAM copy.
This preserves the data for fsck/seal/pack; the child does not use the automatic
throwaway-directory cleanup of a standalone `--overlay-tmpfs` mount. A machine
reboot loses an unfinished RAM overlay.

Crash recovery uses `<TOP>/../.<topname>.ratarmount-run.pid`, outside the layer.
The JSON records the supervisor PID and process start time, mount child, runtime
client, mountpoint, runtime executable, container name, and optional RAM directory.
On Linux, child processes also receive a kernel parent-death signal, closing the
window between spawning a child and recording its PID. A sibling `.lock`
file remains as a stable advisory-lock inode to serialize runs on the same top.
After SIGKILL, a subsequent run stops the recorded container, detaches the stale
mount, stops the recorded mount child if its process identity still matches,
waits for the database lock to clear, and recovers a RAM copy if present. Failed
cleanup retains the record for retry. Recovery requires the recorded runtime to
remain executable. Reusing a sealed top requires explicitly unsealing it first;
for independent episodes, choose a fresh top over the same sealed lower.

Tests use `test-harness/sandbox-run/runtime.sh`, a Bash runtime stand-in that
executes commands inside the bind path with a separate process group. Run
`cargo test -p ratarmount --test sandbox_run` on a host with FUSE and
`user_allow_other`. Set `RATARMOUNT_TEST_DOCKER=1` to also exercise a real local
Docker daemon with the `busybox` image.
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

## Kernel overlayfs interop

`ratarmount overlay import-upperdir` converts a stopped kernel overlayfs
upperdir into a ratarmount overlay. Pass the same base and sealed lower layers
that supplied the kernel's lowerdir, in the same bottom-to-top order:

```bash
ratarmount overlay import-upperdir --lower prepared upperdir attempt base.tar.zst
ratarmount diff --manifest attempt
```

The destination must be new or empty. Import seals it by default and prints
its layer digest; `--no-seal` leaves it writable. Success exits 0, errors exit 2.
The importer shares patch import's base opening, Git revision pinning, lower
stack composition and overlay creation metadata. It reads files in bounded
chunks, preserves modes, mtimes and symlink targets, and never traverses a
symlink entry. Stop writers and unmount the kernel overlay before importing;
if copying its upperdir, preserve xattrs and whiteouts.

Character devices with device number 0:0 and `.wh.NAME` markers become
tombstones. The importer also accepts regular-file whiteouts carrying
`user.overlay.whiteout` or `trusted.overlay.whiteout`. A directory with
`trusted.overlay.opaque=y`, `user.overlay.opaque=y`, or a `.wh..wh..opq` marker
hides lower children absent from its upper tree, including descendants under
retained upper directories. Marker files are not exposed in the imported view.
Redirect and metacopy xattrs cause an error: use `redirect_dir=off,metacopy=off`
when creating the kernel overlay. Other special files and non-UTF-8 names or
symlink targets are refused. Ownership, hardlink relationships and arbitrary
xattrs are not imported.

The intended forker layout mounts a read-only ratarmount stack outside the user
namespace, then uses that mountpoint as overlayfs's `lowerdir` inside
`unshare -Urm`. Both `upperdir` and `workdir` live on one tmpfs. The opt-in test
uses these mount options:

```text
lowerdir=MNT,upperdir=TMPFS/up,workdir=TMPFS/work,userxattr,index=off,xino=off,redirect_dir=off,metacopy=off
```

It uses the same mapped user for the FUSE mount and namespace, without
`allow_other` by default. Set `RATARMOUNT_OVERLAYFS_ALLOW_OTHER=1` to probe
`-o allow_other` when the host's FUSE policy permits it. FUSE lowerdir support
depends on the host kernel and filesystem behavior, including directory entry
types; `index` and `xino` are disabled in the baseline probe. No claim is made
that those options are required on every kernel.

**Result (2026-10-17, Linux 7.2.5, x86_64, unprivileged):** the layout works.
Kernel overlayfs accepted the read-only ratarmount FUSE mount as `lowerdir`
inside `unshare -Urm` with the options above; `make` and its check ran in the
merged view; the native upperdir and its portable copy imported to the same
layer digest; and both imports' `diff --manifest` rows and composed views
matched the kernel's merged view exactly. ratarmount can therefore sit under
an existing overlayfs-based forker as its environment library.

Run the probe on a host with `/dev/fuse`, `fusermount3`, `unshare`, `mount`,
`umount`, Python 3 and make:

```bash
RATARMOUNT_TEST_OVERLAYFS=1 cargo test -p ratarmount --test overlayfs_interop -- --nocapture
```

The test runs a small make/check workload, deletes lower files, replaces an
opaque directory, changes entry types, and imports both the native upperdir
and a portable copy. Its copy preserves xattrs and converts device whiteouts
to `.wh.` markers so copying needs no `mknod` privilege. Independent snapshots
of the kernel's lower and merged trees validate `diff --manifest` paths,
types, modes and hashes; the complete composed imported views are also compared
to the merged snapshot. Missing tools, disabled namespaces, or a rejected
overlayfs mount print a skip reason, including kernel/options for mount errors.
Build, import and comparison errors after a successful mount fail the test.

Always-on tests cover marker whiteouts, recursive opacity, metadata and type
changes without mounting anything.

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

## Limits and portability

Overlay paths use SQLite TEXT and `MountSource` string APIs. Names must be
UTF-8: FUSE mutations reject invalid names with EILSEQ and lookups return
ENOENT. Latin-1 file **content** is supported. JSON's `path_b64` / `target_b64`
encoding is tested with synthetic byte paths, but arbitrary byte filenames are
not supported end to end. Import also requires UTF-8 symlink targets.

Legacy overlays remain mountable and diffable, with `legacy: true` and no
retroactive base identity. Use an explicit base when metadata cannot supply it;
unsealed legacy lowers require `--allow-unsealed-lower`. A seal is an integrity
check, not a security boundary against the layer's owner or root. It covers
canonical content and modes, not timestamps, ownership or arbitrary xattrs.

### Hard links of the overlay database

On POSIX, closing any descriptor of a file releases every lock the process
holds on it, SQLite's included. A payload name that is a hard link of an open
overlay database (made on the host by the same user, or by a link-preserving
copy such as `cp -al` or `rsync -H`; FUSE `link` itself is refused) would hand
out such a descriptor, and closing it after a read would let another process
write the database under the mount. The payload opens (FUSE and NFS reads and
writes, `MountSource::open`, create and truncate, the detached-inode reopen and
the macOS park), the ZIP and TAR commit readers, the read-only layer and live
diff, the seal and pack sentinels, the pack lock and member reads and the sweep
of old pack temp files, the commit-journal reads, the provenance-manifest read
and the `import-upperdir` inputs each check the inode of the descriptor it
obtained against the overlay databases open in this process (this mount's,
and any other overlay mounted or opened by the same process; a `--lower`'s
database is closed once the layer is loaded) and refuses a match with EACCES
and a message naming the database (logged once per inode). On
Linux the check runs on an `O_PATH` descriptor, whose close releases nothing,
and the file is then reopened through `/proc/self/fd`; `O_TRUNC` and the
create mode apply only after the check. Elsewhere (macOS, or Linux without
`/proc`) the refused descriptor, or one whose identity could not be read, is
kept open for the life of the process (one descriptor per refused open).
Remove the extra link to read the file. The
check never holds its lock across an open, so a FIFO under a payload name
blocks only the request that opens it, never another overlay-database open.

Not covered: a payload descriptor opened before its inode is first opened as
a database in this process (no mount path does this: the database is opened
before anything is served), files read by generic folder sources or
backing extents of non-overlay sources, a rename or truncation of the
database after its open (the open proves which file it got, not that the name
keeps pointing at it), and descriptors SQLite itself closes while an open is
still failing, before the database is registered. Nor are these opens, which
do not go through the check: the journal file `overlay pack --include-journal`
reads (a JSON log, not a database) and the commit journal's opens of the
archive itself. Opens that used to bypass the check no longer open a data
descriptor at all: `overlay seal`'s and `unseal`'s permission walk and the
unpack stage's mode pass change modes through an `O_PATH` pin on Linux (by
name with `AT_SYMLINK_NOFOLLOW` elsewhere, where a swap of the name between the
check and the change is not detected) (#149); a failed first open leaves an
existing 0-byte database to SQLite's rollback instead of truncating it (#160);
and `overlay pack` ships SQLite copies of the layer database and of the base
index (#156). Of the checked sites, the ZIP commit reader, the
read-only layer, live diff, the seal sentinels, the pack member, sentinel and
lock reads and the macOS park share the tested helper but have no test of
their own.

These protections keep the SQLite locks of a process that holds the database
for its whole life: a foreground mount or export server (`-f`; `sandbox run`
and the sandbox supervisor run ratarmount that way), or a library or Python
user. A daemonized ratarmount (the default without `-f`, for a FUSE mount and
for an export server alike) currently holds no kernel lock on its overlay
database at all: the database is opened and locked before the fork, POSIX
locks are not inherited by the child, and the parent's exit releases them
(#183). Until that is fixed, run with `-f` when another process may open the
same overlay.

### Checked overlay-database opens by platform

Every overlay-database open goes through a checked SQLite open (#151): wrappers
around the `open` and `stat` calls of ratarmount's bundled SQLite judge the
descriptor SQLite actually opened (or the parked one it reuses), so a name
swapped to another file and back during the open (another database, an empty
file, a FIFO, a symlink to `/dev/null`) is refused instead of read as the
overlay. Which guarantee a process gets depends on the platform and on how the
wrappers could be installed:

| Platform / host | Installation | Checked open |
|---|---|---|
| Linux CLI and Rust test binaries (64-bit little-endian x86_64/aarch64, glibc) | Load-time constructor, only when the process has exactly one thread | `"unix"` VFS; SQLite's own descriptor and every reuse are checked. An unknown thread count (no `/proc`) or a thread started before the constructor leaves the wrappers uninstalled, and checked opens refuse |
| Linux Python wheel (`_native`) | Constructor, or the module installs into its private SQLite before it publishes anything | As above. `import ratarmount_rs` raises `ImportError` if neither can install ([Python](python.md#import-and-checked-sqlite-opens)) |
| Linux Rust program embedding the library | Constructor only | As above; a thread started before the library loads leaves checked opens refusing |
| macOS CLI and test binaries (arm64/x86_64) | Constructor (task thread count) | `"unix-posix"` VFS (POSIX locks only, no fallback to other locking styles); descriptor and reuse checked |
| macOS Python wheel | Constructor or private install, as on Linux | As above |
| Windows library builds | None | The path is checked to be a regular file (no symlink under `SQLITE_OPEN_NOFOLLOW`) before and after SQLite's open; no file identity, so no swap-back detection. Commit-journal recovery needs Linux or macOS |
| Any other Unix ABI (musl, 32-bit, big-endian, BSD) | None | Refused (`UnsupportedAbi` / `UnsupportedPlatform`): every `-w` mount and overlay verb that opens an overlay database fails, rather than falling back to pathname checks |

Ordinary index, SQLAR, digest-cache and publication connections are not checked
opens: they keep SQLite's default `"unix"` VFS (auto locking on macOS). The
checked `overlay pack --include-index` snapshot uses the checked family above
(`"unix-posix"` on macOS). Managed byte readers are not connections; see
[Internal reads of index and database files](#internal-reads-of-index-and-database-files).

The optional `sqlcipher` feature links SQLCipher's SQLite (older than 3.46.0),
which is checked the same way. One difference: when its read-write open is
refused, its read-only retry calls `open` again instead of reusing a parked
descriptor (SQLite 3.46.0 and later reuse one), and the wrappers refuse that
second `open` before it reaches the file.

When threads are already running at import, so the Python wheel installs
into its private SQLite instead of through the load-time constructor (which
does not run this check), on Linux it first reads
every exported dynamic symbol of its own image and refuses on any `sqlite3*`
name, or when it cannot read the symbol table completely; on macOS it checks
only `sqlite3_libversion`. Neither check can see an entry point that other
code obtained and handed out before the module finished initializing (for
example from a dependency's initializer). Proving that for an arbitrary
shared object is not possible from these observations (#192), so it stays the
caller contract of the private-instance path.

Every checked open first checks that SQLite's VFS (`"unix"`, and
`"unix-posix"` on macOS) and its `open` and `stat` slots still hold what the
installation left. If other code replaced them, the open refuses with
`HooksReplaced` naming what changed, repairs nothing, and the installation
status keeps reporting the original installation; restoring the exact state
lets later opens proceed. This is a diagnostic: a replacement that is undone
between two opens, or one made concurrently with an open, is not seen.
Reconfiguring SQLite (`sqlite3_config`, `sqlite3_shutdown`, another VFS or
syscall hook) after the installation remains unsupported.

`ratarmount_rs._native._checked_open_status()` reports the installation in a
Python process. Python's own `sqlite3` module and `_native` may be separate
SQLite instances; opening one database file through both at once in one
process is unsupported (#154, see [Python](python.md#import-and-checked-sqlite-opens)).

### Internal reads of index and database files

The same POSIX rule applies to ratarmount's own reads of a file that is open as
a database in this process: an index read through its pointer, a hash of an
archive that is an SQLAR, a copy of a cached index blob, the HTTP index
sidecar. Closing an ordinary `File` of that inode released the connection's
locks (#151). These internal reads now go through a managed byte reader that
opens the file through the bundled SQLite's own VFS as a read-only main-database
byte file (`"unix"`; `"unix-posix"` on macOS). SQLite registers the descriptor
in its per-inode bookkeeping and, on close, parks it instead of closing it while
any connection of this SQLite instance holds a lock on the inode; a later read
reuses the parked descriptor. The byte reader opens no SQL connection, takes no
lock, never touches `-wal`/`-shm` and never reads the bytes as a database. Each
read is bounded by the current length (and 128 KiB); a short read from SQLite
(which zero-fills the rest of its buffer) is an error, so a zero-filled tail is
never hashed or copied. A file that shrinks between two reads simply ends early
there, as an ordinary read would; the copy helpers compare the copied length
with the length seen at open and refuse, other readers do not. No failure falls back to
an ordinary file read. On Windows the reader reads an ordinary private file.

Covered (each with a regression test; `packaging/internal-read-inventory.json`
lists every site): index pointers (`{archive}.index.ptr`); the index blob hash
behind pointer ids, snapshot verification and publication; the `snapshot_index_id`
copy fallback; the compression probe and decompression input of an index; the
meta-v3 metadata cache (the `$XDG_CACHE_HOME/ratarmount/meta-v3` LRU of whole
sidecar downloads: header, blob digest, install copy); the remote index id
comparison and the copy of a fetched or meta-v3 blob to the local cache name;
the HTTP sidecar endpoint; index publication (snapshot bytes, atomic copy, Hub
body) and live-commit publication (Hub, S3, GCS, Azure: sidecar and staged
archive bodies, multipart parts, MD5 passes); archive digests and their refresh
after a commit, tarstats edge/full hashes and content hashes; strong directory
digests, pending-base hashing, `overlay verify`'s strong check and
`overlay digest-base`; the remote spool fingerprints of a live commit; the
bytes of `overlay pack`'s database snapshot and `--include-index` snapshot;
SQLAR byte probes; export-index inputs; shard artifact hashes; the private
lookup copy of an index with a hot journal; and the sync of a published index.

Not covered, by design of this slice (#196; each site has a residual entry with
its reason, and the list is open): generic folder reads and backing extents,
overlay payload descriptors (admitted opens) and the TAR commit helper, the
plain TAR backend, the HF payload cache and its repository backing, the range
and payload caches (the payload-v1 header read and staging reopen included),
the HTTP body spool, the factory's format probe chain and every other format or
compression reader (protecting SQLAR's own probes does not protect earlier
probes of the chain), foreign-library readers (libgit2, libarchive, PDF),
commit-journal recovery and splice sources (`open_copy_source`, the zstd
splices), the local-index-v1 cache headers of 0.7.x sidecars, the HF
tree-listing cache, the torrent checksum cache and `.torrent` metainfo, and
SQLite's own auxiliary files (`-wal`, `-shm`, `-journal` locking and
lifetime). Configuration and credential files, `/proc` and mount tables,
daemon state and journal records, patch and bundle input streams, logger and
stdio setup and directory handles are outside the internal-read families.

Before every managed open on a Unix target, vacant standard descriptors 0-2
are filled with `/dev/null` (SQLite's `robust_open` closes a new descriptor
that lands below 3, which would release a lock); if that fails the open is
refused before SQLite's `xOpen`. Another thread emptying a standard slot
between that check and the open violates the host contract, as for checked
opens. On a macOS FAT or exFAT volume SQLite writes an `S` byte into an empty
file when it registers it; on the read-only descriptor that fails, so a managed
read of an empty file there is an error.

Failure handling: a read error is never a successful result. Tarstats hashes
stay best effort (size and mtime are still stored; a failed hash is omitted),
an index pointer still records partial archive stats, `overlay verify` reports
a failed strong hash as skipped (`base_ok: null`, exit status unchanged),
content hashing skips a member whose read failed (no partial digest) but fails
when the archive cannot be opened, a meta-v3 read error keeps the cache entry
(no refetch; a missing or malformed entry, or a blob evicted by another
process, is still a miss), a remote id-hash error is not a mismatch (the blob
stays, that candidate is not used), and a failed upload body aborts a
multipart upload without completing it.

Copies: the private lookup copies and the meta-v3 `.part` staging file are
created exclusively (`O_EXCL`) with the source's mode under the umask, get the
source's exact permissions through the handle after the copy, refuse a source
that changed during the copy, and remove only their own output on failure. The
copy of a fetched index to the local cache name keeps create-or-truncate
semantics (an existing, possibly empty, destination is filled): it is opened
with the source's mode and gets the source's exact permissions (0600 for a
fetched blob) through the handle before the first byte is written; on a read
error the fetched path is used and the partial destination stays. These
streaming copies keep bytes and Unix mode bits only: on macOS they do not carry
the ACLs, extended attributes, resource forks or clones that `std::fs::copy`
may carry. Other creates keep their modes: SQLite creates the overlay database
and the cold index `0644 & !umask`, publication's rename keeps the temporary
database's mode, companions take the database's mode, temporary files stay
`0600 & !umask`.

Connections and VFSes: checked overlay-database opens and the checked
`snapshot_index_into` source use `"unix"` on Linux and `"unix-posix"` on macOS
(POSIX locks only). Ordinary index, SQLAR, digest-cache and publication-snapshot
connections keep SQLite's default `"unix"` VFS, which on macOS picks the
locking style per filesystem (auto). Managed byte readers use `"unix"`
(`"unix-posix"` on macOS) and take no lock.

`python3 -I packaging/test-internal-read-inventory.py` checks the inventory
(`--self-test` for the scanner's own tests); a new production pathname read,
copy, create or descriptor conversion fails the check until it is classified.

Linux and arm64 Linux binaries are packaged. Offline subcommands also build
on macOS through the existing macFUSE build; the binary still depends on FUSE
libraries even for offline work. An optional FUSE-free build is not implemented.
The supervisor, verified tmpfs allocator, and kernel overlayfs recipe are
Linux-specific; see [macOS notes](macos.md) for mount requirements. A single
daemon serving many mounts (`serve-sandboxes`) remains a design proposal.

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
