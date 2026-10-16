# Rolling archives

A rolling write mount stores successive commits in numbered TAR generations
and presents their union with the writable overlay on top:

```sh
ratarmount -f -w ./overlay --roll-every 1d,20G \
  --commit-overlay-interval 5s --commit-manifest traces.tar.zst ./mnt
```

`--roll-every` implies `--commit-overlay-on-exit`. Add an interval to commit
settled files while serving; without an interval, changes persist on clean
unmount or SIGINT/SIGTERM. The existing interval rules still apply: recently
modified files and open writers stay in the overlay.

The series base is a **name**, not an archive to rewrite. For `traces.tar.zst`
the files are `traces.000001.tar.zst`, `traces.000002.tar.zst`, etc. Uncompressed
`traces.tar` uses `traces.000001.tar`. Only local `.tar` and `.tar.zst` names
are supported. The parent directory must exist. A pre-existing unnumbered base
is refused; rename it to `traces.000001.tar.zst` before mounting (and move its
index/manifest siblings to the matching names, or allow the index to rebuild).
Generation zero is reserved; the maximum generation is 999999.

At mount, the parent directory is scanned for exact six-digit series members.
They are sorted numerically, gaps are allowed, and the highest generation is
active. Sidecars and manifests do not count as generations. Newer generations
win name collisions using the existing union semantics. The first generation
is created if none exists. Generations added externally require a remount.
Use one writer per series; concurrent series writers are unsupported. A new
number already present at rotation is refused instead of deliberately reused.

Limits may be a duration (`s`, `m`, `h`, `d`), a size (`B`, `K`, `M`, `G`, `T`),
or one of each separated by a comma. Values must be positive integers; sizes
use powers of 1024. The stored archive size (compressed size for `.tar.zst`)
is checked **before each nonempty commit**. A commit can take the active file
past the limit; the following eligible commit creates the next generation.
The freshly created empty archive receives its first commit even if the
limit is smaller than its empty header. Empty interval ticks never roll.

Time uses wall-clock buckets aligned to the Unix epoch in UTC: `1d` rolls
at UTC midnight, `1h` at the hour, and `6h` at 00:00/06:00/12:00/18:00 UTC.
Rotation occurs on the next eligible commit, not on a timer with no changes.
Within a mount the generation's creation bucket is remembered. On remount its
last modification time supplies the bucket. A clock moving backward does
not itself cause a roll. Size or time reaching its boundary is sufficient.

Commits target only the active archive; sealed archives are never rewritten.
Copy, append and auto commit modes retain their existing eligibility and
journal recovery rules. Each generation has its own normal index sidecar and,
with `--commit-manifest`, `<archive>.manifest.jsonl`. Use default index naming
(or `--index-file :memory:`); a single explicit index filename cannot represent
a series. `--commit-overlay` offline mode, publishing, `--index-id`, and
`--disable-union-mount` cannot be combined with rolling. Path transforms,
`--prefix`, recursion, `--bind`, corpus and find mode are also refused.

Sealed payloads can be copied up and changed: writing or truncating an older
file creates a shadow that is committed into the active generation. Unlink,
rmdir and rename of a source name present in **any** sealed generation return
`EROFS`, including names currently shadowed by newer content; otherwise removing
the shadow would resurrect an older version on remount. Rename onto a sealed
name is allowed when its source can be removed. Metadata-only xattr changes
on sealed files also return `EROFS`; copy up the file first to change its
xattrs. A delete or metadata-only edit belonging to the active archive defers
rotation for that commit, so the operation is applied before sealing that
archive. The next eligible commit can roll. Persistent overlay tombstones
from an earlier non-rolling mount are checked again before committing.

For retention, delete sealed archive files on the host. The next daemon
lookup/readdir (or content-generation check) notices missing paths and removes
their contribution to the union. Kernel caches can delay visibility until
another daemon request or cache expiry. Already opened readers retain their
archive file descriptor and continue reading. A stale metadata handle that
tries to open a removed archive returns `EIO`. Routing slots remain stable,
but the removed source is released so storage can be reclaimed after its last
reader closes. Remove unwanted sidecars/manifests separately. Delete
only sealed generations; removing or replacing the active archive or replacing
sealed contents in place is unsupported. Existing generation numbers must
not be recycled while mounted.
