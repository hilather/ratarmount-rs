# ratarmount-rs: sandbox and grading features for agent harnesses and RL loops

**Status:** implemented on branch `sandbox/integration`, draft PR #133 (2026-10-18); not merged, not tagged. Revision 2 (2026-10-17) was the build spec; this revision 2.1 records what the implementation taught us so the spec matches the code.

**Corrections from implementation (2026-10-18):**
- **The `files` table is not the full change set.** A modification of an existing file lands in the overlay files directory *without* a database row; only creates, deletes, renames and attribute changes write rows. §2.2, §4 and §8 must therefore enumerate the change set as *files-directory entries ∪ `files` rows*, never rows alone. This bug made `diff` miss the most common agent edit and made `seal` refuse ordinary overlays; unit fixtures built overlays without going through FUSE and did not catch it. Rule going forward: the default fixture for this crate is a real FUSE mount, and one test must write a DB-less modification and assert that `diff`, `seal`, `fsck`, `pack` and `verify` agree on it.
- **`fsck` must accept ordinary deletes** of files inside directories the overlay never touched (tombstone row, no parent row). Fixed; §4's consistency rules read accordingly.
- **Paths are UTF-8 strings throughout the codebase**, not bytes. §11's "bytes, not strings" is withdrawn for paths (contents remain bytes). FUSE previously mapped non-UTF-8 names to U+FFFD, collapsing distinct names; creating such a name now fails with `EILSEQ`. `path_b64` in §2.4 is unnecessary. Consumers must treat a non-UTF-8 filename in a base archive as unsupported (cpanmine: skip reason `non_utf8_path`).
- **Renames** are delete + add by default as specified; `--detect-renames` on `diff` restores pairing when wanted. The canonical hash never uses rename pairing.
- Smaller: the layer-stack check no longer hides the underlying error for a broken overlay database; the journal records absolute mount paths.
- Open: non-FUSE build of the non-mount subcommands; the `serve-sandboxes` design note (§12); arm64 mount testing on the GB10 boxes.

**Review round (2026-10-18), further corrections and decisions:**
- **Canonical hash, symlink rule (change to §2.5):** regular files contribute `mode`; **symlinks contribute type only** (empty mode field). Symlink modes are `120777` on Linux and umask-dependent on macOS, so a hash covering a symlink was not portable between a Dell and the laptop. This changes golden digests once: bump the fixture's format tag and say so in `docs/sandboxes.md`.
- **`strict` normalization:** "trailing ASCII whitespace" means space, tab, CR, FF; **vertical tab is not whitespace** here. Documented; the Python reference (`test-harness/canonical-hash/reference.py`) matches.
- **Hash algorithm guidance:** SHA-256 costs ~9.5 s/GiB on CPUs without SHA extensions, BLAKE3 ~0.8 s/GiB; strict-mode hashing after the hasher-state fix is 11.4 s vs 3.0 s per GiB of text. Recommend `--algo blake3` for grading-loop hashes (internal) and `sha256` for published digests (base, bundle). `--max-diff-bytes` (8 MiB) means large files never reach the diff algorithm; the cost is hashing only, memory ~20 MiB.
- **Journal overhead is +0.2%** on a quiet machine with alternating benchmark order. The earlier −3% and −8.7% were order bias (baseline always first); the benchmark now alternates. Quote +0.2%.
- **macOS:** `fsck`/`seal`/`verify`/`pack` now work under symlinked parent directories (every macOS temp dir); `unpack` can rename a read-only sealed directory into place. **Required before tagging:** the rustix panic on certain file metadata must become an exit-2 error naming the path, not a crash; a grading command that panics on a real overlay is a silent mis-grade path. Keep the known-limitation note.
- **Fixture policy, final form:** the compositing crate cannot mount FUSE, so the real-mount agreement test lives in `ratarmount/tests/fuse_cow_agreement.rs` (edit through a mount, no DB row; `diff --hash`, `seal`, `verify`, `pack`, `unpack`+`verify` agree; `fsck` clean; hash identical before/after seal and after `fsck --repair`). Every new overlay feature adds a case there.
- **Merge gate:** every CI check green on the final commit (the macOS job was red for the PR's whole life while only the last 15 check lines were read). Then merge #133 and tag, so cpanmine can pin a commit.
**Crates touched:** `ratarmount` (new subcommands `diff`, `overlay`, `journal`, `sandbox`; mount flags), `ratarmount-compositing` (read-only overlay layer source, overlay metadata, seal, fsck), `ratarmount-fuse` (journal hooks, control xattrs), `ratarmount-formats-git` (git-ref bases), packaging (arm64 binaries), docs, README feature table.
**Conventions:** `AGENTS.md` applies: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` before every commit; README feature-comparison table and docs updated in the same commit as the feature.

---

## 0. The problem these features solve

A code-RL rollout on a repository has four phases: environment setup (container start, checkout, dependencies), trajectory generation (the model), the test run, and teardown. ratarmount's write overlay already makes setup and teardown nearly free. What a harness still lacks is a way to get *results* out of an overlay without mounting it or running git, a way to share the expensive part of setup (the build) across attempts, and guarantees that what it grades is what the agent produced. These features add exactly that, in the order a harness needs them:

| § | Feature | What a harness gets |
|---|---|---|
| 1 | Overlay metadata (`meta` table, `overlay info`) | A self-describing overlay: base digest, layer stack, sealed state |
| 2 | `ratarmount diff` | The patch, a manifest, and one canonical hash, from the overlay alone |
| 3 | Layered overlays (`--lower`) | Build once per task, fork per attempt; patches never contain build output |
| 4 | Seal, verify, fsck | Immutable, verifiable attempt layers that survive killed containers |
| 5 | `overlay import` | Patch → overlay without git: re-grade, verify, grade text patches |
| 6 | Journal | What the agent *read*, per turn, not only what it wrote |
| 7 | Read-only rules with exceptions | Prevent test edits at the source |
| 8 | Pack / unpack | One portable, mountable bundle per attempt |
| 9 | Git-ref bases | No snapshot archives; the tree sha is the base digest |
| 10 | `sandbox run` | One command: mount, run, unmount, seal, report |
| 11 | Hardening | Symlinks, path traversal, bytes-not-strings, size bounds |
| 12 | Scale | Shared index, shared immutable layers, one daemon, arm64 |

Implementation order is §1 → §2 → §4 → §3 → §5 → §7 → §6 → §8 → §9 → §10. §1 is first because every later feature reads or writes the metadata.

---

## 1. Overlay metadata

### 1.1 `meta` table

Add to the overlay SQLite (`.ratarmount.overlay.sqlite`, next to the existing `files` table), created on first open and migrated in on existing overlays (missing table ⇒ legacy overlay: no digests, unsealed):

```sql
CREATE TABLE IF NOT EXISTS "meta" (
  "key"   TEXT PRIMARY KEY,
  "value" TEXT NOT NULL
);
```

Keys (all strings; JSON where noted):

| Key | Set when | Meaning |
|---|---|---|
| `format_version` | create | `"2"` for overlays with metadata |
| `ratarmount_version` | create | version that created it |
| `created_at` | create | RFC 3339 UTC |
| `base_url` | create | the base positional exactly as given |
| `base_digest` | create | `sha256:<hex>` or `git-tree:<sha>`; see §1.2 |
| `base_digest_kind` | create | `strong` (content hash), `git-tree`, `weak` (size+mtime fallback), `none` |
| `lower_layers` | create | JSON array, bottom to top: `[{"path":"…","layer_digest":"sha256:…","sealed_at":"…"}]` |
| `stack_digest` | create | §1.3 |
| `sealed_at` | seal | RFC 3339; absent while writable |
| `layer_digest` | seal | canonical hash of this layer's change set (§2.5) against its stack |
| `journal_path` | mount with `--journal` | last journal file written for this overlay |
| `fsck_at`, `fsck_result` | fsck | last check and `ok` / `repaired:<n>` |

`format_version` 1 (no `meta`) stays mountable and `diff`-able; `overlay info` reports `legacy: true`.

### 1.2 Base digest

> **Correction 1 (2026-10-18, fix round for #133):** the "Directory base" bullet below is superseded. A mount never hashes a base it was not asked to: a directory base records a `weak` digest (sorted path, size, mtime manifest) by default, and a strong one only when supplied from `ratarmount snapshot` or `ratarmount overlay digest-base`. See `docs/tasks/plans/sandbox-features.md` lines 22-26. The original text is kept for history.

Computed at overlay creation (first `-w` mount of a new or empty overlay directory, or `overlay import`), never on later mounts unless asked:

- **Local archive file:** SHA-256 of the file bytes, streamed. Cached in the archive's index database keyed by `(path, size, mtime_ns, inode)` so a second overlay on the same snapshot does not re-hash; the index already lives next to the archive.
- **Git-ref base (§9):** `git-tree:<tree sha>`; nothing to hash.
- **Directory base:** SHA-256 over the sorted manifest `(path, mode, size, content hash)`; mark `strong`.
- **Remote base (`http://`, `s3://`, `hf://`, …):** ETag or `Content-Length` + `Last-Modified` → `weak`. A `strong` digest can be supplied.
- `--base-digest sha256:<hex>` on the mount: trust the caller, record it, skip hashing. Harnesses that already know the snapshot digest use this; it is the normal path at scale.
- `--base-digest none`: record `none`, print a warning. For throwaway mounts.

On later mounts of the same overlay, verify only cheaply (size and mtime of a local archive; the tree sha of a git ref). A mismatch refuses the mount with a message naming both digests; `--force-base-mismatch` overrides and records `base_mismatch_forced_at`.

### 1.3 Stack digest

`stack_digest = sha256( base_digest "\n" layer_digest_1 "\n" … layer_digest_n "\n" )` over the recorded lower layers in order. It identifies the exact tree an attempt started from. A grade cache keys on it; a changed build layer therefore misses the cache instead of silently reusing a stale grade.

### 1.4 `ratarmount overlay info <dir> [--json]`

Prints every `meta` key plus derived facts: file count and bytes in the layer, tombstone count, whether the files directory is writable, whether the DB opens read-only. Exit `0`. Also exposed live on a mounted overlay's root as xattrs (§6.5): `user.ratarmount.base_digest`, `user.ratarmount.stack_digest`, `user.ratarmount.sealed`, `user.ratarmount.layers`.

---

## 2. `ratarmount diff`

### 2.1 CLI

```
ratarmount diff [OPTIONS] <OVERLAY_DIR> [BASE]

Modes (one; default --patch):
  --patch                  unified diff against the composed lower view
  --git                    unified diff in `git apply` form
  --manifest               one JSON object per changed path (§2.4)
  --hash                   canonical hash only (§2.5)
  --stat                   files changed, +I/-D lines, bytes written
  --name-only              changed paths, one per line
  --name-status            `A\tpath` / `M\tpath` / `D\tpath` / `T\tpath` (type change)
  --between <OTHER_DIR>    diff two overlays that share a stack: OTHER_DIR's tree → OVERLAY_DIR's tree

Modifiers:
  --lower <DIR>            lower layer (repeatable, bottom to top); defaults to the overlay's recorded stack
  --normalize <exact|strict|loose>   hashing/manifest normalization (§2.5); patches are always exact
  --exclude <GLOB>         drop matching paths (repeatable; gitignore globs on mount-relative paths)
  --ignore-mode            mode-only changes are not changes
  --algo <sha256|blake3>   hash algorithm (default sha256; blake3 recommended for grading loops, see review notes)
  --strict                 refuse an unsealed overlay (§4); default warns on stderr
  --max-diff-bytes <N>     text diffs over N bytes per side fall back to the binary form (default 8 MiB)
  --max-patch-bytes <N>    fail with exit 3 if the rendered patch exceeds N (default unlimited)
  --json                   machine-readable output for --stat and --hash
  -o <FILE>                write to FILE
```

`BASE` is the same positional the mount takes. It is required for `--patch`, `--git`, `--stat`, `--between`; it is read from `meta.base_url` when omitted and the overlay has metadata (stderr notes this). `--manifest`, `--hash`, `--name-only`, `--name-status` work from the overlay alone when neither is available: added-vs-modified cannot then be told apart and is reported as `written`.

Exit codes follow `diff(1)`: `0` no changes, `1` changes, `2` error, `3` patch over `--max-patch-bytes`. `--hash` and `--manifest` exit `0` on success regardless of whether anything changed.

**Patches are always exact bytes.** `--normalize` affects only the hash and the manifest's content hashes; a patch produced by `diff --git` must `git apply` to a byte-identical tree.

### 2.2 Change set

Resolve every path mentioned in the top layer's `files` table against the composed view of (base + lower layers):

| Top layer | Composed lower view | Status |
|---|---|---|
| file present | absent | `added` |
| file present | present, content or mode differs | `modified` |
| file present | present, identical | *not reported* (write-then-revert) |
| file present, different type (file↔symlink↔dir) | present | `type_changed` (rendered as delete + add in patches, `T` in `--name-status`) |
| tombstone | present | `deleted` |
| tombstone | absent | *not reported* |
| empty directory | absent | `added` with `"type":"dir"` in the manifest; omitted from patches |
| symlink | any | status by target string; `"type":"symlink"` |

Renames are not tracked by the overlay: a rename is `deleted` + `added`. Hard links in a base archive are independent paths. Paths are byte-sorted; all output is deterministic.

Binary: NUL in the first 8 KiB (git's rule). Patch output prints `Binary files a/P and b/P differ`; `--git` mode additionally emits `GIT binary patch` in **literal** form (zlib + base85, both `literal` sections) so the patch is importable (§5). Never emit `delta` form.

### 2.3 Composed lower view

The lower view is a `MountSource`: the base wrapped by one read-only overlay layer per `--lower`, bottom to top (§3.2). `diff` opens it exactly as a read-only mount would, so what `diff` reports equals what a reader of the mounted stack saw. Content hashes of the lower view prefer `user.hash.<algo>` xattrs when the base's index carries them (`find --hashes`); otherwise stream the content.

### 2.4 Manifest

One JSON object per line, byte-sorted by path:

```json
{"path":"lib/Foo.pm","status":"modified","type":"file","size":4213,"mode":"100644","hash":"sha256:…","base_hash":"sha256:…","layer":"top"}
{"path":"t/agent/new.t","status":"added","type":"file","size":512,"mode":"100755","hash":"sha256:…"}
{"path":"lib/Old.pm","status":"deleted","type":"file","base_hash":"sha256:…","base_layer":"lower:1"}
{"path":"bin/x","status":"added","type":"symlink","target":"../lib/x.pl","hash":"sha256:…"}
```

`hash` is the normalized content hash; `base_hash` and `base_layer` (`base`, `lower:<n>`) appear when the lower view is available. Non-UTF-8 paths are emitted as `"path_b64":"…"` with `"path"` omitted; the same rule applies to `target`.

### 2.5 Canonical hash

Over a byte stream, never over rendered diff text:

```
for each changed path, byte-sorted, after excludes:
  path "\0" status "\0" type "\0" mode-or-"" "\0" normalized-content-hash-or-target-hash "\0"
  (mode is empty for symlinks: see review notes; regular files keep it)
```

then `algo(stream)`; output `sha256:<hex>`. Normalization levels for text files (binary is hashed as-is):

- `exact` (default for `--hash` when unspecified): bytes as written.
- `strict`: CRLF→LF, trailing whitespace per line stripped, trailing-newline-at-EOF ignored. **The grading default.**
- `loose`: `strict` plus blank lines removed. **Analysis only** (duplicate-rate statistics); never for grading, because blank-line changes can matter to tests. `--hash --normalize loose` prints a stderr warning once.

`--hash --json`:

```json
{"patch":"sha256:…","base":"sha256:…","stack":"sha256:…","files":7,"normalize":"strict","excludes":["…"],"algo":"sha256","sealed":true}
```

Required properties (each a test): same edit via two overlays → same `patch`; same edit with different unrelated files in the stack → same `patch`, different `stack`; whitespace-only difference → same under `strict`, different under `exact`; mode-only → different unless `--ignore-mode`; excludes never affect the hash; empty change set → the documented constant.

### 2.6 `--between`

`diff --between A B base` treats A's tree as the lower view and B's tree as the top: the patch that turns attempt A into attempt B. Both must record the same `stack_digest`; otherwise exit 2. `--hash --between` gives a distance proxy (identical trees → the empty-set constant), which an RL loop uses as a group-diversity measure without materializing either tree.

### 2.7 Implementation notes

- New `ratarmount/src/diff.rs`; argv dispatch like `find` (`diff` after flags is an archive name, not the subcommand).
- Read-only helpers on `WriteOverlay` (`ratarmount-compositing/src/write_overlay.rs`): iterate `files` rows, open layer content by path, list tombstones; no change to write paths.
- Unified diff via a Myers implementation or the `similar` crate (check licence and MSRV); `--git` headers: `diff --git a/P b/P`, `new file mode`, `deleted file mode`, `old mode`/`new mode`, `index <short-base>..<short-new> <mode>`, `--- a/P`/`+++ b/P` with `/dev/null`, `\ No newline at end of file`.
- Excludes before content: a `blib/` of a thousand objects must cost nothing.
- Streaming everywhere; no whole-file buffers for hashing.

---

## 3. Layered overlays

### 3.1 CLI

```
ratarmount [-w <TOP>] --lower <DIR> [--lower <DIR> …] [--allow-unsealed-lower] <BASE> <MOUNT>
```

`--lower` is repeatable, bottom to top. Lower layers are overlay directories opened read-only. `-w` is optional: with no top, the mount is the read-only composed view (for inspection and grading reads). `--commit-overlay` with `--lower` is refused in this revision ("commit of a layered stack is not supported; flatten first").

### 3.2 Semantics

Standard overlay rules, per path, with no opaque-directory special case because tombstones are per path (removing a directory tombstones each child):

- **Resolution:** the top-most layer that mentions a path decides it: present → served from that layer; tombstone → absent, hiding every layer below and the base. A higher layer can re-create a path a lower layer deleted.
- **Listing:** merge of all layers and the base, minus paths whose deciding layer is a tombstone. `list_dirents` merges cheaply (names + modes), as `WriteOverlay::list_dirents` does today.
- **Writes** go to the top only. Copy-up on first modification reads from the composed lower view (so a file created in a lower layer and edited in the top is `modified` relative to the stack). Deletes write tombstones to the top; renames are copy-up + tombstone, as now.
- **`diff`** of the top is always relative to the stack (§2.3). A file that exists only in a lower layer and is untouched by the top never appears in the top's patch. This is what removes build output from attempt patches when the build lives in a lower layer.
- **Lower layers must be sealed** (§4) unless `--allow-unsealed-lower`. Sealed lower DBs are opened `mode=ro&immutable=1`, so any number of mounts share them without lock contention; unsealed lowers are opened read-only without `immutable` and may see `SQLITE_BUSY` under a concurrent writer, which is the reason for the default.
- **Metadata:** the top records `lower_layers` and `stack_digest` at creation (§1). Mounting a top whose recorded stack differs from the `--lower` list given is refused (`--force-stack-mismatch` overrides, recorded).

### 3.3 Implementation

Implement `ReadOnlyOverlayLayer: MountSource` in `ratarmount-compositing`: wraps an inner `MountSource` and one overlay directory, serving `list`/`list_dirents`/`list_mode`/`lookup`/`open`/`read`/`list_xattr`/`get_xattr` with the resolution rule above, tombstone set cached in memory as `WriteOverlay` does, `content_generation` forwarded from the inner source. Then a stack is `base → layer_1 → … → layer_n`, and `WriteOverlay::new(stack, top)` is unchanged: its `current_base()` is the composed view, so copy-up, listing and tombstone logic need no edits. `diff` builds the same stack.

FUSE passthrough (roadmap) applies to files resident in any layer directory; when it lands, prepared-layer reads during a build run at native speed.

### 3.4 Branching an episode (recipe, no new code)

To fork an agent's environment at turn *k* for tree-search or process-reward training: unmount the attempt, `overlay seal` it, then mount N new tops with `--lower prepared --lower attempt-k`. Setup is sub-second per branch; only filesystem state is captured (shell state is the harness's job). Document this in `docs/sandboxes.md`; it is a capability no container runtime offers cheaply.

---

## 4. Seal, verify, fsck

```
ratarmount overlay seal   <DIR> [--lower …] [BASE]   # fsck, compute layer_digest, make immutable
ratarmount overlay unseal <DIR> --i-know                # clear seal; records unsealed_at
ratarmount overlay verify <DIR> [--lower …] [BASE]     # recompute layer_digest, compare; exit 0/1
ratarmount overlay fsck   <DIR> [--repair]              # consistency check of files dir vs DB
```

- **seal:** refuses if the overlay is currently mounted (lock file / `fuser` check). Runs `fsck`; refuses on unrepaired inconsistencies. Computes `layer_digest` = `diff --hash --normalize exact` of the layer against its recorded stack (so the digest covers exact bytes). Writes `sealed_at`, `layer_digest`. Removes write permission recursively from the files directory and the DB, and writes a sentinel file `.ratarmount-sealed` holding the digest for tools that do not open SQLite. Prints the digest.
- A sealed overlay **cannot be mounted with `-w`** ("sealed; mount it with --lower, or `overlay unseal`"). It can be a `--lower`, the subject of `diff`, `pack`, `verify`, `info`.
- **verify:** recompute and compare `layer_digest`; also check the sentinel matches; exit `1` on mismatch with the differing paths listed (via `--between` against a temp import of nothing: in practice, re-run the canonical hash per path and report mismatching rows).
- **fsck:** every `files` row with `deleted = 0` has a backing entry in the files directory with matching type; every entry in the files directory has a row; no row has both `deleted = 1` and backing content; parent directories of rows exist. `--repair`: drop rows without content, add rows for orphan content (with the file's real mode/mtime), delete content under tombstones. Reports counts; records `fsck_at`, `fsck_result`. A FUSE process killed mid-write is the expected cause, so `fsck` must be fast on large overlays (one directory walk, one DB scan).
- **`diff --strict`** and `--lower` default to requiring sealed input, as above.

---

## 5. `overlay import`

```
ratarmount overlay import [--lower …] [--mtime now|<epoch>] [--no-seal] [--reject] (<PATCH>|-) <NEW_OVERLAY_DIR> <BASE>
```

Creates an overlay directory from a patch against the composed view of `BASE` + `--lower` layers, records metadata (§1) as a creation would, and seals it unless `--no-seal`.

- **Accepted input:** unified diffs and `git diff` output: `new file mode`, `deleted file mode`, mode changes, `rename from/to` (treated as delete + add with content copied, then hunks applied), `GIT binary patch` **literal** sections, `\ No newline at end of file`. `delta` binary sections and `Binary files differ` without content are errors (exit 2) naming the path.
- **Application:** exact context, offset allowed (as `git apply` without fuzz). A hunk that does not apply fails the file; with `--reject`, the original content is kept and `<path>.rej` is written into the overlay, else the import aborts and removes the partial overlay. Exit `1` if any file failed with `--reject`.
- **Paths:** must be relative, must not contain `..` components or start with `/`; symlink components in the lower view are not traversed (a patch to `link/file` where `link` is a symlink is refused). Paths and content are bytes.
- **mtime:** default `now`; `--mtime <epoch>` sets every written file's mtime so a replayed layer rebuilds under `make` exactly as the original did relative to a prepared layer.
- **Round trip** is the acceptance test: `diff --git A` → `import` → `diff --hash` equals A's hash, for every case in §13.

---

## 6. Journal

### 6.1 Mount flags

```
--journal <FILE>                 append JSONL records of filesystem operations
--journal-exclude <GLOB>         drop paths (repeatable; e.g. '.git/**', 'blib/**')
--journal-reads <all|first>      per handle: all coalesced ranges (default) or first read only
--journal-sync                   fsync the journal at unmount
```

### 6.2 Records

Header line first: `{"journal":1,"mount":"…","base_digest":"…","stack_digest":"…","overlay":"…","t0":"<RFC3339>","clock":"monotonic_ns"}`.

Then one object per event, `ts` in nanoseconds since `t0`:

| `op` | When | Extra fields |
|---|---|---|
| `open` | file handle opened | `path`, `flags` (`r`/`w`/`rw`), `pid`, `uid`, `comm`, `layer` (`top`/`lower:<n>`/`base`) |
| `read` | handle released | `path`, `bytes`, `ranges` (merged `[off,len]`, capped at 64 then `"ranges_truncated":true`), `pid`, `comm` |
| `write` | handle released | `path`, `bytes`, `ranges`, `pid`, `comm` |
| `create`, `mkdir`, `unlink`, `rmdir`, `rename`, `symlink`, `truncate`, `chmod` | on the op | `path` (`to` for rename), `pid`, `comm` |
| `readdir` | first readdir on a handle | `path`, `entries` |
| `mark` | §6.4 | `label` |

`comm` is best-effort: `/proc/<pid>/comm` on Linux, absent elsewhere. `pid`/`uid` come from the FUSE request. `stat`/`getattr` are not journaled (too noisy; `open` is the signal). Writes are buffered and flushed by a background thread; target overhead under 3% on a `make && prove` run (benchmark in §13, not a CI gate).

### 6.3 `ratarmount journal summarize <FILE> [--json] [--since-mark L] [--until-mark L]`

Produces, per path: first read `ts`, first write `ts`, bytes read/written, read count, `layer` served, `comm` set. And lists: `files_read` (read, never written), `files_read_then_written`, `files_written_blind` (written without a prior read), `reads_by_mark` (paths read between consecutive marks). This is what a harness stores in the trace record.

### 6.4 Marks

`ratarmount journal mark <MOUNT> "<label>"` appends a `mark` record by setting the control xattr `user.ratarmount.mark` on the mount root. A harness calls it at each agent turn boundary so `summarize --since-mark` aligns reads to turns. Setting the xattr is the whole protocol; no socket needed.

### 6.5 Control and status xattrs on the mount root

Read: `user.ratarmount.base_digest`, `.stack_digest`, `.sealed` (`0`/`1`), `.layers` (JSON), `.journal` (path or empty), `.stats` (JSON: bytes read/written, files touched, overlay bytes, op counts). Write: `user.ratarmount.mark`. These let a harness introspect a mount with `getfattr`/`os.getxattr`, no CLI.

---

## 7. Read-only rules with exceptions

Extends roadmap item 2:

```
--overlay-readonly <GLOB>    writes under the glob return EROFS (repeatable)
--overlay-allow <GLOB>       exception to --overlay-readonly (repeatable; most specific wins)
--overlay-quota <SIZE>       ENOSPC past the cap on the top layer (existing roadmap item)
```

`--overlay-readonly 't/**' --overlay-allow 't/agent/**'` lets an agent add its own tests without touching the suite that grades it. Rules are recorded in `meta` (`readonly_rules`) so `info` shows what the agent was allowed to do. Violations are counted in `.stats` (`erofs_denied`) and journaled as `op:"denied"`.

---

## 8. Pack and unpack

```
ratarmount overlay pack   <DIR> <BUNDLE.tar.zst> [--include-journal <FILE>] [--include-index]
ratarmount overlay unpack <BUNDLE.tar.zst> <DIR>
```

A bundle is a tar.zst holding the sealed layer's files directory, its SQLite DB, a `manifest.jsonl` (§2.4), `meta.json`, optionally the journal and its summary, and optionally the base's index. `pack` refuses unsealed overlays. A bundle is itself mountable (`ratarmount bundle.tar.zst mnt` shows the layer's files; `--lower` accepts a bundle path and unpacks to a cache). `unpack` restores a sealed overlay directory and verifies the digest.

Why: one file per attempt is the trace-storage unit a harness wants, it is content-addressed by `layer_digest`, and a directory of bundles published as a dataset is mountable with the `hf://` work on the roadmap.

---

## 9. Git-ref bases

`ratarmount-formats-git` already mounts a tree at a ref. Allow it as the base of an overlay stack:

```
ratarmount -w top --lower prepared git:///srv/repos/Try-Tiny.git#1a2b3c4d mnt
```

- `base_digest` = `git-tree:<tree sha of the commit>`; no hashing.
- With the roadmap's synthetic `.git` HEAD, the agent sees a one-commit repository and no history.
- Dedup across tasks and across commits of one repo is free (one bare clone, many refs).
- Portable bundles still want an archive: `ratarmount snapshot <git-url>#<sha> <out.tar.zst> --with-index` writes the tree as tar.zst plus its index and prints the digest. The two base kinds yield the same tree, and a test checks the composed view's manifest is identical for both.

---

## 10. `sandbox run` (v0 of the sandbox API)

```
ratarmount sandbox run \
  --base <BASE> [--lower <DIR>…] --top <DIR> [--tmpfs] \
  --image <OCI image> [--bind /repo] [--env K=V…] [--cpus N] [--memory SIZE] [--network none] \
  [--journal] [--readonly GLOB…] [--allow GLOB…] [--quota SIZE] [--timeout S] \
  [--seal] [--pack <BUNDLE>] [--json] -- <COMMAND…>
```

Does, in order: mount the stack with the given flags; start the container with the mount bound at `--bind`; run the command with the timeout; stop the container; unmount (lazy on failure, then wait); `fsck --repair`; `seal` if asked; `pack` if asked; print one JSON object: exit code, wall time, `patch_hash` (`--hash --json` output), `manifest_path`, `journal_summary` (if `--journal`), `overlay`, `bundle`, denied-write count, bytes written. The container runtime is `docker` or `podman` (auto-detected or `--runtime`); `bwrap` for rootless no-image runs is a follow-on.

This is the command an RL framework calls per rollout. It composes the other sections and contains no logic of its own beyond sequencing and cleanup (a killed `sandbox run` must leave no mount behind: a PID-file plus `-u --lazy` on startup for stale mounts under the same `--top`).

---

## 11. Hardening

- **Symlinks are data.** `diff`, `import`, `seal`, `verify`, `fsck`, `pack` never dereference symlinks in the overlay files directory or the lower view on the host; a symlink is an entry whose content is its target string. A patch that would write through a symlink component is refused.
- **Path traversal.** Overlay rows and imported patch paths with `..`, absolute paths, or NUL are refused; `fsck` reports such rows as corruption.
- **Bytes, not strings.** Paths and contents are byte strings end to end; JSON output uses `path_b64` for non-UTF-8. Latin-1 repositories must round-trip.
- **Bounds.** `--max-patch-bytes`, `--overlay-quota`, journal `ranges` cap, manifest line cap (`--max-files`, default unlimited, exit 3 when exceeded). An agent that writes a 10 GB file must not take the grader down with it.
- **Immutability is enforced where it can be:** sealed layers are `immutable=1` in SQLite and read-only on disk; `verify` catches the rest.
- **No code execution in `diff`/`import`:** patches are data; no hooks, no shell.

---

## 12. Scale

- **Ship the index with the snapshot.** `snapshot --with-index` and `pack --include-index` write the archive's index next to it so the first of 64 mounts on a new machine is instant and all 64 share one read-only index via the page cache. Document the layout.
- **Shared immutable layers:** §3.2.
- **One daemon, many mounts (follow-on, design only here):** a `ratarmount serve-sandboxes` process holding the base and lower layers once and exposing N FUSE mounts (or one mount with N subtrees) over the `sandbox new|list|destroy` API from the roadmap. Memory and index cost become per-task instead of per-attempt. Not in this revision's done-when.
- **arm64.** Release binaries for `aarch64-unknown-linux-gnu` in `packaging/` outputs; the GB10 boxes are ARM. macOS (macFUSE) builds for the M5 laptop: `diff`, `overlay *`, `journal summarize`, `pack` need no FUSE and must work there; mount features are best-effort.

---

## 13. Tests

All in-tree (`cargo test -p ratarmount`, `-p ratarmount-compositing`), using a synthetic base archive and overlays built through the real write path. Benchmarks under `benchmarks/`, not CI gates.

**§1 metadata:** created overlay has `meta`; legacy overlay (no `meta`) mounts and diffs; `--base-digest` supplied ⇒ archive not read for hashing (count reads in a test `MountSource`); remount with a changed base refused; `info --json` fields.

**§2 diff:** `added`, `modified`, `deleted`, `type_changed`, symlink, empty dir, mode change, binary (literal round-trip), nested dirs, CRLF, no-trailing-newline, Latin-1 content, non-UTF-8 path; write-then-revert and tombstone-of-nothing not reported; **round trip** `extract base → git init → git apply (diff --git) → tree == manifest of the composed stack` for every case; each §2.5 hash property; excludes short-circuit (1,000 files under `blib/`, assert they are never opened); deterministic output across two runs; base omitted ⇒ `--manifest`/`--hash` work, `--patch` exits 2; `--between` of identical trees gives the empty constant and of differing trees applies A→B; `--max-patch-bytes` exit 3.

**§3 layers:** base + prepared (adds `blib/**`, modifies `Makefile`) + attempt (modifies `lib/Foo.pm`, deletes `blib/x`, re-creates a file a lower layer deleted) ⇒ composed listing, lookup and reads match expectation; `diff` of the attempt contains only `lib/Foo.pm` and `blib/x` with an empty exclude list; copy-up from a lower layer produces `modified`; unsealed lower refused without the flag; two tops over one sealed lower mounted concurrently, both read the same bytes; recorded-stack mismatch refused; read-only composed mount without `-w`.

**§4 seal:** seal ⇒ `-w` mount refused, `--lower` accepted, `diff --strict` passes; `verify` passes, then a byte is altered under the files directory (via chmod) ⇒ `verify` exits 1 naming the path; `unseal` restores writability; `fsck` on a deliberately inconsistent overlay (row without file, file without row, content under a tombstone) reports exactly those and `--repair` fixes them; seal refuses a mounted overlay.

**§5 import:** every §2 case round-trips `diff → import → diff --hash` to the same hash; a patch from real `git diff --binary` on an extracted base imports to the same tree; `rename from/to`; `.rej` with `--reject`; `..` path refused; symlink-component path refused; `delta` binary refused with the path named; `--mtime <epoch>` applied.

**§6 journal:** a scripted sequence (open/read/read/release, write, mkdir, rename, denied write) produces the expected records with coalesced ranges, `layer` attribution and `pid`; `mark` via xattr appears in order; `summarize` lists `files_read`, `files_written_blind`, `reads_by_mark` correctly; excluded globs absent; header present; benchmark `make && prove` on a fixture dist with and without `--journal`, report overhead.

**§7 rules:** writes under `t/**` ⇒ `EROFS`, under `t/agent/**` succeed; `.stats` counts denials; rules recorded in `meta`.

**§8 pack:** pack refuses unsealed; `pack → unpack → verify` passes; a bundle mounts directly and as `--lower`; `--include-journal` and `--include-index` present in the tar listing.

**§9 git base:** tar.zst snapshot and `git:` base of the same commit give identical composed manifests; `base_digest` is `git-tree:<sha>`; `snapshot --with-index` output mounts with no index build.

**§10 sandbox run:** with a stub runtime (a shell script standing in for `docker`) the sequence mount → run → unmount → fsck → seal → JSON is exercised, including a command that times out and a stale mount left under `--top` from a previous crash.

**§11 hardening:** symlink pointing outside the overlay is reported as a symlink entry and never followed by `diff`/`pack`/`verify`; NUL in a path refused; 10 GB sparse file in an overlay: `--max-patch-bytes` exits 3 quickly, `--manifest` streams.

**§12:** arm64 build in CI (cross or native runner); macOS build of the non-FUSE subcommands.

---

## 14. Docs

- `docs/sandboxes.md`: the end-to-end flow (snapshot → prepared layer → attempt → seal → diff → grade → pack), the branching recipe, the xattr protocol, the metadata keys, the canonical-hash definition, "renames are delete + add".
- README: `diff`, `overlay`, `journal`, `sandbox` in the subcommand list; feature-comparison rows (Python ratarmount has none of these).
- Man-style `--help` for every subcommand, with the exit codes.

---

## 15. Done when

1. `ratarmount diff --git` output `git apply`s to the exact tree for every §13 case, and `diff --hash --normalize strict` is identical for two overlays holding the same edit on the same stack.
2. A prepared lower layer built once lets a second mount run `make` incrementally, and the attempt's `diff` contains no build output with an empty exclude list.
3. `seal` → `verify` → tamper → `verify` fails; `fsck --repair` recovers an overlay from a killed writer.
4. `diff → import → diff` round-trips every case.
5. A journaled run yields `files_read` per mark with under 3% measured overhead on the fixture dist.
6. `sandbox run` executes a command in a container over a stack and prints the JSON report, leaving no mounts behind after a simulated crash.
7. arm64 Linux binaries are in the release artifacts; non-FUSE subcommands build on macOS.
8. README and `docs/sandboxes.md` updated; fmt, clippy `-D warnings`, tests green.
9. **Interoperability with kernel-overlayfs forkers (positioning test).** A read-only ratarmount stack (base + sealed lower layers, no `-w`) used as the `lowerdir` of a plain kernel overlayfs mount with a tmpfs `upperdir` (the mechanism DeltaBox-style forkers use) behaves as a normal lower directory: a build and test run succeed, and `ratarmount diff --manifest` over an overlay directory produced by copying that `upperdir` back (plus overlayfs whiteouts translated to tombstones by a small `overlay import-upperdir` helper, or documented as unsupported if it proves awkward) matches the kernel's view. This is what lets ratarmount sit *under* existing forkers as their environment library rather than compete with them; document the result either way in `docs/sandboxes.md`.
