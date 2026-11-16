# Issue #341: preimage pins for layers sealed over a local directory base

| Field | Value |
|-------|--------|
| **Issue** | #341 — Weak directory base: `--lower` reuse misses same-size base edits that keep a change modified |
| **Status** | Implemented |
| **Scope** | `ratarmount-compositing/src/overlay_seal.rs` (record, unseal, verify, cheap check), `overlay_changes.rs` (base-side entry lookup), `lower_stack.rs` (check on every sealed lower), `ratarmount/src/overlay_pack.rs` (moved-base pack), `ratarmount/src/overlay_cmd.rs` (verify output) |

## Problem

A sealed layer's canonical rows carry the new side only (path, status, type,
mode, new content hash). Re-verifying a layer recomputes its change set, which
notices a base edit only when it makes a recorded change disappear (the base
now equals the layer's bytes). A base file edited to a *third* value with the
same size and a restored mtime leaves a `modified` row byte-identical, and the
cheap identity checks (weak manifest of path/type/size/mtime; the supplied
strong digest of a directory, which the mount never rehashes) cannot see it. A
sealed *directory* lower was not re-verified at all: `MountLowerStack` only
verified bundles.

The mounted view is unaffected (a modified path's bytes come from the layer).
What breaks is the layer's meaning, "these changes relative to this base":
`diff`/git-patch output over the stack and the seal's own claim.

## Threat model

Integrity against **accidental or casual** base edits that keep a file's size
and mtime (an editor or tool that restores timestamps, `rsync --times` from a
different source, a same-length rewrite). It is **not** a defence against an
adversary who can rewrite the overlay database without resealing: such a party
can delete the pin table and its meta row together and the layer then reads as
a pre-#341 seal. Runtime integrity against a hostile writer is out of scope as
it is for the rest of the seal (docs/sandbox.md).

## What is pinned

At seal time, for every canonical row whose base side exists (`modified`,
`deleted`, `type_changed`; a rename is a `deleted` source plus an `added`
destination, so its source is a `deleted` row), and whose base side is a
regular file or symlink, one pin:

| Column | Value |
|---|---|
| `path` | mount-relative path |
| `kind` | `file` or `symlink` |
| `mode` | `%06o` of the base entry's mode for a file; empty for a symlink (canonical hash format 2 reason: a symlink's mode is not portable) |
| `size` | content size (symlink: target length) |
| `hash` | `sha256:` of the exact content (symlink: target bytes) |

A base *directory* gets no pin: a removed or replaced directory's descendants
are expanded by `compare_paths` and pinned individually. Directories are only
names; an added entry under them is the weak manifest's job.

The preimage hashes are not new work: `compare_paths` already hashes the base
side of every changed path (`Change.old`), through the composed
`MountSource`, at both seal and verify time. The pins record what the seal
already computed. No new file opens are added (no internal-read inventory
change): every read goes through the base `MountSource`, as all change-set
hashing does.

Pins never use size or mtime as a skip-the-hash shortcut; that would
reintroduce the bug. Size is stored to name a size change in messages.

### Which seals record pins

Only layers whose recorded base is a **local directory**: the meta row
`base_weak_digest` is present, `base_git_tree` is absent and
`base_digest_kind` is `weak` or `strong`.

- `weak` (the default for a directory) is the issue.
- `strong` on a directory is a *supplied* `--base-digest` claim. The mount path
  never rehashes a directory: it compares the recorded `base_weak_digest`
  manifest and the claim. So it has the same hole and is pinned too. (This
  answers the "confirm strong needs no pins" question: not for directories.)
- `none` asked for no identity; it is kind-only by design (docs:
  "`none` accepts copies") and records no pins.
- Archive bases (strong or pending digest), Git trees and remote bases are not
  pinned. A Git tree id covers content. An archive's identity is checked by
  `overlay verify` by rehashing its bytes; its cheap mount check (stamp or
  cached digest) has the analogous same-size/restored-mtime limit, which is
  already documented. Pinning archive members would decompress them on every
  reuse; out of scope (residual).

The scope is decided from the meta rows inside the seal transaction, after the
accepted or forced identity is written, never from the caller's token.

## Storage and seal binding

- New table, created by `overlay seal` beside `seal_rows`:
  `seal_preimages(path TEXT PRIMARY KEY, kind TEXT, mode TEXT, size INTEGER, hash TEXT)`.
- New meta row `base_preimage_digest` = `sha256:` over
  `"ratarmount-preimage-pins-v1\0" layer_digest "\0"` followed by every pin
  sorted by path as `path\0kind\0mode\0size\0hash\0`.

Binding: the digest includes the layer digest, so pins left by another seal
(e.g. an older build that unsealed and resealed without knowing the table) do
not validate. `verify` recomputes the expected pins from the change set and
compares them with the table, so an edited pin row is reported against the
real base; the meta digest additionally catches a deleted or added row. A
table with rows and no meta row is also a failure (meta row stripped).

The canonical hash, `layer_digest`, `CANONICAL_HASH_FORMAT` (still `2`),
`seal_rows`, the sentinel and `stack_digest` are unchanged: the golden fixture
and `test-harness/canonical-hash/reference.py` are untouched. `meta.json` in a
bundle carries the new meta row because it is a copy of the meta table.

`unseal` deletes the table and the meta row with the other seal rows.

## Bundles

The layer database travels in the bundle as a `VACUUM INTO` copy, so the table
travels with it, and `meta.json` must equal the database's meta (checked at
unpack and at every bundle-cache hit), so the meta row travels too. There is no
table or key allowlist in `bundle_meta`, `immutable_meta`, `extract` or fsck.
The bundle layout (`bundle.json` `bundle_format` 1) is unchanged: it describes
TAR members, not database contents. An older build reads a pinned bundle and
ignores the pins; this build reads an old bundle as unpinned.

A forced or moved-base `overlay pack` (`--force-base-mismatch`, accepted move)
already refuses when the change set on the new base differs from the sealed
one; it now also refuses when a pin differs, with the same unseal/reseal
advice, so a bundle never names a base its pins do not describe.

## Checks on reuse

1. **`overlay_seal::verify`** (used by `overlay verify`, `unpack`, the bundle
   cache fill and every bundle-cache hit without a trusted marker): compares
   recorded and recomputed pins, checks the binding, folds a failure into `ok`
   and lists the paths in a new `preimage_mismatched` field (`--json` too).
2. **`overlay_seal::check_preimages`** (cheap): hashes only the pinned paths in
   the view beneath the layer and checks the binding. Called by
   `MountLowerStack` for **every sealed lower**, directory or bundle, before
   composing it: mount `--lower`, `-w` tops over a stack, read-only stacks,
   `diff`/`verify`/`seal`/`pack` of a top over lowers, and the sandbox
   supervisor's child mounts. The refusal names the lower, the paths (at most
   ten, then a count) and the remedies: restore the base, or reseal the layer
   over this base (`overlay unseal --i-know`, then `overlay seal
   --force-base-mismatch`), or record a strong identity for an archive copy.
   `--force-stack-mismatch` does **not** bypass it: the flag accepts a base the
   cheap identity disagrees with, but pins describe the layer's own meaning, so
   the remedy is a reseal.
3. **`diff`** of a top over sealed lowers composes them itself; it checks each
   sealed lower's pins against the view beneath it the same way.
4. **`overlay pack`** of a moved/forced base: see Bundles.

Nested lowers: pins of lower N are hashes of what the view beneath it (base +
lowers 0..N-1) served at seal time, because `compare_paths` resolves the base
side through that composed view. `MountLowerStack` checks lower N against the
same composed view, so a path the layer below serves is checked against that
layer (sealed, immutable) and a path the base serves against the base.

The sandbox supervisor's own admission (`check_stack`) already refuses weak
lowers and is unchanged; a strong-claimed directory lower it admits is checked
by the child's `MountLowerStack` and surfaces as `mount_failed`, as a child's
bundle verification failure does today.

## Behaviour table

| Base change of a pinned path | Weak mount gate | Pins |
|---|---|---|
| none | accept | accept |
| `touch` only (mtime) | refuse (manifest) | accept: content unchanged |
| same size, restored mtime, other bytes | accept | **refuse** (was accepted) |
| edit to the layer's bytes, restored mtime | accept | refuse (verify also: change vanished) |
| chmod | accept (mode not in manifest) | refuse (mode in pin) |
| byte-identical copy at another path (other mtimes) | n/a (offline) / `--base-digest` | accept |
| copy whose pinned file has another mode | n/a | refuse (pins are stricter than the strong directory digest) |

## Compatibility

- Seals made before #341 (no meta row, no table): unchanged behaviour;
  documented. `overlay unseal --i-know` + `overlay seal` adds pins.
- A pinned layer read by an older build: pins ignored (older behaviour).
- `overlay seal` re-run on a sealed layer finishes the recorded seal and does
  not add pins (it never rehashes).
- `--force-base-mismatch` seal: the pins are measured on the base actually
  used, as the forced seal records that base.

## Corner cases

- **Unreadable base file** in a pinned position: the seal already fails in
  `compare_paths` (it hashes the base side); unchanged, documented. On reuse an
  unreadable or vanished pinned path is a mismatch (`missing` / read error
  names the path).
- **Symlinks in the base**: the pin hashes the target bytes; a retargeted
  symlink with the same target length is now refused. Lookups go through
  `safe_lookup`, which refuses to look through symlinked ancestors, so a path
  under a now-symlinked directory reads as missing.
- **Excluded paths**: `base_weak_excludes` (journals, lowers, overlays inside
  the base) are not base content and are never canonical rows, so never
  pinned. Seal excludes nothing else.
- **mtime-only touch**: accepted by pins (content hashing); the weak mount
  gate still refuses it at mount, as before.

## Cost

Seal: no extra base reads (the base side is already hashed); one insert per
pin. Reuse: one content read per pinned file (the files the layer modified or
deleted), never the whole base. Measured with `regression_preimage_pin_timing`
(`--release`, aarch64, ext4; 1000 modified files of 64 KiB):

| Step | pinned (`weak`) | unpinned (`none`) |
|---|---|---|
| `overlay seal` | 0.378 s | 0.366 s |
| `MountLowerStack::open_in` (reuse check) | 0.155 s | 0.002 s |
| `overlay_seal::verify` | 0.321 s | 0.335 s |

The reuse cost is reading the 64 MiB of pinned files; it scales with the bytes
the layer modifies or deletes, not with the base.

## Alternatives considered

- **Version the canonical hash to include the base hash** (format 3). Rejected:
  `check_hash_format` refuses other formats, so every existing seal would need
  a reseal; `diff --hash`, `stack_digest` and the `lower_layers` prefix checks
  all key on the current digest; and the layer digest would stop being
  base-independent for strong bases.
- **Refuse weak directory bases for `--lower`** unless explicitly allowed.
  Rejected as the only fix: weak directory lowers are the default workflow, and
  supplied strong digests on directories have the same hole. It remains the
  answer for the sandbox supervisor, which already requires strong/git-tree.
- **Pin by size/mtime triple only.** Rejected: the bug is exactly an edit that
  keeps both.
- **Always pin (every base kind).** Rejected: extra reads of archive members or
  remote objects on every reuse for identities that are already content-based
  or explicitly `none`.

## Residual limits

- Edits of base files the layer does not modify or delete are still invisible
  to a weak identity (unchanged contract; use `--base-digest`).
- Archive bases: the cheap mount check has the analogous same-size,
  restored-mtime limit; not pinned (see "Which seals record pins").
- `diff` run on the sealed layer itself (as the top) compares against the base
  as it is now and does not consult its pins.
- The sandbox supervisor's attempt `diff`/`finalize` compose the lowers the
  child mounted without rechecking pins after the mount; a base edited while
  an attempt runs is seen at the next mount.
- A weak-directory bundle lower hashes its pinned files twice per use (bundle
  verification, then the pin check); each supervisor child repeats the check.
- Resealing a lower to accept a changed base changes its `sealed_at`, so tops
  that recorded the old lower then fail their stack check (as with any reseal).
- An adversary able to rewrite the overlay database without resealing can drop
  the pins together with their meta row (threat model).
