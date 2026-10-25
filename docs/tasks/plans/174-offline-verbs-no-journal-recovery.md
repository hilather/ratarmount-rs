# #174 — Offline verbs recover commit journals through the factory with no #150 guard

Re-scoped 2026-10-25 (Keystone/Matt): keep the `recover_journals: false` flag and
the two read-only refusals, narrow every new symbol below public API, and drop
the `file://` base resolution (moved to a follow-up issue, filed separately by
the orchestrator: "Offline verbs on `file://` bases"). The earlier sweep of this
plan (old scope) lives in `~/src/mud-logs/174.gate.old-scope`.

## Problem

`classify_offline` (`ratarmount/src/base_identity.rs`) opens the base for every
offline verb — `overlay seal`, `overlay pack`, `overlay verify`, `diff`,
`overlay import`, `overlay import-upperdir`, and `sandbox run`'s finish —
through `FactoryOpener` with a mostly-default `OpenOptions`. `recover_journals`
defaults to `true` (`ratarmount-core/src/lib.rs:633`), so the factory at
`ratarmount-session/src/factory.rs:2323` calls
`ratarmount_compositing::recover_journal_at(path, None, Owner::Inode)` before
any identity gate runs.

`Owner::Inode` authorizes any journal that was started for the locked inode —
which a foreign file renamed over the recorded base satisfies (B's journal was
started for B's inode, and B's inode is what the path now resolves to). So an
offline verb next to a foreign or stale journal makes a recovery write that
the mount path (`recover_mount_journals`, `main.rs:4884`) would defer or
refuse, and an offline commit would refuse via `ensure_journal_is_for_archive`.
That undercuts the R7/R10 rule that no recovery write happens before the gate.

Two safety properties of today's (accidental) recovery call must survive the
flip:

- a pending journal started for this inode is *written* by it (the bug);
- a locator in the active (`A`) or complete (`C`) phase whose journal file is
  missing is *refused* by it (`recover` errors with "active journal is
  missing or moved" / `Committed`), keeping a torn archive from being opened.
  `commit_journal::pending()` reports `None` in that case (the header lives in
  the journal file), so a `pending()`-only preflight would miss it.

`--commit-overlay` is already safe: `classify_offline_commit` uses
`factory::served_without_indexing`, which never opens the file and never
recovers. The mount path is safe: `main.rs:1985` sets `recover_journals: false`
and `recover_mount_journals` classifies each member's journal against every
readable overlay record before any write (the subsequent `recover_journal_at`
itself catches the missing-journal locator states). The library
`Session::open` (`session.rs:140`) intentionally recovers with `Owner::Inode` —
the documented "library opener" case, out of scope.

## Approach (agreed in the issue: Keystone/Matt; re-scoped)

Set `recover_journals: false` for the offline-verb classification opens, plus
regression tests with an offline verb next to a foreign journal asserting the
archive and journal are untouched. Additionally refuse, read-only, the journal
states recovery would not safely leave alone: a pending journal started for
the file the name resolves to, or an active/complete locator whose journal is
missing.

**No new public API.** The journal-state probe stays private to
`ratarmount-compress`; the single cross-crate seam is one `#[doc(hidden)]`
helper returning only pre-existing types. `check_offline_journal` lives in
`ratarmount_compositing::journal_recovery` (already a `pub mod`) as
`#[doc(hidden)] pub` — reachable for the `ratarmount` crate's call, but not
added to `lib.rs`'s re-export list. `pending()` keeps its exact main
behaviour.

**Dropped from this change:** resolving `file://` base inputs to their local
path before probing (`remote_url_scheme`/`resolve_to_local` in
`classify_offline_in_memory`), and the `file://` variants of the regression
tests. Behaviour for `file://` bases returns to what `main` does: the probe
runs on the typed path (a `file://` literal names no local file, so it probes
to "no journal"), while `recover_journals: false` still prevents any recovery
write through the factory open. Probing through `file://` resolution is a
follow-up issue ("Offline verbs on `file://` bases"), filed by the
orchestrator — not by this PR.

## Changes

### `ratarmount-compress/src/commit_journal.rs`

All private (module-internal) — replaces the previously public
`LocatorPhase`/`JournalState`/`journal_state`:

```rust
/// What the shared read-only probe found at `archive`.
enum JournalProbe {
    /// Neither a locator nor a journal file is present.
    None,
    /// A journal file is present; the header says whose it is.
    Pending(PendingJournal),
    /// A locator in the recorded phase (`P`/`A`/`C`/`D`) names a journal
    /// that cannot be found.
    Missing(u8, PathBuf),
    /// The located journal entry is not a regular file: an error for a
    /// caller reproducing recovery's refusals, but historically tolerated
    /// as `Ok(None)` by [`pending`].
    NotRegular,
}

fn journal_probe(archive: &Path) -> io::Result<JournalProbe>   // cfg-dispatches to unix::
```

`unix::journal_state` becomes `unix::probe` returning `JournalProbe`: same
open tolerances as the old `pending` probe (directories,
`NotFound`/`NotADirectory`/`PermissionDenied` → `None`); locate → present ⇒
read header ⇒ `Pending`; absent ⇒ `Missing(phase_byte, path)` when a locator
exists, else `None`; a non-regular journal entry yields `NotRegular` instead
of erroring inside the probe so each caller picks its own tolerance.

`pending()` is reimplemented on the shared probe and is provably identical to
main: `Pending → Some`, everything else (`None`, `Missing`, `NotRegular`) →
`Ok(None)` — exactly the old `Ok(None)` arms — and probe `Err`s propagate on
the same conditions (unreadable archive/journal, bad magic). The one
behaviour the old in-line rewrite changed — a non-regular journal entry now
errored — is restored to `Ok(None)` via `NotRegular`.

The only cross-crate export, hidden (unavoidable: `pub(crate)` cannot reach
`ratarmount-compositing`); introduces no new types:

```rust
/// Read-only journal probe backing
/// `ratarmount_compositing::journal_recovery::check_offline_journal` — the
/// offline-open rule's only view, in one pass. Hidden cross-crate seam; not
/// public API. Returns the pending journal's header when a journal file is
/// present, and the locator's phase word and journal path when a locator in
/// the active or complete phase names a journal that cannot be found — the
/// states a recovery would refuse.
#[doc(hidden)]
pub fn offline_journal_probe(
    archive: &Path,
) -> io::Result<(Option<PendingJournal>, Option<(&'static str, PathBuf)>)>
```

`Missing(b'A'|b'C', path) → (None, Some(("active"|"complete", path)))`;
`NotRegular → Err` (matching recovery); `Missing(P|D)` and `None` →
`(None, None)`.

### `ratarmount-compositing/src/journal_recovery.rs`

```rust
/// The journal rule an offline open owes a base. Journals are never applied
/// here — recovery is a mount's or a commit's write — but the states a
/// recovery would refuse stay refused, read-only: a pending journal that was
/// started for the file `member` resolves to now, or an active/complete
/// locator whose journal is missing or moved. A prepare/done locator without
/// its journal (nothing was replaced / the commit finished; mounts clear or
/// tolerate those) and a journal naming another inode are not refused.
#[doc(hidden)] // cross-crate seam for ratarmount's offline classification
pub fn check_offline_journal(member: &Path) -> io::Result<()>
```

Body calls `commit_journal::offline_journal_probe(member)?` once and reuses
the private `owns()` inode check already in this module:

- `Some(header)` + `owns(&header, member)` → `Err`: "carries a pending commit
  journal … recover it first (`ratarmount --no-mount BASE`)".
- `Some((phase, path))` → `Err` mirroring recovery's wording: "carries a
  {phase} commit-journal locator but its journal {path} is missing or moved;
  recover it through the archive's current directory name, or verify the
  archive and remove its `user.ratarmount.commit-journal` xattr".
- Otherwise `Ok`; probe errors propagate.

**Not** added to `lib.rs`'s `pub use journal_recovery::{…}` list — the module
is already `pub`, so `ratarmount` calls
`ratarmount_compositing::journal_recovery::check_offline_journal`. That is the
narrowest reachability the cross-crate call allows. `commit_journal`'s write
entry points stay named only by `journal_recovery` (`clippy.toml`);
`offline_journal_probe` is read-only and needs no entry there.

### `ratarmount/src/base_identity.rs`

In `classify_offline_in_memory`, before building `OpenOptions`:

1. `ratarmount_compositing::journal_recovery::check_offline_journal(base)`
   → `Err` refuses the classification. The probe runs on the path as typed —
   no `file://`/remote resolution (dropped; see above): a `file://` or remote
   literal names no local file, the probe sees no journal, and
   `recover_journals: false` still guards the factory open.
2. `recover_journals: false` in the `OpenOptions` literal — the flag is what
   guarantees no recovery write regardless of the probe (foreign-inode
   sibling journals slip the refusal by design; anything raced in after the
   probe is never applied; `file://` bases the probe cannot see are never
   recovered).
3. Doc comments of `classify_offline`/`classify_offline_in_memory`: the
   classification open never recovers a commit journal and refuses a base
   whose journal state recovery would refuse.

### `docs/sandbox.md`

Keep the sentence added in the "Commits and the base" journal paragraph:
offline verbs (`overlay seal`/`pack`/`verify`, `diff`, `overlay import`, the
`sandbox run` finish) never recover; a base carrying a pending journal for
its own inode or a dangling active/complete locator is refused, left for a
mount or `--no-mount` to recover. It already describes only the kept scope —
no `file://` mention.

### `AGENTS.md`

Keep the regression-catalog row, trimmed to kept parts (drop "also via
`file://`"): "Offline verbs (`seal`/`pack`/`verify`/`diff`/`import`, `sandbox
run`) never recover a pending commit journal: `recover_journals: false` on
the classify open plus a read-only journal-state refusal leave a foreign
journal (B renamed over A) and the archive byte-identical; a missing
active/complete journal still refuses; a foreign-inode sibling journal and a
stale `D` locator do not block (#174)" with commands:

`cargo test -p ratarmount --bin ratarmount regression_offline_classify_` ·
`cargo test -p ratarmount --test overlay_base_gate regression_offline_verbs_` ·
`cargo test -p ratarmount-compress --lib regression_pending_tolerates_nonregular_journal`

## Regression tests

All journal tests are gated `#[cfg(any(target_os = "linux",
target_os = "macos"))]` — `replace_suffix_with_hook` returns `Unsupported`
elsewhere. That includes the CLI helpers/tests in `overlay_base_gate.rs`,
which currently carry the looser `#[cfg(unix)]`: narrow `have_gnu_tar`,
`crash_commit` and both new tests to the linux|macos guard so other Unix
targets never invoke the unsupported journal seam. `replace_suffix_with_hook`
is on `clippy.toml`'s `disallowed-methods` (test-only death seam): the helpers
get a narrowly scoped `#[allow(clippy::disallowed_methods)]` like
`overlay_offline_commit.rs:7`.

Crash helpers (already in the tree, hook-step names verified in `unix::run`):
fail `"archive truncate"` for torn (marker `A`, journal present), `"locator
complete"` for complete (`C`), then optionally `fs::remove_file` the journal
for the missing variants; `"journal unlink"` leaves marker `D` with the
journal already gone (the allowed missing-journal case).

### Unit — `ratarmount-compress/src/commit_journal.rs` `mod tests`

`regression_pending_tolerates_nonregular_journal` (new, linux|macos — the
journal probe lives in `unix::`): create `base.tar`, then a **directory** at
the sibling journal path `journal_path(&base)`. Assert
`commit_journal::pending(&base)` is `Ok(None)` — the exact contract `pending`
had before the probe refactor — while `offline_journal_probe(&base)` is
`Err`. This pins the `NotRegular` split: tolerated by `pending()`, refused by
the offline check the way recovery refuses it.

### Unit — `ratarmount/src/base_identity.rs` `mod tests`

Already in the tree; one trim: the `file://` input variant is removed from
`regression_offline_classify_refuses_pending_commit_journal` (the `file://`
probe path is dropped scope — the follow-up issue owns it).

`regression_offline_classify_refuses_pending_commit_journal` (kept, minus
`file://`):

- For `complete` in `[false, true]`: write `foreign.tar`, crash it, snapshot
  archive and journal bytes, `fs::rename` over `base.tar` (journal found via
  the inode locator, not the sibling name), call `classify_offline(base,
  GitIntent::Replay(None), &ctx)`.
- Assert `Err` naming the pending journal / recovery instruction; archive and
  journal byte-identical; `commit_journal::pending(base)` still `Some`.
- Own-name variant (journal created on `base.tar` itself) — same assertions.

`regression_offline_classify_missing_commit_journal` (kept):

- `A` and `C` variants: crash `base.tar`, delete the journal file, call
  `classify_offline` → `Err` naming the missing journal / xattr escape;
  archive byte-identical; the locator is left alone (journal absent).
- `D` variant: crash at `"journal unlink"` → `classify_offline` succeeds — a
  finished commit's stale locator does not block verbs.

`regression_offline_classify_ignores_foreign_sibling_journal` (kept — pins
`recover_journals: false`; this case reaches the factory open):

- Create `victim.tar`, crash it torn, copy its journal file to
  `base.tar.ratarmount-commit-journal` beside a fresh `base.tar` (header names
  `victim`'s inode — probe returns `Pending` but `owns` fails, so the refusal
  does not fire).
- Assert `classify_offline` **succeeds** and `token.source().lookup("/f", 0)`
  finds the member; archive and journal file byte-identical. Under
  `recover_journals: true` the factory's `recover_journal_at` + `Owner::Inode`
  refuses the inode mismatch and the open fails — this test fails if the flag
  is dropped.

### CLI — `ratarmount/tests/overlay_base_gate.rs`

Kept except the cfg narrowing noted above (no `file://` there):
`regression_offline_verbs_leave_pending_commit_journal_untouched` and
`regression_offline_verbs_refuse_missing_commit_journal` over
`[Seal, Pack, Diff, Verify]` × `complete ∈ [false, true]`, GNU-tar skip via
`have_gnu_tar()`; asserts non-zero exit, untouched archive/journal bytes, no
seal, no bundle.

## Dropped (follow-up issue: "Offline verbs on `file://` bases")

- `remote_url_scheme`/`resolve_to_local` resolution in
  `classify_offline_in_memory` and the `file://` variants of the pending-
  journal unit test. Until then, a `file://` base that carries a pending
  journal is *not recovered* (the flag sees to that) but is also *not
  refused* by the probe — classification proceeds and the base gate decides,
  exactly the flag-only behavior this issue's agreed fix required.

## Out of scope / non-goals

- `Session::open` keeps its documented `Owner::Inode` library-opener recovery.
- `--commit-overlay` and the mount path already gate recovery correctly.
- Verbs never *apply* a journal; recovery is `ratarmount --no-mount`, a mount,
  or a `--commit-overlay` retry, all under the record-vote/`Owner` rules.
- A pending journal naming another inode (stale sibling junk) and a
  `P`/`D` locator whose journal is gone neither refuse nor recover — behavior
  change vs. today (hard refusal / marker clear) is intended: verbs only
  refuse what recovery would have refused anyway.
- `overlay digest-base`/`info`/`fsck`/`unpack` never open the base through the
  factory; unaffected.
- No new public API: nothing in this change is reachable as stable surface
  beyond `#[doc(hidden)]` cross-crate seams.

## Validation

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p ratarmount --bin ratarmount regression_offline_
cargo test -p ratarmount --test overlay_base_gate regression_offline_verbs_
cargo test -p ratarmount-compress --lib regression_pending_tolerates_nonregular_journal
cargo test -p ratarmount --test overlay_offline_commit
cargo test -p ratarmount-compress --lib
cargo test -p ratarmount-compositing --lib
cargo test --workspace    # bounded; note pre-existing failures vs. new ones
```
