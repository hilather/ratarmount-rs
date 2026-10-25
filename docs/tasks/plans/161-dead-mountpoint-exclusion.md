# Issue #161: remove the dead mount-point weak-digest exclusion

| Field | Value |
|-------|--------|
| **Issue** | #161 — Remove the dead mount-point weak-digest exclusion now that a mount point inside a directory base is refused |
| **Status** | Draft |
| **Scope** | `ratarmount/src/main.rs` (`lower_extra_excludes` + its unit tests), `ratarmount-compositing/src/overlay_meta.rs` (one test rename/re-word), `AGENTS.md` regression-catalog row |

## Background

`ratarmount/src/mount_guard.rs` refuses — with exit 2, before anything is
created — a FUSE mount point that is equal to, inside, or an ancestor of a
folder input or of the `-w` directory. That check is authoritative, so a mount
point can no longer sit inside a directory base. The code that excluded such a
mount point from the base's weak digest is dead:

- `lower_extra_excludes` still takes a `mount_point: Option<&Path>` parameter
  whose only caller (`main.rs`, in the `lower_identity` construction) passes a
  literal `None`, and the mount-point branch inside the function is unreachable.
- The `weak_exclude` mechanism in `ratarmount-compositing` is generic — it is
  populated from `--journal` paths and `--lower` records
  (`main.rs:2355–2360`), not from the mount point — and must stay.

## Changes

### `ratarmount/src/main.rs`

1. `lower_extra_excludes` (≈L4839): delete the `mount_point: Option<&Path>`
   parameter and the `if let Some(mp) = mount_point { … }` block. Rewrite the
   doc comment so it no longer names the mount point: the A2 walk excludes
   "the paths of this invocation (journal, a new `-w` overlay)" and
   "an invocation-only path is excluded only if it is not in the base yet or is
   already in a recorded excluded set".
2. Call site (≈L2298): drop the trailing `None` argument and its comment.
3. `lower_extra_excludes_tests` (≈L9032):
   - Delete `regression_mount_point_excluded_only_when_empty_or_new` — it only
     exercises the deleted branch.
   - Drop the trailing `None` argument from all four remaining calls (the
     remount test calls `lower_extra_excludes` twice).

### `ratarmount-compositing/src/overlay_meta.rs`

4. Rename `regression_mountpoint_inside_base_is_in_the_recorded_excluded_set`
   to `regression_late_created_weak_exclude_is_in_the_recorded_excluded_set`
   and re-word it as the generic "path created after the digest" case: the
   `weak_exclude` paths become journal-style names (`basedir.join("j.jsonl")`
   and `basedir.join("journals/j1")`), and the doc comment says a path the
   caller excluded that is created inside the base after the digest was taken
   no longer changes the weak digest on remount because the recorded excluded
   set covers it. Assertions (`["j.jsonl"]`, `[".ov","journals"]`) keep the
   same topmost-new coverage.

### `ratarmount/tests/overlay_exclusions.rs`

5. Module doc comment (L1–3) still lists the mount point among the digest
   exclusions; drop it (the exclusions are overlay, journal, lowers) — the
   mount-point refusal coverage stays in `mounted::`.

### `AGENTS.md`

6. The regression-catalog row for directory-base weak digests names the
   `cargo test -p ratarmount-compositing --lib regression_mountpoint_inside_base`
   filter; point it at the renamed test so the catalog stays accurate.

## Dedicated regression test for this issue

The renamed test in `overlay_meta.rs` is the dedicated regression coverage:
it locks the generic recorded-excluded-set behaviour the mount-point exclusion
used to rely on, now expressed for the paths that can still reach it
(journal/lower paths created after the digest). Behavioural refusal coverage
already exists: `mounted::regression_mountpoint_inside_directory_base_is_refused_with_exit_two`
and `mounted::regression_default_mount_point_of_directory_base_with_overlay_mounts_and_remounts`
in `ratarmount/tests/overlay_exclusions.rs` stay untouched and must keep
passing.

## Verification

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test -p ratarmount --bin ratarmount lower_extra_excludes`
- `cargo test -p ratarmount-compositing --lib regression_late_created_weak_exclude`
- `cargo test -p ratarmount --test overlay_exclusions`
- `cargo test -p ratarmount --test fuse_mount_in_base`
- `cargo test --workspace` (note pre-existing failures vs. new ones)
