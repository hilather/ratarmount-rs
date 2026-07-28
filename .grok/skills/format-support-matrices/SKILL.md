---
name: format-support-matrices
description: >
  Keep ratarmount-rs format / nested / temp-file support matrices up to date when
  changing open paths, AutoMount, factory nested openers, or materialize behavior.
  Use when editing open_nested_reader_fn, open_nested_fn, try_mount_file, MountSource::open
  for archives, temp spool, materialize, or when the user mentions nested archives,
  /tmp, embedded formats, or support matrices. Slash: /format-support-matrices.
---

# Format support & temp-file matrices (keep current)

## Why this exists

Users rely on **documented** answers to:

- Which formats open nested archives **without** writing to `/tmp`?
- Which stacks still **spool / materialize**?
- Is nested random read real, or only “works after inflate”?

Stale matrices cause wrong expectations after code landings. **Code change without matrix update is incomplete.**

## Canonical docs (update these)

| Priority | Path | Content |
|----------|------|---------|
| **P0** | [`docs/embedded-nested-archives.md`](../../../docs/embedded-nested-archives.md) | Nested open flow, no-tmp vs temp, parent×nested table, random-read cost, debug logs |
| **P0** | [`README.md`](../../../README.md) | Short nested cheat sheet + link (must match P0) |
| **P1** | [`docs/parity-todo.md`](../../../docs/parity-todo.md) | Feature table rows for AutoMount / formats when status flips |
| **P1** | [`docs/tasks/embedded-nested-random-access.md`](../../../docs/tasks/embedded-nested-random-access.md) | Implementation checklist / capability matrix IDs (N0…) |
| **P2** | [`docs/tasks/gap-implementation-batch.md`](../../../docs/tasks/gap-implementation-batch.md) | Batch status line for nested/tmp work |
| **P2** | Crate module docs (`//!` in sevenzip/tar/zip/factory) | Only if behavior claim is in crate docs |

Do **not** invent a third competing matrix. Edit **embedded-nested-archives.md** first, then sync README one-liners.

## When you **must** update matrices

Any change that affects:

1. **`open_nested_reader_fn`** / nested magic detection (new format, remove path, gzip→tar, etc.)
2. **`open_nested_fn`** or AutoMount **temp spool** conditions
3. Parent **`MountSource::open`** for nested bodies (store vs deflate vs solid, seekable vs not)
4. Top-level **materialize** vs seekable body (plain `.gz`, SquashFS, lrzip, remote Range)
5. TAR **flatten** limits / nested-without-AutoMount behavior
6. Explicit user-facing claims about `/tmp`, “no temp”, or “true random access”

If unsure: update **P0** with a one-line row change rather than leaving docs silent.

## What to write (checklist)

For each affected stack, document honestly:

- [ ] **Nested no-tmp?** yes / no / partial (e.g. no disk but full inflate to RAM)
- [ ] **Parent open model** (stencil, inflate buffer, progressive solid, path-only)
- [ ] **Nested open model** (from_reader, seekable compress→TAR, path after spool)
- [ ] **Random read quality** (cheap pread vs checkpoint decompress vs full member inflate)
- [ ] **Fallback** still goes to temp spool when magic unknown or open fails
- [ ] **Tests** exist or residual noted (don’t claim no-tmp without a regression test when practical)

## Code map (where behavior lives)

| Behavior | Primary location |
|----------|------------------|
| Nested magic + no-tmp open | `ratarmount/src/factory.rs` → `open_nested_reader_fn` |
| Path open after spool | `ratarmount/src/factory.rs` → `open_nested_fn` |
| Prefer reader then spool | `ratarmount-compositing/src/automount.rs` → `try_mount_file` |
| TAR from_reader / gzip body / flatten | `ratarmount-formats-tar` |
| ZIP store / deflate open | `ratarmount-formats-zip` |
| 7z store / progressive / solid | `ratarmount-formats-sevenzip` |
| Top-level compress materialize | `ratarmount/src/factory.rs` + `ratarmount-compress` |

## Agent / subagent rules

1. **Same PR / commit as the behavior change** when possible — don’t leave “docs later”.
2. Worktree subagents that own **factory**, **automount**, or a **format `open` path** must include matrix updates in their Deliverable (or hand orchestrator an explicit “docs delta” if docs are out of ownership).
3. Orchestrator after merge: skim `docs/embedded-nested-archives.md` vs the diff; fix drift before push.
4. Never claim “all nested formats avoid `/tmp`” — only the matrix rows that are implemented.

## Deliverable snippet (paste when spawning related work)

```text
## Docs (format / temp matrices)
If this changes nested open, materialize, or MountSource::open for archives:
1. Update docs/embedded-nested-archives.md (P0) to match code.
2. Sync README nested cheat sheet if the short table changes.
3. Tick/adjust docs/tasks/embedded-nested-random-access.md rows if applicable.
4. Prefer a regression test for new no-tmp paths (factory or automount).
```

## Related

- Always-on: root `AGENTS.md` (points here)
- Worktrees: skill `ratarmount-worktree-subagent`
- User-facing guide: `docs/embedded-nested-archives.md`
