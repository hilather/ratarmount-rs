# ratarmount-rs — agent instructions

Always-on conventions for Grok (main session and subagents). Keep this file short; longer procedures live in `.grok/skills/`.

## CI gates (non-negotiable)

GitHub Actions job **`fmt + clippy + test`** runs **`cargo fmt --all -- --check` first**. If formatting fails, the job never reaches clippy/test, and **`FUSE phase allowlists` is skipped** (`needs: check`).

Before every commit (including worktree subagent commits):

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # or -p <crate> when scoped
cargo test --workspace                                    # or -p <crate> when scoped
```

Do **not** push code that fails `cargo fmt --check`.

Other CI jobs (cold-index benchmark gates, macOS build) can pass while fmt fails — do not treat those alone as “green CI”.

## Workspace layout

Rust workspace under `ratarmount-*` crates; binary is `ratarmount/`. Prefer non-overlapping crate ownership when parallelizing. Orchestrator owns `ratarmount/src/factory.rs` glue unless a task explicitly owns factory.

## Subagents / parallel worktrees

For isolation=`worktree` tasks, follow skill **`ratarmount-worktree-subagent`** (`.grok/skills/ratarmount-worktree-subagent/SKILL.md`). Always put a **Deliverable** block in the spawn prompt that includes `cargo fmt --all`.

## Commits

- Prefer complete sentences in commit messages.
- Subagents: **one commit, do not push** unless the user asked to publish.
- Orchestrator: cherry-pick / merge, re-run full fmt + clippy + test, then push when asked.

## Docs

Living parity: `docs/parity-todo.md`, `docs/tasks/gap-implementation-batch.md`.

### Format / nested / temp-file matrices (keep current)

**Code that changes how archives open, nest, or use `/tmp` must update the support matrices in the same change.** Stale tables mislead users about embedded random access and temp spool.

| Doc | Role |
|-----|------|
| [`docs/embedded-nested-archives.md`](docs/embedded-nested-archives.md) | **Canonical** nested no-tmp vs temp matrix + parent×nested behavior |
| [`README.md`](README.md) | Short nested cheat sheet (must match the canonical doc) |
| [`docs/tasks/embedded-nested-random-access.md`](docs/tasks/embedded-nested-random-access.md) | Implementation checklist |

Triggers: `open_nested_reader_fn`, AutoMount spool, format `MountSource::open`, materialize vs seekable body, TAR flatten limits.

Full procedure: skill **`format-support-matrices`** (`.grok/skills/format-support-matrices/SKILL.md`).
