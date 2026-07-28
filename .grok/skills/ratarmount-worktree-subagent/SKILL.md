---
name: ratarmount-worktree-subagent
description: >
  Protocol for parallel worktree subagents on ratarmount-rs (parity batches, non-overlapping
  crate ownership, fmt/clippy/test before commit). Use when spawning isolation=worktree
  subagents, running multi-agent gap batches, or when the user mentions worktree agents,
  parallel subagents, or cherry-pick merges. Slash: /ratarmount-worktree-subagent.
---

# ratarmount-rs worktree subagent protocol

## When the orchestrator spawns children

1. Give each agent **non-overlapping ownership** (prefer whole crates or named files only).
2. Paste the **Deliverable** block below into every `spawn_subagent` prompt.
3. After children finish: `git fetch` worktree tips → `git cherry-pick` → run full workspace gates → document in `docs/tasks/gap-implementation-batch.md` if parity work.

## Ownership rules

| Rule | Detail |
|------|--------|
| Prefer one crate | e.g. only `ratarmount-formats-zip/**` |
| Shared glue | Leave `ratarmount/src/factory.rs` and root `Cargo.lock` to orchestrator unless the task explicitly owns factory |
| Compress splits | Different files only (`gzip_seek.rs` vs `bzip2_seek.rs`); minimize concurrent `lib.rs` edits |
| Docs | Agents may update their crate README; living parity tables are orchestrator or docs-only tasks |

## Deliverable block (paste into every spawn prompt)

```text
## Deliverable
1. Stay within owned paths only.
2. Before commit, from the worktree root:
   cargo fmt --all
   cargo clippy -p <YOUR_CRATE(S)> --all-targets -- -D warnings
   cargo test -p <YOUR_CRATE(S)>
3. CI fails on `cargo fmt --all -- --check` first — unformatted code reds the whole suite
   and skips the FUSE harness (`needs: check`).
4. One commit on this worktree branch. Do not push.
5. Report: commit SHA, files changed, residual limits, verify command results.
```

## Verify commands (agent)

Scoped (preferred):

```bash
cargo fmt --all
cargo clippy -p ratarmount-formats-zip --all-targets -- -D warnings
cargo test -p ratarmount-formats-zip --lib
```

Multi-crate ownership:

```bash
cargo fmt --all
cargo clippy -p crate-a -p crate-b --all-targets -- -D warnings
cargo test -p crate-a -p crate-b
```

## Orchestrator after merge

```bash
cargo fmt --all
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
# optional: ./benchmarks/check-rust-gates.sh
```

Then push only when the user asked to publish.

## Common failures

| Symptom | Cause | Fix |
|---------|--------|-----|
| CI red on first step | Missing rustfmt | `cargo fmt --all` before commit |
| FUSE job skipped | `check` job failed | Fix fmt/clippy/test first |
| Cherry-pick `lib.rs` conflicts | Two compress agents | Re-order picks; re-export carefully |
| Nested open regressions | Flattened TAR index | Tests may use flatten without AutoMount reader |

## Related docs

- Always-on: root `AGENTS.md`
- Parity: `docs/parity-todo.md`, `docs/tasks/gap-implementation-batch.md`
- Dual-run / crates.io: `docs/phase12-dual-run.md`, `docs/crates-io-policy.md`
