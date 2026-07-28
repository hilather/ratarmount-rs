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

## Releases / package builds (do this properly)

Tagging alone is not enough: **`Packages` must publish a GitHub Release with real
assets** (`.deb` / `.rpm` / portable tarballs / cosign bundles). Workflow:
[`.github/workflows/packages.yml`](`.github/workflows/packages.yml`).

### Version bump checklist

1. Bump **workspace** `version` in root [`Cargo.toml`](Cargo.toml).
2. Bump every `VERSION: "x.y.z"` env in [`.github/workflows/packages.yml`](.github/workflows/packages.yml)
   (deb / rpm / portable / macos jobs).
3. Update README version strings that mention the release tag.
4. `cargo test -p ratarmount-compress --lib` (and full workspace when touching more).
5. Commit on `main`, then **annotated tag** `vX.Y.Z` matching Cargo version.
6. `git push origin main && git push origin vX.Y.Z`.

### What “success” looks like

| Check | Pass criteria |
|-------|----------------|
| Matrix jobs (`deb` / `rpm` / `portable` / `macos`) | Build artifacts uploaded |
| **Sign & release** | Creates/updates GitHub Release for the tag |
| [github.com/…/releases](https://github.com/hilather/ratarmount-rs/releases) | Tag has **package** assets (not only tiny sidecars) |
| Workflow overall | Prefer green; macOS-only failure is OK if Linux packages published |

**Workflow “failure” with empty Releases is not a release.** Builds may still
leave a downloadable **`signed-release-bundle`** Actions artifact (expires).

### Known failure modes (do not thrash tags)

1. **Empty upload files** — GitHub rejects 0-byte assets (e.g. empty `file-info.txt`).
   Flatten/upload **must skip size 0**. Symptom: release created, few tiny assets, job red.
2. **Permissions** — job needs `contents: write` (workflow already sets this). If
   `POST /releases` is 403, check repo **Settings → Actions → Workflow permissions**
   = Read and write.
3. **Do not** keep bumping `v0.1.N` to “debug” without reading **annotations** /
   the Create Release step. Prefer REST create + `::error::` / `::notice::` so
   failures are visible without private job-log auth.
4. Stuck legacy runners (e.g. scarce `macos-13`) — drop or pin to available labels;
   do not block Linux packages on one matrix leg forever.

### After a bad tag

- Prefer a **new patch tag** with the fix (do not rewrite published tags).
- Incomplete releases (e.g. only `SHA256SUMS`) can stay; next tag supersedes.
- Optional: edit notes on the incomplete release pointing at the next tag.

Full packaging user docs: [`docs/packaging.md`](docs/packaging.md).

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
