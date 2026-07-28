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

## Tests for every fix (non-negotiable)

**Every bugfix and behavior change must land with automated tests in the same
commit** (or the same PR). “Manual repro only” is not enough.

| Requirement | Detail |
|-------------|--------|
| **Regression test** | Reproduce the failure mode in code; assert the fixed behavior. Name/doc with `Regression:` and a short symptom (e.g. “Dec 31 1969 mtime”). |
| **Layer** | Prefer the lowest layer that catches the bug (parse unit → mount source → factory nested → FUSE helper). Add a higher-layer test if the bug only appears there. |
| **No skip without reason** | If a CLI tool is missing (`7z`, `gzip`), `return` early with `eprintln!("skip: …")` — do not silently pass on the happy path without a pure unit test for the core logic. |
| **Shell/CI** | Workflow-only fixes get a script under `packaging/` or `test-harness/` that CI or agents can run (e.g. empty release asset filter). |
| **Do not land** | Fix commits without new/updated tests, unless the user explicitly waived tests (rare). |

### Regression catalog (keep these green)

Run filters **separately** (`cargo test` does not treat `|` as OR).

| Symptom / fix | Commands |
|---------------|----------|
| Truncated `.gz` / UnexpectedEof (FUSE short read = EOF) | `cargo test -p ratarmount-fuse --lib fill_read` · `cargo test -p ratarmount-compress --lib fuse_style` · `cargo test -p ratarmount nested_large_plain_gzip` |
| Nested gzip concurrent wrong/truncated data | `cargo test -p ratarmount-compress --lib shared_from_reader` · `cargo test -p ratarmount-compress --lib stenciled_fuse` |
| 7z mtimes Dec 31 1969 (FILETIME delta) | `cargo test -p ratarmount-formats-sevenzip --lib filetime` · `cargo test -p ratarmount-formats-sevenzip --lib mtime` |
| Encrypted nested open → EACCES not EIO | `cargo test -p ratarmount-fuse --lib io_to_errno` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted` |
| Write-overlay create then cat empty (size-0 cache) | `cargo test -p ratarmount-fuse --lib overlay_file_info` |
| Plain compress no `/tmp` spool (gz/zstd/bz2) | `cargo test -p ratarmount plain_gzip` · `cargo test -p ratarmount plain_zstd` · nested: `nested_plain_gzip` |
| Nested no-tmp openers (factory wiring) | `cargo test -p ratarmount nested_` (CPIO/AR/WARC/ASAR/CAB/XAR/tar.gz/zip/7z) · crate `open_from_reader` tests for ISO/SQLAR/FAT |
| Nested TAR via AutoMount reader | `cargo test -p ratarmount-compositing --lib automount_nested` |
| GitHub Release dies on 0-byte assets | `./packaging/test-release-asset-filter.sh` |

When you fix a **new** production bug, **add a row** here and ship the test in the same commit.

## Workspace layout

Rust workspace under `ratarmount-*` crates; binary is `ratarmount/`. Prefer non-overlapping crate ownership when parallelizing. Orchestrator owns `ratarmount/src/factory.rs` glue unless a task explicitly owns factory.

## Subagents / parallel worktrees

For isolation=`worktree` tasks, follow skill **`ratarmount-worktree-subagent`** (`.grok/skills/ratarmount-worktree-subagent/SKILL.md`). Always put a **Deliverable** block in the spawn prompt that includes `cargo fmt --all`.

## Commits

- Prefer complete sentences in commit messages.
- Subagents: **one commit, do not push** unless the user asked to publish.
- Orchestrator: cherry-pick / merge, re-run full fmt + clippy + test, then push when asked.

## Feature comparisons & README (every relevant commit)

**When a commit changes user-visible capability, update living docs in the same
commit** (or list an explicit “docs delta” for the orchestrator). Do not leave
README / parity tables stale.

| Trigger | Update |
|---------|--------|
| New/removed/changed format, codec, remote, CLI flag, nested/tmp behavior | [`README.md`](README.md) feature tables + Gaps section if needed |
| Parity status flip (`[x]` / `~` / residual) | [`docs/parity-todo.md`](docs/parity-todo.md) |
| Mount option added/changed | [`docs/mount-options-parity.md`](docs/mount-options-parity.md) |
| Nested open / temp spool | [`docs/embedded-nested-archives.md`](docs/embedded-nested-archives.md) (+ README cheat sheet) |
| Dual-run / packaging product status | [`docs/phase12-dual-run.md`](docs/phase12-dual-run.md) / packaging notes |
| Upstream-inspired feature (from mxmlnkn/ratarmount issues) | [`docs/tasks/upstream-feature-requests.md`](docs/tasks/upstream-feature-requests.md) status row + README **Upstream** link |

If the change is pure refactor/tests with **no** user-facing behavior change, skip
doc updates (still add regression tests per above).

Skill for nested/tmp matrices: **`format-support-matrices`**.
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
