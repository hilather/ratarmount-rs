---
name: release-tag-ci-watch
description: >-
  After tagging a ratarmount-rs release, watch GitHub Actions until green (or
  fix and re-tag). Use whenever tagging v*, pushing a release tag, or the user
  asks to release / ship packages.
---

# Release tag → watch CI (mandatory)

**Never treat `git push origin vX.Y.Z` as done.** Tagging starts CI; agents must
**monitor workflows**, fix failures, and harden so the same class of bug does
not recur on the next tag.

## When this applies

- User asks to **tag**, **release**, **ship packages**, or **publish**
- You create or push an annotated tag `v*`
- You bump workspace version for a release

## Procedure (every release)

### 1. Pre-tag (same commit as the tag)

```bash
# Version matches tag (no hardcoding VERSION in packages.yml — resolve from Cargo/tag)
# root Cargo.toml workspace.version == X.Y.Z for tag vX.Y.Z

cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace   # or scoped if docs-only; prefer full before tag

# Official gh CLI (not PyPI gh browser opener)
gh version   # expect: gh version 2.x … github.com/cli/cli
```

Update docs that claim the new version only if they hardcode a tag string.

### 2. Commit, annotated tag, push

```bash
git push origin main
git tag -a "vX.Y.Z" -m "Release vX.Y.Z: <one-line summary>"
git push origin "vX.Y.Z"
```

Do **not** force-push or rewrite a published tag. Bad tags → new patch version.

### 3. Watch CI (blocking until green or residual policy)

Track at least:

| Workflow / job | Role |
|----------------|------|
| **`fmt + clippy + test`** (`check`) | Hard gate: fmt first, then clippy/test; FUSE allowlists need `check` |
| **Packages** (tag `v*`) | deb / rpm / portable / macos matrix + **Sign & release** |
| Other required branch workflows | cold-index gates, macOS build, etc. |

```bash
# List runs for this tag / commit
gh run list --branch "vX.Y.Z" --limit 15
# or
gh run list --commit "$(git rev-parse HEAD)" --limit 15

# Watch the important runs (blocks until complete)
gh run watch <run-id> --exit-status
```

Repeat until:

1. **`fmt + clippy + test`** is green, and  
2. **Packages** either green or only macOS-leg failure **with** Linux package assets published on the GitHub Release.

### 4. Verify the GitHub Release is real

```bash
gh release view "vX.Y.Z"
# Expect: .deb / .rpm / portable tarballs / cosign sidecars — not only empty/tiny files
```

Empty release or **Sign & release** failure with no package assets = **failed release**, not “CI later.”

### 5. If CI fails — fix and harden

1. Pull logs: `gh run view <id> --log-failed` (or job annotations).
2. Fix the root cause on `main` (code, workflow, packaging scripts).
3. **Harden** so the failure mode is harder next time (workflow check, unit test under `packaging/`, skip 0-byte assets, runner label, busy_timeout, etc.).
4. Bump to **new patch** `vX.Y.(Z+1)` if the tag already fired Packages / public Release; do not retag the same `vX.Y.Z`.
5. Re-run watch from step 3.

### 6. Residual OK only when documented

| Residual | OK? |
|----------|-----|
| macOS matrix red, Linux packages on Release | Yes (note in response) |
| fmt/clippy/test red | **No** — fix before calling release done |
| Packages red, no usable assets on Release | **No** |
| “Packages still running” without watching | **No** — stay until settled |

## Agent checklist (copy into release turns)

- [ ] Workspace version = tag body (`vX.Y.Z` ↔ `X.Y.Z`)
- [ ] fmt / clippy / tests green locally before tag
- [ ] Annotated tag pushed
- [ ] `gh run list` / `gh run watch` for tag commit
- [ ] `check` green
- [ ] Packages published assets on Release (or explicit macOS-only residual)
- [ ] Failures fixed **and** hardened for next tag

## Related project docs

- Root [`AGENTS.md`](../../../AGENTS.md) — Releases / package builds
- [`docs/packaging.md`](../../../docs/packaging.md) — packaging user guide
- Skill **`format-support-matrices`** if the release changes nested open behavior (docs in same change)
