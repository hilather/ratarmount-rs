# Implement the sandbox and grading features in ratarmount-rs

Written 2026-10-17 against `main` at `cc55c8c`. Source document:
`~/Downloads/ratarmount-sandbox-features.md` (revision 2, 2026-10-17,
"sandbox and grading features for agent harnesses and RL loops"). Goal: every
section of that spec is supported. Implementation is done by Codex workers in
git worktrees on branches `sandbox/<id>` off `sandbox/integration`; this session
orchestrates, reviews, merges and runs the gates, as for the Local AI roadmap
(`local-ai-roadmap.md`).

This file is the tracker for the SBX items. Each row's status is updated here
when it merges; README and docs are updated in the same merge.

## 1. Scope decisions

| Decision | Detail |
|---|---|
| In scope | §1–§11 and §13–§15 of the spec, including done-when #9 (kernel overlayfs interop). |
| Design only, as the spec says | §12 `serve-sandboxes` (one daemon, many mounts). |
| Already shipped (§12) | arm64 Linux release binaries (`packages.yml`: ubuntu-24.04-arm, bullseye-arm64) and macOS arm64 tarballs. Non-FUSE subcommands build on macOS through the existing macFUSE build. Making `ratarmount-fuse` an optional dependency, so the subcommands build with no FUSE library, is a residual (see section 2, item 9). |
| Outward-facing | Any `git push` / PR, release tags. Ask the user first. |
| Privileged tests | Done-when #9 (kernel overlayfs `lowerdir`) and `sandbox run` against a real docker/podman are env-gated and run by the orchestrator, not CI gates. CI covers `sandbox run` with a stub runtime (§13). |

## 2. Corrections to the spec (verified in the repo, 2026-10-17)

1. **`diff` already exists (AI-SB2, `ratarmount/src/diff.rs`, `diff/patch.rs`).**
   §2 migrates it to the spec instead of rewriting it. It already has a literal-only
   `GIT binary patch` encoder, an in-house Myers diff, git blob ids on `index`
   lines, type change as delete + add, `T` in `--name-status`, and a `git apply`
   comparison test. The sandbox daemon's `sandbox diff` and the inspection
   socket call `render_source(args, source, deleted)`; those entry points stay.
2. **`diff` base becomes positional.** Today it is a required `--base SOURCE`
   flag. The spec's positional `[BASE]` is adopted; `--base` stays as a hidden
   alias so the daemon and existing scripts keep working.
3. **Renames are delete + add by default.** The current `detect_renames` emits
   `R100` / `rename from`. It moves behind an opt-in `--detect-renames`; the
   canonical hash and the manifest never use it. `sandbox diff --git` output
   changes accordingly (documented).
4. **Byte paths end to end are out of scope.** `MountSource` paths are `&str`
   across the workspace and the overlay DB columns are TEXT. What *is* fixed:
   the FUSE frontend converts names with `to_string_lossy`, so creating a
   Latin-1 name in a `-w` mount silently stores a U+FFFD name. Write ops
   (create, mknod, mkdir, symlink, link, rename, setxattr names) now refuse
   non-UTF-8 names with `EILSEQ` (SBX-UTF8). Latin-1 *content* round-trips
   (binary is NUL in the first 8 KiB, git's rule, not "not UTF-8"). `path_b64`
   is implemented in the JSON writers and covered by a unit test, but today no
   input reaches it from an overlay; documented as a residual.
5. **Names that collide with existing code.** `meta` is a new table, distinct
   from the existing `overlay_metadata` (per-path chmod/utime). The CLI verb is
   `journal`, but the module is `oplog` (`ratarmount-fuse/src/oplog.rs`),
   because `ratarmount-compress/src/commit_journal.rs` and
   `user.ratarmount.commit-journal` already mean the append-commit journal.
   Code uses `layer_sealed` / `seal_state`, because "sealed" already means a
   closed rolling-archive member (`refuse_sealed_delete`).
6. **Root control xattrs are intercepted in `ratarmount-fuse`.** The overlay's
   `change_xattr` returns `EPERM` for `/` and for non-`user.` names, and
   `xattr_value` has no synthetic keys. `user.ratarmount.*` on the mount root
   are served and accepted by the FUSE layer before any overlay call.
7. **`base_url` needs plumbing.** `WriteOverlay::new(base, dir)` never sees the
   positional string. §1 adds a creation context (`OverlayCreateInfo`: base URL,
   digest request, lower layers) passed from `main.rs` where the overlay is
   built, and from the sandbox daemon's child argv.
8. **Git bases exist as `repo@rev` / `--git-ref`.** `git:///abs/path#rev` is
   accepted as an alias mapped onto that (local repositories only; `git://host`
   stays unsupported). `GitMountSource` needs a public tree-id accessor for
   `git-tree:<sha>`. `snapshot` today wraps restic (`snapshot add|list`); the
   git export `snapshot <repo>@<rev>|git:///…#rev OUT.tar.zst --with-index` is a
   new mode selected when the first argument is not a restic subcommand.
9. **FUSE-less build is a residual.** `ratarmount` depends on `ratarmount-fuse`
   unconditionally. The spec's macOS requirement is met by the existing macFUSE
   build; an optional `fuse` feature is recorded, not built, unless the user asks.
10. **Docs file.** The spec says `docs/sandboxes.md`; the file is
    `docs/sandbox.md` (linked three times from README). It is extended.
11. **Mounted detection.** A mounted overlay holds its SQLite DB in exclusive
    locking mode; a read-only open gets `SQLITE_BUSY`. `seal`, `fsck --repair`
    and `import` into an existing directory use that as the "currently mounted"
    check (`OverlayError::is_locked`).
12. **Base digest cache.** Reuse `ratarmount-index`'s `archive_full_hash`
    streaming hasher; cache `(path, size, mtime_ns, inode) → sha256` in the
    archive's index database when one is writable, else in the overlay `meta`
    only.
13. **Order.** §2's `--lower` and §4's `layer_digest` (a hash against the
    recorded stack) both need §3's `ReadOnlyOverlayLayer`, so the layer source
    is built in wave 0, before `diff` and `seal`. The `--lower` mount flags land
    in wave 1 with seal, because they check the sealed state.

## 3. Tracking table

Model: **astra** = `gpt-6-astra`, **sol** = `gpt-6.1-sol`, **luna** = `gpt-6-luna`.

| ID | Spec § | Wave | Model | Owned paths | Acceptance | Status |
|---|---|---|---|---|---|---|
| SBX-META | §1 | 0 | astra [xhigh] | `write_overlay.rs` schema/open (meta only), new `ratarmount-compositing/src/overlay_meta.rs`, new `ratarmount/src/overlay_cmd.rs` (`overlay` verb namespace, `info`), overlay construction call sites in `main.rs` and `sandbox/process.rs`, base-digest cache in `ratarmount-index` | `meta` created on new overlays, legacy overlays open/diff and report `legacy: true`; base digest for file/dir/remote/git kinds; `--base-digest sha256:…` reads no base bytes (counting MountSource test); `--base-digest none` warns; remount with a changed base refused, `--force-base-mismatch` records `base_mismatch_forced_at`; `stack_digest` helper with a fixed-vector test; `overlay info [--json]`; `overlay-stats` unchanged | done |
| SBX-LAYER | §3.3 | 0 | astra [xhigh] | new `ratarmount-compositing/src/overlay_layer.rs` | `ReadOnlyOverlayLayer: MountSource` over (inner, overlay dir): resolution by top-most mention, tombstones hide all below, re-create over a lower delete, merged `list_dirents`, xattrs, `content_generation` forwarded; opens DB `mode=ro` and `immutable=1` when asked; never writes; `WriteOverlay::new(stack, top)` copy-up from a lower layer yields the lower bytes; tests with base + 2 layers | done |
| SBX-UTF8 | §11 | 0 | sol [medium] | `ratarmount-fuse/src/lib.rs` name conversion on write ops | Non-UTF-8 names on create/mknod/mkdir/symlink/link/rename refused with `EILSEQ`, nothing written; lookups of such names `ENOENT`; regression tests | done |
| SBX-RULES | §7 | 0 | sol [high] | `overlay_policy.rs`, policy flags in `main.rs` | `--overlay-allow` exceptions (most specific wins; ancestor-rename rule respects allows); `erofs_denied` counter exposed through `QuotaUsage`/status; a denial callback hook (for the oplog); `readonly_rules` JSON recorded via a setter SBX-META's meta API can call at merge | done |
| SBX-DIFF | §2 | 1 | astra [xhigh] | `ratarmount/src/diff.rs`, `diff/**` | Every §2 flag; change set from the `files` table + composed view; streaming hashes; excludes before content; `--lower`; `--between`; normalization levels; exit codes 0/1/2/3; §13 §2 test list incl. `git apply` round trip per case and every §2.5 hash property | done |
| SBX-LOWER | §3.1/3.2, §4 fsck | 1 | astra [xhigh] | `overlay_fsck.rs`, `--lower` flags, fsck arm | §13 §3 list and fsck bullets | done |
| SBX-SEAL | §4 seal/unseal/verify | 1b | astra [xhigh] | compositing `overlay_fsck.rs`, seal/unseal/verify/fsck arms in `overlay_cmd.rs`, `--lower`/`--allow-unsealed-lower`/`--force-stack-mismatch` mount flags | §13 §3 and §4 lists; `-w` on sealed refused; sealed lowers opened immutable; two tops over one sealed lower; commit with `--lower` refused | done |
| SBX-GIT | §9 | 1 | sol [high] | `ratarmount-formats-git` (tree accessor), `git:///` alias in factory, `ratarmount/src/snapshot.rs` git mode | `base_digest` `git-tree:<sha>`; `snapshot <git>#sha out.tar.zst --with-index` mounts with no index build; tar.zst and git bases give identical composed manifests | done |
| SBX-IMPORT | §5 | 2 | astra [xhigh] | new `ratarmount/src/overlay_import.rs` + parser module | Every §2 case round-trips `diff → import → diff --hash`; real `git diff --binary` patch imports; rename from/to; `--reject`; `..`/symlink-component/`delta` refused; `--mtime` | in progress |
| SBX-OPLOG | §6 | 2 | astra [xhigh] | new `ratarmount-fuse/src/oplog.rs`, FUSE callback hooks, root control xattrs, `journal summarize|mark` in new `ratarmount/src/journal_cmd.rs`, benchmark script | §13 §6 list; header; coalesced ranges cap 64; layer attribution; marks via xattr; summarize lists; overhead benchmark reported | done |
| SBX-PACK | §8 | 2 | sol [high] | new `ratarmount/src/overlay_pack.rs` | Pack refuses unsealed; pack → unpack → verify; bundle mounts directly and as `--lower` (unpacked to a cache keyed by `layer_digest`); `--include-journal`, `--include-index` | done |
| SBX-RUN | §10 | 3 | astra [high] | `ratarmount/src/sandbox/run.rs` | Stub runtime test: mount → run → unmount → fsck → seal → pack → JSON; timeout; stale mount under `--top` cleaned via PID file | todo |
| SBX-UPPER | §15.9 | 3 | sol [high] | `overlay import-upperdir` arm, env-gated test, `docs/sandbox.md` interop section | Whiteouts → tombstones, opaque dirs → per-child tombstones; read-only ratarmount stack as overlayfs `lowerdir` (unshare user ns, skip if unavailable) | todo |
| SBX-DOCS | §14 | 3 | luna [medium] | `docs/sandbox.md`, README, `docs/formats.md`/CLI tour | End-to-end flow, branching recipe, xattr protocol, meta keys, hash definition, renames, exit codes; README subcommand list + comparison rows | todo |

## 4. Dependency graph

```
wave 0:  META ─┬─────────────┬──────────────┐
         LAYER ┼─> DIFF ─────┼─> IMPORT     │
         RULES ┤   SEAL ─────┼─> PACK ──────┼─> RUN
         UTF8  ┘   GIT       └─> OPLOG      └─> UPPER, DOCS
```

## 5. Process

- Two to three workers at a time with `CARGO_BUILD_JOBS=4` (the machine is shared).
- Workers do not commit; the orchestrator reviews, commits on the task branch,
  merges into `sandbox/integration`, compiles the whole workspace after every
  merge, and runs FUSE tests the sandbox cannot.
- Every merge adds AGENTS.md regression-catalog rows for the new tests.

## 6. Measurements

| What | Result | Notes |
|---|---|---|
| Journal overhead (`benchmarks/journal-overhead.sh`, release, 3+3 runs) | -3.0% (journal median 1.511 s vs baseline 1.558 s) | Within noise; laptop load average ~13 from another build. Rerun on a quiet machine before quoting. |
