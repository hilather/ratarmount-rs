# crates.io publish policy

Status: **policy documented** (2026-07-28). No coordinated crates.io publish is required for dual-run or 1.0-class **binary** distribution.

Related: [`docs/packaging.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/packaging.md) (binary/deb/rpm/AppImage), [`docs/phase12-dual-run.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/phase12-dual-run.md) (dual-run announce runbook; crates.io not required), [`docs/nfs-export.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/nfs-export.md) (NFSv3 + optional NFSv4.1).

---

## Principles

1. **Primary deliverable is the CLI binary** (`ratarmount`), not a crates.io metapackage. Users install via `make install`, `cargo install --path ratarmount`, distro packages, or portable tarballs.
2. **Library crates are optional** for third-party embedders (custom MountSource stacks, index tooling). Publish them only when APIs are intentionally supported.
3. **Do not publish the FUSE binary as a library.** The product binary crate must not be the crates.io “lib” surface for mount semantics.
4. **Workspace version is shared** via `[workspace.package] version` until a crate is deliberately versioned independently.
5. **Path deps stay path-based in-repo**; published crates use versioned crates.io deps and matching `repository` / `license` metadata.

---

## Crate classification

### L3.5 — embedder session (not published in this slice)

`ratarmount-session` is the **supported in-process Session API** for GUI and other embedders (open / paged list / ranged read / extract / index job). It does **not** pull FUSE.

| Policy | Detail |
|--------|--------|
| **This slice** | **Do not publish** `ratarmount-session` on crates.io. GUI/embedders path-depend the workspace crate. First publish only after G1–G4 are stable (see [`docs/session-api.md`](session-api.md)). |
| **Binary crate** | **Never** publish the `ratarmount` binary crate as the embedder surface. That crate unconditionally depends on fuse/nfs/smb/http/9p/sftp. |
| **Layering** | Session sits on L0–L3 (`ratarmount-core`, `ratarmount-index`, formats, compress, compositing, remote). It is not L0 and must not be folded into `ratarmount-core`. |

### Binary-only (do not publish as a library)

| Crate | Why |
|-------|-----|
| **`ratarmount`** | Application binary (`[[bin]]` only). Entry point, CLI, factory wiring. **Never** published as a reusable lib; if published at all, binary-only with no public `src/lib.rs` API surface. Prefer **not** publishing this crate on crates.io while distro/GitHub releases ship the binary. **Embedders use `ratarmount-session`, not this crate.** |

`cargo install --git` / `--path` and release artifacts replace `cargo install ratarmount` from crates.io until a deliberate binary publish is approved.

### Library-facing (candidates to publish)

Stable-ish building blocks for embedders. Publish only after docs + semver story for that crate.

| Tier | Crates | Role |
|------|--------|------|
| **L0 — foundation** | `ratarmount-core`, `ratarmount-index` | `MountSource` trait, shared types; SQLite 0.7.x index |
| **L1 — codecs** | `ratarmount-compress` | Seekable gzip/bzip2/xz/zstd/… helpers |
| **L2 — formats** | `ratarmount-formats-*` (tar, zip, ar, cpio, sevenzip, …) | Per-format MountSource backends |
| **L3 — I/O & compose** | `ratarmount-remote`, `ratarmount-compositing` | URL backends; union/automount/overlay |
| **L3.5 — embedder session** | `ratarmount-session` | Supported in-process **Session** API (no FUSE). GUI/embedders **path-depend**. **Not published** on crates.io in this slice. **Never** publish the `ratarmount` binary crate as the embedder surface. |
| **L4 — export adapters** | `ratarmount-fuse`, `ratarmount-nfs` | FUSE (`fuser`) and in-process NFSv3 (`nfsserve`) + optional NFSv4.1 (`embednfs` 0.4.1, feature `nfsv4`, rustc ≥ 1.88) bridges — *not* the CLI binary. Path deps only; **do not publish** until embedders need the same export surface. Linux/macOS packages compile `nfsv4`; default crates stay MSRV 1.74. |

### System / FFI caveats

| Crate | Note |
|-------|------|
| `ratarmount-formats-libarchive` | Links system **libarchive**; publish only with clear `links` / build-deps docs |
| `ratarmount-formats-git` | Depends on `git2` / libgit2 |
| `ratarmount-fuse` | Depends on platform FUSE (`fuser`); Linux + macOS arm64 first-class (Intel package deferred) |

Crates that shell out (`debugfs`, `unsquashfs`, `lrzip`, `smbclient`) should document optional runtime tools in their crate README when published.

---

## Versioning

| Policy | Detail |
|--------|--------|
| **Workspace lockstep (default)** | All published workspace members share the same semver (today `0.1.x` from root `Cargo.toml`) until an API break forces a bump. |
| **0.x semantics** | Breaking API changes allowed with minor bumps while major is 0; document in CHANGELOG / release notes. |
| **1.0 libraries** | Only after dual-run cutover experience and a freeze review for `ratarmount-core` + `ratarmount-index` at minimum. |
| **Binary version** | Git tags `v*` and package versions track the same workspace version as the CLI product. |
| **Independent versioning** | Allowed later for leaf format crates if core stays stable; not the default. |

Do **not** publish a crate at a version that does not match the Git tag used for the corresponding binary release without an explicit note.

---

## What not to do

- Do **not** publish `ratarmount` as a library crate that re-exports the whole stack solely to get a crates.io name — keep the binary product separate from embedder APIs. Embedders path-depend **`ratarmount-session`**.
- Do **not** publish `ratarmount-session` in this slice (G0 contract freeze). GUI/embedders stay on path deps until a deliberate L3.5 publish.
- Do **not** confuse **`ratarmount-fuse`** (library adapter) with the **`ratarmount`** binary; naming on crates.io must stay clear in descriptions.
- Do **not** publish internal-only helpers without a supported API surface.
- Do **not** yank patch releases for minor doc fixes; use the next patch.
- Do **not** require crates.io publish for dual-run or distro packaging success.

---

## Workspace publish order (sketch)

When a coordinated first publish is approved, publish **dependency order** (leaves after roots). Dry-run every step with `cargo publish -p <crate> --dry-run`.

Suggested order (adjust if features pull extra edges):

```text
1.  ratarmount-core
2.  ratarmount-index
3.  ratarmount-compress
4.  ratarmount-formats-tar
5.  ratarmount-formats-zip
6.  ratarmount-formats-ar
7.  ratarmount-formats-cpio
8.  ratarmount-formats-iso9660
9.  ratarmount-formats-warc
10. ratarmount-formats-xar
11. ratarmount-formats-cab
12. ratarmount-formats-libarchive
13. ratarmount-formats-sevenzip
14. ratarmount-formats-sqlar
15. ratarmount-formats-squashfs
16. ratarmount-formats-ext4
17. ratarmount-formats-fat
18. ratarmount-formats-asar
19. ratarmount-formats-ogg
20. ratarmount-formats-html
21. ratarmount-formats-pdf
22. ratarmount-formats-git
23. ratarmount-remote
24. ratarmount-compositing
# 25. ratarmount-session     # L3.5 embedder; not in this slice
25. ratarmount-fuse          # library adapter only
# 26. ratarmount             # OPTIONAL binary-only; prefer GitHub/distro artifacts
```

Before each real publish:

1. Replace `path = "…"` workspace deps with versioned crates.io deps for that release set.  
2. Ensure `license`, `repository`, `description`, and `readme` (where useful) are set.  
3. `cargo package -p <crate> --list` and `--dry-run`.  
4. Tag the monorepo `vX.Y.Z` matching the published version.

---

## First-publish recommendation

| Phase | Action |
|-------|--------|
| **Now / dual-run** | Ship binaries only; **no** crates.io requirement. |
| **Post dual-run** | Optionally publish **L0** (`core`, `index`) if external tools need the index schema/API. |
| **Later** | Add compress + selected formats; then remote/compositing/fuse as demand appears. |
| **Binary on crates.io** | Optional convenience for `cargo install ratarmount`; still not a substitute for distro packages. |

---

## Ownership of this policy

Updates live in this file. Packaging rows in [`parity-todo.md`](parity-todo.md) should stay in sync when the policy status changes (documented vs first publish executed).
