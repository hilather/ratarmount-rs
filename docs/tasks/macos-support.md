# macOS support — evaluation & task list

**Status:** Phase A–D implemented in tree; awaiting GHA macOS green + first tag with macOS assets.  
**Target:** ship Apple Silicon + Intel macOS binaries on release tags, with CI that builds and (as far as GHA allows) tests them.  
**Related:** [`docs/macos.md`](../macos.md) (FUSE install + Tahoe); `docs/packaging.md`; `.github/workflows/{ci,packages}.yml`.

---

## 1. Current state (Linux-only product)

| Area | Today | macOS impact |
|------|--------|--------------|
| **FUSE stack** | `fuser` 0.15 + libfuse3; `fuser::mount2` | Compiles against **macFUSE** or **FUSE-T** (libfuse-compatible); runtime needs one of those installed |
| **Unmount** | `fusermount3` / `fusermount` only (`ratarmount-fuse`) | Must use `umount` / `diskutil unmount` on Darwin |
| **Daemonize** | `nix::fork` + `setsid` + `/dev/null` stdio | Same APIs work on macOS (unix); fine for v1 |
| **Mount ready probe** | Linux `statfs` + `FUSE_SUPER_MAGIC` (`0x65735546`) | **Broken on Darwin** — different `statfs` layout / fs type; need `mount` table / NFS (FUSE-T) / readdir heuristics |
| **Control socket** | `std::os::unix::net::UnixListener` | OK on macOS |
| **Unix FS traits** | Widespread `MetadataExt` / `PermissionsExt` / `OpenOptionsExt` | OK (unix, not linux-only) |
| **libc mode bits** | `S_IFDIR` etc. for FUSE attrs | OK on Darwin |
| **libarchive** | `pkg-config` in `build.rs` | Need Homebrew `libarchive` (+ `pkg-config`) |
| **EXT4 / SquashFS MVP** | Shell out to `debugfs` / `unsquashfs` | Tools often missing on Mac; keep soft-skip (already skip-if-absent) |
| **Packaging** | deb / rpm / portable-glibc tarball | Add macOS **tarball** (and optionally `.pkg` later) |
| **CI** | `ubuntu-latest` only | Add `macos-14` (arm64) ± `macos-13` (intel) |

**Good news:** Most of the workspace is already *Unix*-shaped, not *Linux*-shaped. The hard blockers are FUSE install/runtime, unmount + mount-ready detection, packaging/CI, and harness scripts that hardcode `fusermount3`.

**Hard CI constraint:** GitHub-hosted macOS runners **cannot load macFUSE kexts**. Practical approach:

1. **Always:** compile + unit tests on macOS (link against FUSE headers/libs).
2. **Mount tests on GHA:** prefer **FUSE-T** (kext-less, NFS/SMB backend) if it works with `fuser` on runners; otherwise gate full FUSE harness as **manual / self-hosted** and keep a small smoke that does not require a live mount.
3. **Release binaries:** build on `macos-14` (arm64) and optionally `macos-13`/`macos-15` (x86_64 or universal later).

---

## 2. Recommended platform strategy

### Runtime FUSE backends (user machines)

| Backend | Pros | Cons | Priority |
|---------|------|------|----------|
| **macFUSE** | Mature; documented by `fuser` crate (`brew install --cask macfuse` + `pkgconf`) | Kext; Apple Silicon needs reduced security once | **Primary** for local users |
| **FUSE-T** | No kext; better for CI / locked-down Macs | NFS/SMB semantics differ; mount points often under `/Volumes` or custom | **Secondary** + CI candidate |

Document both in README; link against whichever `pkg-config fuse` (or fuse3) provides at build time — same as Linux.

### Binary product shape (v1)

- Ship **native release tarballs**:
  - `ratarmount-<ver>-macos-arm64.tar.gz` (Apple Silicon)
  - `ratarmount-<ver>-macos-x86_64.tar.gz` (Intel), if runner budget allows
- **Do not** ship a fat universal binary in v1 unless linking both arches is painless.
- Dynamic link against system/Homebrew **libfuse** + **libarchive** (document `brew install libarchive macfuse` / `fuse-t`).
- Optional later: Homebrew formula, `.pkg` installer.

### Out of scope for first macOS milestone

- AppImage / deb / rpm on Mac  
- Pure in-process EXT4/SquashFS (already MVP-via-tools on Linux)  
- Windows / WSL  
- Full Python dual-run harness parity on Mac  
- Guaranteed GHA mount tests if FUSE-T proves flaky (fallback: compile + unit tests only)

---

## 3. Code changes required

### 3.1 Unmount (`ratarmount-fuse`)

```text
Linux:  fusermount3 -u / fusermount -u
Darwin: umount <mp> then diskutil unmount <mp> (force optional)
```

Use `#[cfg(target_os = "linux")]` / `#[cfg(target_os = "macos")]` (or `cfg(unix)` with runtime `uname`). Prefer try chain on macOS: `umount` → `diskutil unmount`.

### 3.2 Mount readiness (`ratarmount` main)

Replace Linux-only `path_is_fuse` (`statfs` + `FUSE_SUPER_MAGIC`) with:

1. Parse `mount` output / `/sbin/mount` for the mountpoint path, **or**
2. Platform-specific fs magic / `statfs` fields on Darwin, **or**
3. Robust readdir + “sees expected entry after open” wait (already partially used).

Daemonize via `fork`/`setsid` can stay; optionally document `-f` as the recommended default for GUI/debug on Mac.

### 3.3 FUSE options / mount point quirks

- FUSE-T may ignore some Linux-only options (`allow_other` policy differs).
- Ensure empty mount dir exists (already required).
- Consider defaulting `FSName` / `volname` for Finder-friendly volume names (`volname=…` is a macFUSE option — map via `-o` passthrough if not already).

### 3.4 Dependencies / build

| Dep | macOS install |
|-----|----------------|
| Rust stable | rustup |
| FUSE headers/libs | macFUSE **or** FUSE-T + `pkg-config` |
| libarchive | `brew install libarchive` (often needs `PKG_CONFIG_PATH` for keg-only) |
| openssl | system LibreSSL or `brew install openssl@3` + `OPENSSL_NO_VENDOR=1` if needed |
| e2fsprogs / squashfs | optional; brew formulas exist but skip formats if missing |

`ratarmount-formats-libarchive/build.rs` already uses pkg-config; document:

```bash
export PKG_CONFIG_PATH="$(brew --prefix libarchive)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
```

### 3.5 Soft features

- EXT4 / SquashFS: keep “skip if helper missing” (already done in unit tests).
- Write overlay: `OpenOptionsExt::mode` is unix — OK.
- Control Unix socket path under `$TMPDIR` — OK on Mac.

### 3.6 Test harness portability

Centralize unmount in `test-harness/env.sh`:

```bash
ratar_unmount() {
  local mp="$1"
  if [[ "$(uname -s)" == Darwin ]]; then
    umount "$mp" 2>/dev/null || diskutil unmount "$mp" 2>/dev/null || true
  else
    fusermount3 -u "$mp" 2>/dev/null || fusermount -u "$mp" 2>/dev/null || true
  fi
}
```

Replace scattered `fusermount3` calls (phase scripts + benchmarks) with `ratar_unmount`.  
`mountpoint -q` is Linux util-linux — use `mount | grep` / `df` fallbacks on Darwin.

---

## 4. Tests to add / adapt

### 4.1 Unit / crate tests (run on Mac CI without live FUSE)

| Test | Where | Notes |
|------|--------|------|
| Existing `cargo test --workspace` | all crates | Expect pass once FUSE/libarchive link |
| Unmount helper selection | `ratarmount-fuse` | Unit test of command choice via cfg or injected runner (optional) |
| Mount-ready probe | `ratarmount` | Unit-test path classification with fake mount table lines |
| Format open without mount | tar/zip/7z/gzip | Already strong; primary Mac regression net |
| Skip EXT4/SquashFS without tools | existing | Keep |

### 4.2 Integration / FUSE smoke (Mac, when backend available)

New script: `test-harness/run-macos-smoke.sh`

1. Build release binary.  
2. Create tiny fixture (e.g. `printf … | tar czf /tmp/t.tar.gz`).  
3. `ratarmount -f archive mnt &` (foreground preferred for CI).  
4. Wait until `ls mnt` succeeds (timeout 30s).  
5. Read a known file; assert content.  
6. `ratarmount -u mnt` / `ratar_unmount`.  
7. Optional: ZIP + 7z one-liners (same pattern).

Gate with:

```bash
if ! pkg-config --exists fuse && ! pkg-config --exists fuse3; then exit 0; fi
# or env FORCE_MAC_FUSE_SMOKE=1
```

### 4.3 CI matrix test policy

| Job | Runner | What runs |
|-----|--------|-----------|
| `check` (existing) | ubuntu | fmt, clippy, test, Linux FUSE harness |
| `check-macos` (new) | `macos-14` | fmt optional (linux-only ok), clippy, `cargo test --workspace` |
| `fuse-smoke-macos` (new, allow-fail first) | `macos-14` | install FUSE-T or macfuse stubs; run `run-macos-smoke.sh` |
| `packages` macOS leg | tag/dispatch | build tarball + sha256 → release |

Start `fuse-smoke-macos` as `continue-on-error: true` until green 2–3 releases, then make required.

---

## 5. CI / release packaging tasks

### 5.1 `.github/workflows/ci.yml`

Add job `macos`:

```yaml
macos:
  name: macOS (build + test)
  runs-on: macos-14
  steps:
    - uses: actions/checkout@v4
    - name: Brew deps
      run: |
        brew install pkgconf libarchive
        # Prefer FUSE-T for kext-less CI if available:
        brew install macos-fuse-t/homebrew-cask/fuse-t || brew install --cask macfuse || true
        echo "PKG_CONFIG_PATH=$(brew --prefix libarchive)/lib/pkgconfig" >> "$GITHUB_ENV"
    - uses: dtolnay/rust-toolchain@stable
      with: { components: rustfmt, clippy }
    - uses: Swatinem/rust-cache@v2
    - run: cargo clippy --workspace --all-targets -- -D warnings
    - run: cargo test --workspace
    - name: macOS FUSE smoke (best-effort)
      continue-on-error: true
      run: |
        cargo build --release -p ratarmount
        ./test-harness/run-macos-smoke.sh
```

### 5.2 `.github/workflows/packages.yml`

Add job `macos` (matrix):

| Label | Runner | Artifact |
|-------|--------|----------|
| `macos-arm64` | `macos-14` | `ratarmount-<ver>-macos-arm64.tar.gz` |
| `macos-x86_64` | `macos-13` (Intel) | `ratarmount-<ver>-macos-x86_64.tar.gz` |

Steps:

1. Brew: `pkgconf`, `libarchive`, FUSE (macfuse or fuse-t).  
2. Set `PKG_CONFIG_PATH` for libarchive.  
3. `cargo build --release -p ratarmount`.  
4. Package:

   ```bash
   DEST=dist/ratarmount-${VERSION}-macos-${ARCH}
   mkdir -p "$DEST"
   cp target/release/ratarmount README.md LICENSE "$DEST/"
   # optional: short MACOS.md runtime deps
   tar -czf "${DEST}.tar.gz" -C dist "$(basename "$DEST")"
   shasum -a 256 "${DEST}.tar.gz" | tee "${DEST}.tar.gz.sha256"
   ```

5. Upload-artifact → include in `release` job flatten + cosign + softprops.

Wire `needs: [deb, rpm, portable, macos]` (and success condition OR any of them).

Update release notes body table with macOS tarball rows and runtime deps: **macFUSE or FUSE-T**, **libarchive** (Homebrew).

### 5.3 Packaging script

Either:

- Extend `packaging/build-native-packages.sh` with `uname Darwin` → tarball-only, arch naming, no nfpm; or  
- Add `packaging/build-macos-tarball.sh` called from the workflow (cleaner for first pass).

### 5.4 Docs

- README: Platforms → Linux + macOS (beta); install via tarball + brew deps.  
- `docs/packaging.md`: macOS matrix, verify steps, cosign identity.  
- Short `docs/macos.md`: enable kext (macFUSE), FUSE-T alternative, `PKG_CONFIG_PATH`, known limits (EXT4/SquashFS helpers).

---

## 6. Prioritized task list

Use as implementation order. Effort: **S** &lt; 0.5d, **M** 0.5–2d, **L** multi-day.

### Phase A — Compile on macOS (blocker)

| ID | Task | Effort | Status |
|----|------|--------|--------|
| **A1** | Document local Mac build + **FUSE install** (macFUSE / FUSE-T / Tahoe FSKit) in `docs/macos.md` | S | **done** |
| **A2** | Fix `unmount()` for Darwin (`umount` / `diskutil`) | S | **done** |
| **A3** | Fix `path_is_fuse` / `wait_until_mounted` for Darwin | M | **done** |
| **A4** | Verify `cargo build --release` + `cargo test --workspace` on Apple Silicon | M | **pending GHA / real Mac** |
| **A5** | libarchive brew path notes + CI env | S | **done** (CI + docs) |

### Phase B — Behavior + harness

| ID | Task | Effort | Status |
|----|------|--------|--------|
| **B1** | `ratar_unmount` / mount helpers in `test-harness/env.sh` | S | **done** |
| **B2** | Port critical harness scripts to helpers | M | **done** |
| **B3** | `test-harness/run-macos-smoke.sh` | S | **done** (verified on Linux) |
| **B4** | Manual smoke on real Mac (TAR/ZIP/7z) | M | **pending** |
| **B5** | Unit tests for mount-ready parse | S | **done** |

### Phase C — CI (PR gates)

| ID | Task | Effort | Status |
|----|------|--------|--------|
| **C1** | `macos-14` job: brew, clippy, `cargo test` | M | **done** (in `ci.yml`) |
| **C2** | Best-effort FUSE smoke (`continue-on-error`) | M | **done** |
| **C3** | FUSE-T preferred on GHA; document failure modes | S | **done** (workflow + docs) |
| **C4** | Promote smoke to required after N green runs | S | **pending** |

### Phase D — Release binaries

| ID | Task | Effort | Status |
|----|------|--------|--------|
| **D1** | `packaging/build-macos-tarball.sh` | S | **done** |
| **D2** | `packages.yml` matrix arm64 + x86_64 | M | **done** |
| **D3** | macOS tarballs in signed-release-bundle + Release | S | **done** (wired; needs tag run) |
| **D4** | Cosign sign macOS blobs | S | **done** (same release job) |
| **D5** | packaging docs + release notes + MACOS.txt FUSE install | S | **done** |

### Phase E — Polish (post-v1 Mac)

| ID | Task | Effort | Notes |
|----|------|--------|-------|
| **E1** | Homebrew formula (tap or core) | L | After tarball stable |
| **E2** | Universal binary (lipo) or only arm64 if Intel share is low | M | Optional |
| **E3** | Finder `volname` / icon / xattr quirks | M | UX |
| **E4** | Pure SquashFS/EXT4 (drop external tools) | L | Independent of Mac |
| **E5** | macOS-specific `-o` defaults for FUSE-T | M | If smoke needs it |

---

## 7. Suggested first PR slice (MVP)

Smallest path to “Mac binary on release + CI build/test”:

1. **A2 + A3** — unmount + mount-ready (so the binary actually works on Mac).  
2. **A1** — `docs/macos.md`.  
3. **C1** — macOS unit-test CI.  
4. **B3 + C2** — smoke script + optional job.  
5. **D1 + D2 + D3 + D4** — release tarball arm64 on tags.

Defer intel matrix, Homebrew formula, and required FUSE smoke until arm64 is solid.

---

## 8. Risk register

| Risk | Mitigation |
|------|------------|
| GHA cannot run real FUSE mounts | Build/test always; smoke best-effort; document manual checklist |
| FUSE-T semantic gaps (xattr, unmount) | Primary support macFUSE for users; FUSE-T for CI |
| Homebrew keg-only libarchive | Explicit `PKG_CONFIG_PATH` in docs + CI |
| Dynamic libfuse version skew | Document min macFUSE/FUSE-T; prefer package manager versions |
| `statfs` layout wrong → hang on daemonize | Prefer `mount` table parse; keep `-f` well tested |
| Cosign/release job forgets new artifacts | Explicit `needs.macos` + flatten `*.tar.gz` |

---

## 9. Acceptance criteria (Mac support “done” for release notes)

- [ ] `cargo test --workspace` green on `macos-14` in CI  
- [ ] Tag build produces signed `ratarmount-*-macos-arm64.tar.gz` on GitHub Release  
- [x] Documented install: brew deps + extract binary + mount sample archive (`docs/macos.md`)  
- [x] `ratarmount -u` uses Darwin unmount path (`umount` / `diskutil`)  
- [x] Smoke script: mount tar.gz, read file, unmount (`test-harness/run-macos-smoke.sh`; verified on Linux; Mac CI best-effort)  
- [x] README platforms line mentions macOS beta

---

## 10. File touch map (quick reference)

| File / area | Change |
|-------------|--------|
| `ratarmount-fuse/src/lib.rs` | Darwin unmount |
| `ratarmount/src/main.rs` | `path_is_fuse` / wait logic |
| `test-harness/env.sh` | `ratar_unmount`, mount helpers |
| `test-harness/run-macos-smoke.sh` | **new** |
| `test-harness/run-phase*.sh` | use helpers |
| `.github/workflows/ci.yml` | macos job |
| `.github/workflows/packages.yml` | macos matrix + release needs |
| `packaging/build-macos-tarball.sh` | **new** |
| `docs/macos.md`, `docs/packaging.md`, `README.md` | docs |

---

*Generated from codebase audit (fuse unmount, daemonize, libarchive build.rs, Linux-only CI/packages, harness fusermount3). Implementation not started.*
