# Packaging & distribution

## Binary install

```bash
make release
make install          # → ~/.local/bin/ratarmount
# or
cargo install --path ratarmount
```

## Distro packages (Ubuntu .deb / Rocky .rpm / portable)

CI workflow: [`.github/workflows/packages.yml`](https://github.com/hilather/ratarmount-rs/blob/main/.github/workflows/packages.yml)

| Target | Job | Arch | Artifact |
|--------|-----|------|----------|
| Ubuntu 22.04 | `deb` | amd64 | `.deb` + tarball |
| Ubuntu 24.04 | `deb` | amd64 + **arm64** | `.deb` + tarball |
| Rocky Linux 8 | `rpm` (container) | amd64 | `.rpm` + tarball |
| Portable (Debian bullseye, **glibc 2.31**) | `portable` | amd64 + **arm64** | tarball only |
| **macOS** | `macos` | **arm64** (`macos-14`) only | tarball only (Intel `macos-13` deferred) |

> **v0.1.0 note:** Ubuntu 20.04 container and Rocky 9 matrix legs are temporarily disabled in CI
> (apt hang / exit 127). Use the portable glibc 2.31 tarball on older hosts; Rocky 9 packages
> can be built locally with `PACKAGE_FAMILY=rpm ./packaging/build-native-packages.sh`.

Each native package is built **on** that distro (matching glibc / libfuse). The **portable** job uses Debian bullseye so one tarball runs on most modern Ubuntu/Rocky hosts with glibc ≥ 2.31.

The portable binary vendors OpenSSL statically. Releases up to 0.1.34 linked
bullseye's `libssl.so.1.1`, which Arch, Ubuntu 22.04+ (including DGX OS) and
current Fedora do not ship, so those tarballs fail with "error while loading
shared libraries: libssl.so.1.1". `packaging/test-portable-deps.sh BINARY`
lists the binary's direct `NEEDED` libraries and fails on any `libssl` or
`libcrypto`; the Packages workflow runs it before upload.

Vendoring freezes OpenSSL inside the portable tarball. That tarball receives
OpenSSL fixes only when maintainers rebuild and re-release it. After an
OpenSSL security advisory, rebuild and re-release the portable tarball.
Users get those fixes by upgrading to the new tarball. Updating distro
OpenSSL packages does not change an already-shipped portable tarball.

The runtime still uses the host's `libarchive.so.13` and `libfuse3.so.3`, and
their own dependencies come from those distro packages; on Arch the
`libcrypto.so.3` seen in `ldd` comes from the host libarchive, not ratarmount.

**Triggers**

| Event | Result |
|-------|--------|
| Tag `v*` | Build all + cosign keyless sign + GitHub Release assets |
| **Actions → Packages → Run workflow** | Build all + sign; download `signed-release-bundle` artifact |
| PR touching `packaging/` | Validate packaging matrix |

### Agent / maintainer release procedure

Use this when cutting a version so GitHub actually has installable packages:

1. Bump root `Cargo.toml` `version`, all `VERSION:` fields in `.github/workflows/packages.yml`, and README version mentions.
2. Commit on `main`, push, then push an **annotated** tag `vX.Y.Z` (same as Cargo).
3. Wait for workflow **Packages** on that tag. Confirm under
   https://github.com/hilather/ratarmount-rs/releases that the tag lists `.deb` /
   `.rpm` / portable `.tar.gz` (and cosign bundles), not only tiny text sidecars.
4. If **Sign & release** fails: open job annotations first. Common causes already
   fixed in-tree: empty asset upload (skip 0-byte files), flaky multi-file
   `gh release create` (create empty release then upload one-by-one via REST).
5. Do **not** spam tags to debug. One fix commit + one new patch tag.
6. macOS matrix may flake on artifact upload; Linux packages can still publish.
   Prefer fixing macOS separately rather than blocking the whole release.
7. After the `macos-arm64` tarball is on the GitHub Release, bump
   [`packaging/homebrew/Casks/ratarmount.rb`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/homebrew/Casks/ratarmount.rb)
   `version` + `sha256` to match (Homebrew tap cask; not a source formula).
   The cask is allowed to trail workspace `Cargo.toml` by one release until
   that follow-up; [`packaging/test-homebrew-cask.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/test-homebrew-cask.sh)
   asserts URL/sha256 **format**, not lockstep.

See also root [`AGENTS.md`](../AGENTS.md) section **Releases / package builds**.

### Local package build

```bash
# Ubuntu/Debian host → .deb
sudo apt-get install -y libfuse3-dev fuse3 libarchive-dev zlib1g-dev pkg-config
./packaging/build-native-packages.sh

# Rocky/RHEL host → .rpm
sudo dnf install -y fuse3-devel libarchive-devel zlib-devel openssl-devel gcc
PACKAGE_FAMILY=rpm ./packaging/build-native-packages.sh

# Tarball only (any host)
TARBALL_ONLY=1 DISTRO_LABEL=local ./packaging/build-native-packages.sh

# macOS (run on a Mac)
export PKG_CONFIG_PATH="$(brew --prefix libarchive)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
./packaging/build-macos-tarball.sh
```

Or: `make packages`  
macOS guide: [`docs/macos.md`](macos.md)

Uses [nfpm](https://nfpm.goreleaser.com/) for `.deb`/`.rpm` (auto-downloaded if missing).

**NFS export** is userspace (`nfsserve` NFSv3 + optional `embednfs` NFSv4.1). Packages do **not** depend on `nfs-kernel-server`. Default listen port is **20490** (unprivileged). Binding **2049** needs root or `CAP_NET_BIND_SERVICE` (`--nfs-bind 2049`; already parsed). See [nfs-export.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/nfs-export.md).

**`nfsv4`, `sftp-russh`, and `bittorrent` are enabled in the package compile lines** — a stronger commitment than `gzip-rapidgzip` (still off). Editing only [`.github/workflows/packages.yml`](https://github.com/hilather/ratarmount-rs/blob/main/.github/workflows/packages.yml) does **not** change the scripts’ feature lists.

| Script | `cargo build --release -p ratarmount` |
|--------|----------------------------------------|
| [`packaging/build-native-packages.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/build-native-packages.sh) (deb / rpm / portable) | `--features nfsv4,sftp-russh,bittorrent` |
| [`packaging/build-appimage.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/build-appimage.sh) | `--features nfsv4,sftp-russh,bittorrent` |
| [`packaging/build-macos-tarball.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/build-macos-tarball.sh) | `--features nfsv4,sftp-russh,bittorrent` (rustup **stable**; workspace MSRV 1.90) |

The CLI and library crates keep `bittorrent` off by default; Cargo users opt in
with `--features bittorrent`. Packages compile `bittorrent`, but a torrent mount
contacts no trackers, DHT or LSD peers unless the user opts in with
`--torrent-swarm auto|lan|always` (the default is `never`: cache, `xs` metainfo
and web seeds only). Default CI does not compile librqbit. See [BitTorrent sources](remote-bittorrent.md)
for verification, uploads-disabled behavior, and upstream v2/swarm limitations.
The feature-list regression is `./packaging/test-bittorrent-features.sh`.

Source builds without `--features nfsv4` leave `--nfs --nfs-vers 4` as exit 2 (`rebuild with --features nfsv4 (rustc >= 1.88)`). Without `--features sftp-russh`, `--sftp` exits 2 (`rebuild with --features sftp-russh`). Default `cargo test --workspace` compiles neither embednfs nor russh (opt-in features, not compiled by default CI). Current package jobs install rustup **stable**.

`--print-features` on a packaged binary prints `nfsv4: compiled` and `sftp-russh: compiled`. `--oss-attributions` lists **embednfs** (MIT) and russh when compiled.

Residuals (honest): Linux kernel client **verified** on loopback (privileged Docker [`test-harness/nfs-docker/run.sh`](https://github.com/hilather/ratarmount-rs/blob/main/test-harness/nfs-docker/run.sh), 2026-08-15 — not default CI); no Kerberos / LAN / Windows; no v3/v4 mux; idle TTL is not CLOSE; embednfs is macOS-first over localhost. HTTP/WebDAV/SMB/9P/SFTP bind table: [`export.md`](export.md). Regression: [`packaging/test-nfsv4-features.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/test-nfsv4-features.sh).

### Install examples

```bash
# Ubuntu
sudo apt install ./ratarmount_*_amd64.deb

# Rocky
sudo dnf install ./ratarmount-*.x86_64.rpm

# Portable tarball
tar -xzf ratarmount-*-portable-glibc2.31-x86_64.tar.gz
sudo install -m 755 ratarmount /usr/local/bin/

# macOS Apple Silicon — Homebrew tap cask (needs a clone; not a git-tap of packaging/homebrew/)
brew tap-new hilather/ratarmount
mkdir -p "$(brew --repo hilather/ratarmount)/Casks"
cp packaging/homebrew/Casks/ratarmount.rb "$(brew --repo hilather/ratarmount)/Casks/"
brew install --cask hilather/ratarmount/ratarmount
# or: ./packaging/homebrew/install.sh
```

### Homebrew tap cask (macOS arm64)

v1 is a **cask** that unpacks the signed GitHub Release asset `ratarmount-<ver>-macos-arm64.tar.gz`. It is **not** a source formula (`cargo` / `depends_on "rust"` / `PKG_CONFIG_PATH`). Homebrew-core is out of v1. Intel bottle is deferred with the tarball (no GHA Intel runner — do not re-add `macos-13`).
| Piece | Path |
|-------|------|
| Cask | [`packaging/homebrew/Casks/ratarmount.rb`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/homebrew/Casks/ratarmount.rb) |
| Tap helper | [`packaging/homebrew/install.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/homebrew/install.sh) (`brew tap-new` + copy; `packaging/homebrew/` is not a git repo) |
| Audit | [`packaging/test-homebrew-cask.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/test-homebrew-cask.sh) — static checks always; `brew audit --cask` via `tap-new` when `brew` exists (**not** `--strict`, not a path/URL cask) |
URL pattern (matches this doc’s macOS tarball name):
```text
https://github.com/hilather/ratarmount-rs/releases/download/vVERSION/ratarmount-VERSION-macos-arm64.tar.gz
```
Install from a clone (Homebrew forbids path/URL casks; `packaging/homebrew/` is not a git repository so two-arg `brew tap` of that path fails; always fully-qualified — homebrew/core has a Linux Python formula also named `ratarmount`):
```bash
brew tap-new hilather/ratarmount
mkdir -p "$(brew --repo hilather/ratarmount)/Casks"
cp packaging/homebrew/Casks/ratarmount.rb "$(brew --repo hilather/ratarmount)/Casks/"
brew install --cask hilather/ratarmount/ratarmount
When cutting a release, bump the cask `version` + `sha256` **after** the `macos-arm64` asset exists (see `SHA256SUMS` on the GitHub Release). The cask may trail workspace `Cargo.toml` until that follow-up. Caveats cover **macFUSE or FUSE-T** and runtime **libarchive** — same as [`docs/macos.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/macos.md) / `MACOS.txt`. Do not add formula build deps to the cask.
`.deb` / `.rpm` also install [`packaging/mount.fuse.ratarmount`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/mount.fuse.ratarmount) as `/usr/sbin/mount.fuse.ratarmount` (`Type=fuse.ratarmount` for fstab / systemd `.mount` / autofs). Example units live under `/usr/share/doc/ratarmount/examples/`. Operator guide: [`systemd-mount.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/systemd-mount.md). CSI is spec-only ([`csi.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/csi.md)). Regression: [`packaging/test-systemd-unit.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/test-systemd-unit.sh).

### Cosign verification (release artifacts)

Releases are signed with [Sigstore cosign](https://docs.sigstore.dev/cosign/signing/overview/) **keyless OIDC** (GitHub Actions identity). No long-lived GPG key is required in the repo.

```bash
# Install cosign, then:
cosign verify-blob \
  --bundle ratarmount_0.1.0_amd64.deb.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/hilather/ratarmount-rs/.github/workflows/packages.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ratarmount_0.1.0_amd64.deb
```

Also check `SHA256SUMS` (itself signed as a blob).

### Optional: GPG-signed packages

If you prefer traditional Debian/RPM signing later:

1. Store a private key as GitHub secret `GPG_PRIVATE_KEY` (+ `GPG_PASSPHRASE`).
2. Add a step with `crazy-max/ghaction-import-gpg` and `dpkg-sig` / `rpmsign`.
3. Cosign keyless can stay for supply-chain attestation in parallel.

## Runtime dependencies

| Package | Purpose |
|---------|---------|
| `fuse3` / `libfuse3` | FUSE mount (Linux) |
| macFUSE or FUSE-T | FUSE mount (macOS) — see [`macos.md`](macos.md) |
| `libarchive` | long-tail formats (CAB/XAR/ISO/RAR/…) |
| `e2fsprogs` (`debugfs`) | **optional** — EXT2/3/4 image MVP |
| `squashfs-tools` (`unsquashfs`) | **optional** — SquashFS MVP |

```text
Debian/Ubuntu: fuse3 libarchive13 e2fsprogs squashfs-tools
Rocky/Fedora:  fuse3 libarchive e2fsprogs squashfs-tools
macOS (brew):  brew install --cask macfuse   # or FUSE-T; see docs/macos.md
               brew install libarchive pkgconf
```

### macOS FUSE install (summary)

macOS has **no** system FUSE. Users must install a backend before mounting:

| Backend | Install | When |
|---------|---------|------|
| **macFUSE** (recommended) | `brew install --cask macfuse` | Most desktops; also DMG from [macfuse.github.io](https://macfuse.github.io/) |
| **FUSE-T** | `brew install macos-fuse-t/homebrew-cask/fuse-t` | No kext; CI / locked-down Macs |

On **macOS 26 Tahoe**, prefer FSKit if the kernel extension path is blocked:

```bash
ratarmount -f -o backend=fskit archive.tar.gz mnt/
```

Full steps (approval dialogs, pkg-config paths, troubleshooting): **[`docs/macos.md`](macos.md)**.

## AppImage

Scaffold script: [`packaging/build-appimage.sh`](../packaging/build-appimage.sh).

```bash
./packaging/build-appimage.sh
OUT_DIR=dist BUNDLE_HELPERS=1 ./packaging/build-appimage.sh
```

Prefer distro packages or the **portable-glibc2.31** tarball for production until AppImage is automated with linuxdeploy in CI.

## CI gates

- **Always (Linux):** `cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace` (see `ci.yml`)
- **Always (macOS):** `macos-14` clippy + `cargo test --workspace`; FUSE smoke best-effort
- **Packages:** `packages.yml` on tags / manual dispatch (includes macOS tarballs)
- **FUSE harness (Linux):** phase allowlists when Python fixtures are checked out

## crates.io

**Policy:** [`docs/crates-io-policy.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/crates-io-policy.md). Dual-run still does **not** require a live publish ([`phase12-dual-run.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/phase12-dual-run.md)).

- Primary deliverable is the **CLI binary** (this doc / GitHub Releases / distro packages), not crates.io.
- **Q5=(a) dry-run only.** Maintainer check: [`packaging/test-crates-io-dry-run.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/test-crates-io-dry-run.sh) (`cargo publish -p ratarmount-core --dry-run` and index). No live upload.
- Library crates (`ratarmount-core`, `ratarmount-index`, formats, …) may be published later for embedders under workspace lockstep versioning. L3.5 `ratarmount-session` stays path-depend until a freeze review.
- Do **not** publish the `ratarmount` binary as a library API surface; `ratarmount-fuse` is the optional FUSE **adapter** library, not the CLI.
- Dual-run and 1.0-class packaging do **not** require any crates.io publish.

## Additional package drafts

These formats are prepared for maintainers but are not published by CI.

### Arch Linux (AUR)

`packaging/aur/PKGBUILD` packages the portable release binary as
`ratarmount-rs-bin` for x86_64 and aarch64, installs the FUSE mount helper,
docs and license, and declares `fuse3` and `glibc`. An optional source-build
recipe is in `packaging/aur/PKGBUILD.source`. Before updating a release, set
`pkgver` to the release version and run `packaging/aur/update-sums.sh VERSION`
after `SHA256SUMS` is available on GitHub. Regenerate `.SRCINFO` with
`makepkg --printsrcinfo > .SRCINFO` from `packaging/aur/`.

`packaging/test-aur.sh` checks shell syntax and generated metadata; `namcap`
runs when installed. `ratarmount-rs-bin` sets `options=(!debug)` so makepkg does
not emit an empty debug split package.

### Nix

The root `flake.nix` builds the Rust workspace binary with
`nfsv4,sftp-russh`, exposes `packages.default`, an overlay and a development
shell, and targets Linux. The package uses the checked-in Cargo lockfile.
Validate with `packaging/test-nix.sh` (it skips when Nix is not installed).
A `flake.lock` is not included until `nix flake lock` can be run against the
selected nixpkgs input.

### Conda-forge

`packaging/conda/meta.yaml` is a staged-recipes starting point for the Python
package `ratarmount-rs`. It builds the abi3 extension with maturin and Rust and
tests the import. Review selectors and platform dependencies with conda-build
before opening a conda-forge staged-recipes PR. This recipe does not produce a
second CLI output.

### Homebrew core formula draft

`packaging/homebrew/Formula/ratarmount-rs.rb` is a Linux-only formula draft
that builds the CLI from source. Homebrew core requires supported, declared
dependencies. macFUSE cannot be a core dependency because it is proprietary,
so this formula does not target macOS. A macOS core formula would need a
supported open-source FUSE backend such as FUSE-T and a working core CI build.
The existing macOS tap cask described above is unchanged. See [Homebrew's
formula cookbook](https://docs.brew.sh/Formula-Cookbook) and [acceptable
formula policy](https://docs.brew.sh/Acceptable-Formulae).

### Python wheels on GitHub Releases

`.github/workflows/python.yml` builds Linux x86_64/aarch64 and macOS arm64
wheels as workflow artifacts. They are not attached to GitHub Releases here:
Actions artifacts are scoped to their workflow run, while the package release
job is a separate concurrent workflow. Cross-run artifact API logic would also
need coordination to avoid racing a tag build. The workflow makes no PyPI
publication. A later change can add a workflow-run handoff or coordinated
release job; workflow artifacts are not release assets.

### Manual publication steps

Nothing in this task publishes packages. When a publication is approved:

1. **AUR:** update the version and hashes, regenerate `.SRCINFO`, run
   `packaging/test-aur.sh`, then commit and push the package files to the AUR
   Git repository.
2. **conda-forge:** build and validate the recipe with conda-build, add it to
   `conda-forge/staged-recipes`, and open a PR for review.
3. **Homebrew core:** validate the formula on supported Linux CI, update its
   version and source checksum, then submit it to `Homebrew/homebrew-core`.
   Keep the existing macOS cask in its tap.
4. **PyPI:** download the intended wheels and sdist from the Python workflow,
   verify their provenance and contents, then publish with
   `python -m twine upload dist/*` using an authorized PyPI account.
