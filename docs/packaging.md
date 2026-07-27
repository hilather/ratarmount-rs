# Packaging & distribution

## Binary install

```bash
make release
make install          # → ~/.local/bin/ratarmount
# or
cargo install --path ratarmount
```

## Distro packages (Ubuntu .deb / Rocky .rpm / portable)

CI workflow: [`.github/workflows/packages.yml`](../.github/workflows/packages.yml)

| Target | Job | Arch | Artifact |
|--------|-----|------|----------|
| Ubuntu 22.04 | `deb` | amd64 | `.deb` + tarball |
| Ubuntu 24.04 | `deb` | amd64 + **arm64** | `.deb` + tarball |
| Rocky Linux 8 | `rpm` (container) | amd64 | `.rpm` + tarball |
| Portable (Debian bullseye, **glibc 2.31**) | `portable` | amd64 + **arm64** | tarball only |
| **macOS** | `macos` | **arm64** (`macos-14`) + **x86_64** (`macos-13`) | tarball only |

> **v0.1.0 note:** Ubuntu 20.04 container and Rocky 9 matrix legs are temporarily disabled in CI
> (apt hang / exit 127). Use the portable glibc 2.31 tarball on older hosts; Rocky 9 packages
> can be built locally with `PACKAGE_FAMILY=rpm ./packaging/build-native-packages.sh`.

Each native package is built **on** that distro (matching glibc / libfuse). The **portable** job uses Debian bullseye so one tarball runs on most modern Ubuntu/Rocky hosts with glibc ≥ 2.31.

**Triggers**

| Event | Result |
|-------|--------|
| Tag `v*` | Build all + cosign keyless sign + GitHub Release assets |
| **Actions → Packages → Run workflow** | Build all + sign; download `signed-release-bundle` artifact |
| PR touching `packaging/` | Validate packaging matrix |

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

### Install examples

```bash
# Ubuntu
sudo apt install ./ratarmount_*_amd64.deb

# Rocky
sudo dnf install ./ratarmount-*.x86_64.rpm

# Portable tarball
tar -xzf ratarmount-*-portable-glibc2.31-x86_64.tar.gz
sudo install -m 755 ratarmount /usr/local/bin/
```

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

Library crates may be published later under a coordinated version policy. The CLI package remains the primary deliverable for 1.0.
