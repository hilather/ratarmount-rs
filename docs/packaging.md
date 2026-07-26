# Packaging & distribution

## Binary install

```bash
make release
make install          # → ~/.local/bin/ratarmount
# or
cargo install --path ratarmount
```

## Distro packages (Ubuntu .deb / Rocky .rpm)

CI workflow: [`.github/workflows/packages.yml`](../.github/workflows/packages.yml)

| Distro | Job | Artifact |
|--------|-----|----------|
| Ubuntu 22.04 / 24.04 | `deb` matrix on GitHub runners | `.deb` + portable `.tar.gz` |
| Rocky Linux 8 / 9 | `rpm` matrix in Rocky containers | `.rpm` + portable `.tar.gz` |

**Triggers**

- Tag `v*` → build all packages and attach to a GitHub Release  
- **Actions → Packages → Run workflow** → artifacts downloadable from the run  
- PR touching `packaging/` → validate packaging scripts  

**Local package build**

```bash
# Ubuntu/Debian host → .deb
sudo apt-get install -y libfuse3-dev fuse3 libarchive-dev zlib1g-dev pkg-config
./packaging/build-native-packages.sh          # PACKAGE_FAMILY=auto

# Rocky/RHEL host → .rpm
sudo dnf install -y fuse3-devel libarchive-devel zlib-devel openssl-devel gcc
PACKAGE_FAMILY=rpm ./packaging/build-native-packages.sh
```

Uses [nfpm](https://nfpm.goreleaser.com/) for `.deb`/`.rpm` (auto-downloaded if missing) plus a glibc-linked binary tarball. Runtime depends: **fuse3**, **libarchive**.

**Install examples**

```bash
# Ubuntu
sudo apt install ./ratarmount_0.1.0_amd64.deb

# Rocky
sudo dnf install ./ratarmount-0.1.0-1.x86_64.rpm
# or: sudo rpm -Uvh ./ratarmount-*.rpm
```

**Cross-flavor note:** binaries are built **on** each distro (not cross-compiled). That avoids glibc/libfuse mismatches between Ubuntu and Rocky. The `.tar.gz` from one job may still run on a similar glibc peer but packages are preferred for installs.

## Runtime dependencies

| Package | Purpose |
|---------|---------|
| `fuse3` / `libfuse3` | FUSE mount |
| `libarchive` | long-tail formats (CAB/XAR/ISO/RAR/…) |
| `e2fsprogs` (`debugfs`) | **optional** — EXT2/3/4 image MVP |
| `squashfs-tools` (`unsquashfs`) | **optional** — SquashFS MVP |

```text
Debian/Ubuntu: fuse3 libarchive13 e2fsprogs squashfs-tools
Fedora:        fuse3 libarchive e2fsprogs squashfs-tools
```

## AppImage

Scaffold script: [`packaging/build-appimage.sh`](../packaging/build-appimage.sh).

```bash
# From repo root; builds release binary into dist/AppDir
./packaging/build-appimage.sh

# If linuxdeploy + appimagetool are on PATH, produces a .AppImage under dist/
# Otherwise leaves a populated AppDir and prints next steps.

OUT_DIR=dist BUNDLE_HELPERS=1 ./packaging/build-appimage.sh
```

What the script does:

1. `cargo build --release -p ratarmount`
2. Stages `dist/AppDir` with binary, desktop entry, `AppRun`
3. Optionally bundles ELF helpers `debugfs` / `unsquashfs` (`BUNDLE_HELPERS=1`, default)
4. Invokes `linuxdeploy --output appimage` when available (pulls shared libs)

### Suggested production build

Build on an older glibc base (manylinux / Debian oldstable container) so the AppImage runs on more hosts:

```bash
# Example sketch (adjust image/mounts as needed)
docker run --rm -v "$PWD":/src -w /src rust:bookworm bash -lc '
  apt-get update && apt-get install -y fuse3 libfuse3-dev libarchive-dev \
    desktop-file-utils file e2fsprogs squashfs-tools curl
  # install linuxdeploy + appimagetool for host arch
  ./packaging/build-appimage.sh
'
```

Desktop entry: `packaging/ratarmount.desktop`.  
Icon: use `packaging/ratarmount.png` if present, else the sibling Python tree SVG.

| Component | Notes |
|-----------|--------|
| `ratarmount` | release binary |
| `libfuse3` | runtime; often from host or linuxdeploy |
| `libarchive` | long-tail formats |
| `debugfs` / `unsquashfs` | optional MVP format helpers |

## CI gates

- **Always:** `cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace`
- **FUSE harness:** optional job when Python fixtures are checked out (`RATARMOUNT_PY_ROOT`)
- **AppImage:** not required in CI yet; script is manual/optional

See `.github/workflows/ci.yml`.

## crates.io

Library crates (`ratarmount-core`, `ratarmount-index`, …) may be published later under a coordinated version policy. The CLI package remains the primary deliverable for 1.0.
