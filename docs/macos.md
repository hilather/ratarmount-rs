# macOS support

**Status:** **first-class on Apple Silicon** (signed `macos-arm64` tarball on GitHub Release tags; [Homebrew tap cask](https://github.com/hilather/ratarmount-rs/blob/main/packaging/homebrew/Casks/ratarmount.rb)). Intel package **deferred** (no GHA Intel runner). Homebrew-core / WinFsp residual (F-5 `partial`).  
**Task list:** [docs/tasks/macos-support.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/macos-support.md)

ratarmount needs a **FUSE runtime** on macOS (there is no built-in `/dev/fuse` like Linux).  
Install **one** of the backends below, then install or build `ratarmount`.

---

## 1. Install FUSE (required)

Pick **either** macFUSE (recommended for most users) **or** FUSE-T (no kernel extension).  
Do **not** mix both unless you know how to switch backends.

### Option A — macFUSE (recommended)

[macFUSE](https://macfuse.github.io/) is the primary backend used by most Rust FUSE apps (`fuser`).

#### Install with Homebrew

```bash
brew install --cask macfuse
```

#### Install without Homebrew

1. Download the latest **macFUSE 5.x** DMG from [macfuse.github.io](https://macfuse.github.io/) or [GitHub Releases](https://github.com/macfuse/macfuse/releases).  
2. Open the installer and complete it.  
3. If macOS asks to allow a system extension, open **System Settings → Privacy & Security** and approve **macFUSE** / Benjamin Fleischer, then reboot if prompted.

#### After install (all macOS versions)

```bash
# Headers / pkg-config should appear for building
pkg-config --modversion fuse || pkg-config --modversion fuse3
```

If `pkg-config` cannot find fuse, add common paths:

```bash
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/Library/Filesystems/macfuse.fs/Contents/Resources/pkgconfig:${PKG_CONFIG_PATH:-}"
# Apple Silicon Homebrew:
export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
```

#### Kernel extension path (older flow / some hosts)

On Apple Silicon, enabling a **third-party kernel extension** historically required:

1. Reboot into **Recovery**  
2. **Startup Security Utility** → allow reduced / user-managed security for third-party kexts  
3. Reboot, approve the extension in **System Settings → Privacy & Security**

On **macOS 26 (Tahoe)** and later, prefer the **FSKit** path below so you often **do not** need Recovery / kext approval.

#### macOS 26 Tahoe (including 26.3.x)

macFUSE 5.x can mount via Apple **FSKit** (user space) instead of the classic kext:

```bash
# Force FSKit backend when mounting (recommended on Tahoe if kext is blocked)
ratarmount -f -o backend=fskit archive.tar.gz mnt/
```

Notes:

- Install **current macFUSE 5.3+**, not an old 4.x leftover.  
- If mounts hang on 26.3.x, try a newer macOS point release (e.g. 26.4+) or FUSE-T.  
- Use **foreground** (`-f`) first when debugging.

Official overview: [macfuse.github.io](https://macfuse.github.io/) (“evolving beyond kernel extensions”).

---

### Option B — FUSE-T (kext-less)

[FUSE-T](https://www.fuse-t.org/) implements FUSE without a kernel extension (NFS / SMB / FSKit).  
Good when you cannot enable kexts (managed Macs, CI, some Tahoe setups).

#### Install with Homebrew

```bash
brew install macos-fuse-t/homebrew-cask/fuse-t
# or follow current docs:
# brew install fuse-t
```

#### Install without Homebrew

Download the signed `.pkg` from [fuse-t releases](https://github.com/macos-fuse-t/fuse-t/releases) and run the installer.

#### macOS 26 Tahoe + FSKit

1. Install FUSE-T **1.1+** (FSKit support is for macOS 26+).  
2. Run **`fuse-t.app`** from `/Applications` and follow prompts to enable the FSKit extension.  
3. Mount with:

```bash
ratarmount -f -o backend=fskit archive.tar.gz mnt/
```

You can also set a default backend in FUSE-T’s config (see upstream wiki / `fuse-t.ini`).

#### Caveats vs macFUSE

| Topic | FUSE-T |
|-------|--------|
| Symlinks / AppleDouble `._*` | Different / noisier than macFUSE |
| Mount presentation | Often looks like a network volume |
| Performance / stability | Good for many tools; edge cases remain |

---

### Verify FUSE is usable

```bash
# Library / headers present for builds
pkg-config --exists fuse || pkg-config --exists fuse3 && echo "fuse pkg-config OK"

# After installing ratarmount, smoke-mount a tiny archive
mkdir -p /tmp/ratar-src /tmp/ratar-mnt
echo hello > /tmp/ratar-src/hi.txt
tar -czf /tmp/ratar-sample.tar.gz -C /tmp/ratar-src hi.txt
ratarmount -f /tmp/ratar-sample.tar.gz /tmp/ratar-mnt &
sleep 1
cat /tmp/ratar-mnt/hi.txt    # expect: hello
ratarmount -u /tmp/ratar-mnt
```

Unmount is also: `umount /tmp/ratar-mnt` or `diskutil unmount /tmp/ratar-mnt`.

---

## 2. Other runtime / build dependencies

```bash
brew install libarchive pkgconf
# Optional helpers for EXT4 / SquashFS MVPs (Linux tools; may be limited on Mac):
# brew install e2fsprogs squashfs
```

`libarchive` is often **keg-only** — export for builds:

```bash
export PKG_CONFIG_PATH="$(brew --prefix libarchive)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
```

| Package | Role |
|---------|------|
| macFUSE **or** FUSE-T | FUSE mount runtime + libfuse for linking |
| `libarchive` | Long-tail formats (RAR, etc.) |
| `pkgconf` / `pkg-config` | Discover fuse + libarchive at build time |
| Rust stable | `rustup` |

---

## 3. Install a release binary

### Homebrew tap cask (Apple Silicon, recommended)

v1 is a **cask** that unpacks the signed GitHub Release `macos-arm64` tarball. It is **not** a source formula (no `cargo` / `PKG_CONFIG_PATH`). Homebrew-core is out of v1.

Cask: [`packaging/homebrew/Casks/ratarmount.rb`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/homebrew/Casks/ratarmount.rb) (tap root is [`packaging/homebrew/`](https://github.com/hilather/ratarmount-rs/tree/main/packaging/homebrew)).

```bash
# From a clone of this repo (cwd = repo root). Homebrew forbids path/URL casks,
# and packaging/homebrew/ is not a git repository (so `brew tap … that path` fails).
# Fully-qualified: homebrew/core has a Linux Python formula also named ratarmount.
# or: ./packaging/homebrew/install.sh
brew tap-new hilather/ratarmount
mkdir -p "$(brew --repo hilather/ratarmount)/Casks"
cp packaging/homebrew/Casks/ratarmount.rb "$(brew --repo hilather/ratarmount)/Casks/"
brew install --cask hilather/ratarmount/ratarmount
```

No-clone path: extract the signed GitHub Release `macos-arm64` tarball (section “Manual tarball”). A published `hilather/homebrew-ratarmount` GitHub repo (Casks/ at the tap root) is the longer-term remote tap; Homebrew-core is out of v1.

Cask **caveats** (not formula build deps) remind you to install **macFUSE or FUSE-T** and runtime **libarchive**. Then:

```bash
ratarmount archive.tar.gz mnt/
ratarmount -u mnt/
```

Regression: [`packaging/test-homebrew-cask.sh`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/test-homebrew-cask.sh) (static checks always; `brew audit --cask` via a temporary local tap when `brew` exists).

### Manual tarball

From a GitHub Release asset (after CI packages land):

```bash
tar -xzf ratarmount-*-macos-arm64.tar.gz   # Intel tarball deferred
cd ratarmount-*-macos-*
install -m 755 ratarmount ~/.local/bin/    # or /usr/local/bin
# ensure FUSE is installed first (section 1)
ratarmount archive.tar.gz mnt/
ratarmount -u mnt/
```

See `MACOS.txt` inside the tarball for a short reminder of brew deps.

---

## 4. Building from source

```bash
# 1) FUSE (section 1) + libarchive
brew install libarchive pkgconf
brew install --cask macfuse   # or FUSE-T

export PATH="$HOME/.cargo/bin:$PATH"
export PKG_CONFIG_PATH="$(brew --prefix libarchive)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

# 2) Build
cargo build --release -p ratarmount

# 3) Package a local tarball
./packaging/build-macos-tarball.sh

# 4) Smoke test (no Python fixtures required)
./test-harness/run-macos-smoke.sh
```

If link/configure fails on `fuse`:

```bash
pkg-config --modversion fuse || pkg-config --modversion fuse3
ls /usr/local/lib/libfuse* /opt/homebrew/lib/libfuse* 2>/dev/null
ls /Library/Filesystems/macfuse.fs 2>/dev/null
```

---

## 5. Usage tips on macOS

| Tip | Detail |
|-----|--------|
| **Foreground first** | `ratarmount -f archive mnt/` — easier logs; avoids daemonize races |
| **Tahoe FSKit** | `-o backend=fskit` (macFUSE 5.x or FUSE-T on 26+) |
| **Extra FUSE options** | `-o volname=MyArchive,backend=fskit` (unknown keys pass through as `CUSTOM`) |
| **Unmount** | `ratarmount -u mnt` → `umount` → `diskutil unmount` |
| **Empty mount dir** | Create `mnt/` before mounting |

```bash
mkdir -p mnt
ratarmount -f -o backend=fskit,volname=Sample sample.tar.gz mnt/
# ...
ratarmount -u mnt
```

---

## 6. Known limits

| Topic | Notes |
|-------|--------|
| **EXT4 / SquashFS MVP** | Need `debugfs` / `unsquashfs` on `PATH`; otherwise soft-fail |
| **Daemonize** | Background uses `fork`/`setsid`; use `-f` if mount-ready probing misbehaves |
| **Unmount** | Darwin path only (not Linux `fusermount`) |
| **CI** | GHA `macos-14` cannot load macFUSE kexts; unit tests always; FUSE smoke best-effort (FUSE-T) |
| **Tahoe 26.3.x** | Prefer current macFUSE 5.3+ or FUSE-T + `backend=fskit`; not yet hand-verified on every point release |

---

## 7. CI / releases

- **PR CI:** `macos-14` — clippy + `cargo test --workspace` (`.github/workflows/ci.yml`)  
- **Tags:** `packages.yml` builds `ratarmount-<ver>-macos-arm64.tar.gz` (Intel deferred), cosign-signs, attaches to the GitHub Release
- **Homebrew:** tap cask [`packaging/homebrew/Casks/ratarmount.rb`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/homebrew/Casks/ratarmount.rb) pins that tarball + sha256; bump version/sha256 when cutting a release. Homebrew-core is out of v1.  

---

## 8. Troubleshooting

| Symptom | What to try |
|---------|-------------|
| `mount` / “no FUSE” / connection errors | Install macFUSE 5.x or FUSE-T; reboot after system-extension approval |
| Works on Linux, fails on Tahoe | `-f -o backend=fskit`; upgrade macFUSE; try FUSE-T |
| `pkg-config` missing fuse when building | Reinstall macFUSE/FUSE-T; set `PKG_CONFIG_PATH` (sections 1–2) |
| `libarchive` not found | `brew install libarchive` + keg-only `PKG_CONFIG_PATH` |
| Stuck mount | `diskutil unmount force mnt`; kill leftover `ratarmount` |
| Finder empty / wrong name | `-o volname=Name`; FUSE-T may show a network-style volume |

More design notes: [docs/tasks/macos-support.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/macos-support.md).
