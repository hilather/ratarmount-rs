#!/usr/bin/env bash
# Regression: F-5 Homebrew v1 is a tap *cask* for the signed macos-arm64
# GitHub Release tarball (K17). Not a source formula. Homebrew forbids
# path/URL casks; docs must use brew tap-new + copy (packaging/homebrew/
# is not a git repo). Fully-qualified token.
#
# Static checks always run so Linux CI / agents can validate the cask without
# Homebrew. When brew exists, audit via a temporary local tap (not a filesystem
# path). Do not use `brew audit --strict` (homebrew-core formula rules).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CASK="$ROOT/packaging/homebrew/Casks/ratarmount.rb"

fail=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; fail=1; }

if [[ ! -f "$CASK" ]]; then
  echo "FAIL: missing $CASK" >&2
  exit 1
fi

if grep -qE '^cask "ratarmount" do' "$CASK"; then
  pass 'header is cask "ratarmount" do'
else
  fail 'must start with cask "ratarmount" do (not a Formula class)'
fi

if grep -qE 'class[[:space:]]+Ratarmount[[:space:]]*<[[:space:]]*Formula' "$CASK"; then
  fail 'must not be a source Formula'
else
  pass 'not a source Formula'
fi

if grep -qE '^[[:space:]]*def[[:space:]]+install' "$CASK"; then
  fail 'must not define Formula#install'
else
  pass 'no Formula#install'
fi

cask_version="$(sed -nE 's/^[[:space:]]*version[[:space:]]+"([^"]+)".*/\1/p' "$CASK" | head -1)"
if [[ "$cask_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  pass "version ${cask_version}"
else
  fail "version stanza missing or not semver (got '${cask_version}')"
fi

# Cask is bumped *after* Packages publishes the macos-arm64 tarball, so it may
# trail workspace Cargo.toml by one release. Format always; lockstep is not a gate.
cargo_version="$(grep -m1 '^version' "$ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ "$cask_version" == "$cargo_version" ]]; then
  pass "cask version currently matches workspace Cargo.toml (${cargo_version})"
else
  echo "note: cask ${cask_version} trails Cargo.toml ${cargo_version} (bump sha256 after the GitHub Release asset exists)"
fi

sha="$(sed -nE 's/^[[:space:]]*sha256[[:space:]]+"([0-9a-f]{64})".*/\1/p' "$CASK" | head -1)"
if [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
  pass "sha256 is 64 lowercase hex"
else
  fail "sha256 must be a 64-char lowercase hex digest of the macos-arm64 tarball (not :no_check)"
fi

if grep -qE 'sha256[[:space:]]:no_check' "$CASK"; then
  fail 'sha256 :no_check is not allowed for a versioned release tarball'
fi

want_url='url "https://github.com/hilather/ratarmount-rs/releases/download/v#{version}/ratarmount-#{version}-macos-arm64.tar.gz"'
if grep -F "$want_url" "$CASK" >/dev/null; then
  pass 'url is GitHub Release macos-arm64 tarball with #{version}'
else
  fail "url must be exactly: ${want_url}"
fi

if grep -qE 'releases/latest/download' "$CASK"; then
  fail 'must not use unversioned /releases/latest/download'
else
  pass 'url is version-pinned (not latest/download)'
fi

if grep -qE '^[[:space:]]*binary[[:space:]]+"ratarmount-#\{version\}-macos-arm64/ratarmount"' "$CASK"; then
  pass 'binary artifact is the staged macos-arm64 tarball member'
else
  fail 'binary stanza must link ratarmount-#{version}-macos-arm64/ratarmount'
fi

if grep -qE 'depends_on macos: ">= :sonoma"' "$CASK"; then
  pass 'depends_on macos >= :sonoma (tarball is built on macos-14)'
else
  fail 'depends_on macos: ">= :sonoma" required (packages.yml macos-14)'
fi

if grep -qE 'depends_on arch: :arm64' "$CASK"; then
  pass 'depends_on arch: :arm64 (Intel tarball deferred)'
else
  fail 'depends_on arch: :arm64 required (do not claim Intel)'
fi

# Caveats only for FUSE + runtime libarchive — not formula build deps.
for needle in macfuse FUSE-T libarchive; do
  if grep -qi "$needle" "$CASK"; then
    pass "caveats mention ${needle}"
  else
    fail "caveats must mention ${needle}"
  fi
done

if grep -q 'PKG_CONFIG_PATH' "$CASK"; then
  fail 'cask must not mention PKG_CONFIG_PATH (prebuilt unpack, not a source build)'
else
  pass 'no PKG_CONFIG_PATH'
fi

# Formula-style build dependencies are two products (K17 / brew audit --strict).
if grep -qE 'depends_on[[:space:]]+"libarchive"|depends_on[[:space:]]+"rust"|depends_on[[:space:]]+"pkgconf"|depends_on[[:space:]]+"pkg-config"|depends_on[[:space:]]+"cargo"' "$CASK"; then
  fail 'must not depends_on formula build deps (libarchive/rust/pkgconf); runtime libarchive is caveats-only'
else
  pass 'no formula depends_on "libarchive"/"rust"/"pkgconf"'
fi

if grep -qE '^[[:space:]]*brew[[:space:]]+audit.*--strict' "$ROOT/packaging/test-homebrew-cask.sh"; then
  fail 'must not invoke brew audit --strict (homebrew-core formula rules)'
else
  pass 'does not invoke brew audit --strict'
fi

# Homebrew forbids path/URL casks. packaging/homebrew/ is not a git repo, so
# two-arg `brew tap user/name packaging/homebrew` cannot work.
DOC_FILES=(
  "$ROOT/README.md"
  "$ROOT/docs/macos.md"
  "$ROOT/docs/packaging.md"
)
INSTALL_SH="$ROOT/packaging/homebrew/install.sh"
for f in "${DOC_FILES[@]}"; do
  if grep -nE 'raw\.githubusercontent\.com' "$f" >/dev/null; then
    fail "$(basename "$f") must not document a raw.githubusercontent.com cask URL"
  else
    pass "$(basename "$f") has no raw.githubusercontent.com cask URL"
  fi
  if grep -nE 'brew install --cask \./' "$f" >/dev/null; then
    fail "$(basename "$f") must not document brew install --cask ./…rb"
  else
    pass "$(basename "$f") has no path cask install"
  fi
  if grep -nE 'brew install --cask https://' "$f" >/dev/null; then
    fail "$(basename "$f") must not document brew install --cask https://…rb"
  else
    pass "$(basename "$f") has no https cask install"
  fi
  if grep -nE 'brew tap hilather/ratarmount[[:space:]]+"\$\(pwd\)/packaging/homebrew"' "$f" >/dev/null \
    || grep -nE 'brew tap hilather/ratarmount[[:space:]]+packaging/homebrew' "$f" >/dev/null; then
    fail "$(basename "$f") must not brew tap packaging/homebrew (not a git repo)"
  else
    pass "$(basename "$f") does not git-tap packaging/homebrew"
  fi
  if grep -qF 'brew tap-new hilather/ratarmount' "$f" \
    && grep -qF 'mkdir -p "$(brew --repo hilather/ratarmount)/Casks"' "$f" \
    && grep -qF 'brew --repo hilather/ratarmount' "$f" \
    && grep -qF 'brew install --cask hilather/ratarmount/ratarmount' "$f"; then
    pass "$(basename "$f") documents tap-new + mkdir Casks + copy + fully-qualified install"
  else
    fail "$(basename "$f") must document brew tap-new, mkdir -p Casks, brew --repo copy, and brew install --cask hilather/ratarmount/ratarmount"
  fi
done

if [[ ! -x "$INSTALL_SH" ]]; then
  fail "packaging/homebrew/install.sh must exist and be executable"
else
  pass "packaging/homebrew/install.sh is executable"
fi
if grep -qF 'brew tap-new' "$INSTALL_SH" \
  && grep -qF 'mkdir -p' "$INSTALL_SH" \
  && grep -qF 'brew --repo' "$INSTALL_SH" \
  && grep -qF 'brew install --cask "${TAP}/ratarmount"' "$INSTALL_SH"; then
  pass "install.sh uses tap-new + mkdir Casks + copy + fully-qualified install"
else
  fail "install.sh must brew tap-new, mkdir -p Casks, copy into brew --repo, and brew install --cask"
fi
if grep -nE 'brew tap \$\{TAP\}[[:space:]]+"\$ROOT/packaging/homebrew"|brew tap hilather/ratarmount[[:space:]]+"\$\(pwd\)/packaging/homebrew"' "$INSTALL_SH" >/dev/null; then
  fail "install.sh must not brew tap packaging/homebrew as a git remote"
else
  pass "install.sh does not git-tap packaging/homebrew"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "FAIL: Homebrew cask static checks" >&2
  exit 1
fi

echo "OK: Homebrew cask static checks ($CASK)"

if ! command -v brew >/dev/null 2>&1; then
  echo "skip: brew not on PATH (static cask checks passed)" >&2
  exit 0
fi

# Audit the same way the docs install: brew tap-new + copy into Casks/.
# Do not `brew audit --cask /path/to.rb` (HOMEBREW_FORBID_PACKAGES_FROM_PATHS)
# and do not `brew tap user/name packaging/homebrew` (not a git repo).
TAP="ratarmount-cask-ci/ratarmount"
cleanup_tap() {
  brew untap "$TAP" >/dev/null 2>&1 || true
}
trap cleanup_tap EXIT
brew untap "$TAP" >/dev/null 2>&1 || true

echo "==> brew tap-new ${TAP}"
if ! brew tap-new "$TAP"; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "FAIL: brew tap-new ${TAP} on Darwin" >&2
    exit 1
  fi
  echo "skip: brew tap-new failed on $(uname -s) (static checks passed)" >&2
  exit 0
fi

repo="$(brew --repo "$TAP")"
mkdir -p "$repo/Casks"
cp "$CASK" "$repo/Casks/ratarmount.rb"

echo "==> brew audit --cask ${TAP}/ratarmount"
if brew audit --cask "${TAP}/ratarmount"; then
  echo "OK: brew audit --cask via tap-new"
elif [[ "$(uname -s)" != "Darwin" ]]; then
  echo "skip: brew audit --cask of macos-only cask on $(uname -s) (static checks passed)" >&2
else
  echo "FAIL: brew audit --cask via tap-new" >&2
  exit 1
fi
