#!/usr/bin/env bash
# Regression: F-5 Homebrew v1 is a tap *cask* for the signed macos-arm64
# GitHub Release tarball (K17). Not a source formula. brew audit --cask when
# brew exists; skip the brew audit (not the static checks) if brew is missing.
#
# Static checks always run so Linux CI / agents can validate the cask without
# Homebrew. Do not use `brew audit --strict` (homebrew-core formula rules).
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

cargo_version="$(grep -m1 '^version' "$ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ -n "$cask_version" && "$cask_version" == "$cargo_version" ]]; then
  pass "cask version matches workspace Cargo.toml (${cargo_version})"
else
  fail "cask version '${cask_version}' must match workspace Cargo.toml '${cargo_version}'"
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

if [[ "$fail" -ne 0 ]]; then
  echo "FAIL: Homebrew cask static checks" >&2
  exit 1
fi

echo "OK: Homebrew cask static checks ($CASK)"

if ! command -v brew >/dev/null 2>&1; then
  echo "skip: brew not on PATH (static cask checks passed)" >&2
  exit 0
fi

# Tap-cask audit only. Not --strict (homebrew-core formula rules).
echo "==> brew audit --cask ${CASK}"
brew audit --cask "$CASK"
echo "OK: brew audit --cask"
