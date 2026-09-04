#!/usr/bin/env bash
# Install the tap-ready cask into a local Homebrew tap.
#
# Homebrew forbids path/URL casks, and packaging/homebrew/ is not a git
# repository, so `brew tap hilather/ratarmount packaging/homebrew` cannot
# work. brew tap-new creates a git tap; we copy Casks/ratarmount.rb into it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CASK="$ROOT/packaging/homebrew/Casks/ratarmount.rb"
TAP="hilather/ratarmount"

if ! command -v brew >/dev/null 2>&1; then
  echo "error: brew not on PATH (install Homebrew, then re-run)" >&2
  exit 1
fi
if [[ ! -f "$CASK" ]]; then
  echo "error: missing $CASK (run from a ratarmount-rs clone)" >&2
  exit 1
fi

if ! brew tap | grep -qx "$TAP"; then
  echo "==> brew tap-new ${TAP}"
  brew tap-new "$TAP"
fi

repo="$(brew --repo "$TAP")"
mkdir -p "$repo/Casks"
cp "$CASK" "$repo/Casks/ratarmount.rb"
echo "==> brew install --cask ${TAP}/ratarmount"
brew install --cask "${TAP}/ratarmount"
