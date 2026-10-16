#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
bash -n packaging/aur/PKGBUILD packaging/aur/PKGBUILD.source packaging/aur/update-sums.sh
if command -v makepkg >/dev/null 2>&1; then
  (cd packaging/aur && makepkg --printsrcinfo -p PKGBUILD) > /tmp/ratarmount-srcinfo
  diff -u packaging/aur/.SRCINFO /tmp/ratarmount-srcinfo
else
  echo 'skip: makepkg is unavailable; checked PKGBUILD syntax only'
fi
if command -v namcap >/dev/null 2>&1; then
  namcap packaging/aur/PKGBUILD
else
  echo 'skip: namcap is unavailable'
fi
