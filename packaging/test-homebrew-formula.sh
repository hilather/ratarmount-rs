#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORMULA="$ROOT/packaging/homebrew/Formula/ratarmount-rs.rb"
if command -v ruby >/dev/null 2>&1; then
  ruby -c "$FORMULA"
else
  echo 'skip: ruby is unavailable'
fi
