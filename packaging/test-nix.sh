#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v nix >/dev/null 2>&1; then
  echo 'skip: nix is unavailable'
  exit 0
fi
cd "$ROOT"
nix flake check
