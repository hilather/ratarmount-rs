#!/usr/bin/env bash
# Phase 9: HTML / PDF / zlib (and related) allowlist.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/run-codec-allowlist.sh" "$SCRIPT_DIR/phase9-misc-formats.txt" "Phase 9 misc formats"
