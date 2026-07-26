#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/run-codec-allowlist.sh" "$SCRIPT_DIR/phase9-sqlar-squashfs.txt" "Phase 9 sqlar+squashfs"
