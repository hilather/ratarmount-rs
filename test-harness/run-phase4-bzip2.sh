#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/run-codec-allowlist.sh" "$SCRIPT_DIR/phase4-bzip2.txt" "Phase 4 bzip2"
