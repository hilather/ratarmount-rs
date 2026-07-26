#!/usr/bin/env bash
# Phase: seekable outer stream codecs (lz4, lzip, .Z, lzma, lzo).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/run-codec-allowlist.sh" "$SCRIPT_DIR/phase-stream-codecs.txt" stream-codecs
