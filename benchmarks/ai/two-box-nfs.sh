#!/usr/bin/env bash
# Usage: ./benchmarks/ai/two-box-nfs.sh loopback --mib 16
set -euo pipefail
if ! command -v python3 >/dev/null; then
  echo 'skip: python3 is required' >&2
  exit 0
fi
exec python3 "$(dirname "${BASH_SOURCE[0]}")/two_box_nfs.py" "$@"
