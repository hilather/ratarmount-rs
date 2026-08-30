#!/usr/bin/env bash
# Regression: G6.1 windows-lib job must exist, stay best-effort, and must not
# gate Linux fmt+clippy+test / FUSE allowlists.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WF="$ROOT/.github/workflows/ci.yml"

if [[ ! -f "$WF" ]]; then
  echo "FAIL: missing $WF" >&2
  exit 1
fi

if ! grep -qE '^  windows-lib:' "$WF"; then
  echo "FAIL: no windows-lib job in $WF" >&2
  exit 1
fi

if ! grep -q 'cargo check -p ratarmount-session --all-targets' "$WF"; then
  echo "FAIL: windows-lib must cargo check -p ratarmount-session --all-targets" >&2
  exit 1
fi

if ! awk '
  $0 ~ /^  windows-lib:/ { in_job=1; next }
  in_job && $0 ~ /^  [A-Za-z0-9_-]+:/ { in_job=0 }
  in_job && $0 ~ /continue-on-error: true/ { found=1 }
  END { exit found ? 0 : 1 }
' "$WF"; then
  echo "FAIL: windows-lib must continue-on-error (not a merge gate)" >&2
  exit 1
fi

if awk '
  $0 ~ /^  check:/ { in_job=1; next }
  in_job && $0 ~ /^  [A-Za-z0-9_-]+:/ { in_job=0 }
  in_job && $0 ~ /needs:.*windows-lib/ { found=1 }
  END { exit found ? 0 : 1 }
' "$WF"; then
  echo "FAIL: check job must not need windows-lib" >&2
  exit 1
fi

if awk '
  $0 ~ /^  fuse-harness:/ { in_job=1; next }
  in_job && $0 ~ /^  [A-Za-z0-9_-]+:/ { in_job=0 }
  in_job && $0 ~ /needs:.*windows-lib/ { found=1 }
  END { exit found ? 0 : 1 }
' "$WF"; then
  echo "FAIL: fuse-harness must not need windows-lib" >&2
  exit 1
fi

echo "OK: windows-lib is best-effort and does not gate Linux check / FUSE"
