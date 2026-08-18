#!/usr/bin/env bash
# Regression: v0.1.23 CI cold-index job cancelled after 30m stuck in apt-get
# (FUSE allowlists hung on the same step). Every apt-get in CI must pass
# Acquire::Retries so a CDN blip does not cancel/hang the workflow.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WF="$ROOT/.github/workflows/ci.yml"

if [[ ! -f "$WF" ]]; then
  echo "FAIL: missing $WF" >&2
  exit 1
fi

mapfile -t apt_lines < <(grep -nE 'apt-get ' "$WF" || true)
if [[ "${#apt_lines[@]}" -eq 0 ]]; then
  echo "FAIL: no apt-get lines in $WF" >&2
  exit 1
fi

bad=0
for line in "${apt_lines[@]}"; do
  if [[ "$line" != *'Acquire::Retries='* ]]; then
    echo "FAIL: apt-get without Acquire::Retries: $line" >&2
    bad=1
  fi
done
if [[ "$bad" -ne 0 ]]; then
  exit 1
fi

echo "OK: ${#apt_lines[@]} apt-get line(s) set Acquire::Retries"
