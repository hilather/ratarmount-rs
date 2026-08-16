#!/usr/bin/env bash
# Regression: v0.1.21 portable bullseye-amd64 died on a one-shot apt-get
# ("Connection reset by peer" fetching libfuse3). Every apt-get in Packages
# must pass Acquire::Retries so a CDN blip does not drop the glibc 2.31 tarball.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WF="$ROOT/.github/workflows/packages.yml"

if [[ ! -f "$WF" ]]; then
  echo "FAIL: missing $WF" >&2
  exit 1
fi

# Every apt-get line (update or install) must include Acquire::Retries.
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
