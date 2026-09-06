#!/usr/bin/env bash
# Regression: G6.1 windows-lib job must exist; core+index is a merge gate
# (stable rustc, no windows_by_handle). Session may skip without libarchive.
# Must not gate Linux fmt+clippy+test / FUSE allowlists via `needs:`.
# Linux `check` must run this script so the YAML/API contract cannot drift.
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

if ! grep -q 'cargo check -p ratarmount-core -p ratarmount-index --all-targets' "$WF"; then
  echo "FAIL: windows-lib must cargo check -p ratarmount-core -p ratarmount-index --all-targets" >&2
  exit 1
fi

if ! grep -q 'cargo check -p ratarmount-session --all-targets' "$WF"; then
  echo "FAIL: windows-lib must cargo check -p ratarmount-session --all-targets" >&2
  exit 1
fi

# Job-level continue-on-error (4-space indent) hid the v0.1.30 E0658 failure.
if awk '
  $0 ~ /^  windows-lib:/ { in_job=1; next }
  in_job && $0 ~ /^  [A-Za-z0-9_-]+:/ { in_job=0 }
  in_job && $0 ~ /^    continue-on-error:/ { found=1 }
  END { exit found ? 0 : 1 }
' "$WF"; then
  echo "FAIL: windows-lib must not set job-level continue-on-error (core+index is a merge gate)" >&2
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

if ! awk '
  $0 ~ /^  check:/ { in_job=1; next }
  in_job && $0 ~ /^  [A-Za-z0-9_-]+:/ { in_job=0 }
  in_job && $0 ~ /packaging\/test-windows-lib-ci.sh/ { found=1 }
  END { exit found ? 0 : 1 }
' "$WF"; then
  echo "FAIL: Linux check job must run packaging/test-windows-lib-ci.sh" >&2
  exit 1
fi

# rust-lang/rust#63010: these MetadataExt methods are nightly-only. v0.1.30
# windows-lib failed cargo check with E0658 on volume_serial_number / file_index.
banned=$(git -C "$ROOT" grep -nE 'volume_serial_number\(|\.file_index\(|number_of_links\(|change_time\(|feature\(windows_by_handle\)' -- '*.rs' || true)
if [[ -n "$banned" ]]; then
  echo "FAIL: unstable windows_by_handle APIs (stable rustc E0658):" >&2
  echo "$banned" >&2
  exit 1
fi

echo "OK: windows-lib core+index is a merge gate; session skippable; no windows_by_handle APIs"
