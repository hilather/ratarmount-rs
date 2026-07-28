#!/usr/bin/env bash
# Regression: GitHub Releases reject empty blobs. Flatten/upload must only
# include non-empty files (empty file-info.txt broke v0.1.8 publishing).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/release"
# Simulate flatten output: packages + empty sidecar + real sidecar
: >"$TMP/release/file-info.txt" # 0 bytes — must be skipped
echo "ok" >"$TMP/release/file-info-macos-arm64.txt"
echo "deb-bytes" >"$TMP/release/ratarmount_0.0.0_amd64.deb"
printf '' >"$TMP/release/empty.cosign.bundle" # 0 bytes — skip

# Same filter as packages.yml Sign & release step
mapfile -t files < <(
  find "$TMP/release" -maxdepth 1 -type f ! -name '.*' -size +0c -printf '%f\n' | sort
)
mapfile -t empty_files < <(
  find "$TMP/release" -maxdepth 1 -type f ! -name '.*' -size 0c -printf '%f\n' | sort || true
)

echo "non-empty: ${files[*]}"
echo "empty: ${empty_files[*]}"

printf '%s\n' "${files[@]}" | grep -qx 'ratarmount_0.0.0_amd64.deb'
printf '%s\n' "${files[@]}" | grep -qx 'file-info-macos-arm64.txt'
if printf '%s\n' "${files[@]}" | grep -qx 'file-info.txt'; then
  echo "FAIL: empty file-info.txt must not be in upload list" >&2
  exit 1
fi
if printf '%s\n' "${files[@]}" | grep -qx 'empty.cosign.bundle'; then
  echo "FAIL: empty cosign bundle must not be in upload list" >&2
  exit 1
fi
[[ "${#files[@]}" -eq 2 ]] || {
  echo "FAIL: expected 2 non-empty assets, got ${#files[@]}" >&2
  exit 1
}
[[ "${#empty_files[@]}" -eq 2 ]] || {
  echo "FAIL: expected 2 empty files detected, got ${#empty_files[@]}" >&2
  exit 1
}

echo "OK: release asset filter skips empty files ($ROOT)"
