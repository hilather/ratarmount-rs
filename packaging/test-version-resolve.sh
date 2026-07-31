#!/usr/bin/env bash
# Regression: tag version must match workspace Cargo.toml version.
# Misnamed-asset incident class: tag v0.1.11 while Cargo.toml still 0.1.10 → packages
# named with the wrong version string.
#
# Usage:
#   ./packaging/test-version-resolve.sh              # unit tests (no network)
#   ./packaging/test-version-resolve.sh --resolve    # print VERSION=x.y.z for GITHUB_ENV
#
# --resolve env:
#   GITHUB_REF_TYPE   "tag" | other (PR / workflow_dispatch)
#   GITHUB_REF_NAME   tag name e.g. v0.1.12 (leading v stripped)
#   CARGO_TOML        path to workspace Cargo.toml (default: ./Cargo.toml or repo root)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Pure resolve used by packages.yml "Resolve package version" steps.
# Prints resolved semver (no leading v) on stdout; exits 1 on mismatch / parse fail.
resolve_package_version() {
  local cargo_toml="${1:?Cargo.toml path required}"
  local cargo_version
  if [[ ! -f "$cargo_toml" ]]; then
    echo "error: Cargo.toml not found: ${cargo_toml}" >&2
    return 1
  fi
  cargo_version="$(grep -m1 '^version' "$cargo_toml" | sed -E 's/.*"([^"]+)".*/\1/')"
  if [[ -z "${cargo_version}" || "${cargo_version}" == *"version"* ]]; then
    echo "error: could not parse workspace version from ${cargo_toml}" >&2
    return 1
  fi

  local v
  if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
    local ref="${GITHUB_REF_NAME:-}"
    if [[ -z "$ref" ]]; then
      echo "error: GITHUB_REF_TYPE=tag but GITHUB_REF_NAME is empty" >&2
      return 1
    fi
    v="${ref#v}"
    if [[ -z "$v" ]]; then
      echo "error: empty version after stripping leading v from tag '${ref}'" >&2
      return 1
    fi
    if [[ "${v}" != "${cargo_version}" ]]; then
      echo "error: tag version '${v}' (from ${ref}) does not match Cargo.toml workspace version '${cargo_version}'" >&2
      echo "error: bump workspace version in Cargo.toml to match the tag (or retag), then re-run packages." >&2
      return 1
    fi
  else
    # PR / workflow_dispatch: package as workspace version from Cargo.toml
    v="${cargo_version}"
  fi
  printf '%s\n' "${v}"
}

if [[ "${1:-}" == "--resolve" ]]; then
  if [[ -n "${CARGO_TOML:-}" ]]; then
    cargo_toml="${CARGO_TOML}"
  elif [[ -f Cargo.toml ]]; then
    cargo_toml="Cargo.toml"
  else
    cargo_toml="${ROOT}/Cargo.toml"
  fi
  version="$(resolve_package_version "$cargo_toml")"
  echo "VERSION=${version}"
  exit 0
fi

# ---------------------------------------------------------------------------
# Unit tests (no network)
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

write_cargo() {
  local ver="$1"
  cat >"$TMP/Cargo.toml" <<EOF
[workspace.package]
version = "${ver}"
EOF
}

pass=0
fail=0

assert_eq() {
  local name="$1" got="$2" want="$3"
  if [[ "$got" == "$want" ]]; then
    echo "PASS: $name (got ${got})"
    pass=$((pass + 1))
  else
    echo "FAIL: $name (got '${got}', want '${want}')" >&2
    fail=$((fail + 1))
  fi
}

assert_fail() {
  local name="$1"
  shift
  local rc=0
  "$@" >/dev/null 2>"$TMP/err" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "PASS: $name (exited ${rc})"
    pass=$((pass + 1))
  else
    echo "FAIL: $name (expected non-zero exit)" >&2
    fail=$((fail + 1))
  fi
}

# Tag matches Cargo.toml
write_cargo "0.1.12"
export GITHUB_REF_TYPE=tag
export GITHUB_REF_NAME=v0.1.12
got="$(resolve_package_version "$TMP/Cargo.toml")"
assert_eq "tag match strips v" "$got" "0.1.12"

# Tag without leading v still compared as-is after #v (no-op strip)
export GITHUB_REF_NAME=0.1.12
got="$(resolve_package_version "$TMP/Cargo.toml")"
assert_eq "tag without v prefix" "$got" "0.1.12"

# Tag mismatches Cargo.toml (incident class: v0.1.11 vs cargo 0.1.12)
export GITHUB_REF_NAME=v0.1.11
set +e
out="$(resolve_package_version "$TMP/Cargo.toml" 2>"$TMP/err")"
rc=$?
set -e
if [[ "$rc" -ne 0 ]] && grep -q "does not match" "$TMP/err"; then
  echo "PASS: tag mismatch fails with clear message"
  pass=$((pass + 1))
else
  echo "FAIL: tag mismatch should fail; rc=$rc out='$out' err=$(cat "$TMP/err")" >&2
  fail=$((fail + 1))
fi

# Non-tag uses Cargo.toml only
unset GITHUB_REF_TYPE GITHUB_REF_NAME || true
write_cargo "0.2.0"
got="$(resolve_package_version "$TMP/Cargo.toml")"
assert_eq "non-tag uses cargo version" "$got" "0.2.0"

# workflow_dispatch / branch-style ref type
export GITHUB_REF_TYPE=branch
export GITHUB_REF_NAME=main
write_cargo "1.0.0"
got="$(resolve_package_version "$TMP/Cargo.toml")"
assert_eq "branch ref uses cargo version" "$got" "1.0.0"

# --resolve CLI emits VERSION=
write_cargo "0.3.1"
export GITHUB_REF_TYPE=tag
export GITHUB_REF_NAME=v0.3.1
cli_out="$(CARGO_TOML="$TMP/Cargo.toml" bash "$ROOT/packaging/test-version-resolve.sh" --resolve)"
assert_eq "--resolve emits VERSION=" "$cli_out" "VERSION=0.3.1"

# --resolve fails on mismatch
export GITHUB_REF_NAME=v9.9.9
set +e
CARGO_TOML="$TMP/Cargo.toml" bash "$ROOT/packaging/test-version-resolve.sh" --resolve >"$TMP/out" 2>"$TMP/err"
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
  echo "PASS: --resolve exits non-zero on tag/cargo mismatch"
  pass=$((pass + 1))
else
  echo "FAIL: --resolve should fail on mismatch" >&2
  fail=$((fail + 1))
fi

# Empty / missing Cargo.toml
assert_fail "missing Cargo.toml" resolve_package_version "$TMP/no-such-Cargo.toml"

# Tag with empty name
export GITHUB_REF_TYPE=tag
export GITHUB_REF_NAME=""
write_cargo "0.1.0"
assert_fail "empty tag name" resolve_package_version "$TMP/Cargo.toml"

echo ""
echo "Results: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]] || exit 1
echo "OK: version resolve asserts tag matches Cargo.toml ($ROOT)"
