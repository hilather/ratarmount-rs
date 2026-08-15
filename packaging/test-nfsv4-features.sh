#!/usr/bin/env bash
# Regression: Linux (and macOS-stable) package builds must pass
# `--features nfsv4` on the actual `cargo build` line. Editing only
# `.github/workflows/packages.yml` does not compile embednfs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail=0

# The compile line must appear as a real cargo invocation, not only a comment.
check_script() {
    local f="$1"
    if grep -E '^[[:space:]]*cargo build --release -p ratarmount --features nfsv4[[:space:]]*$' "$f" >/dev/null; then
        echo "PASS: $f compiles nfsv4"
    else
        echo "FAIL: $f missing 'cargo build --release -p ratarmount --features nfsv4'" >&2
        fail=1
    fi
}

check_script "$ROOT/packaging/build-native-packages.sh"
check_script "$ROOT/packaging/build-appimage.sh"
check_script "$ROOT/packaging/build-macos-tarball.sh"

# YAML must not be the only mention (scripts above are the compile lines).
if grep -E '^[[:space:]]*cargo build --release -p ratarmount --features nfsv4' \
    "$ROOT/.github/workflows/packages.yml" >/dev/null; then
    echo "note: packages.yml also has a cargo nfsv4 line (scripts still required)"
else
    echo "OK: packages.yml does not compile v4 itself (scripts do)"
fi

[[ "$fail" -eq 0 ]] || exit 1
echo "OK: package build scripts enable --features nfsv4"
