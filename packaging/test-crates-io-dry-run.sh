#!/usr/bin/env bash
# Regression: F-10 crates.io first-publish is Q5=(a) dry-run only.
# Never live-publish. L0 (ratarmount-core, ratarmount-index) must package;
# the ratarmount binary is not the embedder surface; L3.5 session stays
# path-depend until a freeze review. Dual-run does not wait on crates.io.
#
# G7.3 keep-green (separate from this script):
#   cargo test -p ratarmount-session --lib index_job_sidecar_python_07
#   ./test-harness/run-indexjob-python-interop.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; fail=1; }

# Q5=(a): never authenticate a live crates.io upload from this check.
unset CARGO_REGISTRY_TOKEN CARGO_REGISTRIES_CRATES_IO_TOKEN || true

# Every cargo publish in this file must include --dry-run (no live path).
# Fail closed before any cargo invocation so a stray upload cannot run.
while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" == *'cargo publish'* && "$line" != *'--dry-run'* ]]; then
        echo "FAIL: script must not invoke cargo publish without --dry-run: $line" >&2
        exit 1
    fi
done <"$0"

CORE_TOML="$ROOT/ratarmount-core/Cargo.toml"
INDEX_TOML="$ROOT/ratarmount-index/Cargo.toml"

check_l0_manifest() {
    local name="$1"
    local toml="$2"
    if [[ ! -f "$toml" ]]; then
        fail "missing $toml"
        return
    fi
    if grep -qE '^name = "'"$name"'"' "$toml"; then
        pass "$name package name"
    else
        fail "$toml must set name = \"$name\""
    fi
    if grep -qE '^version\.workspace = true' "$toml"; then
        pass "$name version.workspace"
    else
        fail "$toml must inherit workspace version"
    fi
    if grep -qE '^license\.workspace = true' "$toml"; then
        pass "$name license.workspace"
    else
        fail "$toml must inherit workspace license"
    fi
    if grep -qE '^repository\.workspace = true' "$toml"; then
        pass "$name repository.workspace"
    else
        fail "$toml must inherit workspace repository (crates.io metadata)"
    fi
    if grep -qE '^description = "' "$toml"; then
        pass "$name description"
    else
        fail "$toml must set description"
    fi
    if grep -qE '^publish[[:space:]]*=' "$toml"; then
        fail "$toml must not set publish = false (L0 is the dry-run candidate)"
    else
        pass "$name is not publish = false"
    fi
}

check_l0_manifest ratarmount-core "$CORE_TOML"
check_l0_manifest ratarmount-index "$INDEX_TOML"

if grep -qE '^version = "' "$ROOT/Cargo.toml"; then
    pass "workspace version is set"
else
    fail "root Cargo.toml missing workspace version"
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "skip: cargo not on PATH (manifest metadata already checked)" >&2
    [[ "$fail" -eq 0 ]] || exit 1
    exit 0
fi

# cargo publish wrapper: --dry-run is mandatory and cannot be stripped.
publish_dry_run() {
    local crate="$1"
    shift
    cargo publish -p "$crate" --dry-run --allow-dirty "$@"
}

package_list() {
    local crate="$1"
    cargo package -p "$crate" --list --allow-dirty
}

core_list="$(package_list ratarmount-core)"
if echo "$core_list" | grep -qx 'src/lib.rs'; then
    pass "core package list includes src/lib.rs"
else
    fail "cargo package -p ratarmount-core --list missing src/lib.rs"
fi

index_list="$(package_list ratarmount-index)"
if echo "$index_list" | grep -qx 'src/lib.rs'; then
    pass "index package list includes src/lib.rs"
else
    fail "cargo package -p ratarmount-index --list missing src/lib.rs"
fi
if echo "$index_list" | grep -qx 'create-index-tables.sql'; then
    pass "index package list includes create-index-tables.sql"
else
    fail "cargo package -p ratarmount-index --list missing create-index-tables.sql"
fi

set +e
core_out="$(publish_dry_run ratarmount-core 2>&1)"
core_rc=$?
set -e
echo "$core_out"
if echo "$core_out" | grep -q 'aborting upload due to dry run'; then
    pass "core cargo publish --dry-run aborted upload"
elif echo "$core_out" | grep -qiE 'could not (connect|fetch)|network|offline|timed out|error sending request'; then
    echo "skip: crates.io unreachable for core dry-run (package --list already passed)" >&2
else
    fail "core cargo publish --dry-run did not abort upload (rc=${core_rc})"
fi

# Index still uses a path-only workspace dep today. Live publish must add a
# version requirement; dry-run is success if upload is aborted *or* Cargo
# reports that known residual (not some other packaging error).
set +e
index_out="$(publish_dry_run ratarmount-index --no-verify 2>&1)"
index_rc=$?
set -e
echo "$index_out"
if echo "$index_out" | grep -q 'aborting upload due to dry run'; then
    pass "index cargo publish --dry-run aborted upload"
elif echo "$index_out" | grep -q 'does not specify a version'; then
    pass "index dry-run residual: path dep has no version (first live publish adds versions)"
elif echo "$index_out" | grep -qiE 'could not (connect|fetch)|network|offline|timed out|error sending request'; then
    echo "skip: crates.io unreachable for index dry-run (package --list already passed)" >&2
else
    fail "index cargo publish --dry-run unexpected result (rc=${index_rc})"
fi

# Negative: this check must not treat the CLI binary as a crates.io lib.
if echo "$core_list"$'\n'"$index_list" | grep -qE '^src/main.rs$'; then
    fail "L0 package list must not include the CLI binary src/main.rs"
else
    pass "L0 package lists are library crates (no CLI src/main.rs)"
fi

[[ "$fail" -eq 0 ]] || exit 1
echo "OK: crates.io dry-run only (no live publish) for L0 core+index"
