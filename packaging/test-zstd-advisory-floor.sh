#!/usr/bin/env bash
# Regression: RUSTSEC-2026-0391/0398/0403/0410 zstd floor
# Check every zstd-family entry in the workspace and Clippy witness lockfiles.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export TMPDIR=/var/tmp
TEST_TMP="$(mktemp -d "$TMPDIR/ratarmount-zstd-floor.XXXXXX")"
trap 'rm -rf "$TEST_TMP"' EXIT

python3 - "$ROOT" "$TEST_TMP" <<'PY'
"""Reject zstd versions below the fixed advisory floors without running Cargo."""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
test_tmp = Path(sys.argv[2])
floors = {
    "zstd": "0.13.x >= 0.13.4 or >= 0.14.3",
    "zstd-safe": "7.x >= 7.4.0 or >= 8.2.0",
    "zstd-sys": ">= 2.1.2",
}


def is_fixed(name: str, version: str) -> bool:
    # Cargo's zstd-sys versions include bundled-libzstd build metadata.
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", version.split("+", 1)[0])
    if not match:
        return False
    release = tuple(map(int, match.groups()))
    if name == "zstd":
        return (0, 13, 4) <= release < (0, 14, 0) or release >= (0, 14, 3)
    if name == "zstd-safe":
        return (7, 4, 0) <= release < (8, 0, 0) or release >= (8, 2, 0)
    return release >= (2, 1, 2)


def assert_advisory_floor(path: Path, *, require_zstd: bool = False) -> None:
    with path.open("rb") as lock_file:
        lock = tomllib.load(lock_file)
    found_zstd = False
    for package in lock.get("package", []):
        name = package["name"]
        if name not in floors:
            continue
        found_zstd |= name == "zstd"
        version = package["version"]
        if not is_fixed(name, version):
            raise SystemExit(
                f"FAIL: {path}: {name} {version} below fixed floor ({floors[name]})"
            )
    if require_zstd and not found_zstd:
        raise SystemExit(f"FAIL: {path}: missing zstd entry")


def synthetic_lock(label: str, versions: dict[str, str]) -> Path:
    path = test_tmp / f"{label}.lock"
    path.write_text(
        "version = 4\n\n"
        + "".join(
            f'[[package]]\nname = "{name}"\nversion = "{version}"\n\n'
            for name, version in versions.items()
        )
    )
    return path


def assert_rejected(label: str, versions: dict[str, str], expected: str) -> None:
    path = synthetic_lock(label, versions)
    try:
        assert_advisory_floor(path, require_zstd=True)
    except SystemExit as exc:
        if expected not in str(exc):
            raise
        print(f"PASS: synthetic {label} is rejected")
    else:
        raise SystemExit(f"FAIL: synthetic {label} should be rejected")


# Self-tests use only temporary synthetic lockfiles, never tracked lockfiles.
fixed = {
    "zstd": "0.13.4",
    "zstd-safe": "7.4.0",
    "zstd-sys": "2.1.2+zstd.1.5.7",
}
assert_rejected(
    "all-stale",
    {"zstd": "0.13.3", "zstd-safe": "7.3.0", "zstd-sys": "2.1.0"},
    "zstd 0.13.3 below fixed floor",
)
for label, name, version in [
    ("stale-zstd", "zstd", "0.13.3"),
    ("stale-zstd-safe", "zstd-safe", "7.3.0"),
    ("stale-zstd-sys", "zstd-sys", "2.1.0"),
    ("gap-zstd", "zstd", "0.14.2"),
    ("gap-zstd-safe", "zstd-safe", "8.1.0"),
    ("stale-zstd-sys-build-metadata", "zstd-sys", "2.1.1+zstd.1.5.7"),
]:
    assert_rejected(label, fixed | {name: version}, f"{name} {version} below fixed floor")

for label, versions in [
    ("fixed", fixed | {"zstd-sys": "2.1.2"}),
    ("fixed-build-metadata", fixed),
    ("fixed-newer-branches", fixed | {"zstd": "0.14.3", "zstd-safe": "8.2.0"}),
]:
    assert_advisory_floor(synthetic_lock(label, versions), require_zstd=True)
    print(f"PASS: synthetic {label}")

without_zstd = {name: version for name, version in fixed.items() if name != "zstd"}
assert_rejected("missing-root-zstd", without_zstd, "missing zstd entry")
assert_advisory_floor(synthetic_lock("witness-without-zstd", without_zstd))
print("PASS: a witness lock may omit zstd")

# Check every package entry, including multiple versions of the same crate.
lock_paths = [root / "Cargo.lock"] + sorted(
    (root / "packaging/internal-read-clippy/witnesses").glob("*/Cargo.lock")
)
for path in lock_paths:
    assert_advisory_floor(path, require_zstd=path == root / "Cargo.lock")
    print(f"PASS: {path.relative_to(root)} zstd advisory floors")

ci = (root / ".github/workflows/ci.yml").read_text()
if "\n        run: bash packaging/test-zstd-advisory-floor.sh\n" not in ci:
    raise SystemExit("FAIL: ci.yml check job must run packaging/test-zstd-advisory-floor.sh")
print("PASS: ci.yml invokes zstd advisory floor script")
print("OK: zstd advisory floors hold")
PY
