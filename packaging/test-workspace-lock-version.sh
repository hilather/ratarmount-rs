#!/usr/bin/env bash
# Regression: workspace lock versions stale after version bump (#66).
# After workspace.package.version is bumped, Cargo.lock path crates must
# record the same version (PR #65 left them at 0.1.30). Cargo.toml must
# keep a trailing newline (25d62c7 dropped it).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

python3 - "$ROOT" <<'PY'
"""Check workspace crate versions in Cargo.lock match Cargo.toml."""
from __future__ import annotations

import re
import sys
from pathlib import Path

root = Path(sys.argv[1])


def workspace_version(cargo_toml: str) -> str:
    # Only [workspace.package], not [workspace.dependencies] inline versions.
    m = re.search(
        r"(?ms)^\[workspace\.package\]\s*(.*?)^\[",
        cargo_toml + "\n[",
    )
    if not m:
        raise SystemExit("FAIL: missing [workspace.package] in Cargo.toml")
    vm = re.search(r'(?m)^version\s*=\s*"([^"]+)"', m.group(1))
    if not vm:
        raise SystemExit("FAIL: missing version in [workspace.package]")
    return vm.group(1)


def workspace_members(cargo_toml: str) -> list[str]:
    m = re.search(r"(?ms)^\[workspace\]\s*(.*?)^\[", cargo_toml + "\n[")
    if not m:
        raise SystemExit("FAIL: missing [workspace] in Cargo.toml")
    arr = re.search(r"members\s*=\s*\[(.*?)\]", m.group(1), re.S)
    if not arr:
        raise SystemExit("FAIL: missing members array in [workspace]")
    names = re.findall(r'"([^"]+)"', arr.group(1))
    if not names:
        raise SystemExit("FAIL: empty workspace members list")
    return [n.rsplit("/", 1)[-1] for n in names]


def path_package_versions(lock: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    for block in lock.split("[[package]]\n")[1:]:
        name = ver = None
        source = False
        for line in block.splitlines():
            if line.startswith("name = "):
                name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                ver = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("source = "):
                source = True
        if name and ver and not source:
            versions[name] = ver
    return versions


def assert_lock_matches(cargo_toml: str, lock: str, label: str) -> None:
    want = workspace_version(cargo_toml)
    members = workspace_members(cargo_toml)
    got = path_package_versions(lock)
    missing = [n for n in members if n not in got]
    mismatch = [n for n in members if n in got and got[n] != want]
    if missing or mismatch:
        parts = []
        if missing:
            parts.append(f"missing lock packages: {missing}")
        if mismatch:
            parts.append(
                "version mismatch: "
                + ", ".join(f"{n}={got[n]} (want {want})" for n in mismatch)
            )
        raise SystemExit(f"FAIL: {label}: " + "; ".join(parts))
    print(f"PASS: {label} ({len(members)} crates at {want})")


def assert_trailing_newline(path: Path, data: bytes, label: str) -> None:
    if not data.endswith(b"\n"):
        raise SystemExit(f"FAIL: {label}: {path} missing trailing newline")
    print(f"PASS: {label}")


# ---------------------------------------------------------------------------
# Synthetic fixtures (would fail on the #66 lock / missing-newline shapes)
# ---------------------------------------------------------------------------
good_toml = """[workspace]
members = [
    "ratarmount",
    "ratarmount-core",
]

[workspace.package]
version = "0.1.31"
"""

stale_lock = """[[package]]
name = "ratarmount"
version = "0.1.30"

[[package]]
name = "ratarmount-core"
version = "0.1.30"
"""

fresh_lock = stale_lock.replace("0.1.30", "0.1.31")

try:
    assert_lock_matches(good_toml, stale_lock, "synthetic stale lock")
except SystemExit as e:
    if "version mismatch" not in str(e):
        raise
    print("PASS: synthetic stale lock is rejected")
else:
    raise SystemExit("FAIL: synthetic stale lock should be rejected")

assert_lock_matches(good_toml, fresh_lock, "synthetic matching lock")

try:
    assert_trailing_newline(Path("Cargo.toml"), b'tempfile = "3"', "synthetic no newline")
except SystemExit as e:
    if "missing trailing newline" not in str(e):
        raise
    print("PASS: synthetic missing newline is rejected")
else:
    raise SystemExit("FAIL: synthetic missing newline should be rejected")

# ---------------------------------------------------------------------------
# Live repo (the #66 failure mode)
# ---------------------------------------------------------------------------
cargo_path = root / "Cargo.toml"
lock_path = root / "Cargo.lock"
cargo_bytes = cargo_path.read_bytes()
assert_trailing_newline(cargo_path, cargo_bytes, "repo Cargo.toml trailing newline")
# tomllib needs a trailing newline; we already required one.
assert_lock_matches(
    cargo_bytes.decode(),
    lock_path.read_text(),
    "repo Cargo.lock workspace versions",
)

ci = (root / ".github/workflows/ci.yml").read_text()
if "packaging/test-workspace-lock-version.sh" not in ci:
    raise SystemExit("FAIL: ci.yml check job must run packaging/test-workspace-lock-version.sh")
print("PASS: ci.yml invokes workspace lock version script")

print("OK: workspace lock versions match Cargo.toml")
PY
