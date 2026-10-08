#!/usr/bin/env bash
# Drift check: declared workspace MSRV (Cargo.toml rust-version), the README
# badge / "Workspace MSRV is …" line, and the CI `msrv` job must agree, and the
# job must install that toolchain and run the cargo checks. This script does
# not compile anything; the `msrv` job's cargo check steps are what fail when
# the declaration is below what the lockfile needs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

python3 - "$ROOT" << 'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
cargo_path = root / "Cargo.toml"
ci_path = root / ".github" / "workflows" / "ci.yml"
readme_path = root / "README.md"

def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)

for path in (cargo_path, ci_path, readme_path):
    if not path.is_file():
        fail(f"missing {path}")

cargo = cargo_path.read_text()
vers = re.findall(
    r'^rust-version = "([0-9]+\.[0-9]+(?:\.[0-9]+)?)"\s*$',
    cargo,
    flags=re.M,
)
if len(vers) != 1:
    fail(
        f'root Cargo.toml must contain exactly one rust-version = "X.Y[.Z]" '
        f"(found {len(vers)}: {vers})"
    )
ver = vers[0]

readme = readme_path.read_text()
badge = f"rust-{ver}%2B"
if badge not in readme:
    fail(f"README badge must contain {badge}")
msrv_sentence = f"Workspace MSRV is {ver}"
if msrv_sentence not in readme:
    fail(f"README must contain {msrv_sentence!r}")

ci = ci_path.read_text()
lines = ci.splitlines(keepends=True)
start = None
for i, line in enumerate(lines):
    if line.startswith("  msrv:"):
        start = i
        break
if start is None:
    fail("ci.yml has no msrv: job")
end = len(lines)
for i in range(start + 1, len(lines)):
    if re.match(r"^  [a-z]", lines[i]):
        end = i
        break
job = "".join(lines[start:end])

steps = [
    part
    for part in re.split(r"(?=^      - )", job, flags=re.M)
    if part.startswith("      - ")
]
needles = (
    "sed",
    "rust-version",
    "GITHUB_OUTPUT",
    "rustup toolchain install",
    "rustup override set",
    "rustc --version",
)
matched = [step for step in steps if all(n in step for n in needles)]
if len(matched) != 1:
    fail(
        "msrv job must have exactly one step whose run block contains the "
        "sed rust-version read, GITHUB_OUTPUT, rustup toolchain install, "
        "rustup override set, and rustc --version "
        f"(found {len(matched)} step(s), {len(steps)} step(s) total)"
    )

checks = (
    "cargo check --workspace --all-targets",
    "cargo check -p ratarmount-nfs --all-targets --features nfsv4",
    "cargo check -p ratarmount --all-targets --features nfsv4",
)
for cmd in checks:
    if cmd not in job:
        fail(f"msrv job missing command: {cmd}")

print(f"OK: MSRV {ver} matches Cargo.toml, README badge, and ci.yml msrv job")
PY
