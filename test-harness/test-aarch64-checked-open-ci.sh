#!/usr/bin/env bash
# Drift check (#151, R11-S5, R11-CI-FIX2): every Linux target that docs/sandbox.md lists as
# supported for the checked SQLite open (x86_64, aarch64) must be built as a
# wheel, tested as an installed wheel, and run the checked-open Rust tests
# natively. A compile or export audit alone does not prove the per-target
# `struct stat` / VFS ABI; only native execution does. This script compiles
# nothing; it fails when a workflow matrix drops a target.
# The macOS job must also run the checked-open rows and the DSO fixture at the
# wheel's MACOSX_DEPLOYMENT_TARGET (R11-CI-FIX2: the init-section layout
# differs there), unconditionally.
#
#   ./test-harness/test-aarch64-checked-open-ci.sh              # check the repo
#   ./test-harness/test-aarch64-checked-open-ci.sh --self-test  # check the checker
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

check() {
python3 -I - "$1" << 'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
ci = (root / ".github/workflows/ci.yml").read_text()
py = (root / ".github/workflows/python.yml").read_text()
docs = (root / "docs/sandbox.md").read_text()

def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)

def job(text, name):
    """The lines of top-level job `name` (two-space indented key)."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line == f"  {name}:":
            end = len(lines)
            for j in range(i + 1, len(lines)):
                if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[j]):
                    end = j
                    break
            return "\n".join(lines[i:end])
    fail(f"workflow has no job {name!r}")

row = next((l for l in docs.splitlines() if l.startswith("| Linux CLI and Rust test binaries")), None)
if row is None:
    fail("docs/sandbox.md platform table has no Linux CLI row")
arches = [a for a in ("x86_64", "aarch64") if a in row]
if "aarch64" not in arches:
    fail("docs/sandbox.md Linux row no longer names aarch64; update this check")

runner = {"x86_64": "ubuntu-24.04", "aarch64": "ubuntu-24.04-arm"}
wheels = job(py, "wheels")
tests = job(py, "test")
embedding = job(py, "embedding")
for arch in arches:
    target = f"{arch}-unknown-linux-gnu"
    pair = re.compile(rf"- runner: {re.escape(runner[arch])}\s*\n\s*target: {re.escape(target)}")
    if not pair.search(wheels):
        fail(f"python.yml wheels matrix does not build {target} on {runner[arch]}")
    if not pair.search(tests):
        fail(f"python.yml installed-wheel (test) matrix does not run {target} on {runner[arch]}")
    if not re.search(rf"runner: \[[^\]]*(?<![\w-]){re.escape(runner[arch])}(?![\w-])", embedding):
        fail(f"python.yml embedding job does not run on {runner[arch]}")

native = job(ci, "checked-open-aarch64")
if "runs-on: ubuntu-24.04-arm" not in native:
    fail("ci.yml checked-open-aarch64 does not run on ubuntu-24.04-arm")
for cmd in (
    "cargo test -p ratarmount-index --lib checked_open",
    "cargo test -p ratarmount-checked-open-fixture --test dso",
):
    if cmd not in native:
        fail(f"ci.yml checked-open-aarch64 does not run {cmd!r}")
if "if:" in native or "continue-on-error" in native:
    fail("ci.yml checked-open-aarch64 must not be conditional or allowed to fail")

# R11-CI-FIX2: the macOS wheel's deployment target changes how the linker
# lays out the constructor's init section; the macOS job must run the
# checked-open rows at the wheel's target, unconditionally.
def step(job_text, name):
    """The lines of step `name` (six-space `- name:` item) inside a job."""
    lines = job_text.splitlines()
    for i, line in enumerate(lines):
        if line == f"      - name: {name}":
            end = len(lines)
            for j in range(i + 1, len(lines)):
                if re.match(r"^      - ", lines[j]):
                    end = j
                    break
            return "\n".join(lines[i:end])
    fail(f"workflow job has no step {name!r}")

wheel_target = re.search(r'MACOSX_DEPLOYMENT_TARGET=([0-9.]+)', job(py, "wheels"))
if wheel_target is None:
    fail("python.yml wheels job sets no MACOSX_DEPLOYMENT_TARGET; update this check")
mac = step(job(ci, "macos"), "checked open (macOS 14.0 deployment target)")
if f'MACOSX_DEPLOYMENT_TARGET: "{wheel_target.group(1)}"' not in mac:
    fail(f"ci.yml macOS checked-open step does not build at the wheel's MACOSX_DEPLOYMENT_TARGET={wheel_target.group(1)}")
if "CARGO_TARGET_DIR:" not in mac:
    fail("ci.yml macOS checked-open step must use its own CARGO_TARGET_DIR")
for cmd in (
    "cargo test -p ratarmount-index --lib checked_open",
    "cargo test -p ratarmount-checked-open-fixture --test dso",
):
    if cmd not in mac:
        fail(f"ci.yml macOS checked-open step does not run {cmd!r}")
if "if:" in mac or "continue-on-error" in mac:
    fail("ci.yml macOS checked-open step must not be conditional or allowed to fail")
print(f"ok: checked open runs natively on {', '.join(arches)} (wheel, installed wheel, Rust)"
      f" and on macOS at deployment target {wheel_target.group(1)}")
PY
}

if [[ "${1:-}" == "--self-test" ]]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mutate() { # name, file, python expression over s
        rm -rf "$tmp/r"; mkdir -p "$tmp/r/.github/workflows" "$tmp/r/docs"
        cp "$ROOT/.github/workflows/ci.yml" "$ROOT/.github/workflows/python.yml" "$tmp/r/.github/workflows/"
        cp "$ROOT/docs/sandbox.md" "$tmp/r/docs/"
        python3 -I -c 'import sys; p=sys.argv[1]; s=open(p).read(); n=eval(sys.argv[2]); assert n!=s, "mutation did not apply"; open(p,"w").write(n)' "$tmp/r/$2" "$3"
        if check "$tmp/r" >/dev/null 2>&1; then
            echo "FAIL self-test: $1 was not detected" >&2
            exit 1
        fi
    }
    check "$ROOT" >/dev/null
    mutate "aarch64 dropped from installed-wheel matrix" .github/workflows/python.yml \
        "s.replace(\"          - runner: ubuntu-24.04-arm\n            target: aarch64-unknown-linux-gnu\n            python: '3.12'\n\", '')"
    mutate "aarch64 dropped from embedding runners" .github/workflows/python.yml \
        "s.replace('runner: [ubuntu-24.04, ubuntu-24.04-arm]', 'runner: [ubuntu-24.04]')"
    mutate "native job moved to x86_64" .github/workflows/ci.yml \
        "s.replace('    runs-on: ubuntu-24.04-arm\n', '    runs-on: ubuntu-latest\n', 1)"
    mutate "native job lost the fixture test" .github/workflows/ci.yml \
        "s.replace('cargo test -p ratarmount-checked-open-fixture --test dso', 'true')"
    mutate "native job made optional" .github/workflows/ci.yml \
        "s.replace('    name: checked open (linux aarch64)\n', '    name: checked open (linux aarch64)\n    continue-on-error: true\n')"
    mac_step='      - name: checked open (macOS 14.0 deployment target)\n'
    mutate "macOS step removed" .github/workflows/ci.yml \
        "s.replace('$mac_step', '      - name: renamed step\n')"
    mutate "macOS step lost the deployment target" .github/workflows/ci.yml \
        "s.replace('          MACOSX_DEPLOYMENT_TARGET: \"14.0\"\n', '')"
    mutate "wheel deployment target moved" .github/workflows/python.yml \
        "s.replace('MACOSX_DEPLOYMENT_TARGET=14.0', 'MACOSX_DEPLOYMENT_TARGET=15.0')"
    mutate "macOS step lost its target dir" .github/workflows/ci.yml \
        "s.replace('          CARGO_TARGET_DIR: target/macos-deployment-14\n', '')"
    mutate "macOS step lost the checked_open rows" .github/workflows/ci.yml \
        "s.replace('          cargo test -p ratarmount-index --lib checked_open\n          cargo test -p ratarmount-checked-open-fixture --test dso\n\n      - name: Build release', '          cargo test -p ratarmount-checked-open-fixture --test dso\n\n      - name: Build release')"
    mutate "macOS step lost the fixture test" .github/workflows/ci.yml \
        "s.replace('          cargo test -p ratarmount-checked-open-fixture --test dso\n\n      - name: Build release', '\n      - name: Build release')"
    mutate "macOS step made optional" .github/workflows/ci.yml \
        "s.replace('$mac_step', '$mac_step        continue-on-error: true\n')"
    mutate "macOS step made conditional" .github/workflows/ci.yml \
        "s.replace('$mac_step', '$mac_step        if: github.event_name == \'push\'\n')"
    echo "ok: self-test detected every mutation"
    exit 0
fi

check "$ROOT"
