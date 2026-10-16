#!/usr/bin/env python3
"""Benchmark 3: zlib configure, make, and make test, native versus sandbox."""
import sys
from pathlib import Path

from common import HERE, command, main, parser, positive, repo, require, sandbox, worktree


def build(path, jobs):
    command(["./configure", "--static"], cwd=path)
    command(["make", f"-j{jobs}"], cwd=path)
    output = command(["make", "test"], cwd=path)
    if "test" not in output.lower() or "OK" not in output:
        raise RuntimeError("zlib make test did not report successful tests: " + output)


def run(r, work):
    require("make", "cc")
    repository = repo()
    for i in range(r.args.runs):
        def native():
            with worktree(repository, work / f"native-{i}") as path:
                r.timed("native", lambda: build(path, r.args.jobs), workers=r.args.jobs,
                        note="configure + make + make test; fresh worktree; zlib v1.3.1")
        r.case("native", native)
    def mounted():
        with sandbox(work, repository, r.args.state_root) as client:
            for _ in range(r.args.runs):
                with client.new("bench")[0] as attempt:
                    r.timed("sandbox", lambda: build(attempt.path, r.args.jobs), workers=r.args.jobs,
                            note="configure + make + make test; fresh overlay; mount lifecycle excluded")
    r.case("sandbox", mounted)


if __name__ == "__main__":
    p = parser(__doc__)
    p.add_argument("--jobs", type=positive, default=2)
    p.add_argument("--state-root", type=Path, default=HERE, help="short existing directory for private daemon state; use the same filesystem as fixtures")
    sys.exit(main("build-test", p.parse_args(), run))
