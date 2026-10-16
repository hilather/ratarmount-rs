#!/usr/bin/env python3
"""Benchmark 2: setup plus teardown per attempt, 64 concurrent attempts."""
import sys
from pathlib import Path
import threading
import time

from common import (HERE, Skip, command, main, parallel, parser, positive, repo, require,
                    sandbox, worktree)


def attempts(r, name, create, destroy, note=""):
    """Hold all attempts alive together, then tear down; report latency and makespan."""
    a = r.args
    barrier = threading.Barrier(a.attempts)
    def one(i):
        item = None
        start = time.perf_counter()
        try:
            item = create(i)
            setup = time.perf_counter() - start
            barrier.wait(timeout=180)
        except BaseException:
            barrier.abort()
            raise
        finally:
            if item is not None:
                end = time.perf_counter()
                destroy(item)
        return setup + time.perf_counter() - end
    for _ in range(a.runs):
        start = time.perf_counter()
        durations = parallel(one, range(a.attempts), a.attempts)
        elapsed = time.perf_counter() - start
        r.emit(name, seconds=round(elapsed, 6), value=round(sum(durations) / len(durations), 6),
               unit="seconds/attempt", workers=a.attempts, items=a.attempts,
               note="mean setup+teardown latency excludes hold barrier; seconds=batch makespan; pinned zlib v1.3.1" + ("; " + note if note else ""))


def run(r, work):
    repository = repo()
    def git():
        managers = {}
        def create(i):
            path = work / f"git-{i}"
            manager = worktree(repository, path)
            manager.__enter__()
            managers[str(path)] = manager
            return path
        attempts(r, "git-worktree", create, lambda path: managers.pop(str(path)).__exit__(None, None, None))
    r.case("git-worktree", git)

    def mounted():
        with sandbox(work, repository, r.args.state_root) as client:
            attempts(r, "ratarmount-sandbox", lambda _: client.new("bench")[0], lambda item: item.destroy())
    r.case("ratarmount-sandbox", mounted)

    def docker():
        require("docker")
        try:
            command(["docker", "info"], timeout=15)
        except Exception as error:
            raise Skip(f"Docker daemon unavailable: {error}") from error
        try:
            image_id = command(["docker", "image", "inspect", "--format", "{{.Id}}", r.args.docker_image])
        except Exception as error:
            raise Skip(f"Docker image not local (no automatic pull): {r.args.docker_image}: {error}") from error
        def create(i):
            # A known name lets cleanup recover a create that timed out after success.
            name = f"ai-bench-{r.run_id}-{i}"
            try:
                container = command(["docker", "create", "--name", name, image_id, "true"])
                command(["docker", "cp", str(repository) + "/.", container + ":/repo"])
                return container
            except BaseException:
                # Ignore "no such container"; preserve the original setup failure.
                try:
                    command(["docker", "rm", "-f", name])
                except Exception as error:
                    print(f"cleanup: check container {name}: {error}", file=sys.stderr)
                raise
        attempts(r, "docker-cp", create, lambda item: command(["docker", "rm", "-f", item]), note="image=" + image_id)
    r.case("docker-cp", docker)


if __name__ == "__main__":
    p = parser(__doc__)
    p.add_argument("--attempts", type=positive, default=64)
    p.add_argument("--docker-image", default="alpine:3.20", help="must already exist locally")
    p.add_argument("--state-root", type=Path, default=HERE, help="short existing directory for private daemon state; use the same filesystem as fixtures")
    sys.exit(main("sandbox-attempts", p.parse_args(), run))
