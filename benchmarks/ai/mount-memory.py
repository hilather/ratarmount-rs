#!/usr/bin/env python3
"""Benchmark 5: aggregate steady RSS with 32 concurrent foreground mounts."""
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import sys
import time

from common import (Mount, Skip, add_mount_options, binary, command, fixture,
                    fuse_available, main, mount_options, parser, positive, require,
                    rss_kib, shards)


def run(r, work):
    a = r.args
    if not Path("/proc/self/status").exists():
        raise Skip("RSS measurement uses Linux /proc; run in a Linux VM on Apple silicon")
    source = work / "samples"
    fixture(source, a.samples, 65536)
    def measure(name, argv):
        fuse_available()
        for n in range(a.runs):
            with ExitStack() as stack:
                mounts = [stack.enter_context(Mount(argv, work / f"{name}-{n}-{i}")) for i in range(a.mounts)]
                # Exercise every mount identically before measuring all live processes.
                for mounted in mounts:
                    if (mounted.path / "00000000.bin").read_bytes() != (source / "00000000.bin").read_bytes():
                        raise RuntimeError("mounted bytes differ")
                time.sleep(a.settle)
                if any(m.process.poll() is not None for m in mounts):
                    raise RuntimeError("mount exited before RSS sampling")
                rss = sum(rss_kib(m.process.pid) for m in mounts)
                r.emit(name, value=round(rss / 1024, 3), unit="MiB RSS sum", items=a.mounts,
                       bytes=a.samples * 65536, cache="one sample read per mount", workers=a.mounts,
                       note=f"steady RSS after {a.settle}s; shared pages counted per process; not PSS or peak RSS")
    def rust():
        paths = shards(source, work / "shards", codec="none", size="1G")
        measure("ratarmount", [binary(), "-f", *mount_options(a), *paths])
    r.case("ratarmount", rust)
    def squash():
        require("mksquashfs", "squashfuse")
        image = work / "samples.squashfs"
        command(["mksquashfs", source, image, "-noappend", "-processors", "2"])
        measure("squashfuse", ["squashfuse", "-f", image])
    r.case("squashfuse", squash)
    def python():
        if importlib.util.find_spec("ratarmount") is None:
            raise Skip("Python ratarmount not installed")
        import tarfile
        archive = work / "python.tar"
        with tarfile.open(archive, "w") as tar:
            for path in sorted(source.iterdir()):
                tar.add(path, arcname=path.name)
        measure("python-ratarmount", [sys.executable, "-m", "ratarmount", "-f", archive])
    r.case("python-ratarmount", python)


if __name__ == "__main__":
    p = parser(__doc__)
    p.add_argument("--mounts", type=positive, default=32)
    p.add_argument("--samples", type=positive, default=128)
    p.add_argument("--settle", type=float, default=1)
    add_mount_options(p)
    sys.exit(main("mount-memory", p.parse_args(), run))
