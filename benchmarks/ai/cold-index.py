#!/usr/bin/env python3
"""Benchmark 4: cold shard open/mount with locally published indexes versus scan."""
import math
import sys

from common import (Mount, add_mount_options, binary, command, evict_files, fixture,
                    fuse_available, main, mount_options, parser, shards)


def index_name(path):
    # ratarmount-index::possible_index_paths uses this CLI folder convention.
    return (str(path) + ".index.sqlite").replace("/", "_")


def run(r, work):
    a = r.args
    if not math.isfinite(a.gib) or a.gib <= 0:
        raise ValueError("--gib must be finite and positive")
    source = work / "samples"
    expected = fixture(source, max(1, math.ceil(a.gib * 1024)), 1024 * 1024)
    paths = shards(source, work / "shards", codec=a.codec, size=a.shard_size, no_index=True)
    published = work / "published"
    published.mkdir()
    indexes = []
    for path in paths:
        dest = published / index_name(path)
        command([binary(), "--no-mount", "--index-minimum-file-count", "0", "--publish-index",
                 "--publish-index-to", dest, path])
        indexes.append(dest)
        # Published copies remain; remove creation sidecars outside the timing.
        for sidecar in path.parent.glob(path.name + ".index*"):
            sidecar.unlink()

    for indexed in [False, True]:
        label = "published" if indexed else "scan"
        for n in range(a.runs):
            def options(kind):
                directory = published if indexed else work / f"scan-{kind}-{n}"
                directory.mkdir(exist_ok=True)
                return ["--index-folders", str(directory), "--index-minimum-file-count", "0"] + (
                    ["--no-recreate-index"] if indexed else [])
            cache = evict_files(paths + indexes)
            r.timed("open-" + label,
                    lambda: command([binary(), "--no-mount", *options("open"), *paths]),
                    bytes=expected[1], items=len(paths), cache=cache,
                    note="one new CLI process opens all shards; --no-mount; local index-folder discovery")
            def mounting():
                fuse_available()
                cache = evict_files(paths + indexes)
                # One union mount regardless of shard count; teardown excluded.
                mount = Mount([binary(), "-f", *mount_options(a), *options("mount"), *paths],
                              work / f"mnt-{label}-{n}")
                try:
                    r.timed("mount-" + label, mount.__enter__, bytes=expected[1],
                            items=len(paths), cache=cache, note="one union mount; readiness required; teardown excluded")
                finally:
                    if mount.process is not None and mount.log is not None and not mount.log.closed:
                        mount.__exit__(None, None, None)
            r.case("mount-" + label, mounting)


if __name__ == "__main__":
    p = parser(__doc__)
    p.add_argument("--gib", type=float, default=0.015625, help="uncompressed binary sample GiB; 1024 = 1 TiB")
    p.add_argument("--shard-size", default="8M")
    p.add_argument("--codec", choices=["none", "zstd"], default="zstd")
    add_mount_options(p)
    sys.exit(main("cold-index", p.parse_args(), run))
