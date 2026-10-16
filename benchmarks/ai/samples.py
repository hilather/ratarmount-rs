#!/usr/bin/env python3
"""Benchmark 1: raw WebDataset sample throughput with eight loader workers."""
import importlib.util
import sys

from common import (Mount, Skip, add_mount_options, check_tally, combine, fixture,
                    fuse_available, main, mount_options, parallel, parser, positive,
                    require, shards, tally, binary)


def read_files(paths, workers):
    return combine(parallel(lambda group: tally(p.read_bytes() for p in group),
                            [paths[i::workers] for i in range(workers)], workers))


def read_library_threads(paths, workers, reader, *, index="sidecar"):
    def worker(i):
        return tally(data for sample in reader([str(p) for p in paths], worker_id=i,
                     num_workers=workers, archive_options={"index": index})
                     for key, data in sample.items() if not key.startswith("__"))
    return combine(parallel(worker, range(workers), workers))


def run(r, work):
    a = r.args
    source = work / "samples"
    expected = fixture(source, a.samples, a.sample_bytes)
    metadata = dict(bytes=expected[1], items=a.samples, workers=a.workers, cache="OS cache uncontrolled")

    def measure(name, action, note=""):
        for _ in range(a.runs):
            r.timed(name, lambda: check_tally(action(), expected), amount=a.samples,
                    unit="samples/s", note=note, **metadata)

    r.case("extracted", lambda: measure("extracted", lambda: read_files(sorted(source.iterdir()), a.workers)))
    shard_list = shards(source, work / "shards", codec=a.codec, size=a.shard_size)

    def library():
        if importlib.util.find_spec("ratarmount_rs") is None:
            raise Skip("ratarmount_rs not installed in this Python")
        if importlib.util.find_spec("torch") is not None:
            from torch.utils.data import DataLoader
            from ratarmount_rs.torch import RatarIterableDataset
            def read():
                dataset = RatarIterableDataset([str(p) for p in shard_list], archive_options={"index": a.library_index})
                return tally(data for _, data in DataLoader(dataset, num_workers=a.workers, batch_size=None))
            measure("library-torch", read, f"codec={a.codec}; index={a.library_index}; worker startup included; two components/sample")
        else:
            from ratarmount_rs.webdataset import samples
            measure("library-threads", lambda: read_library_threads(shard_list, a.workers, samples,
                    index=a.library_index), f"codec={a.codec}; index={a.library_index}; no torch; whole-shard partition")
    r.case("library", library)

    def fuse():
        fuse_available()
        with Mount([binary(), "-f", *mount_options(a), *shard_list], work / "fuse") as mounted:
            measure("fuse", lambda: read_files(sorted(mounted.path.glob("*.bin")) +
                                               sorted(mounted.path.glob("*.json")), a.workers), f"codec={a.codec}")
    r.case("fuse", fuse)

    def squash():
        require("mksquashfs", "squashfuse")
        fuse_available()
        from common import command
        image = work / "samples.squashfs"
        command(["mksquashfs", source, image, "-noappend", "-processors", "2"])
        with Mount(["squashfuse", "-f", image], work / "squash") as mounted:
            measure("squashfs", lambda: read_files(sorted(mounted.path.iterdir()), a.workers))
    r.case("squashfs", squash)

    def webdataset():
        if importlib.util.find_spec("webdataset") is None:
            raise Skip("webdataset package not installed")
        import webdataset as wds
        plain = shard_list if a.codec == "none" else shards(source, work / "tar-shards", codec="none", size=a.shard_size)
        def read():
            def worker(i):
                group = [str(p) for p in plain[i::a.workers]]
                if not group:
                    return (0, 0, 0)
                return tally(data for sample in wds.WebDataset(group, shardshuffle=False,
                             nodesplitter=None, workersplitter=None)
                             for key, data in sample.items() if not key.startswith("__"))
            return combine(parallel(worker, range(a.workers), a.workers))
        measure("webdataset-tar", read, "codec=none; package reader with Python threads")
    r.case("webdataset-tar", webdataset)


if __name__ == "__main__":
    p = parser(__doc__)
    p.add_argument("--samples", type=positive, default=256)
    p.add_argument("--sample-bytes", type=positive, default=65536)
    p.add_argument("--workers", type=positive, default=8)
    p.add_argument("--shard-size", default="2M")
    p.add_argument("--codec", choices=["none", "zstd"], default="zstd")
    p.add_argument("--library-index", choices=["sidecar", "temp"], default="sidecar", help="reuse shard sidecars; temp includes rebuilding indexes in sample timing")
    add_mount_options(p)
    sys.exit(main("samples", p.parse_args(), run))
