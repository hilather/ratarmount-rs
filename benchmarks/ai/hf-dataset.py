#!/usr/bin/env python3
"""Benchmark 7: a public Hub dataset with published indexes, read straight from the Hub.

Three mounts, each with fresh ratarmount and Hub caches so nothing is warm:

1. the whole repository (`-r hf://datasets/<repo>@<commit>`): mount startup, then
   the first shard open through its published index, then two file reads;
2. one shard mounted with its published index: mount startup and one read;
3. the same shard mounted with `-c`, which ignores the published index and scans
   the remote archive: mount startup and one read.

Every read hashes the bytes and all reads of the same file must agree.
"""
from contextlib import contextmanager
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

from common import Mount, Skip, add_mount_options, binary, fuse_available, main, mount_options, parser

DATASET_REPO = "RealMattBrewer/oxford-iiit-pet-webdataset"
DATASET_REVISION = "90c62369d1501beb8c717a793dfef52d94d565e6"
DATASET_SHARD = "train/train-000000.tar"
DATASET_FILE = "Abyssinian_1.jpg"
COLD = "fresh process; empty ratarmount and Hub caches"


def run(r, work):
    a = r.args
    if os.getenv("AI_OFFLINE") == "1":
        raise Skip("AI_OFFLINE=1; Hub dataset benchmark requires network")
    fuse_available()
    pointer = f"https://huggingface.co/datasets/{a.repo}/resolve/{a.revision}/{a.shard}.index.ptr"
    try:
        with urllib.request.urlopen(urllib.request.Request(pointer, method="HEAD"), timeout=20):
            pass
    except (urllib.error.URLError, TimeoutError) as error:
        raise Skip(f"dataset or its published index unavailable/offline: {error}") from error
    expected = {}

    def isolated(tag):
        # A private HOME hides ~/.ratarmount (the default --index-folders entry) and the
        # Hub token file, so every mount is anonymous and starts without any index.
        base = work / f"env-{tag}"
        (base / "home").mkdir(parents=True)
        return dict(os.environ, HOME=str(base / "home"), HF_HOME=str(base / "hf"),
                    HF_HUB_CACHE=str(base / "hf" / "hub"), XDG_CACHE_HOME=str(base / "xdg"),
                    RATARMOUNT_PAYLOAD_CACHE_DIR=str(base / "payload"))

    @contextmanager
    def deadline(seconds, what):
        def expired(*_):
            raise TimeoutError(f"{what} did not finish within {seconds} s")
        previous = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    def read(path, key):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if expected.setdefault(key, digest) != digest:
            raise RuntimeError(f"{key}: bytes differ between mounts")
        return len(data)

    def timed_read(case, path, key, **metadata):
        start = time.perf_counter()
        with deadline(a.timeout, f"{case}: reading {path.name}"):
            size = read(path, key)
        seconds = time.perf_counter() - start
        r.emit(case, seconds=round(seconds, 6), value=round(seconds, 6), unit="seconds", bytes=size, **metadata)

    @contextmanager
    def mount_timed(case, argv, path, env, note):
        start = time.perf_counter()
        with Mount(argv, path, env=env) as mount:
            seconds = time.perf_counter() - start
            r.emit(case, seconds=round(seconds, 6), value=round(seconds, 6), unit="seconds", cache=COLD, note=note)
            yield mount

    def dump_stacks(mount, label):
        """Save the daemon's thread stacks when a read stalls, so a hang can be diagnosed."""
        pid = mount.process.pid
        for argv in (["eu-stack", "-p", str(pid)], ["gdb", "--batch", "-ex", "thread apply all bt", "-p", str(pid)]):
            if shutil.which(argv[0]) is None:
                continue
            out = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120)
            (work / f"{label}-stacks.txt").write_text(out.stdout)
            return
        (work / f"{label}-stacks.txt").write_text("neither eu-stack nor gdb is installed\n")

    for n in range(a.runs):
        def repository():
            source = f"hf://datasets/{a.repo}@{a.revision}"
            with mount_timed("repo-mount", [binary(), "-f", "-r", *mount_options(a), source], work / f"repo-{n}",
                             isolated(f"repo-{n}"), "whole repository with -r; revision pinned; no shard opened yet") as m:
                shard = m.path / a.shard
                start = time.perf_counter()
                try:
                    with deadline(a.timeout, "repo-shard-open: listing the shard"):
                        names = sorted(os.listdir(shard))
                except TimeoutError:
                    dump_stacks(m, f"repo-{n}")
                    raise
                seconds = time.perf_counter() - start
                r.emit("repo-shard-open", seconds=round(seconds, 6), value=round(seconds, 6), unit="seconds",
                       items=len(names), cache=COLD,
                       note="first access lists the shard, opening it through its published index")
                timed_read("repo-first-read", shard / a.file, a.file, cache="shard open, nothing read",
                           note=f"{a.file}: HTTP range read through the opened shard")
                others = [name for name in names if name.endswith(".jpg") and name != a.file]
                if others:
                    second = others[len(others) // 2]
                    timed_read("repo-second-read", shard / second, second, cache="same shard; a different file",
                               note=f"{second}: another range read, index already warm")
        r.case("repo-mount", repository)

        def shard_published():
            source = f"hf://datasets/{a.repo}@{a.revision}/{a.shard}"
            with mount_timed("shard-mount-published", [binary(), "-f", *mount_options(a), source],
                             work / f"published-{n}", isolated(f"published-{n}"),
                             "one shard; published .index.ptr and blob discovered and validated") as m:
                timed_read("shard-read-published", m.path / a.file, a.file, cache="mounted, nothing read",
                           note=f"{a.file} through the published index")
        r.case("shard-mount-published", shard_published)

        def shard_scan():
            source = f"hf://datasets/{a.repo}@{a.revision}/{a.shard}"
            with mount_timed("shard-mount-scan", [binary(), "-f", "-c", *mount_options(a), source],
                             work / f"scan-{n}", isolated(f"scan-{n}"),
                             "-c ignores the published index and scans the remote TAR headers") as m:
                timed_read("shard-read-scan", m.path / a.file, a.file, cache="mounted, nothing read",
                           note=f"{a.file} after a remote scan")
        r.case("shard-mount-scan", shard_scan)


if __name__ == "__main__":
    p = parser(__doc__)
    p.add_argument("--repo", default=DATASET_REPO, help="public dataset repository with published indexes")
    p.add_argument("--revision", default=DATASET_REVISION, help="commit SHA to pin")
    p.add_argument("--shard", default=DATASET_SHARD, help="TAR shard path inside the repository")
    p.add_argument("--file", default=DATASET_FILE, help="member of that shard to read")
    p.add_argument("--timeout", type=float, default=300, help="seconds allowed for one listing or read before the case is an error")
    add_mount_options(p)
    sys.exit(main("hf-dataset", p.parse_args(), run))
