#!/usr/bin/env python3
"""Benchmark 6: hf:// mount first/second tensor read versus hf download + read."""
import os
import sys
import time
import urllib.error
import urllib.request

from common import (MODEL_REPO, MODEL_REVISION, Mount, Skip, add_mount_options, binary,
                    command, fuse_available, main, mount_options, parser, require,
                    tensor_bytes)


def run(r, work):
    a = r.args
    if os.getenv("AI_OFFLINE") == "1":
        raise Skip("AI_OFFLINE=1; model benchmark requires network")
    url = f"https://huggingface.co/{a.repo}/resolve/{a.revision}/{a.file}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=20):
            pass
    except (urllib.error.URLError, TimeoutError) as error:
        raise Skip(f"public model unavailable/offline: {error}") from error
    expected = None
    for n in range(a.runs):
        local = work / f"download-{n}"
        local_env = dict(os.environ, HF_HOME=str(work / f"hf-cli-{n}"),
                         HF_HUB_CACHE=str(work / f"hf-cli-{n}" / "hub"), HF_HUB_DISABLE_PROGRESS_BARS="1",
                         HF_XET_CACHE=str(work / f"xet-cli-{n}"))
        def baseline():
            nonlocal expected
            require("hf")
            def download():
                command(["hf", "download", a.repo, a.file, "--revision", a.revision,
                         "--local-dir", local], env=local_env, timeout=600)
                return tensor_bytes(local / a.file)
            expected = r.timed("hf-download-and-load", download, cache="isolated empty HF cache",
                               note="network download + parse header + hash all tensor bytes; " + a.revision)
            r.timed("downloaded-second-load", lambda: verify(local / a.file, expected), bytes=expected[0],
                    cache="same local file; OS warm", note="tensor bytes only, no inference")
        r.case("hf-download", baseline)
        def mounted():
            fuse_available()
            mount_env = dict(os.environ, HF_HOME=str(work / f"hf-mount-{n}"),
                             HF_HUB_CACHE=str(work / f"hf-mount-{n}" / "hub"),
                             XDG_CACHE_HOME=str(work / f"xdg-{n}"),
                             RATARMOUNT_PAYLOAD_CACHE_DIR=str(work / f"payload-{n}"))
            source = f"hf://{a.repo}@{a.revision}"
            # Mount the repo tree without -r so the model remains a raw file.
            start = time.perf_counter()
            with Mount([binary(), "-f", *mount_options(a), source], work / f"model-{n}", env=mount_env) as m:
                path = m.path / a.file
                first = r.timed("hf-mount-first-load", lambda: verify(path, expected),
                                cache="new mount and isolated disk caches; mount/metadata startup excluded",
                                note="parse header + hash all tensor bytes")
                seconds = time.perf_counter() - start
                r.emit("hf-mount-setup-and-first-load", seconds=round(seconds, 6),
                       value=round(seconds, 6), unit="seconds", bytes=first[0],
                       cache="new mount and isolated disk caches", note="includes mount startup + first tensor read; teardown excluded")
                r.timed("hf-mount-second-load", lambda: verify(path, first), bytes=first[0],
                        cache="same mount; OS and range/Hub caches warm", note="tensor bytes only, no inference")
        r.case("hf-mount", mounted)


def verify(path, expected):
    actual = tensor_bytes(path)
    if expected is not None and actual != expected:
        raise RuntimeError("model tensor bytes differ between runs/backends")
    return actual


if __name__ == "__main__":
    p = parser(__doc__)
    p.add_argument("--repo", default=MODEL_REPO)
    p.add_argument("--revision", default=MODEL_REVISION)
    p.add_argument("--file", default="model.safetensors", help="safetensors file; payload bytes are read and hashed")
    add_mount_options(p)
    sys.exit(main("model-load", p.parse_args(), run))
