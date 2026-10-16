"""Index publication through the same validation and writers as the CLI."""
from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import _native
from ._native import RatarmountError
from ._process import _binary, _is_url, _password_args, _public_argument, _source


@dataclass(frozen=True)
class PublishedIndex:
    """Published pointer identity and locations (Hub URLs pin the new commit)."""

    index_id: str
    pointer_url: str
    blob_url: str
    commit: Optional[str] = None
    pull_request_url: Optional[str] = None

    @property
    def urls(self) -> tuple[str, str]:
        return self.pointer_url, self.blob_url


def _pointer_id(data) -> str:
    try:
        pointer = json.loads(bytes(data))
        identity = pointer["index_id"]
        if (pointer["schema"] != "ratarmount.index.pointer.v1"
                or not isinstance(identity, str)
                or re.fullmatch("[0-9a-f]{64}", identity) is None
                or pointer["etag_sha256"] != identity):
            raise ValueError
        return identity
    except (ValueError, TypeError, KeyError):
        raise RatarmountError("publication succeeded but returned an invalid index pointer") from None


class ArchiveIndex:
    """Index operations for an open Archive."""

    def __init__(self, archive):
        self._archive = archive

    def publish(self, destination=None, *, revision=None, create_pr=False) -> PublishedIndex:
        return publish_index(self._archive, destination, revision=revision, create_pr=create_pr)


def publish_index(archive, destination=None, *, revision=None, create_pr=False) -> PublishedIndex:
    """Publish an Archive's index locally or to hf://, s3://, gs:// or az://.

    The CLI rebuilds/validates a private index from the Archive's source and open
    options; it does not modify the Archive's active index. Remote destinations
    name an existing archive with matching bytes, as in --publish-index-to.
    Credentials use the inherited environment/configuration only.
    """
    archive._check_open()
    if archive._source is None:
        raise ValueError("publication requires an Archive created by ratarmount_rs.open")
    source = _source(archive._source)
    target = source if destination is None else _public_argument(os.fsdecode(os.fspath(destination)))
    remote = _is_url(target)
    if remote and not target.startswith(("hf://", "s3://", "gs://", "az://")):
        raise ValueError("publication supports local paths, hf://, s3://, gs:// and az://")
    if (revision is not None or create_pr) and not target.startswith("hf://"):
        raise ValueError("revision and create_pr require an hf:// destination")
    if revision is not None:
        _public_argument(revision)
    argv = [_binary()]
    if destination is None:
        argv.append("--publish-index")
    else:
        argv.append("--publish-index-to=" + target)
    if revision is not None:
        argv.append("--publish-revision=" + revision)
    if create_pr:
        argv.append("--create-pr")
    if archive._process_options.get("recursive"):
        argv.append("--recursive")
    argv.append("--parallelization=" + str(archive._process_options.get("parallelization", 1)))
    with contextlib.ExitStack() as stack:
        directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="ratarmount-publish-"))
        argv.append("--index-file=" + os.path.join(directory, "source.sqlite"))
        argv.extend(_password_args(stack, archive._process_options.get("password")))
        argv.extend(["--", source])
        # Preserve output privately: CLI diagnostics sometimes repeat credential-bearing URLs.
        output = stack.enter_context(tempfile.TemporaryFile())
        result = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=output, stderr=output, check=False,
        )
        if result.returncode:
            raise RatarmountError(f"index publication failed (exit {result.returncode})")
        output.seek(0, os.SEEK_END)
        output.seek(max(0, output.tell() - 65536))
        diagnostics = output.read().decode("utf-8", errors="replace")
    commit_match = re.search(r"published index at Hub commit ([0-9a-fA-F]{40})\b", diagnostics)
    commit = commit_match[1].lower() if commit_match else None
    pr_match = re.search(r"pull request: (https?://\S+)", diagnostics)
    pr = pr_match[1] if pr_match else None
    if remote:
        if target.startswith("hf://") and commit is None:
            raise RatarmountError("publication succeeded but CLI did not report the Hub commit; update ratarmount")
        data, base = _native.published_pointer(target, commit)
    else:
        base = os.path.abspath(target)
        if destination is not None and base.endswith(".index.sqlite"):
            base = base[:-len(".index.sqlite")]
        try:
            data = Path(base + ".index.ptr").read_bytes()
        except OSError:
            raise RatarmountError("publication succeeded but local pointer readback failed") from None
    identity = _pointer_id(data)
    return PublishedIndex(identity, base + ".index.ptr", base + f".index.{identity}.sqlite", commit, pr)
