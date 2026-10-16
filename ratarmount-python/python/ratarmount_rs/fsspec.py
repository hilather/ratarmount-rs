"""Read-only fsspec adapter; archive URLs are opened by Rust, without spooling."""
from __future__ import annotations

import os

from fsspec.spec import AbstractFileSystem
from fsspec.utils import infer_storage_options

from . import MemberNotFound, open as open_archive

# Keep native targets in Rust: do not instantiate a Python remote filesystem.
_NATIVE_PROTOCOLS = {
    "http", "https", "s3", "gs", "az", "azure", "hf", "hf-cache", "ftp", "ftps",
    "ssh", "sftp", "scp", "smb", "webdav", "webdavs", "dropbox", "oci", "docker",
    "ghcr", "ipfs", "ipns", "rclone", "restic",
}


class RatarmountFileSystem(AbstractFileSystem):
    """Expose member paths from ``fo`` using fsspec's archive URL chaining.

    ``ratar://dir/file::file:///data/shard.tar.zst`` selects a member.
    Archive options are password, index, recursive and parallelization.
    Remote credentials use Session's environment/configuration, rather than
    Python filesystem credentials in target_options.
    """

    protocol = "ratar"
    root_marker = ""

    def __init__(
        self, fo="", target_protocol=None, target_options=None, *,
        password=None, index=None, recursive=False, parallelization=1, **kwargs,
    ):
        super().__init__(**kwargs)
        if not isinstance(fo, (str, os.PathLike)):
            raise NotImplementedError(
                "ratar requires an archive path or native URL; Python file-like targets "
                "cannot be passed to Session (no download/spool fallback)"
            )
        fo = os.fsdecode(fo)
        if not fo:
            raise ValueError("fo must select an archive path or URL")
        protocol = target_protocol or infer_storage_options(fo)["protocol"]
        target_options = dict(target_options or {})
        if protocol == "hf":
            # datasets injects these defaults even when no override was requested.
            if target_options.get("token") is None:
                target_options.pop("token", None)
            if target_options.get("endpoint") == os.environ.get("HF_ENDPOINT", "https://huggingface.co"):
                target_options.pop("endpoint", None)
        if target_options:
            raise NotImplementedError(
                "ratar target_options are not translated to Session credentials; "
                "use the native backend's environment/configuration instead"
            )
        if protocol in ("file", "local"):
            from fsspec.implementations.local import LocalFileSystem
            fo = LocalFileSystem._strip_protocol(fo)
        elif protocol in _NATIVE_PROTOCOLS:
            if "://" not in fo and not fo.startswith("restic:"):
                fo = f"{protocol}://{fo}"
        else:
            raise NotImplementedError(
                f"ratar cannot open fsspec target protocol {protocol!r}: Session accepts "
                "local paths and native remote URLs, not Python file objects; "
                "no download/spool fallback is provided"
            )
        self.fo = fo
        self.archive = open_archive(
            fo, password=password, index=index, recursive=recursive,
            parallelization=parallelization,
        )

    @classmethod
    def _strip_protocol(cls, path):
        return super()._strip_protocol(path).lstrip("/").rstrip("/")

    @staticmethod
    def _info(entry):
        return {
            "name": entry.path.lstrip("/"), "size": entry.size,
            "type": "directory" if entry.is_dir else "file",
            "mtime": entry.mtime, "mode": entry.mode,
        }

    def info(self, path, **kwargs):
        path = self._strip_protocol(path)
        try:
            return self._info(self.archive.stat("/" + path))
        except MemberNotFound as exc:
            raise FileNotFoundError(path) from exc

    def ls(self, path="", detail=True, **kwargs):
        path = self._strip_protocol(path)
        info = self.info(path)
        if info["type"] == "directory":
            entries = [self._info(entry) for entry in self.archive.ls("/" + path)]
        else:
            entries = [info]
        entries.sort(key=lambda entry: entry["name"])
        return entries if detail else [entry["name"] for entry in entries]

    def _open(self, path, mode="rb", **kwargs):
        if mode != "rb":
            raise ValueError("ratar is a read-only filesystem")
        path = self._strip_protocol(path)
        try:
            member = self.archive.open("/" + path)
        except MemberNotFound as exc:
            raise FileNotFoundError(path) from exc
        member.size = self.info(path)["size"]
        return member

    def cat_file(self, path, start=None, end=None, **kwargs):
        path = self._strip_protocol(path)
        info = self.info(path)
        if info["type"] == "directory":
            raise IsADirectoryError(path)
        start, end, _ = slice(start, end).indices(info["size"])
        return self.archive.read("/" + path, start, max(0, end - start))

    def close(self):
        """Close this cached filesystem; clear_instance_cache before reopening it."""
        self.archive.close()

    def __del__(self):
        if hasattr(self, "archive"):
            self.archive.close()
