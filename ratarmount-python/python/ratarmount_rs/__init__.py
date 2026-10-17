"""Read indexed archives, supervise CLI mounts and publish indexes.

All blocking native operations release the GIL. An Archive may be shared by
threads and perform Session I/O concurrently. Closing prevents new operations
while in-flight work finishes.
"""
from __future__ import annotations

import builtins
import heapq
import io
import mmap as _mmap
import operator
import os
import posixpath
import threading
from typing import BinaryIO, Iterable, Iterator, Literal, Optional, Union, cast

from . import _native
from ._native import BadPassword, Entry, MemberNotFound, NotMappable, RatarmountError, split_url
from ._process import Mount, _is_url, mount
from ._publish import ArchiveIndex, PublishedIndex, publish_index

__all__ = [
    "Archive", "Entry", "open", "split_url", "RatarmountError",
    "MemberNotFound", "BadPassword", "NotMappable",
    "Mount", "mount", "PublishedIndex", "publish_index",
]

Path = Union[str, os.PathLike[str]]


def _path(path: Path) -> str:
    return os.fsdecode(os.fspath(path))


class Archive:
    """An indexed archive, owned until close() or context manager exit.

    Use open() to construct an Archive. Entries have archive-relative paths
    starting with '/'. mtime is Unix seconds, or None on cheap listing pages;
    stat() requests complete metadata.
    """

    def __init__(self, native: _native.Archive, source=None, process_options=None) -> None:
        self._native = native
        self._source = source
        self._process_options = process_options or {}

    @property
    def index(self) -> ArchiveIndex:
        """Publish a validated index with archive.index.publish(destination)."""
        self._check_open()
        return ArchiveIndex(self)

    def mount(self, mountpoint: Path, **opts) -> Mount:
        """Supervise a separate CLI mount using this Archive's source/options."""
        self._check_open()
        if self._source is None:
            raise ValueError("mount requires an Archive created by ratarmount_rs.open")
        return mount(self._source, mountpoint, **(self._process_options | opts))

    @property
    def closed(self) -> bool:
        """Whether close() has released this archive's Session reference."""
        return self._native.closed

    def _check_open(self) -> None:
        if self.closed:
            raise ValueError("archive is closed")

    def ls(self, path: str = "/") -> list[Entry]:
        """List all immediate children using keyset pages, without duplicates."""
        return self._native.ls(path)

    def stat(self, path: str) -> Entry:
        """Return complete metadata or raise MemberNotFound."""
        return self._native.stat(path)

    def read(self, path: str, offset: int = 0, size: int = -1) -> bytes:
        """Read bytes from offset; size=-1 reads to EOF, size=0 reads nothing.

        Negative offsets or sizes below -1 raise ValueError. Reads beyond EOF
        return b''; reads extending past EOF return the remaining bytes.
        """
        return self._native.read(path, offset, size)

    def open(self, path: str) -> BinaryIO:
        """Open a readable, seekable binary stream with its own file position.

        The parent Archive must remain open. Closing this file leaves the
        Archive open. Blocking reads release the GIL.
        """
        entry = self.stat(path)
        if entry.is_dir:
            raise IsADirectoryError(path)
        return cast(BinaryIO, _MemberFile(self, path, entry.size))

    def mmap(self, path: str) -> memoryview:
        """Map a local plain-TAR payload read-only without copying.

        Returns a memoryview over an mmap, sliced to the exact member range.
        Unsupported members raise NotMappable; use read() for those members.
        Keep the archive file unchanged for the entire mapping lifetime.
        """
        file, offset, length = self._native.extent(path)
        anchor = offset if length else max(offset - 1, 0)
        aligned = anchor - anchor % _mmap.ALLOCATIONGRANULARITY
        start = offset - aligned
        with builtins.open(file, "rb") as backing:
            mapping = _mmap.mmap(
                backing.fileno(), max(start + length, 1),
                access=_mmap.ACCESS_READ, offset=aligned,
            )
        return memoryview(mapping)[start:start + length]

    def iter(
        self, prefix: str = "/", order: Literal["archive", "name"] = "archive"
    ) -> Iterator[Entry]:
        """Iterate regular payloads recursively under a component path prefix.

        Archive order uses bounded offset keyset pages and requires a disk SQL
        catalog. It excludes directories, links and generated entries. Name
        order walks directory listings and includes regular-file hardlinks.
        """
        self._check_open()
        if order not in ("archive", "name"):
            raise ValueError("order must be 'archive' or 'name'")
        prefix = posixpath.normpath("/" + prefix.lstrip("/"))
        return self._iter_entries(prefix, order)

    def _iter_entries(self, prefix: str, order: str) -> Iterator[Entry]:
        if order == "archive":
            cursor = None
            while True:
                entries, cursor = self._native.offset_page(cursor)
                for entry in entries:
                    if prefix == "/" or entry.path == prefix or entry.path.startswith(prefix + "/"):
                        self._check_open()
                        yield entry
                if cursor is None:
                    return
        else:
            first = self.stat(prefix)
            if not first.is_dir:
                if first.is_file:
                    yield first
                return
            pending = [(entry.path, entry) for entry in self.ls(prefix)]
            heapq.heapify(pending)
            while pending:
                _, entry = heapq.heappop(pending)
                self._check_open()
                if entry.is_dir:
                    for child in self.ls(entry.path):
                        heapq.heappush(pending, (child.path, child))
                elif entry.is_file:
                    yield entry

    def extract(
        self, members: Iterable[str], dest: Path, *, existing: Literal["skip", "replace"] = "skip"
    ) -> None:
        """Stream selected members into dest; an empty iterable extracts all.

        Skip preserves existing paths. Replace overwrites existing files.
        Unsafe member paths and symlink directory escapes are rejected.
        """
        self._native.extract(list(members), os.fspath(dest), existing)

    def close(self) -> None:
        """Release the Session, idempotently; new operations raise ValueError.

        Existing mmap views remain valid while their backing file is unchanged.
        """
        self._native.close()
        self._process_options.pop("password", None)

    def __enter__(self) -> Archive:
        self._check_open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class _MemberFile(io.RawIOBase):
    """Binary archive stream; a lock protects the independent file position."""

    def __init__(self, archive: Archive, path: str, size: int) -> None:
        super().__init__()
        self._archive = archive
        self.name = path
        self.mode = "rb"
        self._size = size
        self._position = 0
        self._lock = threading.RLock()

    def _check(self) -> None:
        self._checkClosed()
        self._archive._check_open()

    def readable(self) -> bool:
        self._check()
        return True

    def seekable(self) -> bool:
        self._check()
        return True

    def writable(self) -> bool:
        self._check()
        return False

    def read(self, size: int = -1) -> bytes:
        with self._lock:
            self._check()
            size = -1 if size is None else operator.index(size)
            if size < 0:
                size = -1
            data = self._archive.read(self.name, self._position, size)
            self._position += len(data)
            return data

    def readinto(self, buffer: object) -> int:
        with self._lock:
            self._check()
            with memoryview(buffer) as view:
                if view.readonly:
                    raise TypeError("readinto() requires a writable buffer")
                with view.cast("B") as bytes_view:
                    data = self.read(len(bytes_view))
                    bytes_view[:len(data)] = data
                    return len(data)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        with self._lock:
            self._check()
            offset, whence = operator.index(offset), operator.index(whence)
            if whence == os.SEEK_SET:
                position = offset
            elif whence == os.SEEK_CUR:
                position = self._position + offset
            elif whence == os.SEEK_END:
                position = self._size + offset
            else:
                raise ValueError("invalid whence")
            if position < 0:
                raise ValueError("negative seek position")
            self._position = position
            return position

    def tell(self) -> int:
        with self._lock:
            self._check()
            return self._position

    def close(self) -> None:
        with self._lock:
            super().close()


def open(
    path_or_url: Path, *, password: Optional[str] = None,
    index: Optional[Path] = None, recursive: bool = False, parallelization: int = 1,
) -> Archive:
    """Open a local archive or any URL scheme supported by Session.

    index=None or 'temp' uses a temporary disk index, deleted on close();
    'sidecar' uses the sibling index; any other path selects an explicit index.
    recursive enables nested archives. parallelization=0 uses available CPUs;
    the default is one codec thread. Remote credentials follow Session's usual
    environment and configuration, with password for encrypted archives.
    """
    parallelization = operator.index(parallelization)
    if parallelization < 0 or parallelization > 2**32 - 1:
        raise ValueError("parallelization must be between 0 and 2**32-1")
    source = split_url(_path(path_or_url))
    if not _is_url(source) and not source.lower().startswith("restic:"):
        source = os.path.abspath(source)
    return Archive(_native.open(
        source, password=password,
        index=None if index is None else _path(index),
        recursive=recursive, parallelization=parallelization,
    ), source, {"password": password, "recursive": recursive, "parallelization": parallelization})
