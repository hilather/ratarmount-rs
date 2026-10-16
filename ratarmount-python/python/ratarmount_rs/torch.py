"""Optional PyTorch datasets with lazily opened, process-local Archives."""
from __future__ import annotations

import fnmatch
import os

from torch.utils.data import Dataset, IterableDataset, get_worker_info

from . import open as open_archive
from ._datasets import shard_paths, shuffle_shards, split_by_worker


class _ArchiveOwner:
    def _init_owner(self, pattern, extensions, decode, archive_options):
        self.pattern = pattern
        if isinstance(extensions, str):
            extensions = [extensions]
        self.extensions = tuple("." + ext.lstrip(".") for ext in extensions) if extensions else ()
        self.decode = decode
        self.archive_options = dict(archive_options or {})
        self._archive = None
        self._owner = None

    def _accept(self, path):
        return fnmatch.fnmatchcase(path.lstrip("/"), self.pattern) and (
            not self.extensions or path.endswith(self.extensions)
        )

    def _sample(self, archive, path):
        data = archive.read(path)
        return path, self.decode(data) if self.decode else data

    def _get_archive(self, shard):
        info = get_worker_info()
        owner = (os.getpid(), info.id if info else None, shard)
        if self._owner != owner:
            self.close()
            self._archive = open_archive(shard, **self.archive_options)
            self._owner = owner
        return self._archive

    def close(self):
        if self._archive is not None:
            self._archive.close()
            self._archive = None
        self._owner = None

    def __getstate__(self):
        state = self.__dict__.copy()
        state.update(_archive=None, _owner=None)
        return state


class RatarDataset(_ArchiveOwner, Dataset):
    """Map indices to (member path, bytes), optionally decoding the bytes.

    The member list is built on first len/getitem; native state is never pickled.
    A decode callable must itself be pickleable when using spawned workers.
    """

    def __init__(self, shard, *, pattern="*", extensions=None, decode=None, archive_options=None):
        self.shard = os.fsdecode(shard)
        self._paths = None
        self._init_owner(pattern, extensions, decode, archive_options)

    def _members(self):
        if self._paths is None:
            archive = self._get_archive(self.shard)
            self._paths = [entry.path for entry in archive.iter(order="archive") if self._accept(entry.path)]
        return self._paths

    def __len__(self):
        return len(self._members())

    def __getitem__(self, index):
        path = self._members()[index]
        return self._sample(self._get_archive(self.shard), path)


class RatarIterableDataset(_ArchiveOwner, IterableDataset):
    """Stream shard lists in archive order without a full member list.

    Workers divide shards when possible. With fewer shards than workers,
    workers read each catalog and divide members, avoiding duplicate samples.
    """

    def __init__(
        self, shards, *, pattern="*", extensions=None, decode=None,
        shuffle=False, seed=0, archive_options=None,
    ):
        self.shards = shard_paths(shards)
        self.shuffle = shuffle
        self.seed = seed
        self._init_owner(pattern, extensions, decode, archive_options)

    def __iter__(self):
        info = get_worker_info()
        worker, workers = (info.id, info.num_workers) if info else (0, 1)
        shards = shuffle_shards(self.shards, self.seed) if self.shuffle else self.shards
        divide_members = len(shards) < workers
        if not divide_members:
            shards = split_by_worker(shards, worker, workers)
        position = 0
        try:
            for shard in shards:
                archive = self._get_archive(shard)
                for entry in archive.iter(order="archive"):
                    if not self._accept(entry.path):
                        continue
                    selected = not divide_members or position % workers == worker
                    position += 1
                    if selected:
                        yield self._sample(archive, entry.path)
        finally:
            self.close()
