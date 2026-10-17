"""WebDataset sample dictionaries without a dependency on torch or webdataset."""
from __future__ import annotations

import re

from . import open as open_archive
from ._datasets import shard_paths, shuffle_shards, split_by_worker

__all__ = ["samples", "base_plus_ext", "shuffle_shards", "split_by_worker"]


def base_plus_ext(path):
    """Split at the first dot in the basename, as WebDataset tariterators do."""
    match = re.match(r"^((?:.*/|)[^.]+)[.]([^/]*)$", path)
    return match.groups() if match else (None, None)


def samples(
    shards, *, shuffle=False, seed=0, worker_id=None, num_workers=None,
    split_workers=True, archive_options=None,
):
    """Yield raw byte samples, grouping consecutive keys within each shard.

    Keys retain directory prefixes; extensions are lowercased and multi-part
    extensions stay intact. Duplicate suffixes in one sample raise ValueError.
    Shard boundaries flush a sample even when the next shard has the same key.
    Native catalogs expose newest versions of duplicate paths, not TAR history.
    With split_workers=True, torch workers (if present) divide whole shards.
    """
    paths = shuffle_shards(shards, seed) if shuffle else shard_paths(shards)
    if split_workers:
        paths = split_by_worker(paths, worker_id, num_workers)
    for shard in paths:
        with open_archive(shard, **(archive_options or {})) as archive:
            current = None
            for entry in archive.iter(order="archive"):
                name = entry.path.lstrip("/")
                key, suffix = base_plus_ext(name)
                if key is None:
                    continue
                # Match WebDataset's metadata-file exclusion.
                if re.match(r"__[^/]*__($|/)", name):
                    continue
                suffix = suffix.lower()
                if current is None or key != current["__key__"]:
                    if current is not None:
                        yield current
                    current = {"__key__": key, "__url__": shard}
                if suffix in current:
                    raise ValueError(f"{name}: duplicate suffix {suffix!r} in sample {key!r}")
                current[suffix] = archive.read(entry.path)
            if current is not None:
                yield current
