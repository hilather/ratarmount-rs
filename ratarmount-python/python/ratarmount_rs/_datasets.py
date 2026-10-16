"""Dependency-free shard selection shared by dataset adapters."""
from __future__ import annotations

import os
import random


def shard_paths(shards):
    if isinstance(shards, (str, os.PathLike)):
        return [os.fsdecode(shards)]
    return [os.fsdecode(path) for path in shards]


def shuffle_shards(shards, seed=None):
    """Return a shuffled copy. Use the same seed in every worker."""
    paths = shard_paths(shards)
    random.Random(seed).shuffle(paths)
    return paths


def split_by_worker(shards, worker_id=None, num_workers=None):
    """Round-robin shard assignment, with optional PyTorch worker detection."""
    if worker_id is None and num_workers is None:
        try:
            from torch.utils.data import get_worker_info
        except ImportError:
            info = None
        else:
            info = get_worker_info()
        worker_id, num_workers = (info.id, info.num_workers) if info else (0, 1)
    if worker_id is None or num_workers is None or num_workers < 1:
        raise ValueError("provide worker_id and positive num_workers together")
    if not 0 <= worker_id < num_workers:
        raise ValueError("worker_id must be within num_workers")
    return shard_paths(shards)[worker_id::num_workers]
