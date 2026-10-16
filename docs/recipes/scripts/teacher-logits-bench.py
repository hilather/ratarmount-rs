#!/usr/bin/env python3
"""Small loose-file versus seekable-shard random-read benchmark."""
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile
import time
import os

ratarmount = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("RATARMOUNT_BIN", "ratarmount")
root = pathlib.Path(tempfile.mkdtemp(prefix="ratar-logits-"))
try:
    loose = root / "loose"
    loose.mkdir()
    packed = root / "packed"
    packed.mkdir()
    rng = random.Random(8128)
    count, size = 8, 16 * 1024
    for i in range(count):
        document = loose / f"doc-{i:04}"
        document.mkdir()
        (document / "logits.jsonl").write_bytes(rng.randbytes(size))
        output = packed / f"doc-{i:04}"
        subprocess.run([ratarmount, "shard", str(document), "-o", str(output),
                        "--group-by-key", "--frame-per-sample", "--size", "1M"], check=True)
    shards = sorted(packed.glob("doc-*/*.tar.zst"))
    # The first pass measures loose-file open/read overhead. The second measures
    # warm archive indexing plus exact member-range reads through Python.
    order = list(range(count))
    random.Random(19).shuffle(order)
    start = time.perf_counter()
    for i in order:
        (loose / f"doc-{i:04}" / "logits.jsonl").read_bytes()
    loose_seconds = time.perf_counter() - start
    try:
        import ratarmount_rs
    except ImportError:
        print(f"loose_files_seconds={loose_seconds:.6f}")
        print("skip: install ratarmount_rs to time indexed range reads")
    else:
        start = time.perf_counter()
        for i in order:
            with ratarmount_rs.open(str(shards[i])) as archive:
                got = archive.read("/logits.jsonl")
                assert len(got) == size
        packed_seconds = time.perf_counter() - start
        print(f"loose_files_seconds={loose_seconds:.6f}")
        print(f"shard_open_and_range_reads_seconds={packed_seconds:.6f}")
        total_shard_bytes = sum(shard.stat().st_size for shard in shards)
        print(f"documents={count} bytes_per_document={size} shard_bytes={total_shard_bytes}")
finally:
    shutil.rmtree(root)
