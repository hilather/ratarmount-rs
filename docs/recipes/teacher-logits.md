# Teacher logits and DistillKit stores

Store each document's logits or token-level trace as one file. `ratarmount
shard --group-by-key --frame-per-sample` keeps the document's related files
together and makes each sample a seekable zstd frame. Build the index with the
shard command, publish it beside a Hub-hosted archive where publication is
available, then use `ratarmount_rs.open()` and `Archive.read(path, offset,
length)` to fetch only selected documents or ranges. Keep large sample files
under the chosen frame size limit so a single random read does not require
decoding a very large frame.

The benchmark generates 32 tiny JSONL traces, packs them, and compares a
shuffled pass over loose files with indexed member-range reads. It reports
measurements from the current machine; the shard measurement includes opening
and indexing the archive, so benchmark results are not a claim about model
training throughput.

```sh
python3 docs/recipes/scripts/teacher-logits-bench.py
```

For WebDataset training examples, see [WebDataset shards](webdataset-shards.md).

