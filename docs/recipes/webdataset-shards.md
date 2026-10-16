# WebDataset and img2dataset shards

Use `img2dataset` or another producer to write files named with the same sample
key, such as `000001.jpg`, `000001.json`, and `000001.txt`. Run `ratarmount
shard --group-by-key --frame-per-sample` to keep those files together and make
each sample independently seekable. The command writes an index for every
archive and a `shards.json` manifest. Use `ratarmount export-index` for Parquet,
JSONL, or CSV catalogs where those formats are enabled in the build.

The Python `ratarmount_rs.webdataset` reader can iterate local shards without
mounting. With fsspec, the chain syntax is `ratar://MEMBER_GLOB::hf://...`; for
example, `ratar://*.tar::hf://datasets/org/name/archive.zip` selects raw TAR
shards inside an outer ZIP. The Hugging Face `webdataset` builder requires raw
TAR shard streams: use its native Hub URL for TAR shards stored directly on the
Hub, or an `ratar://*.tar::hf://...zip` chain for TAR members inside a ZIP.
Install the matching optional Python extras and see the [Python guide](../python.md)
for the supported forms. `--publish-index hf://...` is supported by builds
with Hub publishing enabled; it needs a write token for the target repo. The
local smoke script always creates and indexes a tiny two-sample fixture, and
only attempts Hub publication when configured.

```sh
docs/recipes/scripts/webdataset-shards.sh
```
