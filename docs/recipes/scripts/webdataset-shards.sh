#!/usr/bin/env bash
set -euo pipefail

ratarmount_bin=${RATARMOUNT_BIN:-ratarmount}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/input"
printf 'small local image payload\n' > "$work/input/000001.jpg"
printf '{"caption":"fixture"}\n' > "$work/input/000001.json"
printf 'second image\n' > "$work/input/000002.jpg"
printf '{"caption":"second"}\n' > "$work/input/000002.json"

"$ratarmount_bin" shard "$work/input" -o "$work/shards" --group-by-key --frame-per-sample --size 1M
test -s "$work/shards/shards.json"
shard=$(find "$work/shards" -maxdepth 1 -name '*.tar.zst' -print -quit)
test -n "$shard"
"$ratarmount_bin" find '*' "$shard"

if python3 -c 'import ratarmount_rs' 2>/dev/null; then
    python3 - "$shard" <<'PY'
import sys
import ratarmount_rs
from ratarmount_rs.webdataset import samples
with ratarmount_rs.open(sys.argv[1]) as archive:
    names = {entry.path.rsplit('/', 1)[-1] for entry in archive.iter(order="name")}
    assert {"000001.jpg", "000001.json", "000002.jpg", "000002.json"} <= names
    assert archive.read("/000001.json") == b'{"caption":"fixture"}\n'
sample = next(samples([sys.argv[1]]))
assert sample["__key__"] == "000001" and sample["jpg"] == b"small local image payload\n"
print("library-mode shard read passed")
PY
else
    echo 'skip: ratarmount_rs is not installed; CLI indexing and find passed'
fi

if [[ -n "${HF_ARCHIVE_URL:-}" ]]; then
    "$ratarmount_bin" --publish-index "$HF_ARCHIVE_URL"
else
    echo 'skip: set HF_ARCHIVE_URL and HF_TOKEN to publish an index to the Hub'
fi
