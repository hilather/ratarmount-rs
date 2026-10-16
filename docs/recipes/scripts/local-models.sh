#!/usr/bin/env bash
set -euo pipefail
ratarmount_bin=${RATARMOUNT_BIN:-ratarmount}
work=$(mktemp -d)
source=${MODEL_URL:-"$work/tiny.safetensors"}
if [[ -z "${MODEL_URL:-}" ]]; then
    python3 - "$source" <<'PY'
import json
import struct
import sys
header = json.dumps({"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}},
                    separators=(",", ":")).encode()
header += b" " * (-len(header) % 8)
with open(sys.argv[1], "wb") as out:
    out.write(struct.pack("<Q", len(header)))
    out.write(header)
    out.write(struct.pack("<ff", 1.0, 2.0))
PY
    echo 'using generated two-float safetensors fixture'
fi
if [[ ! -e /dev/fuse ]]; then
    echo 'skip: /dev/fuse is unavailable; local fixture creation passed, mount inspection skipped'
    rm -rf "$work"
    exit 0
fi
mountpoint="$work/model"
mkdir "$mountpoint"
mount_pid=
cleanup() { "$ratarmount_bin" -u "$mountpoint" >/dev/null 2>&1 || true; if [[ -n "$mount_pid" ]]; then wait "$mount_pid" 2>/dev/null || true; fi; rm -rf "$work"; }
trap cleanup EXIT
export HF_HOME=${HF_HOME:-"$HOME/.cache/huggingface"}
"$ratarmount_bin" "$source" "$mountpoint" --lazy &
mount_pid=$!
for _ in {1..100}; do
    mountpoint -q "$mountpoint" && break
    kill -0 "$mount_pid" 2>/dev/null || { wait "$mount_pid"; exit 1; }
    sleep 0.1
done
mountpoint -q "$mountpoint" || { echo 'mount did not become ready' >&2; exit 1; }
find "$mountpoint" -maxdepth 2 -type f -print | head -40
find "$mountpoint" -name '__metadata__.json' -o -name '*.safetensors.json' -o -name '*.gguf.json'
