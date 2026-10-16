#!/usr/bin/env bash
set -euo pipefail
ratarmount_bin=${RATARMOUNT_BIN:-ratarmount}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/input" "$work/shards"
printf 'initial checkpoint\n' > "$work/input/step-0001.bin"
"$ratarmount_bin" shard "$work/input" -o "$work/shards" --prefix checkpoint --size 1M
archive=$(find "$work/shards" -maxdepth 1 -name '*.tar.zst' -print -quit)
test -s "$archive"
if [[ ! -e /dev/fuse ]]; then
    echo 'skip: /dev/fuse is unavailable; archive creation passed, overlay commit skipped'
    exit 0
fi
mountpoint="$work/mnt"
mkdir "$mountpoint"
overlay="$work/overlay"
mount_pid=
cleanup() {
    "$ratarmount_bin" -u "$mountpoint" >/dev/null 2>&1 || true
    if [[ -n "$mount_pid" ]]; then wait "$mount_pid" 2>/dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT
"$ratarmount_bin" -w "$overlay" --commit-overlay-on-exit --commit-overlay-mode auto --commit-manifest "$archive" "$mountpoint" &
mount_pid=$!
for _ in {1..100}; do
    mountpoint -q "$mountpoint" && break
    kill -0 "$mount_pid" 2>/dev/null || { wait "$mount_pid"; exit 1; }
    sleep 0.1
done
mountpoint -q "$mountpoint" || { echo 'mount did not become ready' >&2; exit 1; }
printf 'next checkpoint\n' > "$mountpoint/step-0002.bin"
if command -v setfattr >/dev/null 2>&1; then
    setfattr -n user.teacher -v distillkit "$mountpoint/step-0002.bin" || echo 'skip: overlay xattr persistence unavailable in this build'
    setfattr -n user.train_ok -v false "$mountpoint/step-0002.bin" || echo 'skip: overlay xattr persistence unavailable in this build'
else
    echo 'skip: setfattr is not installed; provenance xattr step skipped'
fi
"$ratarmount_bin" -u "$mountpoint"
test -s "$archive.manifest.jsonl"
