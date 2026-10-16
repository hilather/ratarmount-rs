#!/usr/bin/env bash
set -euo pipefail
ratarmount_bin=${RATARMOUNT_BIN:-ratarmount}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git init -q "$work/repo"
mkdir -p "$work/repo/tests"
printf 'base\n' > "$work/repo/app.py"
printf 'test\n' > "$work/repo/tests/test_app.py"
git -C "$work/repo" add .
git -C "$work/repo" -c user.name=smoke -c user.email=smoke@example.invalid commit -qm base
git clone -q --bare "$work/repo" "$work/repo.git"
base=$(git -C "$work/repo" rev-parse HEAD)
source="$work/repo.git@$base"
if [[ ! -e /dev/fuse ]]; then
    echo 'skip: /dev/fuse is unavailable; prepared a bare repo at a pinned base'
    exit 0
fi
mountpoint="$work/task"
overlay="$work/attempt-overlay"
mkdir "$mountpoint"
cleanup() { "$ratarmount_bin" -u "$mountpoint" >/dev/null 2>&1 || true; }
mount_pid=
cleanup() { "$ratarmount_bin" -u "$mountpoint" >/dev/null 2>&1 || true; if [[ -n "$mount_pid" ]]; then wait "$mount_pid" 2>/dev/null || true; fi; rm -rf "$work"; }
trap cleanup EXIT
"$ratarmount_bin" --git-synthetic-head -w "$overlay" --overlay-readonly 'tests/**' "$source" "$mountpoint" &
mount_pid=$!
for _ in {1..100}; do
    mountpoint -q "$mountpoint" && break
    kill -0 "$mount_pid" 2>/dev/null || { wait "$mount_pid"; exit 1; }
    sleep 0.1
done
mountpoint -q "$mountpoint" || { echo 'mount did not become ready' >&2; exit 1; }
printf 'agent result\n' > "$mountpoint/result.txt"
"$ratarmount_bin" diff "$overlay" --base "$source" --git > "$work/attempt.patch"
grep -q '^+agent result$' "$work/attempt.patch"
echo "patch: $work/attempt.patch"
