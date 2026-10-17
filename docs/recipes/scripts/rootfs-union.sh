#!/usr/bin/env bash
set -euo pipefail
ratarmount_bin=${RATARMOUNT_BIN:-ratarmount}
image=${ROOTFS_IMAGE:-docker://ubuntu:24.04}
repo=${REPO_SOURCE:-}
fixture=
if [[ -z "$repo" ]]; then
    fixture=$(mktemp -d)
    git init -q "$fixture/repo"
    printf 'local rootfs smoke\n' > "$fixture/repo/README.txt"
    git -C "$fixture/repo" add README.txt
    git -C "$fixture/repo" -c user.name=smoke -c user.email=smoke@example.invalid commit -qm base
    git clone -q --bare "$fixture/repo" "$fixture/repo.git"
    repo="$fixture/repo.git@$(git -C "$fixture/repo" rev-parse HEAD)"
    echo 'using a generated local Git repository fixture'
fi
work=$(mktemp -d)
cleanup() { "$ratarmount_bin" -u "$work/root" >/dev/null 2>&1 || true; if [[ -n "${mount_pid:-}" ]]; then wait "$mount_pid" 2>/dev/null || true; fi; rm -rf "$work"; if [[ -n "$fixture" ]]; then rm -rf "$fixture"; fi; }
if [[ ! -e /dev/fuse ]]; then
    echo 'skip: /dev/fuse is unavailable; local repo prepared, image + repository mount skipped'
    rm -rf "$work"
    if [[ -n "$fixture" ]]; then rm -rf "$fixture"; fi
    exit 0
fi
mkdir "$work/root"
mount_pid=
trap cleanup EXIT
"$ratarmount_bin" --git-synthetic-head --bind "/repo=$repo" -w "$work/overlay" "$image" "$work/root" &
mount_pid=$!
for _ in {1..100}; do
    mountpoint -q "$work/root" && break
    kill -0 "$mount_pid" 2>/dev/null || { wait "$mount_pid"; exit 1; }
    sleep 0.1
done
mountpoint -q "$work/root" || { echo 'mount did not become ready' >&2; exit 1; }
if command -v bwrap >/dev/null 2>&1; then
    bwrap --bind "$work/root" / --proc /proc --dev /dev --tmpfs /tmp --chdir /repo /bin/sh -lc 'git status --short'
elif command -v systemd-nspawn >/dev/null 2>&1; then
    systemd-nspawn -D "$work/root" --chdir=/repo /bin/sh -lc 'git status --short'
else
    echo 'skip: neither bwrap nor systemd-nspawn is installed'
fi
