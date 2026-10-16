#!/usr/bin/env bash
# Exercises an installed host plugin; never installs a plugin or pulls images.
set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then
  echo 'skip: docker is unavailable' >&2
  exit 0
fi
if ! docker info >/dev/null 2>&1; then
  echo 'skip: docker daemon is unavailable' >&2
  exit 0
fi
if [[ ! -e /dev/fuse ]]; then
  echo 'skip: /dev/fuse is unavailable' >&2
  exit 0
fi
if ! command -v tar >/dev/null 2>&1; then
  echo 'skip: tar is unavailable' >&2
  exit 0
fi
plugin_socket=${RATARMOUNT_PLUGIN_SOCKET:-/run/docker/plugins/ratarmount.sock}
if [[ ! -S "$plugin_socket" ]]; then
  echo "skip: install and start the volume plugin at $plugin_socket" >&2
  exit 0
fi
image=${RATARMOUNT_TEST_IMAGE:-busybox:latest}
if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "skip: local test image $image is unavailable; load it before testing" >&2
  exit 0
fi
scratch=$(mktemp -d /tmp/ratarmount-volume-test.XXXXXXXX)
volume="ratarmount-test-${scratch##*.}"
container="${volume}-holder"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT
mkdir -p "$scratch/source/tests"
echo hello > "$scratch/source/payload.txt"
echo protected > "$scratch/source/tests/test.txt"
tar -cf "$scratch/source.tar" -C "$scratch/source" payload.txt tests
docker volume create -d ratarmount -o "source=$scratch/source.tar" \
  -o overlay=tmpfs:16M -o 'readonly_globs=tests/**' "$volume" >/dev/null
docker run -d --name "$container" -v "$volume:/data" "$image" sleep 300 >/dev/null
docker run --rm -v "$volume:/data" "$image" sh -ec '
  test "$(cat /data/payload.txt)" = hello
  echo changed > /data/new.txt
  if echo forbidden > /data/tests/test.txt; then
    echo "readonly_globs failed" >&2
    exit 1
  fi
'
docker exec "$container" sh -ec 'test "$(cat /data/new.txt)" = changed'
if docker volume rm "$volume" >/dev/null 2>&1; then
  echo 'removed a volume still in use' >&2
  exit 1
fi
docker rm -f "$container" >/dev/null
docker volume rm "$volume" >/dev/null
echo 'Docker volume plugin integration passed'
