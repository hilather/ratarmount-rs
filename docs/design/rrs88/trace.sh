#!/usr/bin/env bash
# Usage (repo root): cargo build --release -p ratarmount && docs/design/rrs88/trace.sh
# Needs fusermount3; leaves trace.log next to this script.
set -u
P=${P:-$(cd "$(dirname "$0")" && pwd)}; B=${B:-$PWD/target/release/ratarmount}  # run from the repo root
W=$(mktemp -d) || exit 1; DPID=
cleanup() {
  if mountpoint -q "$W/mnt" 2>/dev/null; then fusermount3 -u "$W/mnt"; fi
  if [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null; then kill "$DPID"; fi
  rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/src/d" "$W/ov" "$W/mnt"; echo base > "$W/src/d/base.txt"; tar -C "$W/src" -cf "$W/a.tar" d
cd /tmp; RUST_LOG=fuser=debug,ratarmount_fuse=debug $B -f -w "$W/ov" "$W/a.tar" "$W/mnt" > "$P/trace.log" 2>&1 & DPID=$!; echo daemon=$DPID
for i in $(seq 50); do mountpoint -q "$W/mnt" && break; sleep 0.2; done
python3 "$P/poll.py" "$W/mnt/d" 1 200
fusermount3 -u "$W/mnt"; wait $DPID; echo "daemon exit=$?"
