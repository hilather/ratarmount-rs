#!/usr/bin/env bash
# measure.sh: FUSE -w mount at main vs plain dir; writers x cycles x runs.
# Usage (repo root): cargo build --release -p ratarmount && docs/design/rrs88/measure.sh
set -u
P=${P:-$(cd "$(dirname "$0")" && pwd)}; B=${B:-$PWD/target/release/ratarmount}  # run from the repo root
W=$(mktemp -d) || exit 1; DPID=
cleanup() {
  if mountpoint -q "$W/mnt" 2>/dev/null; then fusermount3 -u "$W/mnt"; fi
  if [ -n "$DPID" ] && kill -0 "$DPID" 2>/dev/null; then kill "$DPID"; fi
  rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/src/d" "$W/ov" "$W/mnt" "$W/plain"
echo base > "$W/src/d/base.txt"; tar -C "$W/src" -cf "$W/a.tar" d
cd /tmp
$B -f -w "$W/ov" "$W/a.tar" "$W/mnt" > "$P/daemon.log" 2>&1 & DPID=$!; echo "daemon=$DPID"
for i in $(seq 50); do mountpoint -q "$W/mnt" && break; sleep 0.2; done
mountpoint -q "$W/mnt" || { echo "mount failed"; kill $DPID; exit 1; }
for cfg in "1 400" "8 100"; do set -- $cfg
  for r in 1 2 3; do
    echo "fuse w=$1 c=$2 run=$r $(python3 "$P/poll.py" "$W/mnt/d" $1 $2)"
    echo "plain w=$1 c=$2 run=$r $(python3 "$P/poll.py" "$W/plain" $1 $2)"
  done
done
fusermount3 -u "$W/mnt"; wait $DPID; echo "daemon exit=$?"
