#!/usr/bin/env bash
# Regenerate test-harness/fixtures/overlay-v0.1.35 with a REAL v0.1.35
# ratarmount binary: one `-w` mount over a small tar, one created file.
#
#   git worktree add --detach ../scratch-v0.1.35 v0.1.35
#   (cd ../scratch-v0.1.35 && CARGO_TARGET_DIR=/tmp/target-v0135 cargo build -j2 -p ratarmount)
#   ./test-harness/make-overlay-v0.1.35.sh /tmp/target-v0135/debug/ratarmount
#
# Needs /dev/fuse and fusermount3. The tests (ratarmount/tests/overlay_v035.rs)
# only READ the committed fixture; FUSE is needed to regenerate it, not to run them.
set -euo pipefail

# Replace the generated files in OUT (an overlay and its base) and nothing else:
# the committed README.md beside them is documentation, not output.
publish() { # WORK OUT
  mkdir -p "$2"
  rm -rf "$2/overlay" "$2/base.tar"
  cp -a "$1/overlay" "$2/overlay"
  cp "$1/base.tar" "$2/base.tar"
}
# test-harness/test-make-overlay-v0.1.35.sh exercises this step without FUSE.
if [ "${1:-}" = "--publish-only" ]; then
  publish "${2:?WORK}" "${3:?OUT}"
  exit 0
fi

BIN=${1:?usage: make-overlay-v0.1.35.sh PATH-TO-RATARMOUNT-0.1.35-BINARY}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/fixtures/overlay-v0.1.35"

"$BIN" --version | grep -q '^ratarmount 0\.1\.35$' || {
  echo "error: $BIN is not ratarmount 0.1.35" >&2
  exit 2
}

WORK=$(mktemp -d)
cleanup() {
  fusermount3 -u "$WORK/mnt" 2>/dev/null || true
  if [ -n "${PID:-}" ]; then kill "$PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/src" "$WORK/mnt"
printf 'base member\n' > "$WORK/src/a.txt"
tar --format=ustar --mtime=@0 --owner=0 --group=0 --numeric-owner \
  -cf "$WORK/base.tar" -C "$WORK/src" a.txt

export HOME="$WORK" XDG_CACHE_HOME="$WORK/.cache"
(cd "$WORK" && "$BIN" -f --index-file :memory: -w overlay base.tar mnt > mount.log 2>&1) &
PID=$!
for _ in $(seq 1 50); do
  [ -e "$WORK/mnt/a.txt" ] && break
  sleep 0.1
done
[ -e "$WORK/mnt/a.txt" ] || { cat "$WORK/mount.log" >&2; echo "error: mount did not come up" >&2; exit 1; }
printf 'created by v0.1.35\n' > "$WORK/mnt/created.txt"
fusermount3 -u "$WORK/mnt"
wait "$PID" 2>/dev/null || true
PID=

# A released overlay has a `files` table and no `meta` table.
if sqlite3 "$WORK/overlay/.ratarmount.overlay.sqlite" '.tables' | grep -qw meta; then
  echo "error: this build wrote a meta table; use the released v0.1.35 binary" >&2
  exit 1
fi

publish "$WORK" "$OUT"
echo "wrote $OUT"
