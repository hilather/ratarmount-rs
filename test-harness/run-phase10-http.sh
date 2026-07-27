#!/usr/bin/env bash
# Phase 10: mount archive over HTTP (full GET download to temp).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-phase10-$$"
mkdir -p "$WORKDIR/www"
cp "$RATARMOUNT_PY_ROOT/tests/single-file.tar" "$WORKDIR/www/"
MP="$WORKDIR/mnt"
mkdir -p "$MP"

cleanup() {
    set +e
    [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
    [[ -n "${MNT_PID:-}" ]] && kill "$MNT_PID" 2>/dev/null || true
    ratar_unmount "$MP"
    rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

# Simple HTTP server (full GET is enough for Phase 10 materialize path)
PORT=18765
(
  cd "$WORKDIR/www"
  python3 -m http.server "$PORT" --bind 127.0.0.1
) >"$WORKDIR/http.log" 2>&1 &
SRV_PID=$!

# wait for server
for i in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$PORT/single-file.tar" -o /dev/null 2>/dev/null; then
    break
  fi
  sleep 0.1
done

URL="http://127.0.0.1:$PORT/single-file.tar"
echo "==> Phase 10 HTTP: $URL"

"$RATARMOUNT_CMD" -f -c --index-file "$WORKDIR/idx.sqlite" "$URL" "$MP" \
  >"$WORKDIR/mount.log" 2>&1 &
MNT_PID=$!

for i in $(seq 1 80); do
  mount 2>/dev/null | grep -F -q "$MP" && break
  sleep 0.1
done

if ! mount 2>/dev/null | grep -F -q "$MP"; then
  echo "[FAIL] mount"
  cat "$WORKDIR/mount.log" "$WORKDIR/http.log" || true
  exit 1
fi

got=$(md5sum "$MP/bar" | awk '{print $1}')
want=d3b07384d113edec49eaa6238ad5ff00
if [[ "$got" != "$want" ]]; then
  echo "[FAIL] md5 $got want $want"
  cat "$WORKDIR/mount.log" || true
  exit 1
fi
echo "[ok] http:// archive bar md5 $got"

# file:// URL
ratar_unmount "$MP"
wait "$MNT_PID" 2>/dev/null || true
FILE_URL="file://$RATARMOUNT_PY_ROOT/tests/single-file.tar"
"$RATARMOUNT_CMD" -f -c --index-file "$WORKDIR/idx2.sqlite" "$FILE_URL" "$MP" \
  >"$WORKDIR/mount2.log" 2>&1 &
MNT_PID=$!
for i in $(seq 1 50); do
  mount 2>/dev/null | grep -F -q "$MP" && break
  sleep 0.1
done
got=$(md5sum "$MP/bar" | awk '{print $1}')
if [[ "$got" != "$want" ]]; then
  echo "[FAIL] file:// md5 $got"
  cat "$WORKDIR/mount2.log" || true
  exit 1
fi
echo "[ok] file:// archive bar md5 $got"

echo "Phase 10 HTTP OK"
