#!/usr/bin/env bash
# Phase 10 remote: HTTP smoke + S3/SSH unit coverage + optional live URLs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="${RATARMOUNT_CMD:-$ROOT/target/release/ratarmount}"
WORKDIR="${TMPDIR:-/tmp}/ratarmount-rs-remote-$$"
mkdir -p "$WORKDIR/www" "$WORKDIR/mnt"
MP="$WORKDIR/mnt"

cleanup() {
    [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true
    [[ -n "${MNT_PID:-}" ]] && kill "$MNT_PID" 2>/dev/null || true
    ratar_unmount "$MP"
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

cp "$RATARMOUNT_PY_ROOT/tests/single-file.tar" "$WORKDIR/www/"

PORT=18766
(
  cd "$WORKDIR/www"
  python3 -m http.server "$PORT" --bind 127.0.0.1
) >"$WORKDIR/http.log" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$PORT/single-file.tar" -o /dev/null 2>/dev/null; then
    break
  fi
  sleep 0.1
done

URL="http://127.0.0.1:$PORT/single-file.tar"
echo "==> HTTP remote: $URL"
"$BIN" -f -c --index-file "$WORKDIR/idx.sqlite" "$URL" "$MP" \
  >"$WORKDIR/mount.log" 2>&1 &
MNT_PID=$!
for _ in $(seq 1 80); do
  mount 2>/dev/null | grep -F -q "$MP" && break
  sleep 0.1
done
if ! mount 2>/dev/null | grep -F -q "$MP"; then
  echo "[FAIL] HTTP mount"
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
echo "  [ok] HTTP remote bar md5 $got"
ratar_unmount "$MP"
wait "$MNT_PID" 2>/dev/null || true
MNT_PID=

# Clear error for unsupported / missing creds (API smoke)
if "$BIN" --no-mount -c --index-file "$WORKDIR/bad.sqlite" \
    "s3://no-such-bucket-ratarmount-test/key.tar" 2>"$WORKDIR/s3.err"; then
  echo "[FAIL] s3 without credentials should fail"
  exit 1
fi
if ! grep -qiE 'AWS_|s3|credential|ACCESS' "$WORKDIR/s3.err"; then
  echo "[FAIL] expected S3 credential error, got:"
  cat "$WORKDIR/s3.err"
  exit 1
fi
echo "  [ok] s3:// without creds fails clearly"

if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" && -n "${RATARMOUNT_TEST_S3_URL:-}" ]]; then
  echo "==> S3 live: $RATARMOUNT_TEST_S3_URL"
  "$BIN" --no-mount -c --index-file "$WORKDIR/s3.sqlite" "$RATARMOUNT_TEST_S3_URL"
  echo "  [ok] S3 live"
else
  echo "  [skip] S3 live (set AWS_* + RATARMOUNT_TEST_S3_URL)"
fi

if [[ -n "${RATARMOUNT_TEST_SSH_URL:-}" ]]; then
  echo "==> SSH live: $RATARMOUNT_TEST_SSH_URL"
  "$BIN" --no-mount -c --index-file "$WORKDIR/ssh.sqlite" "$RATARMOUNT_TEST_SSH_URL"
  echo "  [ok] SSH live"
else
  echo "  [skip] SSH live (set RATARMOUNT_TEST_SSH_URL)"
fi

echo "==> unit tests"
(cd "$ROOT" && cargo test -p ratarmount-remote -q)

echo "Phase 10 remote OK"
