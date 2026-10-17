#!/usr/bin/env bash
set -euo pipefail
ratarmount_bin=${RATARMOUNT_BIN:-ratarmount}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 - "$work/tiny.warc" <<'PY'
import sys
payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
header = ("WARC/1.0\r\nWARC-Type: response\r\n"
          "WARC-Target-URI: https://example.invalid/tiny\r\n"
          "WARC-Date: 2026-01-01T00:00:00Z\r\n"
          "Content-Type: application/http; msgtype=response\r\n"
          f"Content-Length: {len(payload)}\r\n\r\n").encode()
open(sys.argv[1], "wb").write(header + payload + b"\r\n\r\n")
PY
"$ratarmount_bin" find '*' "$work/tiny.warc"
if python3 -c 'import ratarmount_rs' 2>/dev/null; then
    python3 - "$work/tiny.warc" <<'PY'
import sys
import ratarmount_rs
with ratarmount_rs.open(sys.argv[1]) as archive:
    entries = list(archive.iter(order="name"))
    assert entries, "WARC index should expose records"
    assert archive.read("/example.invalid/tiny") == b"hello"
print("WARC text payload extracted through the library")
PY
else
    echo 'skip: ratarmount_rs is not installed; CLI WARC indexing passed'
fi
if [[ -n "${WARC_URL:-}" ]]; then
    if [[ ! -e /dev/fuse ]]; then
        echo 'skip: /dev/fuse is unavailable; remote mount/text extraction skipped'
    else
        mkdir "$work/mnt"
        "$ratarmount_bin" "$WARC_URL" "$work/mnt" --lazy
        find "$work/mnt" -type f -maxdepth 3 -print
        "$ratarmount_bin" -u "$work/mnt"
    fi
else
    echo 'tip: set WARC_URL to an S3, hf://, or local WARC source for a mount smoke'
fi
