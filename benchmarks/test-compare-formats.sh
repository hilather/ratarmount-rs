#!/usr/bin/env bash
# Regression: format sweep skips missing producers, verifies deterministic fixtures,
# reports corrupt/count-mismatched reads, and runs cold indexes without FUSE/binary
# requirements leaking into PREPARE_ONLY.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTDIR="$(mktemp -d "${TMPDIR:-/tmp}/test-compare-formats.XXXXXX")"
kept=''
cleanup() {
    [[ -z "$kept" ]] || rm -rf "$kept"
    rm -rf "$TESTDIR"
}
trap cleanup EXIT
export MICRO=1 PREPARE_ONLY=1 LARGE_MIB=2
export RUST_BIN="$TESTDIR/no-binary" COMPARE_KEEP=1
export CSV_OUT="$TESTDIR/results.csv" MD_OUT="$TESTDIR/results.md"
echo '==> Regression: format fixture smoke (MICRO=1 PREPARE_ONLY=1 LARGE_MIB=2; no binary/FUSE)'
if ! "$ROOT/benchmarks/compare-formats.sh" >"$TESTDIR/prepare.log" 2>&1; then
    cat "$TESTDIR/prepare.log"
    exit 1
fi
kept="$(sed -n 's/^Kept //p' "$TESTDIR/prepare.log")"
[[ -d "$kept" ]] || { echo '[FAIL] missing kept work directory'; exit 1; }
export WORKDIR="$kept" ROOT
python3 - "$TESTDIR/prepare.log" <<'PY'
import importlib.util
import os
from pathlib import Path
import re
import sys
spec = importlib.util.spec_from_file_location('sweep', Path(os.environ['WORKDIR']) / 'sweep.py')
sweep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sweep)
log = Path(sys.argv[1]).read_text()
for name, _ in sweep.FIXTURES:
    match = re.search(r'^PREPARE_(OK|SKIP) ' + re.escape(name) + r' (.+)$', log, re.M)
    assert match, 'missing status/reason: ' + name
    print('  [ok] ' + match.group())
assert 'PREPARE_ERROR' not in log
assert 'PREPARE_OK all expected fixtures' in log
PY
python3 - "$TESTDIR" <<'PY'
import contextlib
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
from unittest.mock import patch

w = Path(os.environ['WORKDIR'])
testdir = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('sweep', w / 'sweep.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
meta = s.load()
assert len(meta['fixtures']) == 21
assert meta['files'] == 100 and meta['large_mib'] == 2
files = list((w / 'corpus').rglob('*.bin'))
assert len(files) == 101
assert all(p.stat().st_mtime == s.STAMP for p in files)
assert len({p.parent.name for p in files if p.name != 'blob.bin'}) == 10
# Regression: the corpus and model bytes must reproduce across fresh workdirs.
repeat = testdir / 'repeat'
repeat.mkdir()
with patch.object(s, 'W', repeat), patch.object(s, 'CORPUS', repeat / 'corpus'):
    again = s.corpus()
assert again['blob_sha256'] == meta['blob_sha256']
assert again['tensor_sha256'] == meta['tensor_sha256']
assert s.digest(repeat / 'corpus/d00/f0000.bin') == s.digest(w / 'corpus/d00/f0000.bin')
shutil.rmtree(repeat)
assert len(s.plan()) == 48 and min(s.plan()) == 65536 and max(s.plan()) == 8 * s.MIB
assert sum(s.plan()) == 64 * s.MIB and s.plan().count(65536) == 16
for name in ['model.safetensors', 'model.gguf']:
    s.verify_model(w / name, meta)
# Regression: malformed tensor offsets must not receive PREPARE_OK.
bad = testdir / 'bad.safetensors'
data = (w / 'model.safetensors').read_bytes()
length = struct.unpack('<Q', data[:8])[0]
header = json.loads(data[8:8 + length])
header['layer.1.weight']['data_offsets'][0] += 32
encoded = json.dumps(header).encode()
bad.write_bytes(struct.pack('<Q', len(encoded)) + encoded + data[8 + length:])
try:
    s.verify_model(bad, meta)
    raise RuntimeError('corrupt model passed verification')
except AssertionError:
    pass
bad.unlink()
# Regression: missing tools are explicit skips, including dependent formats.
with patch.object(s.shutil, 'which', return_value=None):
    for name, _ in s.FIXTURES:
        if name.startswith('model.'):
            continue
        try:
            s.produce(name, meta)
            raise AssertionError('missing tools accepted: ' + name)
        except s.Missing as exc:
            assert 'missing' in str(exc)
# Run the exact read/count/hash logic on ordinary directories, requiring no FUSE.
rows = []
def record(*args, **kwargs):
    rows.append((args, kwargs))
with patch.object(s, 'record', side_effect=record):
    assert s.metrics('corpus.tar', w / 'corpus') == 0
    assert any(r[0][1] == 'verify_sha256' for r in rows)
    assert all(r[1].get('status', 'ok') == 'ok' for r in rows)
    extra = w / 'corpus/extra'
    extra.write_bytes(b'extra')
    with contextlib.redirect_stderr(io.StringIO()):
        assert s.metrics('corpus.tar', w / 'corpus') == 1
    assert rows[-1][0][1:5] == ('members', 102, 'files', 'error')
    extra.unlink()
    blob = w / 'corpus/blob.bin'
    with blob.open('r+b') as f:
        old = f.read(1)
        f.seek(0)
        f.write(bytes([old[0] ^ 1]))
    with contextlib.redirect_stderr(io.StringIO()):
        assert s.metrics('corpus.tar', w / 'corpus') == 1
    assert rows[-1][1]['status'] == 'error' and 'SHA-256 mismatch' in rows[-1][1]['note']
    with blob.open('r+b') as f:
        f.write(old)
    # Model tensor paths and synthetic JSON members differ from corpus members.
    model = testdir / 'model-mount'
    with (w / 'tensor-data').open('rb') as payload:
        for i, size in enumerate(s.plan()):
            tensor = model / f'layer/{i}/weight'
            tensor.parent.mkdir(parents=True)
            tensor.write_bytes(payload.read(size))
            tensor.with_suffix('.json').write_text('{}')
    (model / '__metadata__.json').write_text('{}')
    (model / '__header__.json').write_text('{}')
    assert s.metrics('model.safetensors', model) == 0
    (model / '__header__.json').unlink()
    assert s.metrics('model.gguf', model) == 0
    # Partition/nested prefixes must resolve their intended blob and random files.
    partition = testdir / 'partition'
    partition.mkdir()
    shutil.copytree(w / 'corpus', partition / 'p1')
    assert s.metrics('corpus-mbr.img', partition) == 0
    assert s.metrics('corpus.qcow2', partition) == 0
    nested = testdir / 'nested'
    shutil.copytree(w / 'corpus', nested / 'corpus.zip')
    shutil.copytree(w / 'corpus', nested / 'corpus.tar.gz')
    assert s.metrics('nested.tar', nested) == 0
# Regression: CSV notes with quotes, commas and newlines survive reporting.
note = 'comma, quote" | newline\nsecond line'
s.record('model.gguf', 'test_note', status='skip', note=note)
with (w / 'results.csv').open() as f:
    assert list(csv.DictReader(f))[-1]['note'].endswith(note)
with contextlib.redirect_stdout(io.StringIO()):
    assert s.report() == 0
assert 'newline second line' in Path(os.environ['MD_OUT']).read_text()
print('  [ok] Regression: deterministic corpus; valid/corrupt model layouts; missing producer skips')
print('  [ok] Regression: read metrics; member mismatch; checksum mismatch; model/partition/nested paths')
print('  [ok] Regression: CSV quoting and Markdown overview/skips')
PY
for kind in CSV_OUT MD_OUT; do
    if env "$kind=$TESTDIR/missing/output" "$ROOT/benchmarks/compare-formats.sh" >"$TESTDIR/misuse.log" 2>&1; then
        echo "[FAIL] $kind in missing directory succeeded"
        exit 1
    fi
    grep -q 'error: output parent' "$TESTDIR/misuse.log"
done
echo '  [ok] Regression: missing CSV/Markdown output directory fails loudly'
# Regression: NO_FUSE must still run cold indexes; daemon errors retain diagnostics.
cat > "$TESTDIR/fake-rust" <<'PY'
#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
if args == ['--version']:
    print('ratarmount smoke-fake (not benchmark data)')
elif '--repack-seekable' in args:
    print('intentional repack failure for fallback test', file=sys.stderr)
    sys.exit(1)
elif '--no-mount' in args:
    assert '-c' in args and '-f' in args
    assert args[args.index('--index-minimum-file-count') + 1] == '0'
    with open(os.environ['FAKE_CALLS'], 'a') as f:
        f.write(json.dumps(args) + '\n')
    if args[-1].endswith('model.gguf'):
        print('intentional GGUF daemon error, "quoted"\nsecond line', file=sys.stderr)
        sys.exit(1)
else:
    raise RuntimeError('unexpected mount/binary call: ' + repr(args))
PY
chmod +x "$TESTDIR/fake-rust"
if PREPARE_ONLY=0 NO_FUSE=1 COMPARE_KEEP=0 RUST_BIN="$TESTDIR/fake-rust" \
    FAKE_CALLS="$TESTDIR/calls" "$ROOT/benchmarks/compare-formats.sh" >"$TESTDIR/no-fuse.out" 2>"$TESTDIR/no-fuse.log"; then
    echo '[FAIL] daemon error did not produce a nonzero exit'
    exit 1
fi
python3 - "$TESTDIR" <<'PY'
import csv
import json
from pathlib import Path
import sys
p = Path(sys.argv[1])
rows = list(csv.DictReader((p / 'results.csv').open()))
fixtures = [r for r in rows if r['metric'] == 'fixture' and r['status'] == 'ok']
calls = [json.loads(line) for line in (p / 'calls').read_text().splitlines()]
assert len(calls) == len(fixtures)
assert all('--no-mount' in c for c in calls)
assert all(('-r' in c) == c[-1].endswith('nested.tar') for c in calls)
indexes = [r for r in rows if r['metric'] == 'index_cold_s']
assert len(indexes) == len(fixtures)
error = next(r for r in indexes if r['fixture'] == 'model.gguf')
assert error['status'] == 'error' and '"quoted"\nsecond line' in error['note']
assert all(r['value'] == '' for r in rows if r['status'] != 'ok')
assert not any(r['metric'].startswith(('mount_cold', 'mount_warm')) for r in rows)
assert (p / 'no-fuse.log').read_text().count('skip: FUSE unavailable') == 1
assert '| gguf (`model.gguf`) |' in (p / 'no-fuse.out').read_text()
assert 'fallback' in next(r for r in fixtures if r['format'] == 'tar.zst')['note']
print('  [ok] Regression: NO_FUSE cold indexes; nested flags; zstd fallback; daemon error diagnostics')
PY
echo '[ok] format sweep fixture builder and metrics'
