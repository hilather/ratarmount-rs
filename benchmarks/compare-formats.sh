#!/usr/bin/env bash
# Rust-only cross-format sweep. See benchmarks/README.md, "Format sweep".
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_BIN="${RUST_BIN:-$ROOT/target/release/ratarmount}"
PREPARE_ONLY="${PREPARE_ONLY:-0}"
MICRO="${MICRO:-0}"
# MICRO defaults to a 2 MiB blob; an explicit LARGE_MIB takes precedence.
if [[ "$MICRO" == 1 ]]; then
    LARGE_MIB="${LARGE_MIB:-2}"
else
    LARGE_MIB="${LARGE_MIB:-64}"
fi
CSV_OUT="${CSV_OUT:-$ROOT/benchmarks/format-results.csv}"
MD_OUT="${MD_OUT:-$ROOT/benchmarks/format-results.md}"
command -v python3 >/dev/null || { echo 'error: python3 is required' >&2; exit 1; }
[[ "$LARGE_MIB" =~ ^[1-9][0-9]*$ ]] || { echo 'error: LARGE_MIB must be a positive integer' >&2; exit 1; }
# Validate destinations even for PREPARE_ONLY; never silently create a typoed directory.
for dest in "$CSV_OUT" "$MD_OUT"; do
    [[ -d "$(dirname "$dest")" && -w "$(dirname "$dest")" && ! -d "$dest" ]] || {
        echo "error: output parent missing/unwritable or output is a directory: $dest" >&2
        exit 1
    }
done
[[ "$CSV_OUT" != "$MD_OUT" ]] || { echo 'error: CSV_OUT and MD_OUT must differ' >&2; exit 1; }
if [[ "$PREPARE_ONLY" != 1 && ! -x "$RUST_BIN" ]]; then
    echo "error: Rust binary missing: $RUST_BIN; run cargo build --release -p ratarmount or set RUST_BIN" >&2
    exit 1
fi
export RATARMOUNT_ALLOW_NO_PY=1 RATARMOUNT_ENV_QUIET=1
if [[ "$PREPARE_ONLY" == 1 ]]; then
    export RATARMOUNT_CMD="${RATARMOUNT_CMD:-/bin/true}"
else
    export RATARMOUNT_CMD="$RUST_BIN"
fi
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../test-harness/env.sh
source "$ROOT/test-harness/env.sh"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ratarmount-formats.XXXXXX")"
CUR_PID=''
CUR_MP=''
finish_mount() {
    [[ -n "$CUR_MP" ]] || return 0
    ratar_unmount "$CUR_MP"
    if ratar_is_mounted "$CUR_MP"; then
        echo "error: could not unmount $CUR_MP; retaining work directory" >&2
        COMPARE_KEEP=1
        return 1
    fi
    if [[ -n "$CUR_PID" ]]; then
        kill "$CUR_PID" 2>/dev/null || true
        wait "$CUR_PID" 2>/dev/null || true
    fi
    CUR_PID=''
    CUR_MP=''
}
cleanup() {
    finish_mount || true
    if [[ "${COMPARE_KEEP:-0}" == 1 ]]; then
        echo "Kept $WORKDIR" >&2
    else
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export ROOT RUST_BIN WORKDIR MICRO LARGE_MIB CSV_OUT MD_OUT PREPARE_ONLY
# Python supplies portable timers, deterministic bytes, CSV quoting and reporting;
# FUSE lifecycle stays with the shared env.sh helpers above.
cat > "$WORKDIR/sweep.py" <<'PY'
import csv
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import struct
import subprocess
import sys
import tarfile
import time
import zipfile

W = Path(os.environ['WORKDIR'])
CORPUS = W / 'corpus'
MIB = 1048576
STAMP = 1792108800
N = 100 if os.environ['MICRO'] == '1' else 1000
LARGE = int(os.environ['LARGE_MIB'])
BIN = os.environ['RUST_BIN']
FIELDS = 'date host version git_rev load1 fixture format size_bytes metric value unit status note'.split()
FIXTURES = [
    ('corpus.tar', 'tar'), ('corpus.tar.gz', 'tar.gz'),
    ('corpus.tar.bz2', 'tar.bz2'), ('corpus.tar.xz', 'tar.xz'),
    ('corpus.tar.zst', 'tar.zst'), ('corpus.tar.lz4', 'tar.lz4'),
    ('corpus.zip', 'zip-deflate'), ('corpus-store.zip', 'zip-store'),
    ('corpus.cpio', 'cpio'), ('corpus.ar', 'ar'), ('corpus.iso', 'iso'),
    ('corpus.ext4', 'ext4'), ('corpus-mbr.img', 'mbr/ext4'),
    ('corpus.qcow2', 'qcow2/ext4'), ('model.safetensors', 'safetensors'),
    ('model.gguf', 'gguf'), ('nested.tar', 'nested-tar'), ('corpus.7z', '7z'),
    ('corpus.squashfs', 'squashfs'), ('corpus.fat', 'fat'), ('corpus.exfat', 'exfat'),
]


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs).stdout


def digest(path):
    with open(path, 'rb') as f:
        return hash_stream(f)


def hash_stream(f):
    h = hashlib.sha256()
    for chunk in iter(lambda: f.read(MIB), b''):
        h.update(chunk)
    return h.hexdigest()


def randbytes(rng, size):
    # Works with Python 3.8 as well as newer interpreters.
    return rng.getrandbits(size * 8).to_bytes(size, 'little')


def plan():
    return [65536] * 16 + [MIB] * 24 + [4 * MIB] * 6 + [7 * MIB, 8 * MIB]


def corpus():
    rng = random.Random(42017)
    CORPUS.mkdir()
    for i in range(N):
        path = CORPUS / f'd{i // (N // 10):02d}' / f'f{i:04d}.bin'
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(randbytes(rng, 4096) * 8)
    with (CORPUS / 'blob.bin').open('wb') as f:
        for _ in range(LARGE):
            f.write(randbytes(rng, MIB))
    for path in sorted(CORPUS.rglob('*')) + [CORPUS]:
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
        os.utime(path, (STAMP, STAMP))
    sizes = plan()
    offsets, offset = [], 0
    header = {'__metadata__': {'description': 'format sweep deterministic F16 bytes'}}
    for i, size in enumerate(sizes):
        offsets.append(offset)
        header[f'layer.{i}.weight'] = {'dtype': 'F16', 'shape': [size // 2],
                                     'data_offsets': [offset, offset + size]}
        offset += size
    raw = json.dumps(header, separators=(',', ':')).encode()
    raw += b' ' * (-len(raw) % 8)
    (W / 'safe-header').write_bytes(struct.pack('<Q', len(raw)) + raw)
    def string(value):
        b = value.encode()
        return struct.pack('<Q', len(b)) + b
    raw = b'GGUF' + struct.pack('<IQQ', 3, 48, 2)
    raw += string('general.architecture') + struct.pack('<I', 8) + string('llama')
    raw += string('general.alignment') + struct.pack('<II', 4, 32)
    for i, (size, off) in enumerate(zip(sizes, offsets)):
        raw += string(f'layer.{i}.weight') + struct.pack('<IQIQ', 1, size // 2, 1, off)
    raw += b'\0' * (-len(raw) % 32)
    (W / 'gguf-header').write_bytes(raw)
    rng = random.Random(717)
    with (W / 'tensor-data').open('wb') as data:
        for i, size in enumerate(sizes):
            chunk = randbytes(rng, size)
            data.write(chunk)
            if i == 47:
                (W / 'tensor-large.bin').write_bytes(chunk)
    return {'files': N, 'large_mib': LARGE, 'tree_bytes': N * 32768 + LARGE * MIB,
            'blob_sha256': digest(CORPUS / 'blob.bin'),
            'tensor_sha256': digest(W / 'tensor-large.bin')}


class Missing(Exception):
    pass


def tool(*names):
    for name in names:
        if shutil.which(name):
            return name
    raise Missing('missing ' + ' / '.join(names))


def tar(dest, cwd, names):
    cmd = tool('gtar', 'tar')
    if b'GNU tar' in run([cmd, '--version']):
        flags = ['--sort=name', f'--mtime=@{STAMP}', '--owner=0', '--group=0', '--numeric-owner']
    else:
        # Corpus mtimes are fixed already; bsdtar has no GNU --mtime/--sort.
        flags = ['--uid', '0', '--gid', '0', '--uname', 'root', '--gname', 'root']
    run([cmd, *flags, '-cf', dest, '-C', cwd, *names])


def need_fixture(name):
    if not (W / name).is_file():
        raise Missing('requires prepared ' + name)


def produce(name, meta):
    dest = W / name
    base = W / 'corpus.tar'
    files = sorted(p for p in CORPUS.rglob('*') if p.is_file())
    fs_mib = (meta['tree_bytes'] * 5 // 4 + 32 * MIB + MIB - 1) // MIB
    note = ''
    if name == 'corpus.tar':
        tar(dest, CORPUS, ['.'])
        note = 'tar; fixed mtime/owner'
    elif name in ('corpus.tar.gz', 'corpus.tar.bz2', 'corpus.tar.xz', 'corpus.tar.lz4'):
        need_fixture('corpus.tar')
        cmd, args = {
            'corpus.tar.gz': ('gzip', ['-n', '-1', '-c']),
            'corpus.tar.bz2': ('bzip2', ['-1', '-c']),
            'corpus.tar.xz': ('xz', ['-1', '-T0', '--block-size=4MiB', '-c']),
            'corpus.tar.lz4': ('lz4', ['-1', '-B7', '-c']),
        }[name]
        tool(cmd)
        with dest.open('wb') as out:
            subprocess.run([cmd, *args, str(base)], stdout=out, stderr=subprocess.PIPE, check=True)
        note = cmd + ' ' + ' '.join(args)
    elif name == 'corpus.tar.zst':
        need_fixture('corpus.tar')
        if os.path.isfile(BIN) and os.access(BIN, os.X_OK):
            try:
                run([BIN, '--repack-seekable', base, dest])
                note = 'ratarmount --repack-seekable (seek table)'
            except subprocess.CalledProcessError as e:
                print('zstd repack failed; trying independent frames: ' + error_text(e), file=sys.stderr)
        if not note:
            tool('zstd')
            # Same independent-frame helper as compare-python-vs-rust.sh. Also
            # append the standard seek-table footer (decompressed/compressed sizes).
            entries = []
            with base.open('rb') as src, dest.open('wb') as out:
                for chunk in iter(lambda: src.read(4 * MIB), b''):
                    encoded = run(['zstd', '-1', '-c'], input=chunk)
                    out.write(encoded)
                    entries.append((len(encoded), len(chunk)))
                table = b''.join(struct.pack('<II', *entry) for entry in entries)
                table += struct.pack('<IBI', len(entries), 0, 0x8F92EAB1)
                out.write(struct.pack('<II', 0x184D2A5E, len(table)) + table)
            note = 'zstd -1 concatenated independent 4 MiB frames + seek table (fallback)'
    elif name.endswith('.zip'):
        cmd = tool('zip')
        run([cmd, '-qr', '-X', *(['-0'] if name == 'corpus-store.zip' else []), dest, '.'], cwd=CORPUS)
        note = 'zip stored' if name == 'corpus-store.zip' else 'zip deflate'
    elif name == 'corpus.cpio':
        cmd = tool('cpio')
        listing = '\n'.join(p.relative_to(CORPUS).as_posix() for p in files) + '\n'
        reproducible = ['--reproducible', '--owner=0:0'] if b'GNU cpio' in run([cmd, '--version']) else []
        with dest.open('wb') as out:
            subprocess.run([cmd, '-o', '-H', 'newc', *reproducible], cwd=CORPUS, input=listing.encode(),
                           stdout=out, stderr=subprocess.PIPE, check=True)
        note = 'cpio newc'
    elif name == 'corpus.ar':
        run([tool('ar'), 'rc', dest, *files])
        note = 'ar rc; flat unique basenames'
    elif name == 'corpus.iso':
        cmd = tool('xorriso', 'genisoimage', 'mkisofs')
        run([cmd, *(['-as', 'mkisofs'] if cmd == 'xorriso' else []), '-R', '-o', dest, CORPUS])
        note = cmd + ' Rock Ridge'
    elif name in ('corpus.ext4', 'corpus-mbr.img'):
        cmd = tool('mkfs.ext4')
        offset = 0
        partitioner = ''
        if name.endswith('.img'):
            partitioner = tool('sfdisk', 'parted')
            offset = MIB
        with dest.open('wb') as out:
            out.truncate(fs_mib * MIB + offset)
        if partitioner == 'sfdisk':
            run(['sfdisk', dest], input=f'label: dos\nunit: sectors\n\nstart=2048, size={fs_mib * 2048}, type=83\n'.encode())
        elif partitioner:
            run(['parted', '-s', dest, 'mklabel', 'msdos', 'mkpart', 'primary', 'ext4', '1MiB', '100%'])
        run([cmd, '-q', '-F', '-b', '4096', '-d', CORPUS, '-E',
             'lazy_itable_init=0' + (f',offset={offset}' if offset else ''), dest, fs_mib * 256])
        note = f'mkfs.ext4 -d; {fs_mib} MiB' + (f'; {partitioner}; p1 at 1 MiB' if offset else '')
    elif name == 'corpus.qcow2':
        cmd = tool('qemu-img')
        need_fixture('corpus-mbr.img')
        run([cmd, 'convert', '-f', 'raw', '-O', 'qcow2', W / 'corpus-mbr.img', dest])
        note = 'qemu-img convert; p1/ext4'
    elif name in ('model.safetensors', 'model.gguf'):
        with dest.open('wb') as out:
            out.write((W / ('safe-header' if name.endswith('safetensors') else 'gguf-header')).read_bytes())
            with (W / 'tensor-data').open('rb') as data:
                shutil.copyfileobj(data, out)
        note = 'python3 stdlib; 48 F16 tensors; 64 MiB payload'
    elif name == 'nested.tar':
        need_fixture('corpus.zip')
        need_fixture('corpus.tar.gz')
        tar(dest, W, ['corpus.zip', 'corpus.tar.gz'])
        note = 'tar of zip + tar.gz; -r'
    elif name == 'corpus.7z':
        run([tool('7z', '7za', '7zz'), 'a', '-t7z', dest, '.'], cwd=CORPUS)
        note = '7z default compression'
    elif name == 'corpus.squashfs':
        run([tool('mksquashfs'), CORPUS, dest, '-noappend', '-all-root', '-mkfs-time', str(STAMP)])
        note = 'mksquashfs default compression'
    elif name == 'corpus.fat':
        tool('mformat')
        tool('mcopy')
        with dest.open('wb') as out:
            out.truncate(max(64, fs_mib) * MIB)
        run(['mformat', '-F', '-i', dest, '::'])
        run(['mcopy', '-s', '-i', dest, *sorted(CORPUS.iterdir()), '::/'])
        note = 'mtools FAT32'
    elif name == 'corpus.exfat':
        tool('mkfs.exfat')
        tool('guestfish')  # mcopy cannot populate exFAT; no privileged loop mount.
        need_fixture('corpus.tar')
        with dest.open('wb') as out:
            out.truncate(max(64, fs_mib) * MIB)
        run(['mkfs.exfat', dest])
        run(['guestfish', '--rw', '-a', dest, '-m', '/dev/sda', 'tar-in', base, '/'])
        note = 'mkfs.exfat + guestfish tar-in'
    assert dest.stat().st_size > 0, 'empty fixture'
    os.utime(dest, (STAMP, STAMP))
    return note


def verify(name, meta):
    path = W / name
    if name.startswith('corpus.tar') or name == 'nested.tar':
        if name.endswith(('.zst', '.lz4')):
            cmd = 'zstd' if name.endswith('.zst') else 'lz4'
            if not shutil.which(cmd):
                # The binary repack path does not require the zstd CLI.
                assert path.read_bytes()[:4] == b'\x28\xb5\x2f\xfd'
                assert path.read_bytes()[-4:] == struct.pack('<I', 0x8F92EAB1)
                return
            data = run([cmd, '-d', '-c', path])
            archive = tarfile.open(fileobj=io.BytesIO(data))
        else:
            archive = tarfile.open(path)
        with archive:
            members = [m for m in archive if m.isfile()]
            if name == 'nested.tar':
                assert sorted(m.name for m in members) == ['corpus.tar.gz', 'corpus.zip']
            else:
                assert len(members) == N + 1, 'tar member count'
                blob = next(m for m in members if m.name.lstrip('./') == 'blob.bin')
                assert hash_stream(archive.extractfile(blob)) == meta['blob_sha256'], 'tar blob checksum'
    elif name.endswith('.zip'):
        with zipfile.ZipFile(path) as z:
            assert len([f for f in z.infolist() if not f.is_dir()]) == N + 1
            assert z.testzip() is None
            assert hashlib.sha256(z.read('blob.bin')).hexdigest() == meta['blob_sha256']
    elif name == 'corpus.cpio':
        listing = run(['cpio', '-it'], input=path.read_bytes()).decode().splitlines()
        assert len(listing) == N + 1, 'cpio member count'
    elif name == 'corpus.ar':
        assert len(run(['ar', 't', path]).splitlines()) == N + 1, 'ar member count'
        assert hashlib.sha256(run(['ar', 'p', path, 'blob.bin'])).hexdigest() == meta['blob_sha256']
    elif name in ('corpus.ext4', 'corpus-mbr.img'):
        offset = MIB if name.endswith('.img') else 0
        with path.open('rb') as f:
            if offset:
                f.seek(446 + 8)
                assert struct.unpack('<I', f.read(4))[0] == 2048, 'MBR p1 offset'
                f.seek(510)
                assert f.read(2) == b'\x55\xaa'
            f.seek(offset + 1024 + 56)
            assert f.read(2) == b'\x53\xef', 'ext4 superblock'
    elif name == 'corpus.qcow2':
        info = json.loads(run(['qemu-img', 'info', '--output=json', path]))
        assert info['format'] == 'qcow2'
        run(['qemu-img', 'check', path])
    elif name in ('model.safetensors', 'model.gguf'):
        verify_model(path, meta)
    elif name == 'corpus.iso':
        with path.open('rb') as f:
            f.seek(32769)
            assert f.read(5) == b'CD001', 'ISO descriptor'
    elif name == 'corpus.7z':
        run([tool('7z', '7za', '7zz'), 't', path])
    elif name == 'corpus.squashfs':
        assert path.open('rb').read(4) == b'hsqs', 'SquashFS superblock'
    elif name == 'corpus.fat':
        assert b'blob' in run(['mdir', '-i', path, '::/']).lower()
    elif name == 'corpus.exfat':
        assert path.open('rb').read(11)[3:] == b'EXFAT   ', 'exFAT boot sector'


def verify_model(path, meta):
    # Independently decode both headers, contiguous offsets, dimensions and payload.
    with path.open('rb') as f:
        if path.suffix == '.safetensors':
            header = json.loads(f.read(struct.unpack('<Q', f.read(8))[0]))
            start = f.tell()
            assert '__metadata__' in header
            infos = [(header[f'layer.{i}.weight']['shape'][0] * 2,
                      header[f'layer.{i}.weight']['data_offsets']) for i in range(48)]
            assert all(v['dtype'] == 'F16' for k, v in header.items() if k != '__metadata__')
        else:
            def unpack(fmt):
                return struct.unpack(fmt, f.read(struct.calcsize(fmt)))
            def string():
                return f.read(unpack('<Q')[0]).decode()
            assert f.read(4) == b'GGUF'
            assert unpack('<IQQ') == (3, 48, 2)
            assert string() == 'general.architecture' and unpack('<I') == (8,)
            assert string() == 'llama'
            assert string() == 'general.alignment' and unpack('<II') == (4, 32)
            infos = []
            for i in range(48):
                assert string() == f'layer.{i}.weight'
                ndim, dim, dtype, offset = unpack('<IQIQ')
                assert (ndim, dtype, offset % 32) == (1, 1, 0)
                infos.append((dim * 2, [offset, offset + dim * 2]))
            start = (f.tell() + 31) // 32 * 32
        offset = 0
        for (size, bounds), expected in zip(infos, plan()):
            assert size == expected and bounds == [offset, offset + size], 'tensor layout'
            offset += size
        assert path.stat().st_size == start + offset, 'tensor data length'
        f.seek(start + infos[47][1][0])
        assert hashlib.sha256(f.read(infos[47][0])).hexdigest() == meta['tensor_sha256']


def error_text(exc):
    if isinstance(exc, subprocess.CalledProcessError):
        return (exc.stderr or b'').decode(errors='replace')[-4000:].strip() or str(exc)
    return str(exc) or type(exc).__name__


def load():
    return json.loads((W / 'manifest.json').read_text())


def record(fixture, metric, value='', unit='', status='ok', note=''):
    meta = load()
    row = next(r for r in meta['fixtures'] if r['fixture'] == fixture)
    with (W / 'results.csv').open('a', newline='') as f:
        writer = csv.DictWriter(f, FIELDS)
        writer.writerow({**{k: meta[k] for k in FIELDS[:5]},
                         **{k: row[k] for k in ('fixture', 'format', 'size_bytes')},
                         'metric': metric, 'value': value, 'unit': unit, 'status': status,
                         'note': '; '.join(s for s in (row['note'], note) if s)})


def prepare():
    meta = corpus()
    meta.update(date=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
                host=platform.node(), version='not used (prepare only)',
                git_rev=run(['git', '-C', os.environ['ROOT'], 'rev-parse', 'HEAD']).decode().strip(),
                load1=os.getloadavg()[0], fixtures=[])
    if os.environ['PREPARE_ONLY'] != '1':
        meta['version'] = run([BIN, '--version']).decode().strip()
    cpuinfo = Path('/proc/cpuinfo')
    meminfo = Path('/proc/meminfo')
    meta['cpu'] = next((s.split(':', 1)[1].strip() for s in cpuinfo.read_text().splitlines()
                        if s.startswith('model name')), platform.machine()) if cpuinfo.exists() else platform.processor()
    meta['ram'] = meminfo.read_text().splitlines()[0] if meminfo.exists() else 'RAM unavailable (/proc absent)'
    for name, fmt in FIXTURES:
        status, note, size = 'ok', '', ''
        print('Preparing ' + name, file=sys.stderr, flush=True)
        try:
            note = produce(name, meta)
            verify(name, meta)
            size = (W / name).stat().st_size
        except Missing as e:
            status, note = 'skip', str(e)
        except Exception as e:
            status, note = 'error', error_text(e)
        meta['fixtures'].append(dict(fixture=name, format=fmt, status=status, note=note, size_bytes=size))
        label = {'ok': 'OK', 'skip': 'SKIP', 'error': 'ERROR'}[status]
        print(f'PREPARE_{label} {name} {note}', file=sys.stderr, flush=True)
    meta['load1'] = os.getloadavg()[0]
    (W / 'manifest.json').write_text(json.dumps(meta, indent=2))
    with (W / 'results.csv').open('w', newline='') as f:
        csv.writer(f).writerow(FIELDS)
    for r in meta['fixtures']:
        record(r['fixture'], 'fixture', status=r['status'])
    if any(r['status'] == 'error' for r in meta['fixtures']):
        return 1
    print('PREPARE_OK all expected fixtures', file=sys.stderr)
    return 0


def index(name):
    cmd = [BIN, '-f', '--no-mount', '-c', '--index-file', str(W / (name + '.index.sqlite')),
           '--index-minimum-file-count', '0']
    if name == 'nested.tar':
        cmd += ['-r']
    cmd.append(str(W / name))
    start = time.perf_counter()
    try:
        run(cmd)
        record(name, 'index_cold_s', time.perf_counter() - start, 's')
    except Exception as e:
        record(name, 'index_cold_s', status='error', note=error_text(e))
        print('Index error ' + name + ': ' + error_text(e), file=sys.stderr)
        return 1
    return 0


def mounted_files(mp):
    result = []
    def fail(exc):
        raise exc
    for root, dirs, files in os.walk(mp, onerror=fail):
        # The control namespace is synthetic and not part of fixture membership.
        dirs[:] = sorted(d for d in dirs if d != '.ratarmount-control')
        result += [Path(root) / f for f in sorted(files) if (Path(root) / f).is_file()]
    return result


def metrics(name, mp):
    try:
        meta = load()
        files = mounted_files(mp)
        model = name.startswith('model.')
        expected = 98 if name.endswith('safetensors') else 97 if model else (N + 1) * (2 if name == 'nested.tar' else 1)
        if len(files) != expected:
            record(name, 'members', len(files), 'files', 'error', f'expected {expected} regular files')
            return 1
        record(name, 'members', len(files), 'files')
        prefix = 'p1/' if name in ('corpus-mbr.img', 'corpus.qcow2') else 'corpus.zip/' if name == 'nested.tar' else ''
        blob = Path(mp) / prefix / ('layer/47/weight' if model else 'blob.bin')
        if not blob.is_file():
            # ISO 9660 without Rock Ridge names shows upper-case 8.3 names (BLOB.BIN):
            # resolve the member case-insensitively and record that in the CSV note.
            wanted = str(blob.relative_to(mp)).lower()
            folded = {str(f.relative_to(mp)).lower(): f for f in files}
            if wanted in folded:
                blob = folded[wanted]
                record(name, 'member_names', 1, 'case-folded', note='member resolved case-insensitively: ' + str(blob.relative_to(mp)))
        if model:
            candidates = [p for p in files if p.name == 'weight' and p.stat().st_size == 65536]
            wanted_sha = meta['tensor_sha256']
        else:
            candidates = [p for p in files if p.stat().st_size == 32768 and
                          (name != 'nested.tar' or p.relative_to(mp).parts[0] == 'corpus.zip')]
            wanted_sha = meta['blob_sha256']
        assert len(candidates) == (16 if model else N), 'random cat candidate count'
        assert blob.is_file(), 'missing bandwidth member ' + str(blob)
        rng = random.Random(20261016)
        timings = []
        for _ in range(15):
            path = rng.choice(candidates)
            start = time.perf_counter()
            subprocess.run(['cat', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
            timings.append((time.perf_counter() - start) * 1000)
        record(name, 'rand_cat_ms', statistics.median(timings), 'ms')
        size = blob.stat().st_size
        assert size >= 65536, 'bandwidth member too small'
        timings = []
        fd = os.open(blob, os.O_RDONLY)
        try:
            for _ in range(15):
                offset = rng.randrange(size - 65536 + 1)
                start = time.perf_counter()
                data = os.pread(fd, 65536, offset)
                timings.append((time.perf_counter() - start) * 1000)
                assert len(data) == 65536, 'short 64 KiB pread'
        finally:
            os.close(fd)
        record(name, 'rand_pread_64k_ms', statistics.median(timings), 'ms')
        rates = []
        for _ in range(3):
            start = time.perf_counter()
            subprocess.run(['cat', str(blob)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
            rates.append(size / MIB / (time.perf_counter() - start))
        assert digest(blob) == wanted_sha, 'SHA-256 mismatch for bandwidth member'
        record(name, 'seq_mib_s', statistics.median(rates), 'MiB/s')
        record(name, 'verify_sha256', status='ok', note='bandwidth member SHA-256 matches source')
        start = time.perf_counter()
        subprocess.run(['find', str(mp)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        record(name, 'find_ms', (time.perf_counter() - start) * 1000, 'ms')
    except Exception as e:
        record(name, 'reads', status='error', note=error_text(e))
        print('Read error ' + name + ': ' + error_text(e), file=sys.stderr)
        return 1
    return 0


def mount_record(name, phase, start, end, pid):
    record(name, 'mount_' + phase + '_s', float(end) - float(start), 's')
    status = Path('/proc') / pid / 'status'
    rss = next((s.split()[1] for s in status.read_text().splitlines() if s.startswith('VmHWM:')), None) if status.exists() else None
    record(name, 'mount_' + phase + '_rss_kib', rss or '', 'KiB', 'ok' if rss else 'skip',
           '' if rss else 'VmHWM unavailable on this platform')


def report():
    meta = load()
    rows = list(csv.DictReader((W / 'results.csv').open()))
    after = os.getloadavg()[0]
    meta['load1_after'] = after
    (W / 'manifest.json').write_text(json.dumps(meta, indent=2))
    def escape(s):
        return str(s).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
    def value(name, metric, kind):
        r = next((r for r in rows if r['fixture'] == name and r['metric'] == metric and r['status'] == 'ok'), None)
        if not r or r['value'] == '':
            return '—'
        n = float(r['value'])
        return f'{n / MIB:.1f} MiB' if kind == 'size' else f'{n / 1024:.1f}' if kind == 'rss' else f'{n:.3f}' if kind == 's' else f'{n:.1f}' if kind == 'ms' else f'{n:.0f}'
    table = ['| Format (fixture) | Size | Cold index (s) | Cold mount (s) | Warm mount (s) | Peak RSS warm (MiB) | Random cat (ms) | 64 KiB pread (ms) | Sequential (MiB/s) | Find (ms) |',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for r in meta['fixtures']:
        name = r['fixture']
        size = f"{int(r['size_bytes']) / MIB:.1f} MiB" if r['size_bytes'] != '' else '—'
        vals = [value(name, m, k) for m, k in [('index_cold_s', 's'), ('mount_cold_s', 's'), ('mount_warm_s', 's'),
                ('mount_warm_rss_kib', 'rss'), ('rand_cat_ms', 'ms'), ('rand_pread_64k_ms', 'ms'), ('seq_mib_s', 'rate'), ('find_ms', 'ms')]]
        table.append('| ' + ' | '.join([f"{r['format']} (`{name}`)", size, *vals]) + ' |')
    lines = ['# Rust format sweep', '', f"Date: {meta['date']} · Host: {meta['host']}", '',
             f"Binary: {escape(meta['version'])} · Git: `{meta['git_rev']}`", '',
             f"CPU: {escape(meta['cpu'])} · RAM: {meta['ram']}", '',
             f"One-minute load before/after: {meta['load1']:.2f} / {after:.2f}", '',
             f"Corpus: {N} × 32 KiB files in 10 folders + {LARGE} MiB seeded incompressible blob; fixed mtime {STAMP}. Models: 48 tensors, 64 MiB F16 bytes.", '',
             '## Overview', '', *table, '', '## Skipped / errors', '',
             '| Fixture | Metric | Status | Reason / producer |', '|---|---|---|---|']
    problems = [r for r in rows if r['status'] != 'ok']
    lines += ['| ' + ' | '.join(escape(r[k]) for k in ('fixture', 'metric', 'status', 'note')) + ' |' for r in problems]
    if not problems:
        lines.append('| — | — | — | None |')
    lines += ['', '## Methodology and caveats', '',
              '- Rust binary only. Each cold index uses `-f --no-mount -c --index-file … --index-minimum-file-count 0`; cold/warm foreground mounts rebuild/reuse the same index. Nested TAR uses `-r`.',
              '- Cold means index recreation, not a flushed OS page cache. One cold index and one cold/warm mount per fixture. Mount readiness includes polling and a successful directory listing; VmHWM is sampled immediately after readiness (unavailable values are skips).',
              '- Read metrics run on the warm mount: seeded random cat, median of 15 (32 KiB members, 64 KiB tensors for models); 15 exact 64 KiB os.pread calls on one open bandwidth member; median of 3 full cat bandwidth samples. Find is one walk after reads. SHA-256 verifies the bandwidth member after sequential reads.',
              '- Regular-file membership is checked before reads: corpus count + blob; twice that for nested ZIP+tar.gz; models include 48 tensor JSON sidecars, metadata JSON, and safetensors raw-header JSON (98/97 files). Filesystem bookkeeping directories do not add regular members.',
              '- Model bandwidth uses layer/47/weight (8 MiB), nested bandwidth uses corpus.zip/blob.bin, partition images use p1/blob.bin. Producer details are in CSV notes. Missing producer tools are skips; producer/daemon/read/count/checksum failures are errors.',
              '- FUSE plus page cache is not disk speed. This is a single-host directional comparison; process startup and cached reads dominate small timings. Build profile, load, compression layout, temporary storage and fixture size matter. No Python ratarmount baseline is involved.', '']
    shutil.copyfile(W / 'results.csv', os.environ['CSV_OUT'])
    Path(os.environ['MD_OUT']).write_text('\n'.join(lines))
    print('\n'.join(table))
    print(f"Results: {os.environ['CSV_OUT']} and {os.environ['MD_OUT']}", file=sys.stderr)
    return int(any(r['status'] == 'error' for r in rows))


if __name__ == '__main__':
    cmd, *args = sys.argv[1:]
    if cmd == 'prepare':
        sys.exit(prepare())
    elif cmd == 'list':
        print('\n'.join(r['fixture'] for r in load()['fixtures'] if r['status'] == 'ok'))
    elif cmd == 'index':
        sys.exit(index(*args))
    elif cmd == 'metrics':
        sys.exit(metrics(*args))
    elif cmd == 'mount-record':
        mount_record(*args)
    elif cmd == 'record':
        record(*args)
    elif cmd == 'report':
        sys.exit(report())
PY
py() { python3 "$WORKDIR/sweep.py" "$@"; }
clock_s() {
    if [[ -n "${EPOCHREALTIME:-}" ]]; then
        printf '%s\n' "$EPOCHREALTIME"
    else
        python3 -c 'import time; print(time.time())'
    fi
}
prepare_status=0
py prepare || prepare_status=$?
if [[ "$PREPARE_ONLY" == 1 ]]; then
    exit "$prepare_status"
fi
fuse_available=1
if [[ "${NO_FUSE:-0}" == 1 || ( "$(uname -s)" == Linux && ! -e /dev/fuse ) ]]; then
    fuse_available=0
    echo 'skip: FUSE unavailable' >&2
fi
while IFS= read -r fixture; do
    echo "Benchmarking $fixture" >&2
    # Always try the no-FUSE cold-index path, even when mounts are disabled.
    py index "$fixture" || true
    if [[ "$fuse_available" == 0 ]]; then
        py record "$fixture" mount '' '' skip 'FUSE unavailable'
        continue
    fi
    flags=(--index-file "$WORKDIR/$fixture.index.sqlite" --index-minimum-file-count 0)
    [[ "$fixture" != nested.tar ]] || flags+=(-r)
    for phase in cold warm; do
        CUR_MP="$(mktemp -d "$WORKDIR/mnt.XXXXXX")"
        log="$WORKDIR/$fixture.$phase.log"
        mount_flags=("${flags[@]}")
        [[ "$phase" != cold ]] || mount_flags+=(-c)
        start="$(clock_s)"
        "$RUST_BIN" -f "${mount_flags[@]}" "$WORKDIR/$fixture" "$CUR_MP" >"$log" 2>&1 &
        CUR_PID=$!
        ready=0
        # 120 s by default: compressed/recursive formats may take more than 10 s.
        for ((attempt=0; attempt<${MOUNT_ATTEMPTS:-2400}; attempt++)); do
            if ! kill -0 "$CUR_PID" 2>/dev/null; then break; fi
            if ratar_is_mounted "$CUR_MP" && ls -A "$CUR_MP" >/dev/null 2>&1; then
                ready=1
                break
            fi
            sleep 0.05
        done
        if [[ "$ready" == 0 ]]; then
            note="mount failed or timed out: $(tail -c 4000 "$log")"
            echo "$fixture $phase: $note" >&2
            py record "$fixture" "mount_${phase}_s" '' s error "$note"
            finish_mount
            continue
        fi
        end="$(clock_s)"
        py mount-record "$fixture" "$phase" "$start" "$end" "$CUR_PID"
        if [[ "$phase" == warm ]]; then
            py metrics "$fixture" "$CUR_MP" || true
        fi
        finish_mount
    done
done < <(py list)
py report
