#!/usr/bin/env bash
# Non-gating FUSE benchmark for #328: N small-file creates then N unlinks in a
# write overlay, against plain-directory baselines (tmpfs and the bench
# filesystem). RATARMOUNT=/path/to/release/ratarmount N=50 REPS=3
# VARIANTS=comma,separated,names (default: all). TMPDIR picks the filesystem of
# the disk overlay and the disk baseline. `--self-test` needs no binary or FUSE.
set -euo pipefail
exec python3 -I - "$@" <<'PY'
import io
import os
import pathlib
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time

# name -> (overlay kind, extra arguments). Kinds: None is a plain directory
# baseline, 'disk' is `-w DIR`, 'tmpfs' is `--overlay-tmpfs`. The rules variants
# protect everything but `work/`, as a sandbox does; the workload runs in `work/`.
RULES = ['--overlay-readonly', '**', '--overlay-allow', 'work/**']
# `--overlay-durability=relaxed` (#328): the overlay database skips its fsyncs.
RELAXED = ['--overlay-durability=relaxed']
VARIANTS = {
    'baseline-tmpfs': (None, []),
    'baseline-disk': (None, []),
    'disk': ('disk', []),
    'disk-journal': ('disk', ['journal']),
    'disk-rules': ('disk', RULES),
    'disk-relaxed': ('disk', RELAXED),
    'disk-relaxed-rules': ('disk', RELAXED + RULES),
    'tmpfs': ('tmpfs', []),
    'tmpfs-journal': ('tmpfs', ['journal']),
    'tmpfs-rules': ('tmpfs', RULES),
}


def command(binary, kind, extra, root, archive, mount, tag):
    cmd = [str(binary), '-f', '--passthrough', 'off']
    if kind == 'disk':
        cmd += ['-w', str(root / f'overlay-{tag}')]
    elif kind == 'tmpfs':
        cmd += ['--overlay-tmpfs']
    else:
        raise ValueError(kind)
    for arg in extra:
        if arg == 'journal':
            cmd += ['--journal', str(root / f'journal-{tag}.jsonl')]
        else:
            cmd.append(arg)
    return cmd + [str(archive), str(mount)]


def workload(directory, n):
    # Returns (create seconds, unlink seconds). Each create is open(O_CREAT),
    # a 32-byte write and close, as `echo x > f` does; unlinks follow.
    payload = b'x' * 31 + b'\n'
    start = time.perf_counter()
    for i in range(n):
        fd = os.open(directory / f'f{i}.txt', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
    middle = time.perf_counter()
    for i in range(n):
        os.unlink(directory / f'f{i}.txt')
    end = time.perf_counter()
    return middle - start, end - middle


def summary(name, n, reps):
    # reps: list of (create, unlink) seconds; medians per phase in ms/op.
    create = statistics.median(c for c, _ in reps) * 1000 / n
    unlink = statistics.median(u for _, u in reps) * 1000 / n
    total = statistics.median(c + u for c, u in reps)
    return f'{name:15} create_ms_per_op={create:8.3f} unlink_ms_per_op={unlink:8.3f} total_s={total:.4f}'


def unmount(mount):
    # A desktop indexer can briefly hold a fresh mount; retry before failing.
    for _ in range(50):
        if subprocess.run(['fusermount3', '-u', str(mount)], check=False,
                          stderr=subprocess.DEVNULL).returncode == 0:
            return
        time.sleep(.2)
    subprocess.run(['fusermount3', '-uz', str(mount)], check=False)


def fixture(path):
    with tarfile.open(path, 'w') as tar:
        for name in ('README', 'src/main.c', 'work/.keep'):
            payload = f'{name}\n'.encode()
            entry = tarfile.TarInfo(name)
            entry.size = len(payload)
            entry.mode = 0o644
            tar.addfile(entry, io.BytesIO(payload))


def selected(spec):
    names = list(VARIANTS) if not spec else [v for v in spec.split(',') if v]
    unknown = [v for v in names if v not in VARIANTS]
    if unknown:
        sys.exit(f'unknown VARIANTS {unknown}; choose from {list(VARIANTS)}')
    return names


if '--self-test' in sys.argv:
    root = pathlib.Path('/r')
    cmd = command('/b', 'disk', ['journal'] + RULES, root, root / 'a.tar', root / 'm', 'x')
    assert cmd == ['/b', '-f', '--passthrough', 'off', '-w', '/r/overlay-x', '--journal', '/r/journal-x.jsonl',
                   '--overlay-readonly', '**', '--overlay-allow', 'work/**', '/r/a.tar', '/r/m'], cmd
    assert command('/b', 'tmpfs', [], root, root / 'a.tar', root / 'm', 'y')[4] == '--overlay-tmpfs'
    relaxed = command('/b', *VARIANTS['disk-relaxed'], root, root / 'a.tar', root / 'm', 'z')
    assert relaxed[4:7] == ['-w', '/r/overlay-z', '--overlay-durability=relaxed'], relaxed
    assert selected('') == list(VARIANTS) and selected('disk,tmpfs') == ['disk', 'tmpfs']
    line = summary('disk', 2, [(0.002, 0.004), (0.004, 0.008), (0.1, 0.1)])
    assert 'create_ms_per_op=   2.000' in line and 'unlink_ms_per_op=   4.000' in line, line
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        c, u = workload(tmp, 5)
        assert c > 0 and u > 0 and not any(tmp.iterdir())
        fixture(tmp / 'base.tar')
        with tarfile.open(tmp / 'base.tar') as tar:
            assert tar.getnames() == ['README', 'src/main.c', 'work/.keep']
    print('overlay-create-unlink self-test: pass')
    sys.exit(0)

names = selected(os.environ.get('VARIANTS', ''))
needs_fuse = any(VARIANTS[v][0] for v in names)
if needs_fuse:
    if not shutil.which('fusermount3'):
        print('overlay-create-unlink: unavailable (skip: fusermount3 unavailable)')
        sys.exit(77)
    if not pathlib.Path('/dev/fuse').exists():
        print('overlay-create-unlink: unavailable (skip: /dev/fuse unavailable)')
        sys.exit(77)
    binary = pathlib.Path(os.environ.get('RATARMOUNT', 'target/release/ratarmount')).resolve()
    if not binary.is_file():
        sys.exit(f'build a release binary first or set RATARMOUNT: {binary}')
n = int(os.environ.get('N', '50'))
reps = int(os.environ.get('REPS', '3'))
if n < 1 or reps < 1:
    sys.exit('N and REPS must be at least 1')
shm = pathlib.Path('/dev/shm')
with tempfile.TemporaryDirectory(prefix='ratarmount-create-unlink-') as tmp:
    root = pathlib.Path(tmp)
    archive = root / 'base.tar'
    fixture(archive)
    fs = subprocess.run(['stat', '-f', '-c', '%T', str(root)], capture_output=True, text=True).stdout.strip()
    print(f'bench root {root} filesystem={fs} N={n} REPS={reps}', flush=True)
    for name in names:
        kind, extra = VARIANTS[name]
        results = []
        if kind is None:
            if name == 'baseline-tmpfs' and not shm.is_dir():
                print(f'{name:15} skip: /dev/shm unavailable')
                continue
            parent = shm if name == 'baseline-tmpfs' else root
            with tempfile.TemporaryDirectory(dir=parent, prefix='baseline-') as base:
                workload(pathlib.Path(base), n)  # warm-up
                for _ in range(reps):
                    results.append(workload(pathlib.Path(base), n))
            print(summary(name, n, results), flush=True)
            continue
        # One mount per variant: a warm-up round (discarded), then REPS rounds.
        mount = root / f'mnt-{name}'
        mount.mkdir()
        log = root / f'daemon-{name}.log'
        with open(log, 'wb') as err:
            child = subprocess.Popen(command(binary, kind, extra, root, archive, mount, name),
                                     stdout=subprocess.DEVNULL, stderr=err)
        try:
            deadline = time.monotonic() + 30
            while not (mount / 'README').exists():
                if child.poll() is not None or time.monotonic() > deadline:
                    tail = log.read_text(errors='replace')[-2000:]
                    raise RuntimeError(f'{name}: mount failed or timed out; daemon stderr:\n{tail}')
                time.sleep(.02)
            work = mount / 'work'
            workload(work, n)
            for _ in range(reps):
                results.append(workload(work, n))
        finally:
            unmount(mount)
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                raise
        if child.returncode:
            raise RuntimeError(f'{name}: mount exited {child.returncode}')
        print(summary(name, n, results), flush=True)
print('(medians of REPS rounds after one warm-up round; not a CI gate)')
PY
