#!/usr/bin/env bash
# Non-gating FUSE benchmark. RATARMOUNT=/path/to/release/ratarmount RUNS=6 JOBS=4.
set -euo pipefail
exec python3 - "$@" <<'PY'
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


def overhead(baseline, journal):
    return 100 * (statistics.median(journal) / statistics.median(baseline) - 1)


def paired_overhead(runs):
    # runs: (enabled, seconds) in execution order. One ratio per complete ABBA
    # block; the median ratio resists drift that unpaired medians absorb.
    ratios = []
    for i in range(0, len(runs) - len(runs) % 4, 4):
        block = runs[i:i + 4]
        base = sum(s for e, s in block if not e)
        journal = sum(s for e, s in block if e)
        ratios.append(journal / base)
    return 100 * (statistics.median(ratios) - 1) if ratios else None


def unmount(mount):
    # A desktop indexer can briefly hold a fresh mount; retry before failing.
    for _ in range(50):
        if subprocess.run(['fusermount3', '-u', str(mount)], check=False).returncode == 0:
            return
        time.sleep(.2)
    subprocess.run(['fusermount3', '-uz', str(mount)], check=False)


def order(run):
    # Run -1 is a discarded warm-up. Then ABBA pairs, so drift (page cache,
    # CPU clocks) hits both sides equally instead of always favoring the second.
    if run < 0:
        return 0
    return (run % 4) in (1, 2)


def fixture(path):
    files = {}
    for i in range(64):
        files[f'f{i}.c'] = f'int f{i}(void) {{ return {i}; }}\n'
    files['main.c'] = ''.join(f'int f{i}(void);\n' for i in range(64))
    files['main.c'] += 'int main(void) { return (' + '+'.join(f'f{i}()' for i in range(64)) + ') != 2016; }\n'
    files['Makefile'] = 'SOURCES := $(wildcard *.c)\nOBJECTS := $(SOURCES:.c=.o)\nCFLAGS := -O2\nall: fixture\nfixture: $(OBJECTS)\n\t$(CC) $(OBJECTS) -o $@\ncheck: fixture\n\t./fixture\nclean:\n\trm -f $(OBJECTS) fixture\n.PHONY: all check clean\n'
    with tarfile.open(path, 'w') as tar:
        for name, text in files.items():
            payload = text.encode()
            entry = tarfile.TarInfo(name)
            entry.size = len(payload)
            entry.mode = 0o644
            tar.addfile(entry, io.BytesIO(payload))


if '--self-test' in sys.argv:
    assert overhead([1, 2, 3], [2, 4, 6]) == 100
    assert round(paired_overhead([(0, 1), (1, 2), (1, 2), (0, 1), (0, 2), (1, 2), (1, 2), (0, 2), (0, 9)]), 6) == 50
    assert paired_overhead([(0, 1)]) is None
    assert [order(run) for run in range(-1, 8)] == [0, 0, 1, 1, 0, 0, 1, 1, 0]
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / 'base.tar'
        fixture(path)
        with tarfile.open(path) as tar:
            assert len(tar.getnames()) == 66
            assert b'./fixture' in tar.extractfile('Makefile').read()
    print('journal-overhead self-test: pass')
    sys.exit(0)

for tool in ('make', 'cc', 'fusermount3'):
    if not shutil.which(tool):
        print(f'overhead: unavailable (skip: {tool} unavailable)')
        sys.exit(77)
if not pathlib.Path('/dev/fuse').exists():
    print('overhead: unavailable (skip: /dev/fuse unavailable)')
    sys.exit(77)
binary = pathlib.Path(os.environ.get('RATARMOUNT', 'target/release/ratarmount')).resolve()
if not binary.is_file():
    sys.exit(f'build a release binary first or set RATARMOUNT: {binary}')
runs = int(os.environ.get('RUNS', '6'))
if runs < 2:
    sys.exit('RUNS must be at least 2')
times = [[], []]
sequence = []
with tempfile.TemporaryDirectory(prefix='ratarmount-journal-bench-') as tmp:
    root = pathlib.Path(tmp)
    archive = root / 'base.tar'
    fixture(archive)
    for run in range(-1, runs):
        enabled = int(order(run))
        mount = root / f'mnt-{run}'
        mount.mkdir()
        command = [str(binary), '-f', '--passthrough', 'off', '-w', str(root / f'overlay-{run}')]
        if enabled:
            command += ['--journal', str(root / f'trace-{run}.jsonl')]
        command += [str(archive), str(mount)]
        child = subprocess.Popen(command, stdout=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 30
            while not (mount / 'Makefile').exists():
                if child.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('mount failed or timed out')
                time.sleep(.02)
            start = time.monotonic()
            for _ in range(3):
                subprocess.run(['make', '-s', 'clean'], cwd=mount, check=True)
                subprocess.run(['make', '-s', '-j' + os.environ.get('JOBS', '4'), 'all', 'check'], cwd=mount, check=True)
            elapsed = time.monotonic() - start
            if run < 0:
                print(f'warm-up seconds={elapsed:.6f} (discarded)', flush=True)
            else:
                times[enabled].append(elapsed)
                sequence.append((enabled, elapsed))
                print(f'run={run + 1} journal={bool(enabled)} seconds={elapsed:.6f}', flush=True)
        finally:
            unmount(mount)
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                raise
        if child.returncode:
            raise RuntimeError(f'mount exited {child.returncode}')
paired = paired_overhead(sequence)
paired = 'n/a (RUNS < 4)' if paired is None else f'{paired:+.2f}%'
print(f'baseline_median={statistics.median(times[0]):.6f}s journal_median={statistics.median(times[1]):.6f}s overhead={overhead(*times):+.2f}% paired_abba_overhead={paired} (target <3%; not a CI gate; quote the paired figure)')
PY
