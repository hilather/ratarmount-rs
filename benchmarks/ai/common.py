"""Shared Local AI benchmark plumbing; no third-party Python dependencies."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REPO_URL = "https://github.com/madler/zlib.git"
REPO_COMMIT = "51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf"  # v1.3.1
MODEL_REPO = "hf-internal-testing/tiny-random-bert"
MODEL_REVISION = "f171d7baecaf37b5da5a3616d8833b9969753535"
FIELDS = "run_id,timestamp,host,platform,benchmark,case,status,seconds,value,unit,bytes,items,workers,cache,load1,binary,parameters,note".split(",")
ACTIVE_MOUNTS = set()


class Skip(Exception):
    """An unavailable prerequisite, never a failed measurement."""


def command(argv, *, cwd=None, env=None, timeout=300):
    return subprocess.run([str(x) for x in argv], cwd=cwd, env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout).stdout.strip()


def require(*names):
    missing = [n for n in names if shutil.which(n) is None]
    if missing:
        raise Skip("missing " + ", ".join(missing))


def binary():
    candidate = os.getenv("RATARMOUNT_BIN", str(ROOT / "target/release/ratarmount"))
    found = shutil.which(candidate)
    if found is None:
        raise Skip(f"missing ratarmount binary: {candidate}; build or set RATARMOUNT_BIN")
    return str(Path(found).resolve())


def fuse_available():
    if sys.platform.startswith("linux"):
        if not os.access("/dev/fuse", os.R_OK | os.W_OK):
            raise Skip("/dev/fuse missing or inaccessible")
        require("fusermount3" if shutil.which("fusermount3") else "fusermount")
    elif sys.platform == "darwin":
        runtimes = ["/Library/Filesystems/macfuse.fs", "/Library/Filesystems/fuse-t.fs",
                    "/Library/Application Support/fuse-t", "/usr/local/lib/libfuse-t.dylib",
                    "/opt/homebrew/lib/libfuse-t.dylib"]
        if not any(Path(path).exists() for path in runtimes):
            raise Skip("macFUSE/FUSE-T not detected")
        require("umount")
    else:
        raise Skip("FUSE benchmark requires Linux or macOS")


def parser(description):
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--runs", type=positive, default=1)
    p.add_argument("--output", type=Path, help="append CSV (default results/<host>-<UTC date>.csv)")
    p.add_argument("--keep", action="store_true", help="retain fixtures and logs under .cache")
    return p


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def load1():
    return round(os.getloadavg()[0], 2) if hasattr(os, "getloadavg") else ""


class Results:
    def __init__(self, name, args):
        self.name, self.args, self.rows = name, args, []
        self.run_id = uuid.uuid4().hex[:12]
        self.host = platform.node().replace("/", "_")
        self.output = args.output or HERE / "results" / f"{self.host}-{datetime.now(timezone.utc):%Y-%m-%d}.csv"
        self.binary = os.getenv("RATARMOUNT_BIN", str(ROOT / "target/release/ratarmount"))
        try:
            self.binary = f"{binary()} ({command([binary(), '--version'])})"
        except Skip:
            pass
        self.work = None

    def emit(self, case, status="ok", **values):
        row = dict.fromkeys(FIELDS, "")
        row.update(run_id=self.run_id, timestamp=datetime.now(timezone.utc).isoformat(),
                   host=self.host, platform=f"{platform.system()} {platform.release()} {platform.machine()}",
                   benchmark=self.name, case=case, status=status, load1=load1(), binary=self.binary,
                   parameters=json.dumps(vars(self.args), default=str, sort_keys=True), **values)
        self.output.parent.mkdir(parents=True, exist_ok=True)
        with self.output.open("a+", newline="") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            stream.seek(0)
            header = stream.readline().strip()
            if header and header != ",".join(FIELDS):
                raise ValueError(f"CSV schema mismatch: {self.output}")
            stream.seek(0, os.SEEK_END)
            writer = csv.DictWriter(stream, FIELDS)
            if not header:
                writer.writeheader()
            writer.writerow(row)
        self.rows.append(row)
        if status != "ok":
            print(f"{status}: {case}: {row['note']}", file=sys.stderr)

    def case(self, name, action):
        try:
            action()
        except Skip as error:
            self.emit(name, "skip", note=str(error))
        except Exception as error:
            detail = str(error)
            if isinstance(error, subprocess.CalledProcessError):
                detail += ": " + (error.stderr or "")[-2000:]
            self.emit(name, "error", note=detail)

    def timed(self, name, action, *, amount=1, unit="seconds", **metadata):
        start = time.perf_counter()
        result = action()
        seconds = time.perf_counter() - start
        value = seconds if unit == "seconds" else amount / seconds
        self.emit(name, seconds=round(seconds, 6), value=round(value, 6), unit=unit, **metadata)
        return result

    def table(self):
        print("| case | status | value | unit | note |\n|---|---|---:|---|---|")
        for row in self.rows:
            note = str(row["note"]).replace("|", "/").replace("\n", " ")
            print(f"| {row['case']} | {row['status']} | {row['value']} | {row['unit']} | {note} |")
        print(f"CSV: {self.output}")


def main(name, args, run):
    results = Results(name, args)
    (HERE / ".cache").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=name + "-", dir=HERE / ".cache"))
    results.work = work
    try:
        results.case("prepare", lambda: run(results, work))
    finally:
        ACTIVE_MOUNTS.update(mounted_paths(work))
        if args.keep or ACTIVE_MOUNTS:
            print(f"Retained: {work}", file=sys.stderr)
        else:
            shutil.rmtree(work)
        results.table()
    return int(any(r["status"] == "error" for r in results.rows))


def mounted_paths(root):
    """Find live mounts without descending into or deleting their contents."""
    found = []
    for directory, children, _ in os.walk(root, followlinks=False):
        for child in list(children):
            path = Path(directory) / child
            if os.path.ismount(path):
                found.append(path)
                children.remove(child)
    return found


def parallel(function, items, workers):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(function, items))


def tally(payloads):
    """Order-independent full-content fingerprint, component count and bytes."""
    count = size = digest = 0
    for data in payloads:
        count += 1
        size += len(data)
        digest += int.from_bytes(hashlib.sha256(data).digest(), "big")
    return count, size, digest


def combine(tallies):
    return tuple(sum(t[i] for t in tallies) for i in range(3))


def check_tally(actual, expected):
    if actual != expected:
        raise RuntimeError(f"short, duplicate or corrupt samples: {actual} != {expected}")


def fixture(directory, samples=128, sample_bytes=65536):
    directory.mkdir()
    rng = random.Random(42)
    for i in range(samples):
        (directory / f"{i:08d}.bin").write_bytes(rng.randbytes(sample_bytes))
        (directory / f"{i:08d}.json").write_text(json.dumps({"sample": i}) + "\n")
    return tally(p.read_bytes() for p in sorted(directory.iterdir()))


def shards(source, dest, *, codec="zstd", size="2M", no_index=False):
    argv = [binary(), "shard", source, "-o", dest, "--codec", codec, "--size", size,
            "--frame-per-sample"]
    if no_index:
        argv.append("--no-index")
    command(argv)
    manifest = json.loads((dest / "shards.json").read_text())
    paths = [dest / item["name"] for item in manifest["shards"]]
    if not paths:
        raise RuntimeError("fixture produced no shards")
    return paths


def git_env():
    # Ignore developer URL rewrites (e.g. HTTPS -> SSH), signing and hooks.
    return dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                GIT_TERMINAL_PROMPT="0")


def repo():
    require("git")
    cache = HERE / ".cache"
    cache.mkdir(exist_ok=True)
    dest = cache / "zlib"
    # Serialize initial clone and worktree bookkeeping between benchmark invocations.
    with (cache / "repo.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not dest.exists():
            if os.getenv("AI_OFFLINE") == "1":
                raise Skip("offline and pinned zlib repo is not cached")
            staging = Path(tempfile.mkdtemp(prefix="clone-", dir=cache))
            try:
                try:
                    command(["git", "clone", "--no-checkout", "--depth=1", "--branch", "v1.3.1",
                             REPO_URL, staging], env=git_env())
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                    raise Skip(f"cannot clone pinned public repo: {error}") from error
                command(["git", "-C", staging, "checkout", "--detach", REPO_COMMIT], env=git_env())
                staging.rename(dest)
            finally:
                if staging.exists():
                    shutil.rmtree(staging)
        actual = command(["git", "-C", dest, "rev-parse", "HEAD"], env=git_env())
        if actual != REPO_COMMIT:
            raise RuntimeError(f"cached repo has wrong commit: {actual}")
        if command(["git", "-C", dest, "status", "--porcelain"], env=git_env()):
            raise RuntimeError("cached repo is dirty; move .cache/zlib aside before benchmarking")
    return dest


@contextmanager
def worktree(repository, path):
    command(["git", "-C", repository, "worktree", "add", "--detach", path, REPO_COMMIT], env=git_env())
    try:
        yield path
    finally:
        command(["git", "-C", repository, "worktree", "remove", "--force", path], env=git_env())


def mount_options(args):
    return shlex.split(args.mount_options)


def add_mount_options(p):
    p.add_argument("--mount-options", default="", help="extra ratarmount flags, shell-split; use --mount-options='--direct-io --memory-budget 512M'")


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def unmount(path):
    if sys.platform == "darwin":
        command(["umount", path])
    else:
        tool = shutil.which("fusermount3") or shutil.which("fusermount")
        command([tool, "-u", path])
    if os.path.ismount(path):
        raise RuntimeError(f"unmount did not detach {path}")
    ACTIVE_MOUNTS.discard(path)


class Mount:
    def __init__(self, argv, path, *, env=None):
        self.argv, self.path, self.env = argv, path, env
        self.process = None
        self.log = None

    def __enter__(self):
        self.path.mkdir()
        self.log = self.path.with_suffix(".log").open("w+")
        self.process = subprocess.Popen([str(x) for x in self.argv] + [str(self.path)],
                                        stdout=self.log, stderr=self.log, env=self.env)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if os.path.ismount(self.path):
                ACTIVE_MOUNTS.add(self.path)
                return self
            if self.process.poll() is not None:
                break
            time.sleep(0.02)
        stop_process(self.process)
        # Handle a mount completing just as its deadline expires.
        if os.path.ismount(self.path):
            ACTIVE_MOUNTS.add(self.path)
            unmount(self.path)
        self.log.seek(0)
        detail = self.log.read()[-3000:]
        self.log.close()
        raise RuntimeError(f"mount failed: {self.argv}: {detail}")

    def __exit__(self, *_):
        try:
            unmount(self.path)
        finally:
            stop_process(self.process)
            self.log.close()


@contextmanager
def sandbox(work, repository, state_root=None):
    if not sys.platform.startswith("linux"):
        raise Skip("sandbox supervision requires Linux; run inside the Apple Linux VM")
    fuse_available()
    # Keep canonical per-attempt inspect.sock paths within sockaddr_un.sun_path.
    # HERE is on the fixture filesystem but shorter than .cache/<benchmark>-... .
    state_root = Path(state_root or HERE).resolve()
    state = Path(tempfile.mkdtemp(prefix=".s", dir=state_root))
    sock = state / "s"
    process = log = client = None
    try:
        inspection = state / "attempts" / "attempt-123456" / "inspect.sock"
        if len(os.fsencode(inspection)) >= 108:
            raise Skip("sandbox socket path too long; use --state-root on a shorter path on the same filesystem")
        log = (work / "sandbox.log").open("w")
        process = subprocess.Popen([binary(), "sandbox", "--socket", str(sock), "daemon",
                                   "--state-dir", str(state)], stdout=log, stderr=log)
        sys.path.insert(0, str(ROOT / "clients/python"))
        from ratarmount_sandbox import RatarmountSandbox
        client = RatarmountSandbox(sock)
        deadline = time.monotonic() + 30
        while not sock.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"sandbox daemon not ready; see {work / 'sandbox.log'}")
            time.sleep(0.02)
        client.create_base("bench", repository)
        yield client
    finally:
        try:
            if client is not None and process.poll() is None and sock.exists():
                client.destroy(base="bench")
                client.shutdown()
                process.wait(timeout=30)
        finally:
            if process is not None:
                stop_process(process)
            if log is not None:
                log.close()
            remaining = mounted_paths(state)
            if remaining:
                ACTIVE_MOUNTS.update(remaining)
                raise RuntimeError(f"sandbox left live mounts; retained {state}: {remaining}")
            shutil.rmtree(state)


def evict_files(paths):
    """Best-effort targeted eviction; never flush the shared host's page cache."""
    if not hasattr(os, "posix_fadvise"):
        return "new-process; OS cache uncontrolled"
    for path in paths:
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
            os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
    return "new-process; fadvise DONTNEED (advisory)"


def rss_kib(pid, proc=Path("/proc")):
    for line in (proc / str(pid) / "status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise RuntimeError(f"VmRSS absent for live mount pid {pid}")


def tensor_bytes(path):
    """Read every safetensors payload byte, checking non-overlapping bounds."""
    import struct
    with path.open("rb") as stream:
        size = path.stat().st_size
        prefix = stream.read(8)
        if len(prefix) != 8:
            raise ValueError("truncated safetensors header")
        length = struct.unpack("<Q", prefix)[0]
        if length > min(100 * 1024 * 1024, size - 8):
            raise ValueError("oversized safetensors header")
        header = json.loads(stream.read(length))
        base = 8 + length
        ranges = sorted(value["data_offsets"] for key, value in header.items() if key != "__metadata__")
        total, digest, previous = 0, hashlib.sha256(), 0
        for start, end in ranges:
            if not (previous <= start <= end <= size - base):
                raise ValueError("invalid tensor offsets")
            stream.seek(base + start)
            remaining = end - start
            while remaining:
                data = stream.read(min(remaining, 1024 * 1024))
                if not data:
                    raise ValueError("truncated tensor payload")
                digest.update(data)
                remaining -= len(data)
                total += len(data)
            previous = end
        if not ranges or not total:
            raise ValueError("model has no tensor bytes")
        return total, digest.hexdigest()
