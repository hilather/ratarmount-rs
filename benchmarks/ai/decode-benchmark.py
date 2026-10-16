"""Compare the same shard through Session, zstd CLI and cached/direct FUSE.

WORK_DIR retains fixture and daemon logs; NO_FUSE=1 still runs both baselines.
CACHE=warm|cold controls only the backing archive cache, never global drop_caches.
Each FUSE measurement uses a new mount (cold FUSE member page cache).
"""
import csv
import os
from pathlib import Path
import random
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time

FIELDS = ("path,parallelization,direct_io,read_size,cache,bytes,seconds,MB_per_s,"
          "CPU_percent,decode_path,frames_prefetched,frames_ready,frames_waited,"
          "synchronous_frames,decode_wait_ms,fuse_requests,fuse_max_request,"
          "fuse_service_ms").split(",")


def summary(text, marker):
    """Sum reader summaries, keeping the largest observed kernel request."""
    result = {}
    for line in text.splitlines():
        if marker not in line:
            continue
        for key, value in re.findall(r"(\w+)=([0-9]+(?:\.[0-9]+)?)", line.split(marker, 1)[1]):
            number = float(value) if "." in value else int(value)
            result[key] = max(result.get(key, 0), number) if key == "max_request" else result.get(key, 0) + number
    return result


def decode_fields(stats):
    return dict(decode_path="decode-ahead" if stats.get("prefetched", 0) else
                "synchronous" if stats.get("synchronous", 0) else "no-frame-reader",
                frames_prefetched=stats.get("prefetched", 0), frames_ready=stats.get("ready", 0),
                frames_waited=stats.get("waited", 0), synchronous_frames=stats.get("synchronous", 0),
                decode_wait_ms=round(stats.get("wait_ns", 0) / 1e6, 3))


def require_bytes(stats, expected):
    if stats.get("bytes") != expected:
        raise RuntimeError(f"missing or truncated read summary: expected {expected} bytes, got {stats}")


def fuse_cases(threads):
    return [(direct, caller, n) for direct in [0, 1]
            for caller in ["cat", "dd"] for n in dict.fromkeys([1, threads])]


def prepare_cache(archive, cache):
    with open(archive, "rb") as src:
        if cache == "warm":
            while src.read(1024 * 1024):
                pass
        elif hasattr(os, "posix_fadvise"):
            os.posix_fadvise(src.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)


def cpu(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def child_cpu():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def measurement(command, size, clock=child_cpu):
    before, start = clock(), time.monotonic()
    with open(os.devnull, "wb") as sink:
        subprocess.run(command, stdout=sink, check=True, timeout=300)
    elapsed, used = time.monotonic() - start, clock() - before
    return dict(bytes=size, seconds=round(elapsed, 6), MB_per_s=round(size / elapsed / 1e6, 3),
                CPU_percent=round(100 * used / elapsed, 1))


def run(work):
    size_mib, threads = int(os.getenv("SIZE_MIB", "1024")), int(os.getenv("THREADS", str(min(os.cpu_count() or 1, 4))))
    cache = os.getenv("CACHE", "cold")
    if size_mib <= 0 or threads <= 0 or cache not in ("cold", "warm"):
        raise ValueError("SIZE_MIB/THREADS must be positive; CACHE must be cold or warm")
    binary = str(Path("target/release/ratarmount").resolve())
    library = str(Path("target/release/examples/ai-zstd-read").resolve())
    archive, tar, member = work / "input.tar.zst", work / "input.tar", work / "member"
    if not archive.exists():
        rng = random.Random(42)
        with member.open("wb") as output:
            for _ in range(size_mib):
                block = rng.randbytes(512 * 1024)
                output.write(block)
                output.write(block)
        subprocess.run(["tar", "-cf", str(tar), "-C", str(work), "member"], check=True)
        subprocess.run([binary, "--repack-seekable", str(tar), str(archive), "--repack-frame-size", "1M"], check=True, stdout=sys.stderr)
        with archive.open("rb") as source:
            os.fsync(source.fileno())
    size = member.stat().st_size
    writer = csv.DictWriter(sys.stdout, FIELDS)
    writer.writeheader()

    def emit(row):
        writer.writerow(dict(cache=cache, **row))
        sys.stdout.flush()

    # Index creation and cache preparation are outside the Session timed read.
    for n in dict.fromkeys([1, threads]):
        output = subprocess.check_output([library, str(archive), "/member", str(n)],
                                         env=dict(os.environ, CACHE=cache), text=True)
        stats = summary(output, "session-read-summary")
        require_bytes(stats, size)
        emit(dict(path="session", parallelization=n, direct_io=0, read_size=131072,
                  **{key: stats[key] for key in ("bytes", "seconds", "MB_per_s", "CPU_percent")}, **decode_fields(stats)))
    if shutil.which("zstd"):
        prepare_cache(archive, cache)
        emit(dict(path="zstd-cli", parallelization=1, direct_io=0, decode_path="zstd-cli",
                  **measurement(["zstd", "-q", "-d", "-c", str(archive)], tar.stat().st_size)))
    else:
        print("skip: zstd CLI unavailable (Session baseline still ran)", file=sys.stderr)
    if os.getenv("NO_FUSE") == "1" or not Path("/dev/fuse").exists():
        print("skip: FUSE benchmarks disabled or /dev/fuse unavailable; baselines completed", file=sys.stderr)
        return
    for tool in ("fusermount3", "mountpoint", "cat", "dd"):
        if not shutil.which(tool):
            print(f"skip: FUSE benchmarks need {tool}; baselines completed", file=sys.stderr)
            return
    mount = work / "mnt"
    mount.mkdir(exist_ok=True)
    # cat exposes syscall round trips; dd's larger requests show whether the
    # negotiated 256-page limit helps. Fresh mount for every row, no hot re-read.
    for direct, caller, n in fuse_cases(threads):
        log_path = work / f"daemon-{direct}-{caller}-{n}.log"
        with log_path.open("w+") as log:
            flags = ["--direct-io"] if direct else []
            daemon = subprocess.Popen([binary, "-f", "-d", "2", "-P", str(n),
                                       "--readahead", os.getenv("READAHEAD", "16M"),
                                       "--passthrough", "off", *flags, str(archive), str(mount)],
                                      stdout=log, stderr=log, env=dict(os.environ, RUST_LOG="info"))
            try:
                deadline = time.monotonic() + 60
                while subprocess.run(["mountpoint", "-q", str(mount)]).returncode:
                    if daemon.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(f"mount failed: {log_path.read_text()}")
                    time.sleep(0.05)
                log.seek(0, 2)
                offset = log.tell()  # exclude cold-index frame readers
                prepare_cache(archive, cache)
                command = ["cat", str(mount / "member")] if caller == "cat" else [
                    "dd", f"if={mount / 'member'}", "bs=1M", "status=none"]
                row = measurement(command, size, lambda: cpu(daemon.pid))
                subprocess.run(["fusermount3", "-u", str(mount)], check=True)
                if daemon.wait(timeout=30):
                    raise RuntimeError(f"daemon failed: {log_path.read_text()}")
                log.seek(offset)
                output = log.read()
                frames = summary(output, "zstd-read-summary")
                if not frames:
                    raise RuntimeError(f"missing decoder counters in {log_path}")
                fuse = summary(output, "fuse-read-summary")
                emit(dict(path=f"fuse-{caller}", parallelization=n, direct_io=direct,
                          read_size=131072 if caller == "cat" else 1048576, **row, **decode_fields(frames),
                          fuse_requests=fuse.get("requests", 0), fuse_max_request=fuse.get("max_request", 0),
                          fuse_service_ms=round(fuse.get("service_ns", 0) / 1e6, 3)))
            finally:
                if daemon.poll() is None:
                    subprocess.run(["fusermount3", "-uz", str(mount)], check=False)
                    daemon.terminate()
                    try:
                        daemon.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait()

if __name__ == "__main__":
    if os.getenv("WORK_DIR"):
        directory = Path(os.environ["WORK_DIR"]).resolve()
        directory.mkdir(parents=True, exist_ok=True)
        run(directory)
    else:
        Path("target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="zstd-ahead-", dir=Path("target").resolve()) as directory:
            run(Path(directory))
