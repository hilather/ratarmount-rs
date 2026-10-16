"""Serve on box A, read on box B, or run the same path on loopback."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import random
import socket
import subprocess
import sys
import tarfile
import time

from common import (ACTIVE_MOUNTS, Skip, binary, command, evict_files, main, parser,
                    positive, require, stop_process)


def read_all(path):
    size, digest = 0, hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            size += len(data)
            digest.update(data)
    if size == 0:
        raise RuntimeError("empty throughput fixture")
    return size, digest.hexdigest()


def nfs_options(version, port):
    if version == "4":
        return f"vers=4.1,tcp,port={port},sec=sys,ro"
    return f"vers=3,tcp,nolock,port={port},mountport={port},ro"


def client_available():
    if not sys.platform.startswith("linux"):
        raise Skip("kernel NFS client harness requires Linux; run inside the Apple VM")
    require("mount.nfs", "mount", "umount")
    status = Path("/proc/self/status").read_text()
    caps = next(line.split()[1] for line in status.splitlines() if line.startswith("CapEff:"))
    if not int(caps, 16) & (1 << 21):
        raise Skip("kernel NFS mount requires CAP_SYS_ADMIN (use sudo outside sandbox)")


@contextmanager
def server(source, bind, port, version, work):
    log = (work / "nfs-server.log").open("w+")
    process = subprocess.Popen([binary(), "--nfs", "--nfs-vers", version,
                               "--nfs-bind", f"{bind}:{port}", str(source)], stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                log.seek(0)
                raise RuntimeError("NFS server exited: " + log.read()[-3000:])
            try:
                connection = socket.create_connection(("127.0.0.1" if bind == "0.0.0.0" else bind, port), timeout=0.1)
            except OSError:
                time.sleep(0.05)
                continue
            connection.close()
            yield process
            return
        raise RuntimeError("NFS server readiness timeout")
    finally:
        stop_process(process)
        log.close()


def client(r, work, expected=None):
    client_available()
    a = r.args
    mount = work / "nfs"
    mount.mkdir()
    try:
        command(["mount", "-t", "nfs", "-o", nfs_options(a.version, a.port), f"{a.host}:/", mount], timeout=40)
        if not os.path.ismount(mount):
            raise RuntimeError("NFS mount returned success without a mounted filesystem")
        ACTIVE_MOUNTS.add(mount)
        for n in range(a.runs):
            start = time.perf_counter()
            actual = read_all(mount / a.member)
            elapsed = time.perf_counter() - start
            if expected is not None and actual != expected:
                raise RuntimeError("NFS payload differs from local baseline")
            if a.sha256 and actual[1] != a.sha256:
                raise RuntimeError("NFS payload sha256 differs")
            r.emit("nfs-read", seconds=round(elapsed, 6), value=round(actual[0] / elapsed / 1e6, 3),
                   unit="MB/s", bytes=actual[0], cache="fresh client mount" if n == 0 else "same mount; warm client cache",
                   note=f"NFSv{a.version} TCP {a.host}:{a.port}; includes sha256; sha256={actual[1]}")
    finally:
        if os.path.ismount(mount):
            command(["umount", mount])
        if not os.path.ismount(mount):
            ACTIVE_MOUNTS.discard(mount)


def local(r, path):
    cache = evict_files([path])
    start = time.perf_counter()
    actual = read_all(path)
    elapsed = time.perf_counter() - start
    r.emit("local-copy-read", seconds=round(elapsed, 6), value=round(actual[0] / elapsed / 1e6, 3),
           unit="MB/s", bytes=actual[0], cache=cache, note="read + sha256; sha256=" + actual[1])
    return actual


def run(r, work):
    a = r.args
    if a.mode == "serve":
        if not a.source:
            raise ValueError("serve requires --source ARCHIVE_OR_DIRECTORY")
        with server(a.source.resolve(), a.bind, a.port, a.version, work) as process:
            interrupted = False
            try:
                print(f"Serving {a.source} on {a.bind}:{a.port}; Ctrl-C stops this server", flush=True)
                process.wait()
            except KeyboardInterrupt:
                interrupted = True
            if not interrupted and process.poll() not in (None, 0):
                raise RuntimeError(f"server exited {process.returncode}")
        r.emit("serve", note="server stopped")
    elif a.mode == "read":
        expected = local(r, a.local_file) if a.local_file else None
        r.case("nfs-read", lambda: client(r, work, expected))
    else:
        payload = work / "payload.bin"
        rng = random.Random(42)
        with payload.open("wb") as stream:
            for _ in range(a.mib):
                stream.write(rng.randbytes(1024 * 1024))
        expected = local(r, payload)
        archive = work / "fixture.tar"
        with tarfile.open(archive, "w") as tar:
            tar.add(payload, arcname="payload.bin")
        def loopback():
            client_available()
            with server(archive, "127.0.0.1", a.port, a.version, work):
                client(r, work, expected)
        r.case("nfs-read", loopback)


if __name__ == "__main__":
    p = parser(__doc__)
    p.add_argument("mode", choices=["serve", "read", "loopback"])
    p.add_argument("--source", type=Path)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--bind", default="127.0.0.1", help="server bind IP; use private ConnectX IP on box A")
    p.add_argument("--port", type=positive, default=20490)
    p.add_argument("--version", choices=["3", "4"], default="4", help="4 requires a binary built with nfsv4")
    p.add_argument("--member", default="payload.bin")
    p.add_argument("--mib", type=positive, default=16)
    p.add_argument("--sha256", help="expected member checksum from box A")
    p.add_argument("--local-file", type=Path, help="same member stored locally on box B for comparison")
    args = p.parse_args()
    if Path(args.member).is_absolute() or ".." in Path(args.member).parts:
        p.error("--member must stay within the export")
    sys.exit(main("two-box-nfs", args, run))
