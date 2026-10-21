"""Checked SQLite opens in the extension module (#151).

`_native` installs ratarmount's SQLite system-call wrappers before it
publishes anything: by the load-time constructor when the process has one
thread, otherwise by the private-instance initializer. These tests import the
module in fresh interpreters (pytest has already imported it here).
"""
import importlib.util
import json
import subprocess
import sys
import tarfile
import io
from pathlib import Path

import pytest

import ratarmount_rs._native as native

CHILD = r"""
import json, sys, threading
stop = threading.Event()
worker = None
if sys.argv[1] == "thread":
    # A live worker before the import: the constructor must abstain.
    worker = threading.Thread(target=stop.wait)
    worker.start()
import ratarmount_rs
status = ratarmount_rs._native._checked_open_status()
with ratarmount_rs.open(sys.argv[2], index=sys.argv[3]) as archive:
    names = sorted(entry.path for entry in archive.ls("/"))
    data = archive.read("/hello.txt", 0, 5)
stop.set()
if worker is not None:
    worker.join()
print(json.dumps({"status": status, "names": names, "data": data.decode()}))
"""


def _tar(path):
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        payload = b"hello world"
        entry = tarfile.TarInfo("hello.txt")
        entry.size = len(payload)
        archive.addfile(entry, io.BytesIO(payload))
    return path


def _child(mode, tmp_path):
    tar = _tar(tmp_path / (mode + ".tar"))
    index = tmp_path / (mode + ".index.sqlite")
    result = subprocess.run(
        [sys.executable, "-I", "-c", CHILD, mode, str(tar), str(index)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
        cwd=str(tmp_path), timeout=120,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["names"] == ["/hello.txt"]
    assert report["data"] == "hello"
    assert index.is_file(), "the index was written through SQLite"
    return report["status"]


def _supported():
    status = native._checked_open_status()
    return status["status"] not in ("UnsupportedPlatform", "UnsupportedAbi")


def test_regression_native_thread_before_import(tmp_path):
    """Regression (#151): a worker thread alive before the import made the
    load-time constructor abstain, and nothing installed later: `_native` must
    take the private-instance path (`PrivateInstance`, constructor
    `AbstainedThreads`) and index/session work must still succeed. Without a
    thread the constructor installs (`SingleThread`)."""
    if not _supported():
        pytest.skip("skip: checked opens are not supported on this platform")
    threaded = _child("thread", tmp_path)
    assert threaded["installed"] is True, threaded
    assert threaded["why"] == "PrivateInstance", threaded
    assert threaded["constructor"].startswith("AbstainedThreads("), threaded
    assert threaded["constructor"] != "AbstainedThreads(Some(1))", threaded
    assert threaded["threads_at_install"] != 1, threaded

    single = _child("single", tmp_path)
    assert single["installed"] is True, single
    assert single["why"] == "SingleThread", single
    assert single["threads_at_install"] == 1, single
    assert single["constructor"] == "AttemptedSingleThread", single


def test_regression_native_status_exposes_no_installer():
    """Regression (#151): the status function reports the installation and
    the constructor observation; the module publishes no installer."""
    status = native._checked_open_status()
    assert set(status) == {
        "installed", "why", "threads_at_install", "status", "detail", "constructor",
    }
    if _supported():
        assert status["installed"] is True, status
    assert not [name for name in dir(native) if "install" in name.lower()]


def _audit_module():
    path = Path(__file__).resolve().parents[2] / "packaging" / "audit_native_exports.py"
    if not path.exists():
        pytest.skip("skip: packaging/audit_native_exports.py is not shipped in a wheel/sdist")
    spec = importlib.util.spec_from_file_location("audit_native_exports", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_regression_native_exports_are_private():
    """Regression (#151, design §4 "Symbol privacy"): the private-instance
    initializer is sound only if the module's SQLite is not exported. The
    audit must reject a deliberately exported non-`libversion` `sqlite3_*`
    symbol and an unexpected export (self-test, with real shared objects when
    a C compiler exists), and the installed `_native` must pass it."""
    audit = _audit_module()
    assert audit.self_test() == []
    if audit.shutil.which("nm") is None:
        pytest.skip("skip: nm is not installed")
    assert audit.audit(native.__file__) == []
