"""Regression: Python mounts/publish must supervise children and keep secrets off argv."""
import gc
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import weakref

import pytest

import ratarmount_rs as ratar
from ratarmount_rs import _process, _publish


pytestmark = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="Unix CLI script fixtures")


@pytest.fixture
def fake_binary(tmp_path, monkeypatch):
    script = tmp_path / "ratarmount fake"
    record = tmp_path / "argv.jsonl"
    # Use this interpreter, not a shell; archive names remain literal argv entries.
    script.write_text(f"#!{sys.executable}\n" + r'''
import hashlib, json, os, pathlib, signal, stat, sys, time
args = sys.argv[1:]
row = {"argv": args, "pid": os.getpid(), "HF_TOKEN": os.environ.get("HF_TOKEN"),
       "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY")}
if "--password-file" in args:
    password_path = pathlib.Path(args[args.index("--password-file") + 1])
    row["password"] = password_path.read_text().rstrip("\n")
    row["password_mode"] = stat.S_IMODE(password_path.stat().st_mode)
with open(os.environ["FAKE_RECORD"], "a") as out:
    out.write(json.dumps(row) + "\n")
if "--unmount" in args:
    if os.environ.get("FAKE_UNMOUNT_FAIL"):
        sys.exit(4)
    (pathlib.Path(args[-1]) / ".fake-mounted").unlink(missing_ok=True)
    sys.exit(0)
if "--publish-index" in args or any(a.startswith("--publish-index-to=") for a in args):
    if os.environ.get("FAKE_PUBLISH_FAIL"):
        print("secret-password", file=sys.stderr)
        sys.exit(7)
    if os.environ.get("FAKE_NO_POINTER"):
        sys.exit(0)
    source = args[-1]
    dest = next((a.split("=", 1)[1] for a in args if a.startswith("--publish-index-to=")), source + ".index.sqlite")
    if "://" in dest:
        if dest.startswith("hf://"):
            print("published index at Hub commit " + "b" * 40, file=sys.stderr)
            if "--create-pr" in args:
                print("pull request: https://hub.example/datasets/org/data/discussions/1", file=sys.stderr)
    else:
        dest = pathlib.Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = b"fake sqlite snapshot"
        dest.write_bytes(data)
        identity = hashlib.sha256(data).hexdigest()
        base = str(dest).removesuffix(".index.sqlite")
        pathlib.Path(base + ".index." + identity + ".sqlite").write_bytes(data)
        pathlib.Path(base + ".index.ptr").write_text(json.dumps({
            "schema": "ratarmount.index.pointer.v1", "index_id": identity, "etag_sha256": identity,
        }))
    sys.exit(0)
if os.environ.get("FAKE_MOUNT_FAIL"):
    print("secret-password", file=sys.stderr)
    sys.exit(3)
marker = pathlib.Path(args[-1]) / ".fake-mounted"
def stop(*unused):
    marker.unlink(missing_ok=True)
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
if os.environ.get("FAKE_MOUNT_HANG"):
    while True:
        time.sleep(.01)
if os.environ.get("FAKE_MOUNT_DELAY"):
    time.sleep(.15)
marker.touch()
while marker.exists():
    time.sleep(.01)
''')
    script.chmod(0o755)
    monkeypatch.setenv("RATARMOUNT_BIN", str(script))
    monkeypatch.setenv("FAKE_RECORD", str(record))
    monkeypatch.setenv("HF_TOKEN", "fake-default-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-default-key")
    monkeypatch.setattr(_process.os.path, "ismount", lambda path: (Path(path) / ".fake-mounted").exists())
    return script, record


def records(fake_binary):
    return [json.loads(line) for line in fake_binary[1].read_text().splitlines()]


def test_regression_mount_lifecycle_and_literal_union_argv(fake_binary, tmp_path, monkeypatch):
    monkeypatch.setenv("HF_TOKEN", "secret-token")
    monkeypatch.setenv("FAKE_MOUNT_DELAY", "1")
    sources = [tmp_path / "one ; $(touch injected).tar", "hf://datasets/org/data/a.tar"]
    with ratar.mount(
        sources, tmp_path / "mount point", write_overlay=tmp_path / "overlay",
        recursive=True, options="noatime", readonly_globs=[".git/**", "t/**"],
        quota="2G", uid=123, gid=456, passthrough="off", password="secret-password",
        parallelization=2, foreground=False,
    ) as mounted:
        assert isinstance(mounted, ratar.Mount)
        assert mounted.path == str(tmp_path / "mount point")
        assert mounted.alive
        with pytest.raises(subprocess.TimeoutExpired):
            mounted.wait(timeout=.01)
        row = records(fake_binary)[0]
        assert row["HF_TOKEN"] == "secret-token"
        assert row["password"] == "secret-password"
        assert row["password_mode"] == 0o600
        argv = row["argv"]
        assert "secret-password" not in repr(argv) and "secret-token" not in repr(argv)
        assert "--foreground" in argv
        assert "--fuse=noatime,uid=123,gid=456" in argv
        assert "--overlay-quota=2G" in argv
        assert "--overlay-readonly=.git/**" in argv
        assert argv[-3:] == [str(sources[0]), sources[1], mounted.path]
        assert not (tmp_path / "injected").exists()
        password_path = Path(argv[argv.index("--password-file") + 1])
        assert password_path.exists()
    assert not mounted.alive
    assert mounted.wait() == 0
    mounted.unmount()
    assert not password_path.exists()
    assert records(fake_binary)[1]["argv"] == ["--unmount", "--", mounted.path]


def test_regression_archive_mount_preserves_open_options_and_source_after_chdir(fake_binary, sample, tmp_path, monkeypatch):
    source, _ = sample
    monkeypatch.chdir(source.parent)
    with ratar.open(source.name, recursive=True, parallelization=3, password="secret-password") as archive:
        monkeypatch.chdir(tmp_path.parent)
        mounted = archive.mount(tmp_path / "mnt", overlay_tmpfs="16M", uid=0)
        archive.close()
        assert "password" not in archive._process_options
        assert mounted.alive
        mounted.unmount()
        argv = records(fake_binary)[0]["argv"]
        assert "--recursive" in argv and "--parallelization=3" in argv
        assert "--overlay-tmpfs=16M" in argv and "--fuse=uid=0" in argv
        assert argv[-2] == str(source)
        assert records(fake_binary)[0]["password"] == "secret-password"
        with pytest.raises(ValueError, match="closed"):
            archive.mount(tmp_path / "other")


def test_regression_mount_gc_unmounts_without_retaining_handle(fake_binary, tmp_path):
    mounted = ratar.mount("a.tar", tmp_path / "mnt")
    process = mounted._process
    reference = weakref.ref(mounted)
    del mounted
    gc.collect()
    assert reference() is None
    assert process.wait(timeout=5) == 0
    assert records(fake_binary)[-1]["argv"][0] == "--unmount"


def test_regression_local_colon_path_does_not_become_remote_url(fake_binary, sample, tmp_path, monkeypatch):
    nested = tmp_path / "http:" / "local.tar"
    nested.parent.mkdir()
    shutil.copyfile(sample[0], nested)
    monkeypatch.chdir(tmp_path)
    with ratar.open("./http://local.tar") as archive:
        monkeypatch.chdir(tmp_path.parent)
        with archive.mount(tmp_path / "mnt"):
            assert records(fake_binary)[0]["argv"][-2] == str(nested)
        result = archive.index.publish()
        assert result.pointer_url == str(nested) + ".index.ptr"


def test_regression_mount_detach_survives_gc(fake_binary, tmp_path):
    mounted = ratar.mount("a.tar", tmp_path / "mnt", detach=True)
    process, path = mounted._process, mounted.path
    del mounted
    gc.collect()
    try:
        assert process.poll() is None
        assert _process.os.path.ismount(path)
        assert len(records(fake_binary)) == 1
    finally:
        _process._unmount(str(fake_binary[0]), path, process, 5)


@pytest.mark.parametrize("detach", [False, True])
def test_regression_mount_interpreter_exit_cleanup(fake_binary, tmp_path, detach):
    path = tmp_path / "exit-mount"
    script = (
        "from pathlib import Path; import ratarmount_rs as r; "
        "from ratarmount_rs import _process; "
        "_process.os.path.ismount=lambda p: (Path(p)/'.fake-mounted').exists(); "
        f"m=r.mount('a.tar', {str(path)!r}, detach={detach!r})"
    )
    subprocess.run([sys.executable, "-c", script], check=True, timeout=15)
    try:
        assert (path / ".fake-mounted").exists() is detach
    finally:
        if detach:
            subprocess.run([str(fake_binary[0]), "--unmount", "--", str(path)], check=True)


@pytest.mark.parametrize("mode, exception", [("FAIL", ratar.RatarmountError), ("HANG", TimeoutError)])
def test_regression_failed_mount_reaps_child_and_password_file(fake_binary, tmp_path, monkeypatch, mode, exception):
    monkeypatch.setenv("FAKE_MOUNT_" + mode, "1")
    with pytest.raises(exception) as error:
        ratar.mount("a.tar", tmp_path / "mnt", password="secret-password", timeout=2)
    assert "secret-password" not in str(error.value)
    argv = records(fake_binary)[0]["argv"]
    assert not Path(argv[argv.index("--password-file") + 1]).exists()
    assert not (tmp_path / "mnt/.fake-mounted").exists()
    with pytest.raises(ChildProcessError):
        os.waitpid(records(fake_binary)[0]["pid"], os.WNOHANG)


def test_regression_failed_unmount_remains_retryable(fake_binary, tmp_path, monkeypatch):
    mounted = ratar.mount("a.tar", tmp_path / "mnt")
    monkeypatch.setenv("FAKE_UNMOUNT_FAIL", "1")
    try:
        with pytest.raises(ratar.RatarmountError, match="unmount failed"):
            mounted.unmount()
        assert mounted.alive
    finally:
        monkeypatch.delenv("FAKE_UNMOUNT_FAIL")
        mounted.unmount()


@pytest.mark.parametrize("source, kwargs", [
    ("https://user:secret@host/a.tar", {}),
    ("https://host/a.tar?token=secret", {}),
    ("restic:rest:http://user:secret@host/repo", {}),
    ("http://[secret-password", {}),
    ("a.tar", {"options": "password=secret"}),
    ("a.tar", {"token": "secret"}),
    ("a.tar", {"password": "line\nbreak"}),
    ("a.tar", {"write_overlay": "overlay", "overlay_tmpfs": True}),
    ([], {}), ("a.tar", {"timeout": float("nan")}),
    ("a.tar", {"uid": -1}), ("a.tar", {"quota": "2G"}),
    ("a.tar", {"passthrough": "bad"}),
])
def test_regression_unsafe_or_invalid_mount_arguments_never_spawn(fake_binary, tmp_path, source, kwargs):
    with pytest.raises((ValueError, TypeError)) as error:
        ratar.mount(source, tmp_path / "mnt", **kwargs)
    assert "secret" not in str(error.value)
    assert not fake_binary[1].exists()


def test_regression_mount_unsupported_platform_and_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(_process.sys, "platform", "win32")
    with pytest.raises(NotImplementedError):
        ratar.mount("a.tar", tmp_path / "mnt")
    monkeypatch.setattr(_process.sys, "platform", "linux")
    monkeypatch.setenv("RATARMOUNT_BIN", str(tmp_path / "missing"))
    with pytest.raises(FileNotFoundError, match="RATARMOUNT_BIN"):
        ratar.mount("a.tar", tmp_path / "mnt")


@pytest.mark.parametrize("destination", [None, "published.index.sqlite", "custom-name"])
def test_regression_publish_local_returns_pointer_and_immutable_blob(fake_binary, sample, tmp_path, destination):
    source, _ = sample
    target = None if destination is None else tmp_path / destination
    with ratar.open(source) as archive:
        result = archive.index.publish(target)
        assert archive.read("empty") == b""
    pointer = json.loads(Path(result.pointer_url).read_bytes())
    assert result.index_id == pointer["index_id"]
    assert hashlib.sha256(Path(result.blob_url).read_bytes()).hexdigest() == result.index_id
    assert result.urls == (result.pointer_url, result.blob_url)
    argv = records(fake_binary)[0]["argv"]
    private = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--index-file="))
    assert not Path(private).parent.exists()


@pytest.mark.parametrize("scheme", ["hf", "s3", "gs", "az"])
def test_regression_remote_publish_argv_env_and_pointer_identity(fake_binary, sample, monkeypatch, scheme):
    monkeypatch.setenv("HF_TOKEN", "secret-hf-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret-aws-key")
    target = f"{scheme}://datasets/org/data/archive.tar"
    calls = []
    identity = "c" * 64
    def pointer(target, commit):
        calls.append((target, commit))
        return json.dumps({"schema": "ratarmount.index.pointer.v1", "index_id": identity, "etag_sha256": identity}).encode(), target
    monkeypatch.setattr(_publish._native, "published_pointer", pointer)
    with ratar.open(sample[0], password="secret-password") as archive:
        result = ratar.publish_index(archive, target, **({"revision": "refs/heads/dev", "create_pr": True} if scheme == "hf" else {}))
    argv = records(fake_binary)[0]["argv"]
    assert "--publish-index-to=" + target in argv
    assert not any(secret in repr(argv) for secret in ["secret-hf-token", "secret-aws-key", "secret-password"])
    assert records(fake_binary)[0]["HF_TOKEN"] == "secret-hf-token"
    assert records(fake_binary)[0]["AWS_SECRET_ACCESS_KEY"] == "secret-aws-key"
    assert calls == [(target, "b" * 40 if scheme == "hf" else None)]
    assert result.index_id == identity
    if scheme == "hf":
        assert "--publish-revision=refs/heads/dev" in argv and "--create-pr" in argv
        assert result.pull_request_url.endswith("/discussions/1")


def test_regression_hf_publish_readback_uses_reported_commit_and_auth(fake_binary, sample, monkeypatch):
    identity = "c" * 64
    payload = json.dumps({"schema": "ratarmount.index.pointer.v1", "index_id": identity, "etag_sha256": identity}).encode()
    requests = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_HEAD(self):
            self.respond(False)
        def do_GET(self):
            self.respond(True)
        def respond(self, body):
            requests.append((self.path, self.headers.get("Authorization")))
            if "/revision/" in self.path:
                data = json.dumps({"sha": "b" * 40 if self.path.endswith("b" * 40) else "a" * 40}).encode()
            elif f"/resolve/{'b' * 40}/archive.tar.index.ptr" in self.path:
                data = payload
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("ETag", '"pointer-v1"')
            self.end_headers()
            if body:
                self.wfile.write(data)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    monkeypatch.setenv("HF_ENDPOINT", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("HF_TOKEN", "secret-hf-token")
    monkeypatch.setenv("HF_HUB_OFFLINE", "0")
    try:
        with ratar.open(sample[0]) as archive:
            result = archive.index.publish("hf://datasets/org/data/archive.tar", create_pr=True)
        assert result.index_id == identity
        assert f"/resolve/{'b' * 40}/archive.tar.index.ptr" in result.pointer_url
        assert all(auth == "Bearer secret-hf-token" for _, auth in requests)
        assert any("/resolve/" in path for path, _ in requests)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("data", [b"{}", b"[]", b"null", b"not json", json.dumps({
    "schema": "ratarmount.index.pointer.v1", "index_id": "../escape", "etag_sha256": "../escape",
}).encode()])
def test_regression_invalid_pointer_cannot_invent_blob_urls(data):
    with pytest.raises(ratar.RatarmountError, match="invalid index pointer"):
        _publish._pointer_id(data)


def test_regression_publish_failures_and_closed_archive(fake_binary, sample, monkeypatch):
    with ratar.open(sample[0]) as archive:
        for target, kwargs in [("https://host/a.tar", {}), ("s3://bucket/a.tar?token=x", {}), (None, {"revision": "dev"})]:
            with pytest.raises(ValueError):
                archive.index.publish(target, **kwargs)
        assert not fake_binary[1].exists()
        monkeypatch.setenv("FAKE_PUBLISH_FAIL", "1")
        with pytest.raises(ratar.RatarmountError, match="exit 7") as error:
            archive.index.publish()
        assert "secret-password" not in str(error.value)
    with pytest.raises(ValueError, match="closed"):
        ratar.publish_index(archive)


def test_regression_publish_success_without_pointer_reports_readback_failure(fake_binary, sample, monkeypatch):
    monkeypatch.setenv("FAKE_NO_POINTER", "1")
    with ratar.open(sample[0]) as archive:
        with pytest.raises(ratar.RatarmountError, match="publication succeeded but local pointer readback failed"):
            archive.index.publish()


def _real_binary():
    binary = os.environ.get("RATARMOUNT_TEST_BIN") or os.environ.get("RATARMOUNT_BIN") or shutil.which("ratarmount")
    if not binary:
        pytest.skip("skip: install ratarmount or set RATARMOUNT_TEST_BIN")
    return binary


def test_regression_real_cli_local_publish_produces_valid_sqlite(sample, tmp_path, monkeypatch):
    monkeypatch.setenv("RATARMOUNT_BIN", _real_binary())
    source, _ = sample
    with ratar.open(source) as archive:
        result = archive.index.publish(tmp_path / "real.index.sqlite")
    import sqlite3
    assert hashlib.sha256(Path(result.blob_url).read_bytes()).hexdigest() == result.index_id
    with sqlite3.connect(result.blob_url) as db:
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert db.execute("SELECT count(*) FROM files").fetchone()[0] > 0


def test_regression_real_fuse_mount_reads_payload_and_unmounts(sample, tmp_path, monkeypatch):
    if sys.platform == "linux" and not os.access("/dev/fuse", os.R_OK | os.W_OK):
        pytest.skip("skip: /dev/fuse is unavailable")
    if sys.platform == "darwin" and not Path("/Library/Filesystems/macfuse.fs").exists():
        pytest.skip("skip: macFUSE is unavailable")
    monkeypatch.setenv("RATARMOUNT_BIN", _real_binary())
    source, payloads = sample
    path = tmp_path / "real-mount"
    with ratar.open(source) as archive:
        with archive.mount(path, passthrough="off") as mounted:
            assert mounted.alive
            for name, data in payloads.items():
                assert (path / name).read_bytes() == data
    assert not os.path.ismount(path)
    assert mounted.wait(timeout=5) == 0
