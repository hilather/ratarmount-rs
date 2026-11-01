"""Regression tests using a local fake daemon; no FUSE or third-party client code."""

import json
from pathlib import Path
import socket
import sys
import threading

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ratarmount_sandbox import RatarmountSandbox, SandboxError  # noqa: E402


class Requests(list):
    """Parsed requests; `raw` holds each request line's exact bytes."""

    def __init__(self):
        super().__init__()
        self.raw = []


def fake_daemon(tmp_path, stale_replay=False):
    """A fake daemon answering in the request's version.

    With stale_replay, a new() with request_id returns attempts the fake does
    not hold, as a replay after a daemon restart does, and destroy of an
    unknown ID answers not_found.
    """
    address = str(tmp_path / "api.sock")
    requests = Requests()
    attempts = {}
    stopped = threading.Event()
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(address)
    listener.listen()
    listener.settimeout(0.1)

    def serve():
        while not stopped.is_set():
            try:
                stream, _ = listener.accept()
            except socket.timeout:
                continue
            with stream, stream.makefile("rb") as reader:
                line = reader.readline()
                requests.raw.append(line)
                request = json.loads(line)
                requests.append(request)
                op = request["op"]
                result = {}
                if op == "new":
                    if request["base"] == "missing":
                        stream.sendall(b'{"version":1,"ok":false,"error":{"code":"not_found","message":"unknown base"}}\n')
                        continue
                    if request["base"] == "old-daemon":
                        stream.sendall(b'{"version":1,"ok":false,"error":{"code":"unsupported_version","message":"version must be 1"}}\n')
                        continue
                    if request["base"] == "old-ok":
                        stream.sendall(b'{"version":1,"ok":true,"result":[]}\n')
                        continue
                    result = [dict(id=str(i), base=request["base"], path=f"/mnt/{i}",
                                   overlay_dir=f"/overlay/{i}", status="ready")
                              for i in range(request["count"])]
                    if not (stale_replay and "request_id" in request):
                        attempts.update((a["id"], a) for a in result)
                elif op == "destroy" and stale_replay and request.get("id") \
                        and request["id"] not in attempts:
                    reply = dict(version=request["version"], ok=False,
                                 error=dict(code="not_found", message="unknown attempt"))
                    stream.sendall((json.dumps(reply) + "\n").encode())
                    continue
                elif op == "list":
                    if request.get("base") == "bad-version":
                        stream.sendall(b'{"version":9,"ok":true,"result":[]}\n')
                        continue
                    if request.get("base") == "truncated":
                        stream.sendall(b'{"version":1')
                        continue
                    result = list(attempts.values())
                elif op == "diff":
                    result = {"patch": "diff --git a/a b/a\n+snowman: ☃\n"}
                elif op == "stats":
                    result = {"bytes_in_overlay": 42, "files_present": 1}
                elif op == "destroy":
                    if request.get("id"):
                        attempts.pop(request["id"], None)
                    else:
                        attempts.clear()
                elif op == "shutdown":
                    attempts.clear()
                reply = dict(version=request["version"], ok=True, result=result)
                encoded = (json.dumps(reply) + "\n").encode()
                # Fragment the JSON and newline across writes.
                stream.sendall(encoded[:7])
                stream.sendall(encoded[7:])

    thread = threading.Thread(target=serve)
    thread.start()
    yield RatarmountSandbox(address, timeout=2), requests, attempts
    stopped.set()
    thread.join(timeout=3)
    listener.close()
    assert not thread.is_alive()


@pytest.fixture
def daemon(tmp_path):
    yield from fake_daemon(tmp_path)


@pytest.fixture
def stale_daemon(tmp_path):
    yield from fake_daemon(tmp_path, stale_replay=True)


def test_regression_batch_context_cleans_only_its_attempts(daemon):
    client, requests, attempts = daemon
    with client:
        client.create_base("task", "/repo.git@sha", git_synthetic_head=True,
                           readonly_globs=["tests/**"])
        created = client.new("task", count=8, overlay="tmpfs", quota=1024)
        assert len(created) == 8
        assert created[0].path == "/mnt/0"
        assert created[0].overlay_dir == "/overlay/0"
        assert created[0].diff() == "diff --git a/a b/a\n+snowman: ☃\n"
        assert created[0].stats()["bytes_in_overlay"] == 42
        assert len(client.list("task")) == 8
        created[0].destroy()
        created[0].destroy()
        attempts["external"] = {"base": "external"}
    assert list(attempts) == ["external"]
    assert len([r for r in requests if r["op"] == "destroy"]) == 8
    assert all(r["version"] == 1 for r in requests)
    assert requests[0]["options"]["readonly_globs"] == ["tests/**"]
    assert requests[1]["quota"] == 1024
    assert not any(r["op"] == "shutdown" for r in requests)


def test_regression_v1_request_bytes_unchanged(daemon):
    """Regression: methods called without request_id send the baseline v1 bytes."""
    client, requests, _ = daemon
    client.create_base("task", "/srv/base.tar")
    client.create_base("task", "/repo.git@sha", git_synthetic_head=True,
                       readonly_globs=["tests/**"])
    created = client.new("task")
    client.new("task", count=2, overlay="tmpfs", quota=1024, readonly_globs=["a", "b/**"])
    client.list()
    client.list("task")
    created[0].diff()
    created[0].diff(git=False)
    created[0].stats()
    created[0].destroy()
    client.destroy(base="task")
    client.shutdown()
    # Captured from the baseline client (2b96837).
    assert requests.raw == [
        b'{"version": 1, "op": "create_base", "name": "task", "source": "/srv/base.tar", "options": {}}\n',
        b'{"version": 1, "op": "create_base", "name": "task", "source": "/repo.git@sha", "options": {"git_synthetic_head": true, "readonly_globs": ["tests/**"]}}\n',
        b'{"version": 1, "op": "new", "base": "task", "count": 1, "overlay": "disk", "quota": null, "readonly_globs": []}\n',
        b'{"version": 1, "op": "new", "base": "task", "count": 2, "overlay": "tmpfs", "quota": 1024, "readonly_globs": ["a", "b/**"]}\n',
        b'{"version": 1, "op": "list", "base": null}\n',
        b'{"version": 1, "op": "list", "base": "task"}\n',
        b'{"version": 1, "op": "diff", "id": "0", "git": true}\n',
        b'{"version": 1, "op": "diff", "id": "0", "git": false}\n',
        b'{"version": 1, "op": "stats", "id": "0"}\n',
        b'{"version": 1, "op": "destroy", "id": "0", "base": null}\n',
        b'{"version": 1, "op": "destroy", "id": null, "base": "task"}\n',
        b'{"version": 1, "op": "shutdown"}\n',
    ]


def test_regression_attempt_context_cleanup_on_exception(daemon):
    client, _, attempts = daemon
    with pytest.raises(RuntimeError, match="agent failed"):
        with client.new("task")[0]:
            raise RuntimeError("agent failed")
    assert attempts == {}
    client.close()


def test_regression_structured_errors_and_bad_framing(daemon):
    client, _, _ = daemon
    with pytest.raises(SandboxError) as error:
        client.new("missing")
    assert error.value.code == "not_found"
    for base in ("bad-version", "truncated"):
        with pytest.raises(SandboxError) as error:
            client.list(base)
        assert error.value.code == "protocol"
    with pytest.raises(ValueError):
        client.destroy()
    with pytest.raises(ValueError):
        client.destroy(id="a", base="b")


def test_regression_base_destroy_and_shutdown_do_not_double_destroy(daemon):
    client, requests, attempts = daemon
    client.new("task", 2)
    client.destroy(base="task")
    client.close()
    assert not attempts
    assert len([r for r in requests if r["op"] == "destroy"]) == 1
    client.new("task", 2)
    client.shutdown()
    client.close()
    assert requests[-1]["op"] == "shutdown"


def test_regression_latin1_patch_bytes_are_not_replaced():
    from ratarmount_sandbox import Attempt

    class Client:
        def _call(self, op, **kwargs):
            assert op == "diff"
            return {"patch_b64": "K2NhZukK"}

    attempt = Attempt(Client(), dict(id="1", base="base", path="/mnt/1",
                                     overlay_dir="/overlay/1", status="ready"))
    assert attempt.diff() == b"+caf\xe9\n"


def test_regression_request_id_sends_v2(daemon):
    """Regression: new(..., request_id=...) sends protocol v2 with the field."""
    client, requests, _ = daemon
    created = client.new("task", count=2, request_id="r")
    assert [a.id for a in created] == ["0", "1"]
    assert requests.raw[-1] == (
        b'{"version": 2, "op": "new", "base": "task", "count": 2, "overlay": "disk", '
        b'"quota": null, "readonly_globs": [], "request_id": "r"}\n'
    )
    client.new("task")
    assert requests[-1]["version"] == 1
    assert "request_id" not in requests[-1]
    client.close()


def test_regression_v1_error_envelope_answering_v2(daemon):
    """Regression: an older daemon's v1 error answering v2 is its server error."""
    client, _, _ = daemon
    with pytest.raises(SandboxError) as error:
        client.new("old-daemon", request_id="r")
    assert error.value.code == "unsupported_version"
    with pytest.raises(SandboxError) as error:
        client.new("old-ok", request_id="r")
    assert error.value.code == "protocol"


def test_regression_stale_replay_client_context_cleanup(stale_daemon):
    """Regression: a client context exits cleanly after a stale replay."""
    client, requests, _ = stale_daemon
    with client:
        replayed = client.new("task", count=2, request_id="r")
        assert client.list() == []
    assert client._owned == {}
    assert all(attempt._destroyed for attempt in replayed)
    destroyed = [r["id"] for r in requests if r["op"] == "destroy"]
    assert sorted(destroyed) == sorted(a.id for a in replayed)


def test_regression_stale_replay_attempt_context_cleanup(stale_daemon):
    """Regression: an attempt context exits cleanly after a stale replay, but an
    explicit destroy() still raises not_found."""
    client, _, _ = stale_daemon
    first, second = client.new("task", count=2, request_id="r")
    with first:
        pass
    assert first._destroyed
    assert first.id not in client._owned
    with pytest.raises(SandboxError) as error:
        second.destroy()
    assert error.value.code == "not_found"
    assert not second._destroyed
    client.close()
    assert client._owned == {}
