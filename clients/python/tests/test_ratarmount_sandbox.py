"""Regression tests using a local fake daemon; no FUSE or third-party client code."""

import json
from pathlib import Path
import socket
import sys
import threading

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ratarmount_sandbox import RatarmountSandbox, SandboxError  # noqa: E402


@pytest.fixture
def daemon(tmp_path):
    address = str(tmp_path / "api.sock")
    requests = []
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
                request = json.loads(reader.readline())
                requests.append(request)
                op = request["op"]
                result = {}
                if op == "new":
                    if request["base"] == "missing":
                        stream.sendall(b'{"version":1,"ok":false,"error":{"code":"not_found","message":"unknown base"}}\n')
                        continue
                    result = [dict(id=str(i), base=request["base"], path=f"/mnt/{i}",
                                   overlay_dir=f"/overlay/{i}", status="ready")
                              for i in range(request["count"])]
                    attempts.update((a["id"], a) for a in result)
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
                encoded = (json.dumps(dict(version=1, ok=True, result=result)) + "\n").encode()
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
