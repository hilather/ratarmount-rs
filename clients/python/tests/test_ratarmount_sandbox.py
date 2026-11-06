"""Regression tests using a local fake daemon; no FUSE or third-party client code."""

import json
import os
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


def reply_error(stream, request, code, message):
    """Send a structured error in the request's version."""
    reply = dict(version=request["version"], ok=False, error=dict(code=code, message=message))
    stream.sendall((json.dumps(reply) + "\n").encode())


def fake_daemon(tmp_path, stale_replay=False):
    """A fake daemon answering in the request's version.

    With stale_replay, a new() with request_id returns attempts the fake does
    not hold, as a replay after a daemon restart does, and destroy of an
    unknown ID answers not_found. Otherwise a repeated request_id replays the
    stored new() answer. New IDs skip IDs in use or retained. finalize of an
    attempt created with retain moves it to retained/ID/, which list(all=True)
    appends and destroy refuses with retained.
    """
    address = str(tmp_path / "api.sock")
    requests = Requests()
    attempts = {}
    retained = {}
    retain = {}
    answers = {}
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
                    if request.get("request_id") in answers:
                        result = [dict(a) for a in answers[request["request_id"]]]
                    else:
                        taken = set(attempts) | set(retained)
                        ids = [str(i) for i in range(len(taken) + request["count"])
                               if str(i) not in taken][:request["count"]]
                        result = [dict(id=i, base=request["base"], path=f"/mnt/{i}",
                                       overlay_dir=f"/overlay/{i}", status="ready")
                                  for i in ids]
                        if not (stale_replay and "request_id" in request):
                            attempts.update((a["id"], a) for a in result)
                            retain.update((i, request.get("retain", False)) for i in ids)
                        if "request_id" in request:
                            answers[request["request_id"]] = [dict(a) for a in result]
                elif op == "destroy" and request.get("id") in retained:
                    reply_error(stream, request, "retained", f"attempt {request['id']} is "
                                "retained; retained attempts are never destroyed")
                    continue
                elif op == "destroy" and stale_replay and request.get("id") \
                        and request["id"] not in attempts:
                    reply_error(stream, request, "not_found", "unknown attempt")
                    continue
                elif op == "finalize":
                    key = request["id"]
                    if key in attempts and retain.get(key):
                        retained[key] = dict(attempts.pop(key), status="retained",
                                             path=f"/state/retained/{key}/mnt",
                                             overlay_dir=f"/state/retained/{key}/overlay")
                    elif key in attempts:
                        attempts[key] = dict(attempts[key], status="finalized")
                    attempt = attempts.get(key) or retained.get(key)
                    if attempt is None:
                        reply_error(stream, request, "not_found", "unknown attempt")
                        continue
                    root = os.path.dirname(attempt["path"])
                    result = dict(status=attempt["status"], attempt=attempt,
                                  patch_hash={"files": 1}, layer_digest="sha256:" + "0" * 64,
                                  stack_digest=None, fsck_result="ok", bytes_written=6,
                                  erofs_denied=None, manifest_path=f"{root}/manifest.jsonl",
                                  journal_summary=None,
                                  bundle=f"{root}/bundle.tar.zst" if request.get("pack") else None)
                elif op == "list":
                    if request.get("base") == "bad-version":
                        stream.sendall(b'{"version":9,"ok":true,"result":[]}\n')
                        continue
                    if request.get("base") == "truncated":
                        stream.sendall(b'{"version":1')
                        continue
                    result = list(attempts.values())
                    if request.get("all"):
                        result += retained.values()
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


def test_regression_new_lowers_journal_sends_v2(daemon):
    """Regression: lowers= and journal= send protocol v2, with string paths and
    the mapping as given; an omitted keyword sends no key (never null), and a
    new() without keywords keeps the v1 bytes."""
    client, requests, _ = daemon
    client.new("task", lowers=[Path("/a"), "/b"], journal={"reads": "first"})
    assert requests.raw[-1] == (
        b'{"version": 2, "op": "new", "base": "task", "count": 1, "overlay": "disk", '
        b'"quota": null, "readonly_globs": [], "lowers": ["/a", "/b"], '
        b'"journal": {"reads": "first"}}\n'
    )
    client.new("task", lowers=["relative/layer"])
    assert requests[-1]["version"] == 2
    assert requests[-1]["lowers"] == ["relative/layer"]
    assert "journal" not in requests[-1] and "request_id" not in requests[-1]
    client.new("task", journal={})
    assert requests[-1]["version"] == 2 and requests[-1]["journal"] == {}
    assert "lowers" not in requests[-1]
    client.new("task", request_id="r", lowers=["/a"])
    assert requests.raw[-1] == (
        b'{"version": 2, "op": "new", "base": "task", "count": 1, "overlay": "disk", '
        b'"quota": null, "readonly_globs": [], "request_id": "r", "lowers": ["/a"]}\n'
    )
    client.new("task")
    assert requests.raw[-1] == (
        b'{"version": 1, "op": "new", "base": "task", "count": 1, "overlay": "disk", '
        b'"quota": null, "readonly_globs": []}\n'
    )
    for request in requests:
        assert request.get("lowers", []) is not None
        assert request.get("journal", {}) is not None
    client.close()


def test_regression_new_lowers_single_path_is_refused(daemon):
    """Regression: lowers="/a" (one path, not a list) was sent as one lower per
    character; it raises TypeError and sends nothing."""
    client, requests, _ = daemon
    sent = len(requests)
    for single in ["/a", b"/a", Path("/a")]:
        with pytest.raises(TypeError, match="list of paths"):
            client.new("task", lowers=single)
    assert len(requests) == sent
    client.new("task", lowers=("/a",))
    assert requests[-1]["lowers"] == ["/a"]
    client.close()


def test_regression_attempt_journal_path(daemon):
    """Regression: Attempt.journal_path is <dirname(path)>/journal.jsonl for
    attempts this client created with a journal, else None (and for list())."""
    client, _, _ = daemon
    journaled = client.new("task", count=2, journal={"exclude": ["skip/**"]})
    assert journaled[0].journal_path == "/mnt/journal.jsonl"
    for attempt in journaled:
        assert attempt.journal_path == os.path.join(os.path.dirname(attempt.path),
                                                    "journal.jsonl")
    assert all(a.journal_path is None for a in client.new("task", lowers=["/a"]))
    assert all(a.journal_path is None for a in client.new("task"))
    listed = client.list()
    assert listed and all(a.journal_path is None for a in listed)
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


def test_regression_finalize_and_retain_send_v2(daemon):
    """Regression: finalize() and new(retain=True) send protocol v2 with only the
    keys given (never null or false), a new() without v2 arguments keeps the v1
    bytes, and Attempt.finalize takes status, paths and journal_path from the
    report; a finalized attempt that was not retained is still destroyed."""
    client, requests, _ = daemon
    plain = client.new("task", retain=False)[0]
    assert requests.raw[-1] == (
        b'{"version": 1, "op": "new", "base": "task", "count": 1, "overlay": "disk", '
        b'"quota": null, "readonly_globs": []}\n'
    )
    kept = client.new("task", journal={}, retain=True)[0]
    assert requests.raw[-1] == (
        b'{"version": 2, "op": "new", "base": "task", "count": 1, "overlay": "disk", '
        b'"quota": null, "readonly_globs": [], "journal": {}, "retain": true}\n'
    )
    client.new("task", request_id="n", retain=True)
    assert requests.raw[-1] == (
        b'{"version": 2, "op": "new", "base": "task", "count": 1, "overlay": "disk", '
        b'"quota": null, "readonly_globs": [], "request_id": "n", "retain": true}\n'
    )
    report = plain.finalize()
    assert requests.raw[-1] == b'{"version": 2, "op": "finalize", "id": "0"}\n'
    assert report["status"] == "finalized"
    assert (plain.status, plain.path, plain.overlay_dir, plain.journal_path) == (
        "finalized", "/mnt/0", "/overlay/0", None)
    client.finalize("0", pack=True)
    assert requests.raw[-1] == b'{"version": 2, "op": "finalize", "id": "0", "pack": true}\n'
    client.finalize("0", request_id="f")
    assert requests.raw[-1] == (
        b'{"version": 2, "op": "finalize", "id": "0", "request_id": "f"}\n')
    plain.finalize(pack=True, request_id="g")
    assert requests.raw[-1] == (
        b'{"version": 2, "op": "finalize", "id": "0", "pack": true, "request_id": "g"}\n')
    assert kept.journal_path == "/mnt/journal.jsonl"
    report = kept.finalize()
    assert requests.raw[-1] == b'{"version": 2, "op": "finalize", "id": "1"}\n'
    assert report["status"] == "retained"
    assert report["attempt"] == dict(id="1", base="task", path="/state/retained/1/mnt",
                                     overlay_dir="/state/retained/1/overlay", status="retained")
    assert (kept.status, kept.path, kept.overlay_dir, kept.journal_path) == (
        "retained", "/state/retained/1/mnt", "/state/retained/1/overlay",
        "/state/retained/1/journal.jsonl")
    for request in requests:
        for key in ("retain", "pack", "request_id", "all"):
            assert request.get(key, "absent") not in (None, False)
    client.close()
    assert sorted(r["id"] for r in requests if r["op"] == "destroy") == ["0", "2"]


def test_regression_replay_does_not_reown_retained_attempt(daemon):
    """Regression: a replayed new() re-owned an attempt this client had retained
    (Codex note #6), so leaving the context sent it a destroy."""
    client, requests, _ = daemon
    with client:
        created = client.new("task", count=2, request_id="r", retain=True)
        assert client.finalize(created[0].id)["status"] == "retained"
        assert (created[0].status, created[0].path) == ("retained", "/state/retained/0/mnt")
        assert client._retained == {"0"} and set(client._owned) == {"1"}
        replayed = client.new("task", count=2, request_id="r", retain=True)
        assert requests.raw[-1] == requests.raw[0]
        assert [(a.id, a.status) for a in replayed] == [("0", "ready"), ("1", "ready")]
        assert "0" not in client._owned
        with created[0], replayed[0]:
            pass
        assert not created[0]._destroyed and not replayed[0]._destroyed
    assert client._owned == {}
    assert [r["id"] for r in requests if r["op"] == "destroy"] == ["1"]


def test_regression_fresh_client_replay_exits_cleanly(daemon):
    """Regression: a fresh client that replays new() owns an attempt another
    client retained, and leaving its context raised destroy's retained error;
    cleanup treats retained like not_found, an explicit destroy() raises it."""
    first, requests, _ = daemon
    with first:
        for attempt in first.new("task", count=2, request_id="r", retain=True):
            assert attempt.finalize()["status"] == "retained"
    fresh = RatarmountSandbox(first.socket, timeout=2)
    with fresh:
        replayed = fresh.new("task", count=2, request_id="r", retain=True)
        assert [(a.id, a.status) for a in replayed] == [("0", "ready"), ("1", "ready")]
        assert sorted(fresh._owned) == ["0", "1"]
        with pytest.raises(SandboxError) as error:
            replayed[1].destroy()
        assert error.value.code == "retained"
        assert not replayed[1]._destroyed
    assert fresh._owned == {}
    assert all(attempt._destroyed for attempt in replayed)
    with pytest.raises(SandboxError) as error:
        fresh.destroy(id="0")
    assert error.value.code == "retained"
    assert [r["id"] for r in requests if r["op"] == "destroy"] == ["1", "0", "1", "0"]
    # Once it saw them retained, a further replay does not own them again.
    fresh.new("task", count=2, request_id="r", retain=True)
    assert fresh._owned == {}
    assert [(a.id, a.status) for a in fresh.list(all=True)] == [
        ("0", "retained"), ("1", "retained")]


def test_regression_list_all_includes_retained(daemon):
    """Regression: list(all=True) sends v2 {"op": "list", "all": true} and builds
    the retained entries without KeyError; list() keeps the v1 bytes."""
    client, requests, _ = daemon
    created = client.new("task", count=2, retain=True)
    created[0].finalize()
    listed = client.list(all=True)
    assert requests.raw[-1] == b'{"version": 2, "op": "list", "all": true}\n'
    assert [(a.id, a.status, a.path, a.overlay_dir) for a in listed] == [
        ("1", "ready", "/mnt/1", "/overlay/1"),
        ("0", "retained", "/state/retained/0/mnt", "/state/retained/0/overlay")]
    client.list("task", all=True)
    assert requests.raw[-1] == b'{"version": 2, "op": "list", "base": "task", "all": true}\n'
    assert [a.id for a in client.list()] == ["1"]
    assert requests.raw[-1] == b'{"version": 1, "op": "list", "base": null}\n'
    client.list("task", all=False)
    assert requests.raw[-1] == b'{"version": 1, "op": "list", "base": "task"}\n'
    with listed[1]:
        pass
    client.close()
    assert [r["id"] for r in requests if r["op"] == "destroy"] == ["1"]
