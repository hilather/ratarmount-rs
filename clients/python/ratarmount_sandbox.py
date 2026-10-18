"""Stdlib-only client for ratarmount sandbox protocol v1 (Python 3.9+).

A client context destroys only attempts it created, never the shared daemon.
Transport failures are not retried: a timed-out mutation may have completed;
use list() to reconcile before issuing another new().
"""

import base64
import json
import socket as _socket

_VERSION = 1
_MAX_REQUEST = 1024 * 1024
_MAX_RESPONSE = 64 * 1024 * 1024


class SandboxError(RuntimeError):
    """Structured server error, or an invalid protocol response."""

    def __init__(self, code, message):
        self.code = code
        super().__init__(f"{code}: {message}")


class Attempt:
    """An attempt's mount path and overlay, with explicit/context cleanup."""

    def __init__(self, client, data):
        self._client = client
        self.id = data["id"]
        self.base = data["base"]
        self.path = data["path"]
        self.overlay_dir = data["overlay_dir"]
        self.status = data["status"]
        self._destroyed = False

    def diff(self, git=True):
        """Return a UTF-8 patch as str, or non-UTF-8 patch content as bytes."""
        result = self._client._call("diff", id=self.id, git=git)
        if "patch_b64" in result:
            return base64.b64decode(result["patch_b64"], validate=True)
        return result["patch"]

    def stats(self):
        return self._client._call("stats", id=self.id)

    def destroy(self):
        if not self._destroyed:
            self._client.destroy(id=self.id)
            self._destroyed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.destroy()
        return False


class RatarmountSandbox:
    """Connect to a supervisor socket; calls use separate connections.

    Example::

        with RatarmountSandbox('/run/user/1000/sandbox.sock') as client:
            client.create_base('task', '/srv/repo.git@COMMIT',
                               git_synthetic_head=True,
                               readonly_globs=['tests/**'])
            attempts = client.new('task', count=8, quota=2 * 1024**3)
            # Run agents at attempt.path, stop their writes, then collect:
            patches = [attempt.diff() for attempt in attempts]
    """

    def __init__(self, socket, timeout=3600):
        self.socket = str(socket)
        self.timeout = timeout
        self._owned = {}

    def _call(self, op, **fields):
        request = json.dumps(dict(version=_VERSION, op=op, **fields))
        data = request.encode("utf-8") + b"\n"
        if len(data) > _MAX_REQUEST:
            raise ValueError("sandbox request exceeds 1 MiB")
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as stream:
            stream.settimeout(self.timeout)
            stream.connect(self.socket)
            stream.sendall(data)
            with stream.makefile("rb") as reader:
                line = reader.readline(_MAX_RESPONSE + 1)
        if len(line) > _MAX_RESPONSE or not line.endswith(b"\n"):
            raise SandboxError("protocol", "oversized or incomplete response")
        try:
            response = json.loads(line)
            if not isinstance(response, dict) or response.get("version") != _VERSION:
                raise ValueError("unsupported response version")
            if response.get("ok") is False:
                error = response["error"]
                raise SandboxError(error["code"], error["message"])
            if response.get("ok") is not True or "result" not in response:
                raise ValueError("invalid response envelope")
            return response["result"]
        except (ValueError, KeyError, TypeError) as error:
            raise SandboxError("protocol", str(error)) from error

    def create_base(self, name, source, **options):
        return self._call("create_base", name=name, source=str(source), options=options)

    def new(self, base, count=1, overlay="disk", quota=None, readonly_globs=None):
        data = self._call("new", base=base, count=count, overlay=overlay,
                          quota=quota, readonly_globs=readonly_globs or [])
        attempts = [Attempt(self, item) for item in data]
        self._owned.update((a.id, a) for a in attempts)
        return attempts

    def list(self, base=None):
        return [Attempt(self, item) for item in self._call("list", base=base)]

    def destroy(self, *, id=None, base=None):
        if (id is None) == (base is None):
            raise ValueError("destroy requires exactly one of id or base")
        result = self._call("destroy", id=id, base=base)
        for key, attempt in list(self._owned.items()):
            if key == id or (base is not None and attempt.base == base):
                attempt._destroyed = True
                del self._owned[key]
        return result

    def shutdown(self):
        result = self._call("shutdown")
        for attempt in self._owned.values():
            attempt._destroyed = True
        self._owned.clear()
        return result

    def close(self):
        error = None
        for attempt in list(self._owned.values()):
            try:
                attempt.destroy()
            except (SandboxError, OSError) as failure:
                error = failure
        if error is not None:
            raise error

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
