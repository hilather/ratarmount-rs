"""Stdlib-only client for the ratarmount sandbox protocol (Python 3.9+).

Requests use protocol v1, except finalize(), list(all=True) and new() with
request_id, lowers, journal or retain=True, which send protocol v2. A client
context destroys only attempts it created, never the shared daemon. Transport
failures are not retried automatically: a timed-out mutation may have
completed. Retry new() or finalize() with the same request_id and arguments,
which never acts twice, or use list() to reconcile before issuing another
new() without one.

finalize() stops an attempt, seals its layer and returns a report. A
finalized attempt is still destroyed with its context, and its bundle,
manifest and journal summary with it: copy them out, or create the attempt
with new(retain=True). Its finalize then moves it to the daemon's
retained/ID/ directory and hands it off: retained attempts are never
destroyed, so the client stops owning it, list(all=True) shows it, and
destroy() of it raises SandboxError with code retained.

A replay returns the original answer, even after a daemon restart discarded
its attempts or a finalize retained one; list() shows the current state. A
client never re-owns an attempt it saw retained. Leaving a client or attempt
context treats destroy's not_found as already destroyed and its retained as
handed off, so a stale replay does not fail the cleanup.
"""

import base64
import json
import os
import socket as _socket

_VERSION = 1
_VERSION_2 = 2
_MAX_REQUEST = 1024 * 1024
_MAX_RESPONSE = 64 * 1024 * 1024


class SandboxError(RuntimeError):
    """Structured server error, or an invalid protocol response."""

    def __init__(self, code, message):
        self.code = code
        super().__init__(f"{code}: {message}")


class Attempt:
    """An attempt's mount path and overlay, with explicit/context cleanup.

    journal_path is the attempt's operation journal (<dirname(path)>/journal.jsonl)
    when this client created it with a journal, else None; it is deleted with
    the attempt, so summarize it before destroy(). finalize() takes status,
    path, overlay_dir and journal_path from its report. Leaving the context of
    a retained attempt sends no destroy.
    """

    def __init__(self, client, data, journal=False):
        self._client = client
        self.id = data["id"]
        self.base = data["base"]
        self.path = data["path"]
        self.overlay_dir = data["overlay_dir"]
        self.status = data["status"]
        self.journal_path = (os.path.join(os.path.dirname(self.path), "journal.jsonl")
                             if journal else None)
        self._destroyed = False

    def diff(self, git=True):
        """Return a UTF-8 patch as str, or non-UTF-8 patch content as bytes."""
        result = self._client._call("diff", id=self.id, git=git)
        if "patch_b64" in result:
            return base64.b64decode(result["patch_b64"], validate=True)
        return result["patch"]

    def stats(self):
        return self._client._call("stats", id=self.id)

    def finalize(self, pack=False, request_id=None):
        """RatarmountSandbox.finalize() of this attempt; returns the report.

        status, path, overlay_dir and a set journal_path follow the report's
        attempt (a retained one moves to retained/ID/). Unless retained, the
        attempt is still destroyed on exit, with its bundle, manifest and
        summary: copy them out or retain.
        """
        report = self._client.finalize(self.id, pack=pack, request_id=request_id)
        # The client already updated its owned object (maybe this one); idempotent.
        self._update(report["attempt"])
        return report

    def _update(self, data):
        """Take the status and paths of a finalize report's attempt."""
        self.status, self.path, self.overlay_dir = (
            data["status"], data["path"], data["overlay_dir"])
        if self.journal_path is not None:
            self.journal_path = os.path.join(os.path.dirname(self.path), "journal.jsonl")

    def destroy(self):
        if not self._destroyed:
            self._client.destroy(id=self.id)
            self._destroyed = True

    def _destroy_implicitly(self):
        """destroy(), except for attempts that are gone or retained.

        A replay can name attempts that are gone (a daemon restart or another
        client destroyed them: not_found) or retained (destroy answers
        retained); implicit cleanup must not fail on those, and sends nothing
        for an attempt known to be retained.
        """
        if self.status == "retained" or self.id in self._client._retained:
            self._client._hand_off(self.id)
            return
        try:
            self.destroy()
        except SandboxError as error:
            if error.code not in ("not_found", "retained"):
                raise
            self._destroyed = True
            owned = self._client._owned.pop(self.id, None)
            if owned is not None:
                owned._destroyed = True
            if error.code == "retained":
                self._client._retained.add(self.id)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._destroy_implicitly()
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
        self._retained = set()

    def _call(self, op, version=_VERSION, **fields):
        request = json.dumps(dict(version=version, op=op, **fields))
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
            if not isinstance(response, dict):
                raise ValueError("unsupported response version")
            # An older daemon answers a v2 request with a v1 error envelope.
            older = version == _VERSION_2 and response.get("version") == _VERSION \
                and response.get("ok") is False
            if response.get("version") != version and not older:
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

    def new(self, base, count=1, overlay="disk", quota=None, readonly_globs=None, *,
            request_id=None, lowers=None, journal=None, retain=False):
        """Start attempts. Any of these keywords sends protocol v2, and an
        omitted one (or retain=False) sends no key:

        - request_id: a retry with the same ID and arguments returns the stored
          answer instead of a second batch.
        - lowers: sealed layer directories or bundles under every attempt,
          bottom first; absolute paths (str or os.PathLike), sent unchanged.
        - journal: a mapping with optional "exclude" (globs), "reads" ("all" or
          "first") and "sync" (bool); see Attempt.journal_path.
        - retain: finalize() keeps each attempt in the daemon's retained/ID/
          directory instead of leaving it to be destroyed; see finalize().

        An attempt this client saw retained is returned but never owned again,
        so a replay cannot hand it back to this client's cleanup.
        """
        fields = dict(base=base, count=count, overlay=overlay, quota=quota,
                      readonly_globs=readonly_globs or [])
        if request_id is None and lowers is None and journal is None and not retain:
            data = self._call("new", **fields)
        else:
            if request_id is not None:
                fields["request_id"] = request_id
            if lowers is not None:
                # One path would be iterated character by character.
                if isinstance(lowers, (str, bytes, os.PathLike)):
                    raise TypeError("lowers must be a list of paths, not one path")
                fields["lowers"] = [os.fspath(lower) for lower in lowers]
            if journal is not None:
                fields["journal"] = dict(journal)
            if retain:
                fields["retain"] = True
            data = self._call("new", version=_VERSION_2, **fields)
        attempts = [Attempt(self, item, journal=journal is not None) for item in data]
        self._owned.update((a.id, a) for a in attempts if a.id not in self._retained)
        return attempts

    def list(self, base=None, all=False):
        """Attempts, of one base if given. all=True sends protocol v2 and also
        returns the retained attempts (status "retained", or "finalizing" while
        a retain is not acknowledged); base is then sent only when given."""
        if not all:
            return [Attempt(self, item) for item in self._call("list", base=base)]
        fields = {} if base is None else dict(base=base)
        fields["all"] = True
        return [Attempt(self, item) for item in self._call("list", version=_VERSION_2, **fields)]

    def finalize(self, id, pack=False, request_id=None):
        """Finalize attempt id (protocol v2): stop it, seal its layer and
        return the report. pack=True also writes a bundle; pack and request_id
        are sent only when given. An Attempt this client owns takes the
        report's status and paths, as Attempt.finalize() does.

        writers_active means something still uses the mount: stop it, wait at
        least a second and retry with backoff. A "finalized" attempt stays
        owned and is destroyed on exit, with its bundle, manifest and summary:
        copy them out or retain. A "retained" one is handed off: this client
        no longer owns it and never destroys it.
        """
        fields = dict(id=id)
        if pack:
            fields["pack"] = True
        if request_id is not None:
            fields["request_id"] = request_id
        report = self._call("finalize", version=_VERSION_2, **fields)
        owned = self._owned.get(id)
        if report["status"] == "retained":
            self._hand_off(id)
        if owned is not None:
            owned._update(report["attempt"])
        return report

    def _hand_off(self, id):
        """A retained attempt is the daemon's: never owned or destroyed again."""
        self._retained.add(id)
        self._owned.pop(id, None)

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
                attempt._destroy_implicitly()
            except (SandboxError, OSError) as failure:
                error = failure
        if error is not None:
            raise error

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
