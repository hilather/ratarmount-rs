"""CLI supervision shared by the optional mount and publication APIs."""
from __future__ import annotations

import contextlib
import math
import operator
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import weakref
from urllib.parse import urlsplit

from ._native import RatarmountError, split_url


def _binary() -> str:
    selected = os.environ.get("RATARMOUNT_BIN", "ratarmount")
    binary = shutil.which(selected)
    if binary is None:
        raise FileNotFoundError("install the ratarmount CLI or set RATARMOUNT_BIN to its executable")
    return os.path.abspath(binary)


def _source(value) -> str:
    value = split_url(os.fsdecode(os.fspath(value)))
    _public_argument(value)
    # Freeze relative paths so later cwd changes cannot redirect Archive.mount/publish.
    return value if _is_url(value) or value.lower().startswith("restic:") else os.path.abspath(value)


def _is_url(value: str) -> bool:
    return re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value) is not None


def _public_argument(value: str) -> str:
    """Never pass URL credentials or signed query strings through process argv."""
    if "://" in value:
        authorities = re.findall(r"[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)", value)
        try:
            parts = urlsplit(value)
        except ValueError:
            raise ValueError("invalid subprocess source/destination URL") from None
        if any("@" in authority for authority in authorities) or parts.query or parts.fragment:
            raise ValueError("URLs in subprocess APIs must use environment/config credentials, without userinfo, query or fragment")
    if "\x00" in value:
        raise ValueError("arguments cannot contain NUL")
    return value


def _password_args(stack: contextlib.ExitStack, password) -> list[str]:
    if password is None:
        return []
    if not isinstance(password, str) or any(c in password for c in "\n\r\x00"):
        raise ValueError("subprocess passwords must be strings without newline, CR or NUL")
    directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="ratarmount-password-"))
    path = os.path.join(directory, "password")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        os.chmod(path, 0o600)
        file.write(password + "\n")
    # Close before spawning: Windows cannot reopen a live delete-on-close tempfile.
    return ["--password-file", path]


def _timeout(value) -> float:
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise ValueError("timeout must be a finite positive number")
    return value


def _stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def _unmount(binary: str, path: str, process: subprocess.Popen, timeout: float) -> None:
    if os.path.ismount(path):
        # Avoid CalledProcessError: its repr includes argv, and stderr may contain credentials.
        result = subprocess.run(
            [binary, "--unmount", "--", path], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
        )
        if result.returncode:
            raise RatarmountError(f"unmount failed (exit {result.returncode})")
        deadline = time.monotonic() + timeout
        while os.path.ismount(path):
            if time.monotonic() >= deadline:
                raise TimeoutError("mount is still live after unmount")
            time.sleep(0.02)
    # A live child with no mounted filesystem may still be finishing shutdown.
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop(process)


def _cleanup(binary, path, process, resources, detach, timeout):
    try:
        if not detach:
            _unmount(binary, path, process, timeout)
    except Exception as error:
        # Finalizers/atexit cannot return an error to the caller.
        import warnings
        warnings.warn(f"ratarmount cleanup failed: {type(error).__name__}", ResourceWarning)
    finally:
        resources.close()


class Mount:
    """A supervised CLI mount. Use a context manager or call unmount()."""

    def __init__(self, path, binary, process, resources, detach, timeout):
        self.path = path
        self._binary = binary
        self._process = process
        self._resources = resources
        self._timeout = timeout
        # weakref.finalize also runs at interpreter exit and does not retain self.
        self._finalizer = weakref.finalize(
            self, _cleanup, binary, path, process, resources, detach, timeout,
        )

    @property
    def alive(self) -> bool:
        return self._process.poll() is None and os.path.ismount(self.path)

    def unmount(self) -> None:
        """Unmount and reap the child; safe to call repeatedly."""
        if self._finalizer.alive:
            _unmount(self._binary, self.path, self._process, self._timeout)
            self._finalizer.detach()
            self._resources.close()

    def wait(self, timeout=None) -> int:
        """Wait for the child to exit and return its status (does not unmount)."""
        return self._process.wait(timeout=timeout)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.unmount()


def mount(
    source, mountpoint, *, write_overlay=None, overlay_tmpfs=False,
    recursive=False, options="", passthrough="auto", readonly_globs=None,
    quota=None, uid=None, gid=None, foreground=False, **kwargs,
) -> Mount:
    """Mount one source or a union through the installed ratarmount CLI.

    Extra options: detach=False, timeout=30, password=None, parallelization=1.
    foreground is accepted for CLI compatibility; the supervised child always
    stays in the foreground and this call returns once the filesystem is live.
    """
    if sys.platform not in ("linux", "darwin"):
        raise NotImplementedError("mount requires Linux or macOS and a FUSE-enabled ratarmount CLI")
    unknown = kwargs.keys() - {"detach", "timeout", "password", "parallelization"}
    if unknown:
        raise TypeError("unsupported mount keyword(s): " + ", ".join(sorted(unknown)))
    timeout = _timeout(kwargs.get("timeout", 30))
    sources = [source] if isinstance(source, (str, bytes, os.PathLike)) else list(source)
    if not sources:
        raise ValueError("mount requires at least one source")
    sources = [_source(item) for item in sources]
    path = os.path.abspath(os.fsdecode(os.fspath(mountpoint)))
    if os.path.ismount(path):
        raise ValueError("mountpoint is already mounted")
    if passthrough not in ("auto", "on", "off"):
        raise ValueError("passthrough must be auto, on or off")
    if write_overlay is not None and overlay_tmpfs:
        raise ValueError("write_overlay and overlay_tmpfs are mutually exclusive")
    if (readonly_globs or quota is not None) and write_overlay is None and not overlay_tmpfs:
        raise ValueError("readonly_globs and quota require a write overlay")
    # FUSE options are not a generic CLI escape hatch; credentials belong in env/config.
    if not isinstance(options, str) or re.search(r"password|token|secret|credential|://", options, re.I):
        raise ValueError("options must be FUSE options without credentials or URLs")
    fuse_options = [options] if options else []
    for key, value in (("uid", uid), ("gid", gid)):
        if value is not None:
            value = operator.index(value)
            if value < 0 or value > 2**32 - 1:
                raise ValueError(f"{key} must fit an unsigned 32-bit integer")
            fuse_options.append(f"{key}={value}")
    argv = [_binary(), "--foreground", f"--passthrough={passthrough}"]
    if write_overlay is not None:
        argv.append("--write-overlay=" + os.fsdecode(os.fspath(write_overlay)))
    if overlay_tmpfs:
        argv.append("--overlay-tmpfs" if overlay_tmpfs is True else f"--overlay-tmpfs={overlay_tmpfs}")
    if recursive:
        argv.append("--recursive")
    if fuse_options:
        argv.append("--fuse=" + ",".join(fuse_options))
    if isinstance(readonly_globs, str):
        readonly_globs = [readonly_globs]
    for glob in readonly_globs or []:
        argv.append("--overlay-readonly=" + glob)
    if quota is not None:
        argv.append(f"--overlay-quota={quota}")
    if "parallelization" in kwargs:
        count = operator.index(kwargs["parallelization"])
        if count < 0 or count > 2**32 - 1:
            raise ValueError("parallelization must be between 0 and 2**32-1")
        argv.append(f"--parallelization={count}")
    with contextlib.ExitStack() as resources:
        argv.extend(_password_args(resources, kwargs.get("password")))
        argv.extend(["--", *sources, path])
        os.makedirs(path, exist_ok=True)
        # Daemons may log for their entire lifetime; do not retain an unread pipe.
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
        try:
            deadline = time.monotonic() + timeout
            while True:
                code = process.poll()
                if code is not None:
                    raise RatarmountError(f"mount exited before readiness (exit {code}); check CLI/FUSE availability")
                if os.path.ismount(path):
                    return Mount(path, argv[0], process, resources.pop_all(), kwargs.get("detach", False), timeout)
                if time.monotonic() >= deadline:
                    raise TimeoutError("timed out waiting for mount readiness")
                time.sleep(0.02)
        except BaseException:
            try:
                if os.path.ismount(path):
                    _unmount(argv[0], path, process, timeout)
            finally:
                _stop(process)
            raise
