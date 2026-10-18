#!/usr/bin/env python3
"""Independent kernel-view snapshot and a no-follow, portable upperdir copy."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(131072), b""):
            result.update(chunk)
    return "sha256:" + result.hexdigest()


def snapshot(root):
    rows = {"": {"type": "dir", "mode": f"{root.lstat().st_mode:06o}", "size": 0}}

    def walk(directory):
        for path in sorted(directory.iterdir()):
            info = path.lstat()
            row = {"mode": f"{info.st_mode:06o}"}
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                data = os.fsencode(target)
                row.update(type="symlink", size=len(data), target=target,
                           hash="sha256:" + hashlib.sha256(data).hexdigest())
            elif stat.S_ISDIR(info.st_mode):
                row.update(type="dir", size=0)
                walk(path)
            elif stat.S_ISREG(info.st_mode):
                row.update(type="file", size=info.st_size, hash=digest(path))
            else:
                raise AssertionError(f"unexpected merged file type: {path}")
            rows[str(path.relative_to(root))] = row

    walk(root)
    return rows


def copy_upper(source, destination):
    destination.mkdir()
    for path in sorted(source.iterdir()):
        info = path.lstat()
        target = destination / path.name
        if stat.S_ISDIR(info.st_mode):
            copy_upper(path, target)
        elif stat.S_ISCHR(info.st_mode) and info.st_rdev == 0:
            (destination / (".wh." + path.name)).touch()
        elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            shutil.copy2(path, target, follow_symlinks=False)
        else:
            raise AssertionError(f"unexpected upper file type: {path}")
    # Includes user.overlay.opaque and nanosecond timestamps; copying ordinary
    # files also preserves user.overlay.whiteout via copy2.
    shutil.copystat(source, destination, follow_symlinks=False)


if __name__ == "__main__":
    command, source, destination = sys.argv[1:]
    if command == "snapshot":
        Path(destination).write_text(json.dumps(snapshot(Path(source)), sort_keys=True))
    elif command == "copy":
        copy_upper(Path(source), Path(destination))
    else:
        raise ValueError(command)
