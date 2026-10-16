"""All fixtures are local and require neither a mount nor network access."""
import io
import tarfile

import pytest


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "sample.tar"
    payloads = {
        "z-last-name.bin": bytes(range(256)) * 8193,
        "a/second.txt": b"second\nline\n",
        "a/first.txt": b"first\x00payload",
        "a-/adjacent.txt": b"outside a prefix",
        "empty": b"",
    }
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        directory = tarfile.TarInfo("a")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        for name, data in payloads.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mtime = 1234567890
            entry.mode = 0o640
            archive.addfile(entry, io.BytesIO(data))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "a/first.txt"
        archive.addfile(link)
    return path, payloads


@pytest.fixture
def many(tmp_path):
    path = tmp_path / "many.tar"
    # Reverse name order makes archive-order paging distinguishable from name order.
    names = [f"entry-{i:04}.bin" for i in reversed(range(2107))]
    with tarfile.open(path, "w") as archive:
        for name in names:
            data = name.encode()
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return path, names
