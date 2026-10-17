"""Regression tests for the installed native extension and Python public API."""
import concurrent.futures
import gc
import io
import mmap
import os
import shutil
import subprocess
import tarfile
import threading
import tempfile
import weakref
from pathlib import Path

import pytest

import ratarmount_rs as ratar


def test_regression_ls_stat_metadata(sample):
    path, payloads = sample
    with ratar.open(path) as archive:
        assert sorted(entry.name for entry in archive.ls()) == ["a", "a-", "empty", "link", "z-last-name.bin"]
        entries = archive.ls("/a")
        assert [entry.name for entry in entries] == ["first.txt", "second.txt"]
        entry = archive.stat("/a/first.txt")
        assert isinstance(entry, ratar.Entry)
        assert entry.path == "/a/first.txt"
        assert entry.size == len(payloads["a/first.txt"])
        assert entry.mtime == 1234567890
        assert entry.mode & 0o777 == 0o640
        assert entry.is_file and not entry.is_dir and not entry.is_symlink
        assert archive.stat("/a").is_dir
        assert archive.stat("/link").is_symlink
        with pytest.raises(AttributeError):
            entry.size = 0


def test_regression_paging_over_2000_members_without_duplicates(many):
    path, names = many
    with ratar.open(path) as archive:
        listed = archive.ls()
        assert len(listed) == len(names) == len({entry.path for entry in listed})
        ordered = list(archive.iter(order="archive"))
        assert [entry.name for entry in ordered] == names
        assert len({entry.path for entry in ordered}) == len(names)
        assert [entry.name for entry in archive.iter(order="name")] == sorted(names)


@pytest.mark.parametrize("offset,size", [(0, -1), (0, 0), (7, 4096), (511, 200000), (9999999, 20), (2097400, 1000)])
def test_regression_range_read_returns_bytes_equal_tarfile(sample, offset, size):
    path, _ = sample
    with tarfile.open(path) as expected, ratar.open(path) as archive:
        with expected.extractfile("z-last-name.bin") as member:
            member.seek(offset)
            data = member.read(size)
        result = archive.read("/z-last-name.bin", offset, size)
        assert isinstance(result, bytes)
        assert result == data


@pytest.mark.parametrize("offset,size", [(-1, 2), (0, -2), (-1, -1)])
def test_regression_invalid_range_raises_value_error(sample, offset, size):
    with ratar.open(sample[0]) as archive:
        with pytest.raises(ValueError):
            archive.read("/empty", offset, size)


@pytest.mark.parametrize("operation", ["stat", "ls", "read", "open", "mmap"])
def test_regression_missing_member_is_keyerror_and_ratarmount_error(sample, operation):
    with ratar.open(sample[0]) as archive:
        with pytest.raises(ratar.MemberNotFound) as exc:
            getattr(archive, operation)("/missing")
        assert isinstance(exc.value, KeyError)
        assert isinstance(exc.value, ratar.RatarmountError)


def test_regression_binary_file_readinto_seek_tell(sample):
    path, payloads = sample
    with ratar.open(path) as archive:
        with archive.open("/z-last-name.bin") as member:
            assert isinstance(member, io.IOBase)
            assert member.readable() and member.seekable() and not member.writable()
            assert member.tell() == 0
            assert member.read(13) == payloads["z-last-name.bin"][:13]
            assert member.seek(4999) == 4999
            target = bytearray(1024)
            assert member.readinto(target) == 1024
            assert target == payloads["z-last-name.bin"][4999:6023]
            assert member.seek(-7, os.SEEK_CUR) == 6016
            assert member.seek(-5, os.SEEK_END) == len(payloads["z-last-name.bin"]) - 5
            assert member.read() == payloads["z-last-name.bin"][-5:]
            assert member.read(1) == b""
            assert member.seek(99999999) == 99999999
            assert member.read() == b""
            with pytest.raises(ValueError):
                member.seek(-1)
            with pytest.raises(ValueError):
                member.seek(0, 9)
            with pytest.raises(TypeError):
                member.seek(1.5)
            member.seek(0)
            with pytest.raises(TypeError):
                member.readinto(b"readonly")
            assert member.tell() == 0
            member.seek(-3, os.SEEK_END)
            assert member.read(-2) == payloads["z-last-name.bin"][-3:]
        assert member.closed
        with pytest.raises(ValueError):
            member.read()
        assert not archive.closed
        with archive.open("/a/second.txt") as member:
            assert list(member) == [b"second\n", b"line\n"]
        with pytest.raises(IsADirectoryError):
            archive.open("/a")
        with pytest.raises(IsADirectoryError):
            archive.read("/a")


def test_regression_mmap_unaligned_member_is_zero_copy_and_survives_close(sample):
    path, payloads = sample
    archive = ratar.open(path)
    for name, data in payloads.items():
        view = archive.mmap(name)
        assert isinstance(view, memoryview)
        assert isinstance(view.obj, mmap.mmap)
        assert view.readonly
        assert view == archive.read(name) == data
        # Access the actual exporter: this is a slice of mmap, not bytes copied into a view.
        with tarfile.open(path) as tar:
            offset = tar.getmember(name).offset_data % mmap.ALLOCATIONGRANULARITY
        assert view.obj[offset:offset + len(data)] == data
        with pytest.raises(TypeError):
            view[0:0] = b""
        backing = view.obj
        view.release()
        backing.close()
    held = archive.mmap("a/first.txt")
    archive.close()
    assert held == payloads["a/first.txt"]
    backing = held.obj
    held.release()
    backing.close()


def test_regression_compressed_member_mmap_does_not_copy(sample, tmp_path):
    path, payloads = sample
    compressed = tmp_path / "sample.tar.zst"
    try:
        import zstandard
    except ImportError:
        if shutil.which("zstd") is None:
            pytest.skip("skip: neither zstandard nor zstd CLI is available")
        subprocess.run(["zstd", "-q", str(path), "-o", str(compressed)], check=True)
    else:
        compressed.write_bytes(zstandard.ZstdCompressor().compress(path.read_bytes()))
    with ratar.open(compressed, parallelization=4) as archive:
        assert archive.read("/a/first.txt") == payloads["a/first.txt"]
        with pytest.raises(ratar.NotMappable, match=r"read\(\)"):
            archive.mmap("/a/first.txt")
        assert [entry.path.lstrip("/") for entry in archive.iter()] == list(payloads)


@pytest.mark.parametrize("member", ["/a", "/link"])
def test_regression_non_payload_mmap_rejected(sample, member):
    with ratar.open(sample[0]) as archive:
        with pytest.raises(ratar.NotMappable):
            archive.mmap(member)


def test_regression_archive_iteration_matches_tarfile_order_and_prefix(sample):
    path, _ = sample
    with tarfile.open(path) as tar:
        names = [member.name for member in tar if member.isfile()]
    with ratar.open(path) as archive:
        assert [entry.path.lstrip("/") for entry in archive.iter()] == names
        assert [entry.path for entry in archive.iter(prefix="a")] == ["/a/second.txt", "/a/first.txt"]
        assert [entry.path for entry in archive.iter(prefix="/a/first.txt")] == ["/a/first.txt"]
        assert [entry.path for entry in archive.iter(prefix="/a", order="name")] == ["/a/first.txt", "/a/second.txt"]
        assert [entry.path.lstrip("/") for entry in archive.iter(order="name")] == sorted(names)
        with pytest.raises(ValueError):
            archive.iter(order="random")


def test_regression_extract_skip_replace_and_path_escape(sample, tmp_path):
    path, payloads = sample
    dest = tmp_path / "extracted"
    with ratar.open(path) as archive:
        archive.extract(["a/first.txt"], dest)
        output = dest / "a/first.txt"
        assert output.read_bytes() == payloads["a/first.txt"]
        output.write_bytes(b"changed")
        archive.extract(["a/first.txt"], dest, existing="skip")
        assert output.read_bytes() == b"changed"
        archive.extract(["a/first.txt"], dest, existing="replace")
        assert output.read_bytes() == payloads["a/first.txt"]
        with pytest.raises(ValueError):
            archive.extract([], dest, existing="ask")
        with pytest.raises(ValueError):
            archive.extract(["../outside"], dest)
        archive.extract([], dest, existing="replace")
        for name, expected in payloads.items():
            assert (dest / name).read_bytes() == expected


def test_regression_concurrent_reads_from_eight_threads(sample):
    path, payloads = sample
    barrier = threading.Barrier(8)
    with ratar.open(path) as archive:
        def read(worker):
            barrier.wait(timeout=10)
            with archive.open("z-last-name.bin") as member:
                for i in range(30):
                    offset = worker * 1000 + i * 377
                    assert archive.read("z-last-name.bin", offset, 8000) == payloads["z-last-name.bin"][offset:offset + 8000]
                    member.seek(offset)
                    assert member.read(4096) == payloads["z-last-name.bin"][offset:offset + 4096]
            return worker
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            assert sorted(executor.map(read, range(8))) == list(range(8))


def test_regression_context_manager_closes_files_and_iteration(sample):
    with ratar.open(sample[0]) as archive:
        member = archive.open("/a/first.txt")
        iterator = archive.iter()
        next(iterator)
    assert archive.closed
    archive.close()
    for operation in [lambda: archive.ls(), lambda: archive.stat("/empty"),
                      lambda: archive.read("/empty"), lambda: archive.mmap("/empty"),
                      lambda: archive.open("/empty"), lambda: archive.iter(),
                      lambda: next(iterator), lambda: member.read(), lambda: member.tell(),
                      lambda: member.seek(0), lambda: archive.__enter__()]:
        with pytest.raises(ValueError, match="closed"):
            operation()
    member.close()
    with pytest.raises(RuntimeError):
        with ratar.open(sample[0]) as failed:
            raise RuntimeError("body failed")
    assert failed.closed


@pytest.mark.parametrize("index", [None, "temp", "sidecar", "explicit"])
def test_regression_index_policy_and_temp_cleanup(sample, tmp_path, index):
    path, _ = sample
    explicit = tmp_path / "explicit.sqlite"
    index = explicit if index == "explicit" else index
    temp_dir = Path(tempfile.gettempdir()) / f"ratarmount-session-{os.getpid()}"
    before = set(temp_dir.glob("index-*.sqlite*"))
    with ratar.open(path, index=index, password="unused-plain-tar", parallelization=0) as archive:
        assert archive.read("empty") == b""
        if index in (None, "temp"):
            assert not list(tmp_path.glob("sample.tar.index*"))
            created = set(temp_dir.glob("index-*.sqlite*")) - before
            assert created
    if index in (None, "temp"):
        assert all(not entry.exists() for entry in created)
    if index == explicit:
        assert explicit.exists()
    if index == "sidecar":
        assert list(tmp_path.glob("sample.tar.index*"))


def test_regression_recursive_session_mmap_is_conservatively_rejected(sample):
    with ratar.open(sample[0], recursive=True) as archive:
        assert archive.read("a/first.txt")
        with pytest.raises(ratar.NotMappable):
            archive.mmap("a/first.txt")


@pytest.mark.parametrize("value", [-1, 2**32])
def test_regression_invalid_parallelization_is_value_error(sample, value):
    with pytest.raises(ValueError):
        ratar.open(sample[0], parallelization=value)


def test_regression_archive_deallocation_closes_session(sample):
    temp_dir = Path(tempfile.gettempdir()) / f"ratarmount-session-{os.getpid()}"
    before = set(temp_dir.glob("index-*.sqlite*"))
    archive = ratar.open(sample[0])
    created = set(temp_dir.glob("index-*.sqlite*")) - before
    assert created
    ref = weakref.ref(archive)
    del archive
    gc.collect()
    assert ref() is None
    assert all(not entry.exists() for entry in created)


@pytest.mark.parametrize("url", ["http://host/a.tar", "https://host/a.tar", "s3://bucket/a.tar", "hf://org/repo/a.tar", "restic:/abs/repo"])
def test_regression_split_url_preserves_archive_url(url):
    assert ratar.split_url("ratar://" + url) == url


def test_regression_empty_member_at_aligned_archive_eof_maps_empty_view(tmp_path):
    path = tmp_path / "no-eof-blocks.tar"
    # The final empty member's data offset is exactly the allocation granularity.
    # A zero-length map must use the preceding byte, not map beyond archive EOF.
    granularity = mmap.ALLOCATIONGRANULARITY
    prefix = tarfile.TarInfo("prefix")
    prefix.size = granularity - 1024
    empty = tarfile.TarInfo("empty")
    path.write_bytes(prefix.tobuf() + bytes(prefix.size) + empty.tobuf())
    with ratar.open(path) as archive:
        view = archive.mmap("empty")
        assert view == b""
        backing = view.obj
        view.release()
        backing.close()


@pytest.mark.parametrize("kind", ["tar", "tar.zst", "nested"])
def test_regression_32_threads_read_sibling_payloads_without_cursor_race(tmp_path, kind):
    """Regression: concurrent ranged reads must not consume a sibling's cursor."""
    import io
    import tarfile

    payloads = {f"member-{i}.bin": bytes([i]) * (262144 + i * 509) for i in range(8)}
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w") as tar:
        for name, data in payloads.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
    path = tmp_path / ("outer.tar" if kind == "nested" else "shard." + kind)
    prefix = ""
    if kind == "nested":
        with tarfile.open(path, "w") as tar:
            entry = tarfile.TarInfo("inner.tar")
            entry.size = len(inner.getvalue())
            tar.addfile(entry, io.BytesIO(inner.getvalue()))
        prefix = "inner.tar/"
    elif kind == "tar.zst":
        zstandard = pytest.importorskip("zstandard", reason="skip: zstandard is unavailable")
        path.write_bytes(zstandard.ZstdCompressor().compress(inner.getvalue()))
    else:
        path.write_bytes(inner.getvalue())
    barrier = threading.Barrier(32)
    with ratar.open(path, recursive=kind == "nested") as archive:
        # Trigger lazy nested mounting before the simultaneous member reads.
        assert archive.read(prefix + "member-0.bin", 0, 1) == b"\0"

        def read(worker):
            barrier.wait(timeout=30)
            for turn in range(40):
                name = f"member-{(worker + turn) % 8}.bin"
                offset = (worker * 7907 + turn * 1543) % 230000
                assert archive.read(prefix + name, offset, 16384) == payloads[name][offset:offset + 16384]
                with archive.open(prefix + name) as member:
                    member.seek(offset)
                    assert member.read(8192) == payloads[name][offset:offset + 8192]
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
            list(executor.map(read, range(32)))
