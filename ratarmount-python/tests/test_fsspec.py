"""Regression: chained archive URLs retain range, seek and consumer behavior."""
import io
import pickle
import tarfile

import pytest

fsspec = pytest.importorskip("fsspec", reason="skip: fsspec is optional")
from ratarmount_rs.fsspec import RatarmountFileSystem


def test_regression_entry_point_chaining_and_member_glob(sample, tmp_path):
    zstandard = pytest.importorskip("zstandard", reason="skip: zstandard is unavailable")

    path, payloads = sample
    compressed = tmp_path / "shard.tar.zst"
    compressed.write_bytes(zstandard.ZstdCompressor().compress(path.read_bytes()))
    assert fsspec.get_filesystem_class("ratar") is RatarmountFileSystem
    fs, root = fsspec.core.url_to_fs(f"ratar::{compressed.as_uri()}")
    assert root == ""
    assert fs.ls("/", detail=False) == ["a", "a-", "empty", "link", "z-last-name.bin"]
    assert fs.info("a")["type"] == "directory"
    assert fs.info("a/first.txt")["size"] == len(payloads["a/first.txt"])
    assert fs.glob("a/*.txt") == ["a/first.txt", "a/second.txt"]
    assert "a/first.txt" in fs.find("/")
    with fsspec.open(f"ratar://a/first.txt::{compressed.as_uri()}", "rb") as member:
        member.seek(3)
        assert member.read(4) == payloads["a/first.txt"][3:7]
        assert member.size == len(payloads["a/first.txt"])
    with pytest.raises(IsADirectoryError):
        fsspec.open(f"ratar::{compressed.as_uri()}").open()


@pytest.mark.parametrize("start,end", [(None, None), (1, 6), (-5, None), (None, -2), (20, 5), (-200, 200), (100, None)])
def test_regression_cat_file_ranges_match_python_slices(sample, start, end):
    fs = fsspec.filesystem("ratar", fo=str(sample[0]))
    assert fs.cat_file("a/first.txt", start=start, end=end) == sample[1]["a/first.txt"][start:end]


def test_regression_filesystem_cache_respects_archive_options(sample):
    fo = str(sample[0])
    fs = fsspec.filesystem("ratar", fo=fo)
    assert fsspec.filesystem("ratar", fo=fo) is fs
    other = fsspec.filesystem("ratar", fo=fo, parallelization=2)
    assert other is not fs
    restored = pickle.loads(pickle.dumps(other))
    assert restored.cat_file("empty") == b""
    assert fs.ls("a/first.txt", detail=False) == ["a/first.txt"]
    with pytest.raises(FileNotFoundError):
        fs.open("missing")
    with pytest.raises(FileNotFoundError):
        fs.info("missing")
    with pytest.raises(ValueError, match="read-only"):
        fs.open("new", "wb")
    with pytest.raises(IsADirectoryError):
        fs.cat_file("a")


def test_regression_native_urls_do_not_download_via_python(monkeypatch):
    import ratarmount_rs.fsspec as adapter

    calls = []
    monkeypatch.delenv("HF_ENDPOINT", raising=False)
    monkeypatch.setattr(adapter, "open_archive", lambda fo, **opts: calls.append((fo, opts)))
    for protocol in ("https", "s3", "gs", "az", "hf"):
        fs = RatarmountFileSystem(fo="host/shard.tar.zst", target_protocol=protocol, skip_instance_cache=True)
        assert calls[-1][0] == f"{protocol}://host/shard.tar.zst"
        del fs.archive  # this test double has no close method
    fs = RatarmountFileSystem(
        fo="hf://datasets/org/repo/shard.tar", skip_instance_cache=True,
        target_options={"endpoint": "https://huggingface.co", "token": None},
    )
    assert calls[-1][0] == "hf://datasets/org/repo/shard.tar"
    del fs.archive
    with pytest.raises(NotImplementedError, match="target_options"):
        RatarmountFileSystem(fo="hf://org/repo/shard.tar", target_options={"token": "secret"})
    with pytest.raises(NotImplementedError, match="no download/spool"):
        RatarmountFileSystem(fo="memory://a.tar")
    with pytest.raises(NotImplementedError, match="target_options"):
        RatarmountFileSystem(fo="s3://bucket/a.tar", target_options={"key": "secret"})
    with pytest.raises(ValueError, match="fo must select"):
        RatarmountFileSystem()
    with pytest.raises(NotImplementedError, match="file-like"):
        RatarmountFileSystem(fo=io.BytesIO())


@pytest.fixture
def tables(tmp_path):
    pa = pytest.importorskip("pyarrow", reason="skip: pyarrow is optional")
    import pyarrow.parquet as pq

    output = io.BytesIO()
    pq.write_table(pa.table({"value": [1, 2]}), output)
    path = tmp_path / "tables.tar"
    payloads = {"data.parquet": output.getvalue(), "data.csv": b"value\n1\n2\n", "data.jsonl": b'{"value":1}\n{"value":2}\n'}
    with tarfile.open(path, "w") as tar:
        for name, data in payloads.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
    return path


def test_regression_pyarrow_parquet_member_seek(tables):
    import pyarrow.parquet as pq

    with fsspec.open(f"ratar://data.parquet::{tables.as_uri()}", "rb") as stream:
        assert pq.read_table(stream).to_pydict() == {"value": [1, 2]}


def test_regression_pandas_csv_jsonl_chained_url(tables):
    pd = pytest.importorskip("pandas", reason="skip: pandas is optional")
    assert pd.read_csv(f"ratar://data.csv::{tables.as_uri()}", compression=None)["value"].tolist() == [1, 2]
    assert pd.read_json(f"ratar://data.jsonl::{tables.as_uri()}", lines=True, compression=None)["value"].tolist() == [1, 2]
