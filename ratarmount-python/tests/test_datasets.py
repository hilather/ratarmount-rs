"""Regression: dataset adapters stay lazy, pickle-safe, ordered and disjoint."""
import importlib.util
import io
import pickle
import sys
import tarfile
import types
from pathlib import Path

import pytest

from ratarmount_rs import _datasets
from ratarmount_rs import webdataset as adapter


@pytest.fixture
def shards(tmp_path):
    paths = []
    for shard in range(2):
        path = tmp_path / f"shard-{shard}.tar"
        with tarfile.open(path, "w") as tar:
            for name in ["dir/a.JPG", "dir/a.json", "dir/b.txt.gz", "dir/b.json", "no-extension", "__meta__/info.json"]:
                entry = tarfile.TarInfo(name)
                data = f"{shard}:{name}".encode()
                entry.size = len(data)
                tar.addfile(entry, io.BytesIO(data))
        paths.append(str(path))
    return paths


@pytest.fixture
def fake_torch(monkeypatch):
    """Exercise all adapter logic without downloading PyTorch in wheel CI."""
    data = types.ModuleType("torch.utils.data")
    data.Dataset = type("Dataset", (), {})
    data.IterableDataset = type("IterableDataset", (), {})
    data.get_worker_info = lambda: None
    monkeypatch.setitem(sys.modules, "torch.utils.data", data)
    name = "ratarmount_rs._fake_torch"
    path = Path(adapter.__file__).with_name("torch.py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def test_regression_map_dataset_lazy_pickle_decode_and_filter(shards, fake_torch):
    dataset = fake_torch.RatarDataset(shards[0], pattern="dir/*", extensions="json", decode=bytes.decode)
    assert dataset._archive is None
    restored = pickle.loads(pickle.dumps(dataset))
    assert len(dataset) == len(restored) == 2
    assert dataset[0] == ("/dir/a.json", "0:dir/a.json")
    assert dataset[-1] == ("/dir/b.json", "0:dir/b.json")
    restored = pickle.loads(pickle.dumps(dataset))
    assert restored._archive is None
    assert restored[0] == dataset[0]
    with pytest.raises(IndexError):
        dataset[2]
    dataset.close()
    restored.close()


@pytest.mark.parametrize("workers", [2, 4])
def test_regression_iterable_workers_do_not_duplicate_samples(shards, fake_torch, monkeypatch, workers):
    full = list(fake_torch.RatarIterableDataset(shards, extensions=["json", "JPG"]))
    parts = []
    for worker in range(workers):
        monkeypatch.setattr(fake_torch, "get_worker_info", lambda: types.SimpleNamespace(id=worker, num_workers=workers))
        dataset = fake_torch.RatarIterableDataset(shards, extensions=["json", "JPG"], shuffle=True, seed=9)
        assert dataset._archive is None
        part = list(dataset)
        assert dataset._archive is None
        parts.extend(part)
    assert sorted(parts) == sorted(full)
    assert len(parts) == len(set(parts))


def test_regression_map_dataset_reopens_after_worker_change(shards, fake_torch, monkeypatch):
    dataset = fake_torch.RatarDataset(shards[0])
    first = dataset[0]
    old = dataset._archive
    monkeypatch.setattr(fake_torch, "get_worker_info", lambda: types.SimpleNamespace(id=0, num_workers=2))
    assert dataset[0] == first
    assert old.closed
    assert dataset._archive is not old
    dataset.close()


def test_regression_webdataset_grouping_matches_tarfile(shards):
    expected = []
    for shard, path in enumerate(shards):
        with tarfile.open(path) as tar:
            members = {member.name: tar.extractfile(member).read() for member in tar if member.isfile()}
        expected.extend([
            {"__key__": "dir/a", "__url__": path, "jpg": members["dir/a.JPG"], "json": members["dir/a.json"]},
            {"__key__": "dir/b", "__url__": path, "txt.gz": members["dir/b.txt.gz"], "json": members["dir/b.json"]},
        ])
    assert list(adapter.samples(shards)) == expected
    assert list(adapter.samples(shards, worker_id=0, num_workers=2)) == expected[:2]
    assert list(adapter.samples(shards, worker_id=1, num_workers=2)) == expected[2:]


def test_regression_webdataset_matches_optional_package(shards):
    wds = pytest.importorskip("webdataset", reason="skip: webdataset is optional")
    import webdataset.tariterators as tariterators

    def members():
        for path in shards:
            with tarfile.open(path) as tar:
                for member in tar:
                    if member.isfile() and not member.name.startswith("__"):
                        yield {"fname": member.name, "data": tar.extractfile(member).read(), "__url__": path}
            yield {}
    assert list(adapter.samples(shards)) == list(tariterators.group_by_keys(members()))
    assert list(wds.DataPipeline(lambda: adapter.samples(shards))) == list(adapter.samples(shards))


def test_regression_webdataset_duplicate_suffix_rejected_and_boundaries_flush(tmp_path):
    paths = []
    for i in range(2):
        path = tmp_path / f"{i}.tar"
        with tarfile.open(path, "w") as tar:
            for name in (["a.JPG", "a.jpg"] if i == 0 else ["a.json"]):
                entry = tarfile.TarInfo(name)
                entry.size = 1
                tar.addfile(entry, io.BytesIO(b"x"))
        paths.append(path)
    with pytest.raises(ValueError, match="duplicate suffix"):
        list(adapter.samples(paths[0]))
    assert len(list(adapter.samples([paths[1], paths[1]]))) == 2


@pytest.mark.parametrize("name,expected", [("dir/a.txt.gz", ("dir/a", "txt.gz")), ("a", (None, None)), ("dir/.hidden", ("dir/", "hidden")), ("a.JPG", ("a", "JPG"))])
def test_regression_webdataset_key_semantics(name, expected):
    assert adapter.base_plus_ext(name) == expected


def test_regression_shuffle_and_split_are_deterministic_and_do_not_mutate():
    paths = [str(i) for i in range(20)]
    shuffled = _datasets.shuffle_shards(paths, 13)
    assert shuffled == _datasets.shuffle_shards(paths, 13)
    assert shuffled != paths
    assert paths == [str(i) for i in range(20)]
    assert sorted(shuffled) == sorted(paths)
    assert _datasets.split_by_worker(paths, 1, 3) == paths[1::3]
    for args in [(None, 2), (0, 0), (3, 3)]:
        with pytest.raises(ValueError):
            _datasets.split_by_worker(paths, *args)


def test_regression_real_torch_dataloader_spawn(shards):
    torch = pytest.importorskip("torch", reason="skip: torch is optional and not installed by default")
    from ratarmount_rs.torch import RatarDataset, RatarIterableDataset

    dataset = RatarDataset(shards[0], extensions="json")
    expected = list(dataset)
    loader = torch.utils.data.DataLoader(dataset, batch_size=None, num_workers=2, multiprocessing_context="spawn")
    assert [tuple(sample) for sample in loader] == expected
    iterable = RatarIterableDataset(shards, extensions="json")
    loader = torch.utils.data.DataLoader(iterable, batch_size=None, num_workers=2, multiprocessing_context="spawn")
    assert sorted(tuple(sample) for sample in loader) == sorted(iterable)
    dataset.close()


def test_regression_huggingface_datasets_reads_shard_members(tmp_path):
    datasets = pytest.importorskip("datasets", reason="skip: datasets is optional")
    pytest.importorskip("fsspec", reason="skip: fsspec is optional")
    import zipfile

    # datasets consumes TAR streams. Use ZIP around TAR shards because the
    # Session TAR index exposes small nested TARs as flattened directories.
    path = tmp_path / "shards.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as outer:
        for shard in range(2):
            inner = io.BytesIO()
            with tarfile.open(fileobj=inner, mode="w") as members:
                for sample in range(2):
                    entry = tarfile.TarInfo(f"{shard}-{sample}.txt")
                    data = f"sample {shard}-{sample}".encode()
                    entry.size = len(data)
                    members.addfile(entry, io.BytesIO(data))
            outer.writestr(f"shard-{shard}.tar", inner.getvalue())
    # datasets < 5 loses the target hop when expanding a chained glob.
    if int(datasets.__version__.split(".")[0]) < 5:
        data_files = "ratar://*.tar"
        options = {"storage_options": {"ratar": {"fo": str(path)}}}
    else:
        data_files = f"ratar://*.tar::{path}"
        options = {}
    dataset = datasets.load_dataset(
        "webdataset", data_files=data_files, **options,
        split="train", streaming=True, cache_dir=str(tmp_path / "cache"),
    )
    assert [row["txt"] for row in dataset] == ["sample 0-0", "sample 0-1", "sample 1-0", "sample 1-1"]
