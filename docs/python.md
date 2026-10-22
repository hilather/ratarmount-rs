# Python library

Everything ratarmount can open, from Python and without FUSE: open an archive
or a remote URL, read members by name, map uncompressed members with zero
copies, iterate WebDataset samples, feed a PyTorch `DataLoader`, read through
fsspec as `ratar://`, publish indexes, and mount through the installed CLI when
a real directory is needed. Wheels are built in CI for Linux x86_64 and
aarch64 and for macOS arm64; publication to PyPI is pending, so install a
release artifact or build from source as shown below.


The `ratarmount-rs` Python distribution imports as `ratarmount_rs`. It reads
archives through the blocking Rust Session API without FUSE or a
mount point. CPython 3.9+ is supported using PyO3's `abi3-py39` stable ABI.
The native module is `ratarmount_rs._native`; use the public package API.
Type information ships as `__init__.pyi` and `py.typed`.

## Install from source

From the workspace root, with Rust 1.90+ and `uv` installed:

```bash
export UV_CACHE_DIR="/tmp/ratarmount-uv-cache"
uv venv --python python3 ratarmount-python/.venv
uv pip install --python ratarmount-python/.venv/bin/python maturin pytest fsspec zstandard patchelf
PATH="$PWD/ratarmount-python/.venv/bin:$PATH" VIRTUAL_ENV="$PWD/ratarmount-python/.venv" \
  ratarmount-python/.venv/bin/maturin develop -m ratarmount-python/Cargo.toml
ratarmount-python/.venv/bin/pytest ratarmount-python/tests
```

For a wheel, run `ratarmount-python/.venv/bin/maturin build
-m ratarmount-python/Cargo.toml --release`. On Linux, install `patchelf` in the
build environment if it is not already available; maturin uses it to bundle
linked shared libraries (`uv pip install --python
ratarmount-python/.venv/bin/python patchelf`). The version comes from the Rust
workspace. The Python wheels workflow builds abi3 wheels for manylinux_2_28
x86_64/aarch64 and macOS 14+ arm64, plus an sdist, and tests installed wheels in
fresh venvs on Linux x86_64 and aarch64 and macOS arm64. Linux wheels require glibc 2.28+;
linked libraries such as libarchive are bundled by maturin on Linux and
delocate on macOS. Library reads need no FUSE; optional mounting uses a separate CLI.
The workflow uploads build artifacts only; PyPI publishing is not enabled, so
`pip install ratarmount-rs` is not yet the installation path.
The Python crate is outside the workspace's default build members and no
other crate depends on it. Its default features do not compile PyO3.

Rust embedders can build the rlib with `--features python` and explicitly
initialize Python, or use `--features embedding` for `auto-initialize`.
Wheels use `--features extension-module`, without `auto-initialize`. Keep
`embedding` and `extension-module` as separate build modes. The obsolete
source branch's rustc/header probing build script is not needed.

## Open and inspect

```python
import ratarmount_rs

with ratarmount_rs.open("shard.tar", parallelization=4) as archive:
    for entry in archive.ls("/"):
        print(entry.path, entry.size, entry.is_dir)
    entry = archive.stat("/samples/0001.json")
    data = archive.read(entry.path, offset=0, size=4096)
    with archive.open(entry.path) as member:
        member.seek(10)
        buffer = bytearray(128)
        count = member.readinto(buffer)
```

`open(path_or_url, *, password=None, index=None, recursive=False,
parallelization=1)` accepts strings and filesystem path objects. Local paths
and URL schemes are passed to Session: for example `https://host/shard.tar`,
`s3://bucket/shard.tar`, and `restic:/absolute/repository`. New schemes such
as `hf://` become usable when their Session backend is available. An optional
`ratar://` prefix is stripped without splitting an inner archive URL.
Remote credentials follow the same environment and configuration as Session;
`password` supplies an archive decryption password.

`index=None` and `index="temp"` create a disk-backed temporary index that is
removed on close. `index="sidecar"` uses the archive's sibling index and
reports an error if it cannot be written. Any other string or path object
selects an explicit index file. `recursive=True` enables nested archives.
`parallelization=0` selects the available CPU count; positive integers select
codec thread counts. Sequential codecs remain sequential.

`ls(path="/")` returns all immediate children, paging internally without
duplicate names. `stat(path)` returns complete metadata. `Entry` has read-only
`name`, `path`, `is_dir`, `is_file`, `is_symlink`, `size`, `mtime`, and `mode`
properties. Paths start with `/`. Sizes are bytes; modes include Unix type
bits. `mtime` is Unix seconds, or `None` when cheap listing/iteration rows do
not carry it; call `stat` when a timestamp is needed.

`read(path, offset=0, size=-1)` returns `bytes`. `size=-1` reads through EOF;
zero reads nothing. Negative offsets and sizes below -1 raise `ValueError`.
Reads beyond EOF return empty bytes and ranges crossing EOF return the
remaining bytes. `open(path)` returns a readable, seekable binary file object
supporting `read`, `readinto`, `seek`, `tell`, iteration and context management.
Each file has its own position and retains a reference to its parent archive;
the archive must remain open. Closing the file leaves the archive open.

## Zero-copy mapping

```python
with ratarmount_rs.open("weights.tar") as archive:
    view = archive.mmap("/model.safetensors")
    # view is read-only and view.obj is a Python mmap.mmap, not a bytes copy.
    try:
        consume_buffer(view)
    finally:
        mapping = view.obj
        view.release()
        mapping.close()
```

`mmap(path)` returns a `memoryview` of a read-only `mmap.mmap`. The mapping's
file offset is aligned to `mmap.ALLOCATIONGRANULARITY`; the view slices away
the alignment prefix, so it exposes exactly the member bytes, including an
empty view for an empty member. No payload copy is made. Consumers must
accept the buffer protocol to preserve zero-copy behavior.

Mapping is available only when `Session.member_extent` returns an extent:
top-level, local, uncompressed, contiguous regular TAR payloads. Compressed
TAR (including `.tar.zst`), sparse files, links, directories, remote archives,
nested payloads, recursive sessions and other formats raise `NotMappable`
with a suggestion to use `read()`. There is no silent copying fallback.

The mapping owns its backing memory independently of the Archive; closing
the Archive does not invalidate it. Keep the backing archive **unchanged**
for the entire mapping lifetime. Session's extent does not pin an inode
between querying the range and opening the file. Release all exported views
before explicitly closing their mmap. Releasing a view alone does not close
an mmap still held elsewhere.

## Iterate and extract

```python
with ratarmount_rs.open("shard.tar.zst") as archive:
    for entry in archive.iter(prefix="/samples", order="archive"):
        process(entry.path, archive.read(entry.path))
    archive.extract(["samples/0001.json"], "output", existing="skip")
    archive.extract([], "output", existing="replace")  # all payloads
```

`iter(prefix="/", order="archive")` is a lazy iterator over regular payload
files. Prefix matching follows path components (`/a` does not include `/ab`).
Archive order uses `Session.iter_by_offset_page` with bounded keyset pages,
returns newest versions in logical/decompressed header order, and excludes
directories, symlinks, TAR hardlinks and generated entries. It requires a
disk-backed SQL catalog; live folder sources or sources with no catalog raise
`RatarmountError`. It walks the outer catalog, not recursively mounted
AutoMount catalogs. Keep the catalog unchanged during iteration.

`order="name"` walks directory listings in full path order and includes
regular-file hardlinks. It buffers directory entries in a heap as needed;
it does not sort a full archive catalog. It can traverse nested directories
when recursive mode makes them available. Symlinks are not traversed.

`extract(members, dest, *, existing="skip")` streams members to disk through
Session. Empty `members` means all payloads. `existing="skip"` preserves
existing paths; `"replace"` replaces files. Path escapes and intermediate
symlink directory escapes are rejected. Use relative member names for
extraction. Session performs safe temporary-file publication, not Python
`tarfile.extractall`.

## Threads, lifetime and errors

An Archive can be shared by Python threads. All blocking native Session
operations, including open, reads, listing, lookup, paging, extraction,
extent inspection and final Session destruction, release the GIL. The
wrapper serializes each binary stream's position updates. Session I/O on a
shared Archive runs concurrently using independent member readers; no
per-Archive operation lock is held. A small lifecycle lock protects the Session
reference during close. `read()` allocates the requested bytes; prefer bounded
reads or a binary stream for large members, and mmap for eligible zero-copy access.

`close()` is idempotent. Context exit closes even on exceptions. After close,
new archive operations and member stream operations raise `ValueError`;
in-flight native operations may finish using their existing Session
reference. Live mmap views remain usable subject to the backing-file rules.
Dropping an unused Archive also releases its Session.

`RatarmountError` is the base library error. `MemberNotFound` inherits both
`KeyError` and `RatarmountError` (also used for a missing input archive).
`BadPassword` means a password was required or rejected. `NotMappable`
reports an ineligible extent. Session path escapes and invalid arguments
raise `ValueError`; directory reads raise `IsADirectoryError`. Unsupported
formats, corrupt indexes, cancellation, write-permission and other engine
errors raise `RatarmountError` with the engine detail. Standard Python I/O
and mmap errors retain their usual types.

### Import and checked SQLite opens

Overlay databases are opened through checked SQLite opens, which need
wrappers around the `open` and `stat` calls of the SQLite bundled in
`_native` (#151). The wrappers are installed when the module loads. If the
process has one thread at that point, a load-time constructor installs them.
If other threads are already running, the module installs them into its
private SQLite as its first step, before it publishes anything. That is safe
only because the wheel exports no `sqlite3_*` symbol, and the wheels workflow
audits every repaired wheel for that (`packaging/audit_native_exports.py`).
On Linux and macOS (64-bit x86_64/aarch64, glibc or macOS), if neither path
can install the wrappers, `import ratarmount_rs` raises `ImportError` naming
the reason; nothing from the module is usable then. On Windows and other
platforms the module imports, and checked opens refuse or use the Windows
path-type check. A Rust program that embeds the rlib (`--features embedding`)
gets only the load-time constructor; threads started before it loads leave
checked opens refusing, and if that program also registers `_native` (for
example through `wrap_pymodule!` or the inittab), its import raises the same
`ImportError`. A wheel you build yourself from the sdist is not audited.
Before it installs into its private SQLite, the module also checks its own
image at run time. On Linux (glibc, 64-bit x86_64/aarch64) it reads every
defined, externally visible dynamic symbol of `_native` and refuses (the
import raises `ImportError`) if any name starts with `sqlite3` (any case),
or if the dynamic symbol table cannot be read completely (a malformed table,
a pointer it cannot place, a work limit). On macOS the check refuses only an
image that itself exports `sqlite3_libversion`; the wheel audit is the full
check there. Neither check sees an entry point that something else published
before the module initialized; that is still the caller contract of the
private-instance path (#192).

Python's own `sqlite3` module may load a different SQLite library than the
one inside `_native`; the wheel's SQLite is private, so the two are separate
SQLite instances. Do not open the same database file (an overlay database, an
index sidecar) through both at the same time in one process (#154): each
instance keeps its own lock bookkeeping, and closing a connection of one can
release the POSIX locks the other holds ([SQLite: multiple copies of SQLite
in one application](https://www.sqlite.org/howtocorrupt.html#multiple_copies_of_sqlite_linked_into_the_same_application)).
Hiding `_native`'s symbols keeps the checked-open wrappers out of the other
instance; it does not make the two share locks. See the platform table in
[sandbox.md](sandbox.md#checked-overlay-database-opens-by-platform).

`ratarmount_rs._native._checked_open_status()` is a diagnostic. It returns a
dict with `installed`, `why` (`"SingleThread"` or `"PrivateInstance"`),
`threads_at_install`, `exports_checked` (how many exported symbols the Linux
private-instance check read; `None` for the single-thread constructor and on
macOS), `status`, `detail` and `constructor` (what the load-time constructor
saw, such as `"AbstainedThreads(Some(2))"`). It installs nothing.

## Mount from Python

```python
with ratarmount_rs.mount(
    ["base.tar.zst", "extra.tar"], "mnt", write_overlay="changes",
    readonly_globs=[".git/**", "tests/**"], quota="2G", uid=1000, gid=1000,
) as mounted:
    print(mounted.path, mounted.alive)
    # Ordinary filesystem access through mnt/.

with ratarmount_rs.open("shard.tar", recursive=True) as archive:
    with archive.mount("mnt", overlay_tmpfs="512M", passthrough="off"):
        train_from_directory("mnt")
```

`mount(source_or_sources, mountpoint, *, write_overlay=None,
overlay_tmpfs=False, recursive=False, options="", passthrough="auto",
readonly_globs=None, quota=None, uid=None, gid=None, foreground=False,
detach=False, timeout=30, password=None, parallelization=1)` requires Linux or
macOS and a separately installed FUSE-enabled **ratarmount CLI**. It finds
`ratarmount` on PATH, or uses the executable selected by `RATARMOUNT_BIN`.
The wheel does not link ratarmount-fuse or libfuse: subprocess supervision
keeps FUSE dependencies out of wheel repair and lets ordinary library reads
work without a host FUSE installation. No extension `fuse` feature is needed.
Other platforms raise `NotImplementedError`; a missing executable raises
`FileNotFoundError`. FUSE/CLI startup failures raise `RatarmountError`.

The child always receives `--foreground` so Python owns its lifetime;
`foreground` is accepted for CLI compatibility and does not block the Python
call. The call waits for the OS to report a live mount, up to `timeout`
seconds, before returning `Mount`. Timeout raises `TimeoutError` and reaps
the child. `.path` is an absolute string; `.alive` checks both the child and
mountpoint; `.wait(timeout=None)` waits for child exit and returns its status
without unmounting. `.unmount()` invokes the CLI's platform-specific unmount
path, waits for shutdown, and is idempotent after success. Unmount failures
raise an error and can be retried.

Context exit unmounts explicitly. Garbage collection and normal interpreter
exit also unmount, unless `detach=True`. Detached handles can still be
explicitly unmounted or used as context managers. Cleanup cannot run after a
forced process termination. Keep the mount handle alive while using the
filesystem. Closing an Archive does not close a mount created from it:
`Archive.mount` opens the source independently through the CLI, inheriting
password, recursive and parallelization settings unless overridden. Relative
archive paths are anchored when `open()` is called.

`options` is the comma-separated FUSE `-o` string; `uid`/`gid` append ownership
options. `write_overlay` and `overlay_tmpfs` are mutually exclusive.
`overlay_tmpfs=True` uses the CLI default cap, or pass a size such as `"512M"`.
`readonly_globs` (a string or iterable) and `quota` require an overlay. The
CLI validates sizes, policies and host capabilities. Unknown keyword options
raise `TypeError`; there is no arbitrary argv passthrough.

Credentials follow the CLI's inherited environment and configuration (for
example `HF_TOKEN` or the cloud SDK environment). Passwords use a private
mode-0600 temporary file, never argv. Password strings containing newline,
CR or NUL are rejected because the CLI reads newline-separated passwords.
Credential-bearing URLs, query strings (including signed URLs), fragments,
and credential-like FUSE options are rejected by these subprocess APIs.
CLI diagnostics are kept private; exceptions report the operation and exit
status without echoing credentials. Archive wrappers retain an explicitly
provided password for these operations until `close()`.

## Publish indexes

```python
with ratarmount_rs.open("shard.tar") as archive:
    published = archive.index.publish()  # shard.tar.index.ptr + immutable blob
    published = archive.index.publish("published/shard.tar.index.sqlite")
    print(published.index_id, published.urls)

    # The remote archive must already exist and match the local archive bytes.
    published = archive.index.publish(
        "hf://datasets/org/data/shard.tar", revision="main", create_pr=True,
    )
    print(published.commit, published.pull_request_url)
```

`Archive.index.publish(destination=None, *, revision=None, create_pr=False)`
and `ratarmount_rs.publish_index(archive, ...)` use `ratarmount --publish-index`
or `--publish-index-to`. They require the separate CLI on every platform;
publication itself does not mount FUSE. The CLI builds and validates a private
disk index from the source with the Archive's recursive/password/parallelization
options; the Archive's active index is left alone. This can repeat an archive
scan. Publication uses the CLI's existing validation, atomic local publication,
blob-before-pointer object-store uploads and HF commit implementation.

With no destination, a local archive gets `archive.index.sqlite`,
`archive.index.ptr` and `archive.index.<index_id>.sqlite`. An explicit local
destination names the SQLite file: a `.index.sqlite` suffix is replaced for
pointer/blob names; otherwise `.index.ptr` and `.index.<id>.sqlite` are appended
to that exact destination. Remote `hf://`, `s3://`, `gs://` and `az://`
destinations name the **existing archive**, with sibling pointer/blob names.
`revision` and `create_pr` are HF-only. Credentials use the same environment
and configuration as the CLI and native remote backend; no Python token
parameter is accepted.

The frozen `PublishedIndex` result contains `index_id`, `pointer_url`,
`blob_url`, `urls` (pointer and blob), `commit` and `pull_request_url` (optional).
Local locations are absolute paths; cloud locations use their native scheme.
For HF, native readback uses the commit reported by the CLI, including PR
commits, and returns HTTP resolve URLs pinned to that commit. Remote readback
uses the existing Rust authentication and range readers, with the GIL released.
If publication succeeds but pointer readback fails, `RatarmountError` explicitly
reports that distinction; the upload may already be visible. Object-store
readback observes the current pointer, so serialize concurrent publications
to the same archive when correlating results. Keep source bytes unchanged
during publication, just as during native reads/mapping.

## fsspec

Install `fsspec` alongside the built wheel (or use its `[fsspec]` extra).
The distribution registers protocol `ratar` through the `fsspec.specs` entry
point; no call to `register_implementation` is needed. URLs follow
[fsspec's archive chaining](https://filesystem-spec.readthedocs.io/en/latest/features.html#url-chaining):

```python
import fsspec

fs = fsspec.filesystem("ratar", fo="/data/shard.tar.zst")
print(fs.ls("/", detail=True))
print(fs.glob("samples/*.json"))
print(fs.cat_file("samples/0001.json", start=10, end=100))

with fsspec.open("ratar://samples/0001.json::file:///data/shard.tar.zst", "rb") as f:
    f.seek(10)
    print(f.read(90))

# The bare chain selects the filesystem root, which is a directory.
fs, root = fsspec.core.url_to_fs("ratar::file:///data/shard.tar.zst")
print(fs.ls(root))
```

Member paths are relative to the archive root. `ratar://archive.tar::member`
is not supported. `ratar::file:///path/a.tar.zst` and
`ratar::hf://datasets/org/name/shards/a.tar.zst` select an archive filesystem;
include a member (or a glob) in the first component to open files.
Calling `fsspec.open` on a bare chain raises `IsADirectoryError` on opening.

The constructor accepts `fo`, `target_protocol`, `target_options`, and the
Archive options `password`, `index`, `recursive`, `parallelization`. For example,
`fsspec.filesystem("ratar", fo="bucket/a.tar", target_protocol="s3")`.
Local targets and native remote URLs (HTTP(S), S3, GS, AZ, HF, and the other
Session schemes) go directly to Rust. The HF backend must be available in the
installed native build; this adapter does not implement HF transport itself.
Chained URLs may require the target protocol's Python plugin for fsspec to
parse the chain; using `fo` directly avoids that parser requirement.
Credentials follow Session's environment/configuration. `target_options` that
require translation raise `NotImplementedError` because Python credentials/options cannot currently be
translated to Session. HF defaults injected by `datasets` (`token=None` and
an endpoint equal to the native default or `HF_ENDPOINT`) are accepted; explicit
Python tokens or different endpoints are rejected. Set native credentials
through the environment instead. Other fsspec targets (such as
`memory://`) and file objects also raise `NotImplementedError`; there is no
Python download or temporary spool fallback.

The adapter supports `ls(detail=...)`, `info`, seekable binary/text `open`,
`cat_file` ranges (including negative slice bounds), and default `find`/`glob`.
Missing members raise `FileNotFoundError`; writes are rejected. Fsspec's
instance cache reuses an opened Archive for the same constructor arguments
within a process/thread. Use `skip_instance_cache=True` for an independent
instance. Close the filesystem when finished, and call
`RatarmountFileSystem.clear_instance_cache()` before recreating a closed cached
instance. Treat the backing archive as unchanged during an instance's lifetime.

```python
import pandas as pd
import pyarrow.parquet as pq

frame = pd.read_csv("ratar://data.csv::file:///data/tables.tar.zst", compression=None)
records = pd.read_json("ratar://data.jsonl::file:///data/tables.tar.zst", lines=True, compression=None)
with fsspec.open("ratar://data.parquet::file:///data/tables.tar.zst", "rb") as f:
    table = pq.read_table(f)
```

These consumers are covered by optional integration tests. PyArrow and pandas
are optional and are not imported by `ratarmount_rs`. Explicit `compression=None`
prevents older pandas from inferring compression from the outer archive suffix.

### Hugging Face datasets

The `datasets` WebDataset builder needs raw TAR shard streams. If an outer
archive contains TAR shards, select those members:

```python
from datasets import load_dataset

# Tested with a local ZIP containing two TAR shards.
rows = load_dataset(
    "webdataset",
    data_files="ratar://*.tar::/data/shards.zip",
    streaming=True,
    split="train",
)

# Equivalent Hub form; untested against the live Hub, requires the HF backend.
rows = load_dataset(
    "webdataset",
    data_files="ratar://*.tar::hf://datasets/org/name/shards.zip",
    streaming=True,
    split="train",
)
```

For `datasets` older than version 5 (including versions available on Python
3.9), glob expansion loses chained targets. Supply `fo` via storage options:

```python
rows = load_dataset(
    "webdataset", data_files="ratar://*.tar",
    storage_options={"ratar": {"fo": "/data/shards.zip"}},
    streaming=True, split="train",
)
```

Both forms are covered by the installed-wheel tests on Python 3.9 and 3.12.
Use a plain absolute local target in the chained example: `datasets` 5.1 normalizes
`file:///` hops incorrectly when constructing its streaming iterator.

The proposed `datasets.load_dataset("webdataset", data_files="ratar::hf://...")`
form selects a directory, so it cannot supply the raw TAR stream the builder
requires. Small nested TARs inside an outer TAR are flattened into directories by
Session, even without recursive mode; use a ZIP container when selecting raw
TAR shard members. For samples directly inside a Hub TAR shard, use its native
`hf://` URL with `datasets`, or the sample iterator below to read through Rust.

## PyTorch datasets

PyTorch is optional: install it separately, or request the wheel's `[torch]`
extra. Importing `ratarmount_rs` does not import torch.

```python
from torch.utils.data import DataLoader
from ratarmount_rs.torch import RatarDataset, RatarIterableDataset

dataset = RatarDataset("shard.tar.zst", pattern="samples/*", extensions=["jpg", "json"])
path, data = dataset[0]
text = RatarDataset("shard.tar", extensions="txt", decode=bytes.decode)

stream = RatarIterableDataset(["shard-0.tar.zst", "shard-1.tar.zst"], shuffle=True, seed=42)
loader = DataLoader(stream, batch_size=None, num_workers=2, multiprocessing_context="spawn")
for path, data in loader:
    consume(path, data)
```

Both return `(path, bytes)` or `(path, decode(bytes))`. Paths start with `/`;
`pattern` matches without that leading slash using shell-style `fnmatch`;
`extensions` is a string or sequence, with or without dots, and is case
sensitive. Map datasets build their filtered path list on first `len`/indexing.
Iterable datasets use `Archive.iter(order="archive")` without collecting the
catalog. Pass `archive_options={"parallelization": 4}` to either constructor.

Archives open lazily in each worker and are excluded from pickles. The map
path list can be pickled; decode callables must also be pickleable. Prefer
spawned workers for native libraries, and guard DataLoader startup with
`if __name__ == "__main__":` in scripts. Iterable workers split shards; when
there are fewer shards than workers, they divide the member sequence instead
(each worker scans the catalogs, but only reads its assigned payloads).
A fixed shuffle seed gives every worker the same shard order. Call `close()`
on a map dataset when finished; iterable completion/closing releases its archive.
Torch tests use fake base classes in default CI, with a real spawned DataLoader
test when torch is installed.

## WebDataset samples

```python
from ratarmount_rs.webdataset import samples, shuffle_shards, split_by_worker

for sample in samples(["shard-0.tar.zst", "shard-1.tar.zst"], shuffle=True, seed=42):
    print(sample["__key__"], sample["jpg"], sample["json"])

# Optional webdataset integration: use a fresh iterator factory for each epoch.
import webdataset as wds
pipeline = wds.DataPipeline(lambda: samples(["shard.tar.zst"]))
```

`samples` does not require torch or webdataset. It emits raw dictionaries with
`__key__`, `__url__`, and byte fields grouped by consecutive keys in archive
order. Following [WebDataset tariterators](https://github.com/webdataset/webdataset/blob/main/src/webdataset/tariterators.py),
it splits the basename at its first dot: `dir/001.JPG` becomes key `dir/001`
and field `jpg`; `001.txt.gz` has field `txt.gz`. Extensionless and metadata
files are ignored; duplicate suffixes in a sample raise `ValueError`. Shard
boundaries always flush a sample. Session exposes newest versions of duplicate
member paths; overwritten TAR history is not emitted, unlike a raw tar stream.

`shuffle_shards(paths, seed)` returns a shuffled copy. `split_by_worker(paths,
worker_id, num_workers)` returns round-robin shards; without explicit IDs it
uses torch's worker info when available. `samples` applies worker splitting by
default; use `split_workers=False` to disable it or supply explicit IDs. Workers
with no assigned shards yield nothing. This iterator does not partition by
distributed rank; split a shard list by rank before passing it to workers.
Use `archive_options` to pass options to `ratarmount_rs.open`.
