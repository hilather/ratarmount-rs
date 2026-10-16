# Python library

The `ratarmount-rs` Python distribution imports as `ratarmount_rs`. It reads
archives through the blocking Rust Session API without FUSE or a
mount point. CPython 3.9+ is supported using PyO3's `abi3-py39` stable ABI.
The native module is `ratarmount_rs._native`; use the public package API.
Type information ships as `__init__.pyi` and `py.typed`.

## Install from source

From the workspace root, with Rust 1.90+ and `uv` installed:

```bash
uv venv --python python3 ratarmount-python/.venv
uv pip install --python ratarmount-python/.venv/bin/python maturin pytest
VIRTUAL_ENV="$PWD/ratarmount-python/.venv" \
  ratarmount-python/.venv/bin/maturin develop -m ratarmount-python/Cargo.toml
ratarmount-python/.venv/bin/pytest ratarmount-python/tests
```

For a wheel, run `ratarmount-python/.venv/bin/maturin build
-m ratarmount-python/Cargo.toml --release`. On Linux, install `patchelf` in the
build environment if it is not already available; maturin uses it to bundle
linked shared libraries (`uv pip install --python
ratarmount-python/.venv/bin/python patchelf`). The version comes from the Rust
workspace. PyPI publication and a multi-platform wheel CI matrix are later
work (AI-PY2); `pip install ratarmount-rs` is not yet the installation path.
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
wrapper serializes each binary stream's position updates. Complete Session
operations on one Archive are also serialized, including consumption of a
ranged reader: backing streams may share a seek position even though Session
is Send + Sync. Waiting for this lock releases the GIL too. Separate Archive
instances can work concurrently. `read()` allocates the requested bytes; prefer bounded reads or a
binary stream for large members, and mmap for eligible zero-copy access.

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

fsspec integration, dataset helpers and wheel CI belong to AI-PY2. The
Python `.mount()` API belongs to AI-PY3 and is not provided here.
