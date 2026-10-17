# Hugging Face Hub (`hf://`)

Mount Hub files, repositories, or directories through the blocking HTTP reader:

```sh
ratarmount 'hf://datasets/org/name@v1/shards/00001.tar.zst' mnt/
ratarmount -r 'hf://datasets/org/name@v1' mnt/
ratarmount 'hf://org/model@main' model/
ratarmount 'hf://spaces/org/demo@main/assets' assets/
```

These use the [Hub filesystem path convention](https://huggingface.co/docs/huggingface_hub/en/package_reference/hf_file_system):
`hf://[datasets/|spaces/]<org>/<name>[@<revision>]/<path>`.
Models have no prefix. With no path the whole repository is mounted. A directory
path mounts only that subtree. Parquet, JSONL, images, configuration, and model
weights are ordinary lazy files; `-r` also opens archive shards as directories.
The existing nested-format support matrix applies to those shards.

Legacy model IDs without an owner work as `hf://gpt2`. To address a file in a
legacy repository, supply the revision: `hf://gpt2@main/config.json`. Otherwise
two components mean `org/name`. Names, revisions, and paths remain case sensitive.
Paths support percent-encoded UTF-8; queries, fragments, traversal components,
and empty internal path components are rejected.

## Revision pinning and provenance

The default revision is `main`. Branches, tags, and full commit SHAs work.
`@refs/pr/3` and `@refs/convert/parquet` are recognized without escaping their
slashes; their `%2F` forms work too. Other revision names containing slashes
must encode them, for example `@feature%2Fnew/config.json`.

Each mount resolves the revision once using the Hub revision API. Every listing,
file open, retry, and index-sibling request then uses that commit SHA. The startup
line prints the SHA. The root and entries served directly by the Hub source
expose `user.hf.commit` (nested archive sources may have their own xattrs):

```sh
getfattr -n user.hf.commit mnt/
```

Writable archive indexes record `hf.commit` and `hf.resolve_url` in their SQLite
metadata. Folder listing caches also record the commit. Read-only indexes must
already have matching provenance; rebuild an older index once if it lacks it.
An explicitly reused index path is rebuilt when its endpoint, commit, or file
changes. A branch or tag can move between mounts: use the printed **full SHA** in
the URL to obtain the same bytes on a later mount. A pinned mount does not follow
new commits while it is open.

## Recursive repository indexes and cold TAR scans

`-r hf://datasets/org/name` and repository subfolder mounts open archive shards
on first access. Mounting or listing a folder does not probe every shard's index.
For each accessed shard, ratarmount discovers `.index.ptr` and its immutable
`.index.<sha256>.sqlite` blob, then the well-known `.index.sqlite` siblings,
at the repository's pinned commit. It validates the index against that shard's
size and content fingerprints and caches the metadata. Invalid or missing
sidecars fall back to building the index. `--recreate-index` skips discovery.
Each shard has its own local index; a folder-level explicit index path is not
shared among shards. Archives inside a shard still use the normal nested reader.
HTTP autoindex and S3 folder mounts use their existing remote sibling discovery
through the same lazy archive opener.

Cold uncompressed TAR scans recognize repeated nearby forward header reads.
After three forward skips of at most 1 MiB, the HTTP reader fetches one aligned
4 MiB window (the configured range-cache chunk size when available), reusing it
across seeks. Isolated probes and large sparse jumps remain small Range requests.
The window also works without a persistent cache or ETag, is private to its
reader, and falls back to exact reads when the memory budget cannot reserve it.
The shared HTTP connection pool and resolved CDN URL remain in use.

A 3,000-member, 99,841,024-byte mock TAR measured 9,005 → 55 Range GETs
for HTTP without an ETag, and 9,006 → 29 for pinned HF with chunk caching.
The parser performs GNU incremental detection, indexing, and nested-TAR magic
probes; cached chunks serve these repeated small reads. On 2026-10-16, the
public Oxford pet shard opened through its repository's published index in
2.28 seconds and rebuilt cold in 26.51 seconds (debug build, this machine/network).
These timings are observations, not a network latency guarantee.

The opt-in network/timing regression reads the public Oxford pet dataset:

```sh
RATARMOUNT_TEST_HFREPO=1 cargo test -p ratarmount-session --lib regression_hf_repo_live -- --ignored --nocapture
```


## Authentication and mirrors

Token lookup order is:

1. `HF_TOKEN`, then legacy `HUGGING_FACE_HUB_TOKEN` when `HF_TOKEN` is unset or empty.
2. The file named by `HF_TOKEN_PATH`.
3. `$HF_HOME/token`.
4. `$XDG_CACHE_HOME/huggingface/token`, or `~/.cache/huggingface/token` when
   `XDG_CACHE_HOME` is unset.

The selected token file overrides later locations, even if missing. Leading and
trailing whitespace and embedded CR/LF are removed. A whitespace-only environment
token falls back to the token file. `HF_HOME` and `HF_TOKEN_PATH` expand `~`,
`$VAR` and `${VAR}`, matching upstream
[constants.py](https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/constants.py)
and [_auth.py](https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/utils/_auth.py).
Tokens are kept out of URLs and logs. Bearer
credentials go only to the configured Hub endpoint; redirects to the CDN drop
authentication, including when a signed URL expires and is resolved again.
Unrelated `RATARMOUNT_HTTP_*` Basic-auth and cookie settings do not apply to Hub
files. Private/gated 401/403 errors identify the repository and token sources;
gated repositories may additionally require accepting their access terms.

`HF_ENDPOINT` defaults to `https://huggingface.co`. Set it to a compatible mirror
or drop-in Hub API; HTTP(S) endpoints with a base path are supported. The backend
uses `/api/{models|datasets|spaces}/{repo}/revision/{revision}`, the recursive
tree API, and the usual commit-pinned `/resolve/` URLs. Mirrors must implement
those APIs. A plain-HTTP endpoint sends the token in cleartext; an authenticated
mount logs this warning once per process. Use HTTPS for remote endpoints.
No `hf-hub`, reqwest, or asynchronous runtime is needed.

## Listings, indexes, and rate limits

Listings use `recursive=true` without `expand`, follow `Link: ...; rel="next"`, and
publish the cache only after the entire listing has succeeded. Pagination cycles,
links leaving the endpoint, malformed entries, and excessive listings fail
closed. Limits are one million entries, 256 MiB of JSON, and 1,000,001 pages
(the page guard also permits mirrors returning one entry per page).
Git blob IDs, LFS metadata, and `xetHash` fields are retained in the persisted JSON.

Verified against the public Hub on **2026-10-16**, without `expand`:
`HuggingFaceFW/fineweb-edu` at `87f09149ef4734204d70ed1d046ddc9ca3f2b8f9`
returned **1,000 entries** on its first page with a next-page Link. File entries
retained `path`, `type`, `size`, `oid`, `lfs.{oid,size,pointerSize}` and `xetHash`
(883 entries had `xetHash`). The smaller Xet fixture below returned 35 entries,
14 with `xetHash`. Expanded commit/security metadata is unnecessary for mounting
and reduces the Hub's page size to about 50.

Complete listings are cached in memory and at
`$XDG_CACHE_HOME/ratarmount/hf-tree-v1/` (default `~/.cache/ratarmount/hf-tree-v1/`),
next to the ratarmount index caches. `RATARMOUNT_HF_TREE_CACHE` overrides that
directory. Keys include endpoint, repository type, repository ID, commit, and
subdirectory. Remounting the same directory snapshot still resolves the revision once but
makes **zero tree requests**. An unwritable cache only disables persistence.
The listing cache currently has no automatic eviction; removing it is safe when
mounts are closed. Budget up to 256 MiB of JSON per cached snapshot/subdirectory,
plus a small identity envelope; multiple commits or overlapping subdirectories
consume separate files and can grow disk usage without bound. It contains
filenames/metadata, not tokens or file contents.

[Hub API requests are rate limited](https://huggingface.co/docs/hub/api).
Large cold listings can require many pages; warm listing reuse avoids repeating
that traffic. Revision and tree API requests retry HTTP 429 at most three times,
honoring `Retry-After` seconds or HTTP dates with a five-second maximum wait per
retry (one second if absent/invalid). Exhaustion fails without caching a partial
listing. Data reads and index-sidecar downloads do not use this retry loop.
`X-Error-Code` distinguishes missing repositories, revisions, entries and gated
access. A 401 without that header reports “not found or private.” Only an
`EntryNotFound` tree response triggers the file-open path.

For single archives, `.index.ptr`, `.index.<id>.sqlite`, and `.index.sqlite`
siblings (including the existing compressed-index suffixes) are requested through
resolve URLs at the same commit. The existing pointer hash and archive-fingerprint
validation apply, and private sidecars use the same Hub token. No branch-relative
or CDN-relative sibling URLs are guessed. Explicit in-memory indexes and forced
rebuilds skip remote index discovery.

## Publishing indexes

Dataset authors can build and publish a reusable index with:

```sh
ratarmount --publish-index 'hf://datasets/org/name@main/shards/00001.tar.zst'
```

A token with repository **write scope** is required, using the same token lookup
and `HF_ENDPOINT` as reads. Without a mountpoint the command exits after
publication. Local publication retains its existing copy, pointer, and keep-last-2
snapshot behavior. Remote `--publish-index-to URL` names the destination archive;
its bytes must match the source archive. `s3://`, `gs://`, and `az://` destinations
use the existing backend credentials and refuse anonymous writes.

The publisher builds/validates the sidecar through the mount factory, copies it
into a temporary publication snapshot, and stores tarstats of the remote archive.
The immutable blob is `{archive}.index.<sha256>.sqlite`; the pointer is
`{archive}.index.ptr`. Its `index_id` equals the blob SHA-256. For Hub sources the
pointer also records `archive_hf_commit` and `archive_hf_resolve_url`; the SQLite
metadata retains the original pinned archive identity.

On object stores the blob PUT completes before the pointer PUT; failures leave
at most an orphan blob. On the Hub **both files go into one atomic commit** after
LFS upload, so no pointer can precede its blob. Upload negotiation uses preupload,
LFS batch, basic or multipart PUT, optional verification, then NDJSON commit,
following the upstream [commit implementation](https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/_commit_api.py)
and [LFS implementation](https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/lfs.py).
The Hub Bearer token goes only to the Hub endpoint; LFS storage requests use only
headers supplied in the batch action. Native Xet uploads are unsupported. If a
Hub requires Xet and refuses the LFS path, publication fails with an explicit
message. Existing Xet-backed read support is unaffected.

`--publish-revision BRANCH` selects an existing destination branch (default: the
archive revision if it is a branch, otherwise `main`); `--create-pr` adds
`?create_pr=1` to preupload and commit. The destination archive is fingerprinted
and `parentCommit` rejects concurrent branch changes. Readers must use the
**new commit** or updated branch: an earlier pinned commit cannot see sidecars
added later. Failed commits are not retried automatically because a lost response
may hide a successful commit or PR. Remote snapshots are not automatically
pruned. Publication currently refuses blobs above 64 MiB, matching the existing
S3 sibling publisher and bounding in-memory Hub commit encoding; the reader can
accept larger sidecars without retaining them in its metadata cache.

See the [dataset-author recipe](recipes/publish-hf-index.md) for a complete
“run once, every downloader gets a zero-scan mount” workflow. Fingerprint checks
still read archive byte ranges even when no indexing scan is needed.

## Writing archive changes back to the Hub

```sh
ratarmount -w ./outputs-overlay --commit-overlay-interval 30s \
  --commit-overlay-on-exit \
  'hf://datasets/org/name@main/outputs/archive.tar.zst' outputs/
# Open one PR, then continue subsequent intervals on that PR's refs/pr/N:
ratarmount -w ./review-overlay --commit-overlay-interval 30s --create-pr \
  'hf://datasets/org/name@main/outputs/archive.tar.zst' review/
```

Live overlay commits support existing uncompressed TAR and `.tar.zst` archives
(including `.tzst` and `.tar.zstd`). The token needs repository **write scope**;
the read backend's token lookup and `HF_ENDPOINT` apply. The URL must select an
existing branch. Commit SHAs and tags are refused explicitly. The target stays
on the mount's branch; `--publish-revision` is for index publication and cannot
redirect live archive writes. Whole-repository mounts and other archive formats
do not support live write-back.

Each commit downloads the pinned archive to a temporary spool outside the overlay,
uses the existing TAR rewrite or zstd splice, and builds a fresh SQLite index
from the resulting archive. The archive streams through LFS basic or multipart
upload without loading it all into memory. The archive, immutable
`{archive}.index.<sha256>.sqlite`, and `{archive}.index.ptr` are then published in
**one atomic Hub commit**. Readers resolving a commit see matching archive and
index bytes. Live pointers bind archive bytes through tarstats fingerprints;
they do not embed the new commit SHA, which the Hub assigns during publication.
Even mounts using `--index-file :memory:` publish all three files.
The sidecar limit is 64 MiB; exceeding it refuses the entire publication, leaving
the remote archive unchanged. Archive size is bounded by spool disk space and
the Hub's upload limits, rather than the index publication limit. Each interval
currently rebuilds the full file table and reopens the committed archive; it
does not incrementally patch the mount's existing index.

The commit header's `parentCommit` equals the SHA pinned when the mount opened,
or its last successful commit. The branch is checked before downloading, and
the Hub precondition protects changes during upload. A concurrent push fails
without overwriting the other writer. Conflicts and upload/commit errors stop
further publication for this mount and log that a remount is required; the
overlay is retained. A lost response may conceal a successful commit, so inspect
the branch and reconcile retained changes before retrying on a new mount.
Successful interval commits reopen the exact returned SHA, update
`user.hf.commit`, remove the committed overlay files, and keep serving new bytes.
An on-exit commit publishes remaining changes through the same queue.

`--create-pr` creates one PR on the first successful publication, then directs
later commits to `refs/pr/N` with the last committed SHA as parent. The original
branch remains unchanged. As documented by the
[Hub commit API](https://huggingface.co/docs/huggingface_hub/package_reference/hf_api#huggingface_hub.HfApi.create_commit),
PR creation uses the supplied parent as its starting commit; subsequent writes
to the PR use the usual parent precondition. The PR is not merged automatically.
Native Xet uploads remain unsupported; LFS-compatible uploads are required.
Tokens and storage response bodies are omitted from publication diagnostics.

Offline `--commit-overlay hf://...` exits **2**, matching object-store URLs:
use `--commit-overlay-on-exit` or `--commit-overlay-interval` instead.

Normal regressions use a local mock Hub and need no FUSE mount. This ignored
test writes a unique archive and sidecars into a private test dataset and leaves
them there; run it only when those writes are authorized:

```sh
RATARMOUNT_TEST_HF_REPO=your-name/private-test-repo HF_TOKEN=hf_... \
  cargo test -p ratarmount --bin ratarmount regression_hf_live_private_repo_writeback -- --ignored --nocapture
```

The ignored write test additionally requires explicit approval and both a test
repository and an environment token; it leaves test artifacts in that repository:

```sh
RATARMOUNT_TEST_HF_REPO=your-name/test-repo HF_TOKEN=hf_... cargo test -p ratarmount --bin ratarmount regression_publish_index_hf_live -- --ignored --nocapture
```

## Range reads and Xet verification

Files use the shared pooled HTTP agent, redirect-target caching, expired-target
re-resolution, and bounded parallel sequential reads. The probe and source are
shared per commit/path for the mount lifetime, including concurrent opens; a new
handle does not repeat `/resolve/`. Available final-response `X-Repo-Commit`,
`X-Linked-Etag`, `X-Linked-Size`, and `ETag` headers are recorded in debug logs;
a conflicting final-response `X-Repo-Commit` is rejected. This check normally
applies only to non-redirected responses: intermediate redirect headers are not
retained or checked, and CDNs generally omit this header. Pinning uses the SHA in
the resolve URL. Transport errors omit URL query strings and userinfo.
The CLI suppresses ureq's raw request debug traces, even with
`RUST_LOG=ureq::unit=trace`. Applications embedding `ratarmount-remote` must likewise
keep the `ureq::unit` log target at WARN or below in verbosity: those third-party
traces include unredacted signed URLs and bypass the library's diagnostics.
A one-byte GET verifies
Range support rather than relying on CDN HEAD headers. If the server returns
200 and ignores Range, its response is read sequentially once into the existing
HTTP reader's shared memory buffer, **up to 64 MiB per file**. Larger responses
are refused with a clear error, including responses without Content-Length;
refusal is remembered until unmount. Use a Range-capable endpoint or download
such a file locally. Repeated opens share the buffer rather than downloading or
copying it again. Buffers remain alive for the mount lifetime, so opening many
non-Range files adds their memory use. Unsupported archive formats may additionally
use the existing temporary file materialization path.

Live check on **2026-10-16**:

- Dataset: `hf-internal-testing/fixtures_image_utils`.
- Commit: `4539dd3e9faa39d54e606b4c875f85c7561f5423`.
- File: `snowman.jpg`, 103,645 bytes; tree API reported
  `xetHash=9adc71509dcc3795628bd185b6eace1265ab285dc2377997b24c52bc4a9dc530`.
- The resolve endpoint redirected to `us.aws.cdn.hf.co` (the public CDN host
  observed for this Xet file; a `cas-bridge` hostname is not required).
- The one-byte probe and four concurrent 1 KiB ranges against the **same resolved
  target** all returned 206 and exact `Content-Range` values. Every range matched
  the corresponding complete-file bytes.
- Complete-file SHA-256 matched tree `lfs.oid`:
  `ec1e7dc759b7cfbbd70ecff48b712c2829e02ec37db92655d3285f048e274f18`.

This verifies parallel Range reads for that public Xet object, rather than
assuming every mirror/CDN behaves identically. Repeat the ignored live test with:

```sh
RATARMOUNT_TEST_HF_LIVE=1 cargo test -p ratarmount-remote --lib hf_live_xet_concurrent_ranges -- --ignored --nocapture
```

The test selects a small public Xet-backed fixture, checks four concurrent ranges
and the complete SHA-256, and skips with a reason unless explicitly enabled.
Normal CI only uses in-process mock servers.

## One shared Hub cache

`hf://` reads existing `huggingface_hub` files before requesting file bytes.
The cache root follows upstream [constants.py](https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/constants.py):
`HF_HUB_CACHE`, then legacy `HUGGINGFACE_HUB_CACHE`, then `$HF_HOME/hub`.
Without `HF_HOME`, use `$XDG_CACHE_HOME/huggingface/hub`, or
`~/.cache/huggingface/hub`. Paths expand `~`, `$VAR`, and `${VAR}`.
If no cache location or home directory can be determined, sharing is disabled
and explicit offline mounts ask for `HF_HUB_CACHE`; no relative `~/` cache is created.

Sharing defaults **on only when that cache directory already exists**.
`RATARMOUNT_HF_SHARE_CACHE=1` enables it and permits creating the directory;
`RATARMOUNT_HF_SHARE_CACHE=0` disables read-through and write-back for `hf://`.
It does not disable explicit `hf-cache://` mounts. This avoids creating a new
Hugging Face cache for users who have never used the Hub libraries.

The layout matches the [Hub cache](https://huggingface.co/docs/huggingface_hub/guides/manage-cache):

```text
$HF_HUB_CACHE/
  datasets--org--name/
    blobs/<etag>
    snapshots/<commit>/shards/part.tar -> ../../../blobs/<etag>
    refs/main                         # commit SHA, no newline required
  .locks/datasets--org--name/<etag>.lock
```

Files are matched by pinned commit/path or known blob hash and expected size
when tree/response metadata is available. Snapshot symlinks may resolve only
into that repository's `blobs` directory; symlink directories, `.incomplete`
files, and escaping pointers are rejected. Copied snapshot files (used by the
Python library on systems without symlink support) are also accepted.
`.no_exist` markers and unfinished downloads are never presented as payloads.
Normal `hf://` mounts still resolve the revision and may fetch tree metadata;
a cache hit avoids **file** requests, not necessarily all Hub API requests.

By default, regular Git blobs trust size and name. LFS blobs verify SHA-256
before their first open. `RATARMOUNT_HF_CACHE_VERIFY=1` also verifies regular
files using Git's SHA-1 blob format (`blob <size>\0<bytes>`).
`RATARMOUNT_HF_CACHE_VERIFY=0` trusts size/name for both types. Successful and
failed verification results use an in-memory LRU of 1,024 entries, keyed by
path, expected hash, size, mtime, inode/device, and ctime on Unix. Eviction
removes the least recently used entry rather than clearing the memo. The first
open after eviction or process restart can rehash; verification is not persisted.

Read-through keeps the verified descriptor and uses positional reads from it.
Byte reads do not reopen its pathname, rehash the file, or walk cache directories.
Backing extents use that descriptor too, so replacing a blob pathname cannot
switch an existing reader or backing extent to an unverified inode. Cache misses
are remembered for that file for the mount lifetime; remount to discover files
that another process downloads later. Ratarmount's own background publication
can populate a remembered miss. Avoid editing cache blobs in place while using
open readers: descriptors pin inodes, not immutable copies of their contents.

`HF_HUB_DISABLE_SYMLINKS=1` (also `true`, `yes`, or `on`) makes publication write
ordinary snapshot copies instead of symlinks. Copied snapshots use available
Hub tree hashes (`lfs.oid`/`lfs_sha256` or Git `oid`/`blob_id`) when verifying.
Ratarmount also records expected hashes for its own copied files under the
repository's `.ratarmount-hashes-v1/<commit>/<path>`. If a pre-existing copied
snapshot has no expected hash metadata, it remains readable using size checks,
including with `RATARMOUNT_HF_CACHE_VERIFY=1`; its contents cannot be hash-verified
until that metadata is available. Offline listings inspect sizes without hashing
all cached weights; opening a file or requesting a backing extent applies the
configured verification. A known hash mismatch is a miss for `hf://` and an
error for offline reads.

When all verified chunks are available, a bounded background pool (two workers,
64 queued jobs) assembles and publishes the whole file. A worker attempts the
same per-blob `flock` as Python without waiting. Busy locks, a full queue, and
failed writes retain the range data and back off for 30 seconds; later reads,
opens of buffered files, or completion requests can retry. Workers hash while
copying to a temporary file inside `blobs`, verify the full LFS SHA-256 or Git
blob SHA-1 regardless of the read-verification setting, sync the file, and rename
it into place. Reads never wait for the copy/hash or hold their file-state mutex
while it runs. Non-Range buffered responses are also published asynchronously;
their spool is under the Hub cache's `blobs` directory, never system `/tmp`.

Publication atomically replaces the snapshot pointer (or copy) after the blob is
complete. It never writes a revision ref. Named refs are updated only while the
mount opens, conditional on the ref still matching what was observed before the
revision API request, or created without clobbering an existing file when absent.
A long-running pinned mount therefore cannot roll a newer Python `refs/main`
back when one of its old files finishes downloading.

New blobs, snapshot copies, metadata, and refs use `0o666 & ~umask` permissions;
new directories use `0o777 & ~umask`. A temporary permission probe reads the
kernel-applied mask without changing the process-global umask. Temporary files
remain private until their permissions are set on the descriptor before rename.
Snapshot symlink staging names have automatic cleanup on errors. Background
publication also reclaims ratarmount-owned temporary blob files older than one
hour when their publishing process has exited. It leaves active publishers,
Python `.incomplete` downloads, and unrecognized temporary names alone.

No partial blob or `.incomplete` download is published. Each pathname is replaced
atomically; an interrupted publication can leave an unreferenced complete blob.
Publication is best effort: closing the process can interrupt a queued job, and
cache failures leave normal reads working. A complete Hub blob exposes both a
local complete-file path and a verified backing descriptor for whole-repository
mounts and FUSE passthrough consumers. Embedders should pass the descriptor from
`HttpRangeFile::backing_file()` to such consumers: a `complete_file()` pathname
can be replaced by another cache writer, while the descriptor pins the verified
inode.

After successful installation, the corresponding `range-v1` chunks and complete
file are removed. Subsequent reads use the Hub blob. The Hub cache belongs to
`huggingface_hub`: **it is not counted against `RATARMOUNT_PAYLOAD_CACHE_BYTES`**
and is not evicted by ratarmount. Use the Hub cache-management tools to prune it.
The ratarmount cap still limits chunks and assembly before this handoff; a file
larger than that cap cannot be completed through this path. Set a sufficient cap
when syncing large weights. `RATARMOUNT_PAYLOAD_CACHE_BYTES=0` disables range-cache
write-back, while existing Hub blobs can still be read. Non-Range buffered files
can be shared independently of that cap. Mounts using a custom `HF_ENDPOINT`
share the same root, like Python; select a separate `HF_HUB_CACHE` for mirrors
whose repository IDs do not represent the same content.

## Offline snapshots (`hf-cache://`)

```sh
# List cached repository folders (models--org--name, datasets--org--name, ...).
ratarmount 'hf-cache://' cached-repos/
# Mount the cached main revision, with archive shards opened recursively.
ratarmount -r 'hf-cache://datasets/org/name' offline/
ratarmount 'hf-cache://org/model@0123456789abcdef0123456789abcdef01234567' model/
ratarmount 'hf-cache://spaces/org/demo@v1/assets' assets/
```

`hf-cache://[datasets/|spaces/]org/name[@revision]` uses **only local files**,
without resolving an endpoint, loading a token, or making network requests.
It works with `HF_HUB_OFFLINE=1` and even an unreachable/invalid `HF_ENDPOINT`.
The default revision is `main`; named revisions resolve through `refs/<revision>`,
and a full 40-hex SHA directly selects `snapshots/<sha>`. A 4–39 hex commit prefix
also works when it uniquely matches a cached snapshot; ambiguous prefixes fail.
The same percent-encoding
and revision syntax as `hf://` applies. An optional path selects a cached
directory. Missing snapshots report available named revisions and commit SHAs.
Bare `hf-cache://` is a repository catalog: its named directories are empty and
are not browsable snapshot mounts. For example, after seeing `datasets--org--name`,
mount `hf-cache://datasets/org/name` to inspect that repository. Non-UTF-8 cache
entry names are skipped because they cannot be represented by this URL API.

Snapshot pointers appear as ordinary read-only files with their blob sizes,
not as symlinks. `-r` opens cached archive shards through the existing nested
readers in place, without a download or a temporary copy of the shard. The
existing nested-format matrix still determines whether a particular format
needs materialization. A snapshot can be **partial**: only files actually cached
are listed. This is a browser of cached files, not proof that every file from a
remote repository has been synced. Root and file xattrs expose `user.hf.commit`.

`HF_HUB_OFFLINE=1` (also `true`, `yes`, or `on`) still refuses `hf://` mounts
before network access; use `hf-cache://` to browse offline. Legacy
`TRANSFORMERS_OFFLINE` is used when `HF_HUB_OFFLINE` is unset or empty; an explicit
`HF_HUB_OFFLINE=0` overrides it. The separate ratarmount tree cache stores only
listing metadata and is not itself an offline snapshot.

Hub base sources remain immutable snapshots. Live overlays can publish archive
changes through `hf://` as described above. `hf-cache://` remains a local,
read-only snapshot browser; it does not publish writes.

Persistent range data uses the [shared body cache](phase10-remote.md#persistent-remote-range-cache-ai-rc).
Every source carries endpoint, repository kind/name, pinned commit and path as
its content token. `X-Linked-Etag` and tree `lfs.oid` additionally verify LFS
completions. A new commit has a separate range identity. Non-Hub HTTP readers
retain on-demand complete-file assembly; Hub sharing triggers assembly after
all chunks have been observed and hands the verified result to the shared cache.

## Example dataset

[`RealMattbrewer/oxford-iiit-pet-webdataset`](https://huggingface.co/datasets/RealMattbrewer/oxford-iiit-pet-webdataset)
is a public dataset built with `ratarmount shard` and published with
`ratarmount --publish-index hf://...`: seven uncompressed WebDataset shards,
each with a published index. Measured from a laptop on a cold cache: the whole
repository mounts with `-r` in 0.23 s, and one 128 MiB shard opens in
1.2-1.5 s with its published index versus 16.5 s scanning it.

