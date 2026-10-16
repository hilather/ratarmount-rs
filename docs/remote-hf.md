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

## Authentication and mirrors

Token lookup order is:

1. Nonempty `HF_TOKEN`.
2. The file named by `HF_TOKEN_PATH`.
3. `$HF_HOME/token`.
4. `~/.cache/huggingface/token`.

The selected token file overrides later locations, even if missing. Leading and
trailing whitespace is removed. Tokens are kept out of URLs and logs. Bearer
credentials go only to the configured Hub endpoint; redirects to the CDN drop
authentication, including when a signed URL expires and is resolved again.
Unrelated `RATARMOUNT_HTTP_*` Basic-auth and cookie settings do not apply to Hub
files. Private/gated 401/403 errors identify the repository and token sources;
gated repositories may additionally require accepting their access terms.

`HF_ENDPOINT` defaults to `https://huggingface.co`. Set it to a compatible mirror
or drop-in Hub API; HTTP(S) endpoints with a base path are supported. The backend
uses `/api/{models|datasets|spaces}/{repo}/revision/{revision}`, the recursive
tree API, and the usual commit-pinned `/resolve/` URLs. Mirrors must implement
those APIs. No `hf-hub`, reqwest, or asynchronous runtime is needed.

## Listings, indexes, and rate limits

Listings use `recursive=true&expand=true`, follow `Link: ...; rel="next"`, and
publish the cache only after the entire listing has succeeded. Pagination cycles,
links leaving the endpoint, malformed entries, and excessive listings fail
closed. Limits are 10,000 pages, one million entries, and 256 MiB of JSON.
Git blob IDs, LFS metadata, and `xetHash` fields are retained in the persisted JSON.

Complete listings are cached in memory and at
`$XDG_CACHE_HOME/ratarmount/hf-tree-v1/` (default `~/.cache/ratarmount/hf-tree-v1/`),
next to the ratarmount index caches. `RATARMOUNT_HF_TREE_CACHE` overrides that
directory. Keys include endpoint, repository type, repository ID, commit, and
subdirectory. Remounting the same directory snapshot still resolves the revision once but
makes **zero tree requests**. An unwritable cache only disables persistence.
The listing cache currently has no automatic eviction; removing it is safe when
mounts are closed. It contains filenames/metadata, not tokens or file contents.

[Hub API requests are rate limited](https://huggingface.co/docs/hub/api).
Large cold listings can require many pages; warm listing reuse avoids repeating
that traffic. HTTP 429 fails clearly rather than publishing a partial listing;
there is no automatic rate-limit retry loop in this backend.

For single archives, `.index.ptr`, `.index.<id>.sqlite`, and `.index.sqlite`
siblings (including the existing compressed-index suffixes) are requested through
resolve URLs at the same commit. The existing pointer hash and archive-fingerprint
validation apply, and private sidecars use the same Hub token. No branch-relative
or CDN-relative sibling URLs are guessed. Explicit in-memory indexes and forced
rebuilds skip remote index discovery.

## Range reads and Xet verification

Files use the shared pooled HTTP agent, redirect-target caching, expired-target
re-resolution, and bounded parallel sequential reads. Available final-response `X-Repo-Commit`,
`X-Linked-Etag`, `X-Linked-Size`, and `ETag` headers are recorded in debug logs;
a conflicting `X-Repo-Commit` is rejected. A one-byte GET verifies
Range support rather than relying on CDN HEAD headers. If the server returns
200 and ignores Range, its response is read sequentially once into the existing
HTTP reader's memory buffer. This fallback can use memory proportional to file
size. Unsupported archive formats may additionally use the existing temporary
file materialization path.

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

## Offline and write-back limits

`HF_HUB_OFFLINE=1` (also `true`, `yes`, or `on`) refuses `hf://` mounts before any
network access. Listing caches alone cannot supply the file data. Shared Hub
blob-cache reuse and `hf-cache://` offline mounts belong to AI-HF3 and are not
implemented here. Do not treat this listing cache as an offline snapshot.

Hub reads are read-only. `--commit-overlay` and live overlay commit report that
`hf://` is not supported for commit. Hub publication and write-back are separate
roadmap tasks. Full-file LFS hash verification is performed by the live test;
ordinary partial reads validate HTTP byte ranges, not the entire LFS object hash.
