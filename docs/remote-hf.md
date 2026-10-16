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

## Offline and write-back limits

`HF_HUB_OFFLINE=1` (also `true`, `yes`, or `on`) refuses `hf://` mounts before any
network access. Legacy `TRANSFORMERS_OFFLINE` is used when `HF_HUB_OFFLINE` is
unset or empty; an explicit `HF_HUB_OFFLINE=0` overrides it. Listing caches alone cannot supply the file data. Shared Hub
blob-cache reuse and `hf-cache://` offline mounts belong to AI-HF3 and are not
implemented here. Do not treat this listing cache as an offline snapshot.

Hub reads are read-only. `--commit-overlay` and live overlay commit report that
`hf://` is not supported for commit. Hub publication and write-back are separate
roadmap tasks. Full-file LFS hash verification is performed by the live test;
ordinary partial reads validate HTTP byte ranges, not the entire LFS object hash.

Persistent range data uses the [shared body cache](phase10-remote.md#persistent-remote-range-cache-ai-rc).
Every file source carries endpoint, repository kind/name, pinned commit and
path as its content token. `X-Linked-Etag` (including on the Hub redirect) and
tree `lfs.oid` SHA-256 values additionally verify completed files. Reopening a
file within the same pinned repository reuses its probe/redirect state and
cached body bytes, issuing zero CDN GETs when the requested bytes are cached.
A new commit uses a separate identity. If a strong response ETag changes within
a source, caching is bypassed while network reads continue. Multi-chunk complete
files are assembled only when a consumer calls `complete_file`, with one
assembly per token at a time; byte reads do not trigger whole-file copies.
