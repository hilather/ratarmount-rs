# Caches: what ratarmount stores and where

ratarmount keeps several caches so that the second mount of anything is fast
and so that remote bytes are fetched once. All of them are safe to delete when
no mount is running. This page lists each one, its default size and the
environment variable that controls it.

## The cache root

| Platform | Default root |
|---|---|
| Linux | `$XDG_CACHE_HOME/ratarmount/`, usually `~/.cache/ratarmount/` |
| macOS | `~/Library/Caches/ratarmount/`, or `$XDG_CACHE_HOME/ratarmount/` when that variable is set |
| Windows (library crates) | `%LOCALAPPDATA%\ratarmount\` |

On a training host, point `XDG_CACHE_HOME` at local NVMe scratch before
starting mounts; see [NVMe placement](local-ai/nvme-placement.md). Home
directories with quotas are a poor place for a 4 GiB range cache.

## What lives under the root

| Directory | Holds | Cap | Variables |
|---|---|---|---|
| `local-index-v1/` | SQLite indexes saved with the user-cache index policy of the Session API and GUI embedders (`{sha256}.sqlite` + `.json`) | 2 GiB, LRU | `RATARMOUNT_LOCAL_INDEX_CACHE_BYTES` (`0` disables), `RATARMOUNT_LOCAL_INDEX_DIR` |
| the root itself | `.index.sqlite` files the CLI writes when the archive's own directory is not writable; `--index-folders` lists the search order (default: next to the archive, then `$XDG_CACHE_HOME/ratarmount`, then `~/.ratarmount`) | none | `--index-folders`, `--index-file` |
| `meta-v3/` | Downloaded remote index sidecars (whole SQLite blobs up to 64 MiB), keyed by the sidecar URL so a remount needs no `.ptr` fetch | 256 MiB, LRU | `RATARMOUNT_META_CACHE_BYTES` (`0` disables) |
| `payload-v1/` | Decompressed member bodies keyed by SHA-256, used when the index carries `sha256` hashes (`--hashes sha256`); skipped for `:memory:` indexes and overlay writes | 4 GiB, shared with `range-v1/`, LRU | `RATARMOUNT_PAYLOAD_CACHE_BYTES` (`0` disables both), `RATARMOUNT_PAYLOAD_CACHE_DIR`, `RATARMOUNT_PAYLOAD_CACHE_MEMBER_MAX` (default 64 MiB) |
| `payload-v1/range-v1/` | Verified 4 MiB chunks of remote files from HTTP, the Hub and torrents, keyed by an immutable content token (commit, strong ETag, object version, SHA-256) | shares the 4 GiB cap above | same as above |
| `hf-tree-v1/` | Complete Hub repository listings per endpoint, repository, commit and subdirectory, so remounting a pinned snapshot makes zero tree requests | no automatic eviction | `RATARMOUNT_HF_TREE_CACHE` |
| `torrent-v1/` | Torrent metainfo keyed by infohash, spooled sibling indexes for TAR shards inside torrents, and per-session swarm scratch under `scratch/` | scratch 2 GiB per swarm session | `--torrent-scratch-limit` |

`payload-v1/` and `local-index-v1/` are siblings; payload data is never nested
under the index cache, and remote sidecars never go into `local-index-v1/`.

A member larger than `RATARMOUNT_PAYLOAD_CACHE_MEMBER_MAX` is not cached as a
whole; remote ranges are not limited by that value. Caching plain HTTP ranges
requires a strong ETag that stays stable within a mount, because the ETag is
the only proof the bytes have not changed. Pinned Hub commits, object versions
and SHA-256 digests need no ETag. Set `RATARMOUNT_PAYLOAD_CACHE_BYTES=0` when a
server's validators cannot be trusted.

Once every chunk of a remote file is present and the whole file fits the cap,
the chunks can be assembled into one complete file, which is what FUSE
passthrough and the Hub cache hand-off use. Full details, including the
security checks on the cache directories, are in
[the range cache section of Remote inputs](phase10-remote.md#persistent-remote-range-cache-ai-rc).

## The Hugging Face cache is shared, not owned

`hf://` mounts read complete files from the standard `huggingface_hub` cache
(`HF_HUB_CACHE`, then `$HF_HOME/hub`, then `~/.cache/huggingface/hub`) before
fetching anything, and publish files they have fully downloaded back into it in
the standard layout. Sharing is on when that directory already exists;
`RATARMOUNT_HF_SHARE_CACHE=1` turns it on and allows creating the directory,
`RATARMOUNT_HF_SHARE_CACHE=0` turns it off. That cache belongs to
`huggingface_hub`: ratarmount neither counts it against its own caps nor
evicts from it. Prune it with the Hub's own tools. Everything about
verification and the hand-off from `range-v1/` is in
[Hugging Face: one shared Hub cache](remote-hf.md#one-shared-hub-cache).

## HTTP connection settings

| Variable | Effect |
|---|---|
| `RATARMOUNT_HTTP_PARALLEL` | Parallel sequential-read workers per file on the shared keep-alive pool |
| `RATARMOUNT_HTTP_PREFETCH_LIMIT` | Bound on outstanding prefetch requests |
| `RATARMOUNT_HTTP_*` Basic and Cookie settings | See [Remote inputs](phase10-remote.md); they do not apply to Hub files |

Torrent piece buffers hold at most four verified pieces or 256 MiB in memory
per process, separately from the disk caches, and are not yet charged to
`--memory-budget`.
