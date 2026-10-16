# BitTorrent sources

The `bittorrent` feature mounts `magnet:?xt=…`, local `.torrent` files, and
HTTP(S) URLs whose path ends in `.torrent`. Quote magnets so the shell does
not interpret `&`. The feature is enabled in the three Linux/macOS release scripts listed in
[packaging](packaging.md). Cargo builds of the CLI
and library crates require `--features bittorrent`; default CI does not build librqbit.
With the feature off, local `.torrent` files and HTTP URLs keep their ordinary
file/HTTP behavior. Directories named `*.torrent` are always directories.

```sh
ratarmount ./dataset.torrent mnt/
ratarmount -r --readahead 8M 'https://example.org/dataset.torrent' mnt/
ratarmount 'magnet:?xt=urn:btih:…&tr=…&ws=…' mnt/
cargo build -p ratarmount                           # no BitTorrent dependency
cargo build -p ratarmount --features bittorrent
cargo build -p ratarmount-session --features bittorrent
```

Check the company network policy before running BitTorrent at work. Firewalls
may block or flag the protocol regardless of the content being transferred.

**Network policy: `--torrent-swarm auto|always|never` defaults to `auto`.**

* `auto` starts the swarm only if metadata cannot be obtained from the cache,
  `xs` or metainfo file, or if no web seed can supply a verified requested piece.
  Available metadata plus a working web seed means **no DHT socket, tracker
  announce, or peer connection**. Checksum discovery can still use HTTPS APIs.
* `never` allows cache and web seeds only. Missing metadata or a piece that
  cannot be obtained and verified fails with a `--torrent-swarm never` error.
* `always` creates the swarm runtime at mount time, including DHT when enabled.
  Torrent peer streaming and tracker requests begin when the swarm is used.

At first swarm activation per mount, an info-level log says:
`BitTorrent swarm enabled for <infohash>: your IP is visible to trackers/DHT peers`.
It uses normal log filtering; it does not bypass quiet logging. Disabling uploads
or TCP listening does **not** prevent tracker announcements or IP disclosure.
On Unix the DHT uses librqbit's interface binding on the kernel-selected IPv4
route interface (determined without sending a packet); failure to determine or
bind that interface fails swarm startup. On non-Unix platforms this build cannot
determine the default interface: librqbit binds DHT on all interfaces. Use `never`
if that is unacceptable. LSD and UPnP listening remain disabled.

```sh
ratarmount --torrent-swarm never ./dataset.torrent mnt/
ratarmount --torrent-swarm auto --torrent-scratch-limit 2GiB ./dataset.torrent mnt/
```


## Metadata and lazy reads

Metainfo is parsed before the file tree is exposed. Listing files and opening
handles do not fetch payload pieces. Sizes come from the info dictionary.
Local metainfo, HTTP metainfo, v1 hex/base32 `btih` magnets, and SHA-256 `btmh`
magnets are recognized. Multiple `xt` hashes must all match resolved metadata.
Invalid paths, duplicate dictionary keys, contradictory hybrid file trees,
invalid piece layers, and unsupported versions fail closed. Limits are 64 MiB
for metainfo and individual pieces, and 64 bencode nesting levels.

Magnets first consult the platform cache's `ratarmount/torrent-v1/`, keyed by
the exact info dictionary hash. They then try HTTP(S) `xs` metadata URLs (also
`ws` URLs explicitly ending in `.torrent`), then librqbit metadata exchange
using the magnet's trackers and DHT. Swarm operations time out after 30 seconds
by default; library users can configure `TorrentOptions.swarm.timeout` and
explicit peers or disable DHT/trackers. HTTP metadata requests also have that
timeout. Cached metainfo retains the exact info bytes, v2 piece layers, web
seeds and trackers, and is rehashed on every remount. A cached magnet can list
its tree offline. Payload reads offline still need the verified pieces. Explicit
`ws` parameters replace the cached web-seed list, so a prior magnet cannot
carry a different repository’s checksum context into the new mount.

A normal BEP 19 `ws` URL identifies payload files, **not** a metainfo endpoint.
It cannot reconstruct the piece hashes. A magnet with only `ws`, no reachable
metadata peer, and no cached metadata needs an `xs` URL or a `.torrent` file.
No guessed metadata URL downloads a model file to try to discover its tree.

Each read fetches complete pieces. For v1, the piece spans the concatenated
file stream; a boundary piece may fetch ranges from several files. Padding
files supply zero bytes and are hidden. For v2, pieces belong to individual
files: 16 KiB block hashes and zero padding form the Merkle tree. Piece layers
must first match the roots inside the hashed info dictionary. Hybrids use v2
verification when available and retain the v1 mapping for swarm fallback.
V1 metadata exchange omits the external v2 piece layers; a hybrid received this
way uses its authenticated v1 piece hashes until full metainfo is supplied.
Supplied layers that fail validation are always rejected. Hybrid file paths,
lengths, alignment and independent SHA-256 fields must agree. BEP 47 padding
entries (including repeated `.pad/<size>` names) are omitted from path collision
checks and the mounted tree. Non-Unix builds also reject Windows device names,
unsafe trailing characters and case-insensitive duplicate file paths.

BEP 19 HTTP(S) web seeds are tried in order through the shared HTTP connection
pool. Multi-file paths are `base/name/path`, with each path component URL
encoded; a single-file URL can identify the file directly. The HTTP transport
cache is disabled for this path. Only after SHA-1 (v1) or the SHA-256 Merkle
check (v2) succeeds does the torrent layer publish bytes into `range-v1`, under
`TorrentPiece { infohash, file, piece, size }`. Cache hits are checked again
against the torrent hashes. A corrupt piece is never returned or published;
the next seed, then the policy-permitted swarm, is tried instead. An HTTP server
ignoring Range is refused for offsets beyond 1 MiB instead of streaming a large
prefix; another seed or the swarm can serve that piece.

`--readahead` reaches the torrent backend through `OpenOptions.readahead_bytes`.
Each reader can prefetch following pieces, bounded to 64 MiB per window;
seeks cancel only that reader’s previous window between pieces. The demanded piece is fetched
before that window is scheduled. The range cache shares the existing
`RATARMOUNT_PAYLOAD_CACHE_BYTES` budget with other remote/payload reads; `0`
disables persistent pieces and HTTP prefetch. A shared LRU holds at most four
verified pieces / 256 MiB; concurrent misses for a piece share one fetch. This
branch has no core memory-budget API. Active readers and in-flight requests may
hold additional piece buffers.

## Swarm behavior and current limits

librqbit 9.0.1 runs on a dedicated thread with a private Tokio runtime and a
bounded request channel. In `auto` it is created for metadata exchange or on the first
failed/absent web seed, never for a successful web-seed-only read. No files are
selected for background downloading; active file streams request pieces. The
bridge registers a stream while paused before starting peers, and retains the
current stream between pieces. This avoids rqbit's idle-peer reconnect race
when uploads are disabled and no files are selected.
Unverified protocol blocks use a temporary scratch directory under
`torrent-v1/scratch/`, separate from the verified range cache, removed on normal
shutdown. `--torrent-scratch-limit` defaults to 2 GiB per swarm session;
compact 16 KiB slots count both demanded and speculative protocol writes.
Large logical file offsets do not allocate large sparse files. At quota
exhaustion further writes are refused; this implementation does not evict
rqbit pieces behind its completion bitmap. Increase the quota or use web seeds
for longer swarm-only sessions. This quota is separate from the range-cache
budget, and several simultaneous mounts each have a quota.

At swarm startup, owned `swarm-*` directories older than 24 hours are swept
only when their owner lock is free; foreign and live directories are retained.
Unmarked directories from older builds are retained; remove those only after
stopping the old torrent mounts. A crash can leave a marked directory until the
sweep. Unmount never joins an unfinished
network request: detached shutdown keeps its owner lock and cleans up when its
request timeout expires. Reader-capable nested formats, including TAR,
do not need an archive-body spool; formats requiring a path keep their existing
temporary-file fallback.

The dependency is compiled with `disable-upload`, and every production session
sets `disable_upload: true`. It does not advertise completed pieces or answer
payload upload requests. There is no incoming listener, UPnP port mapping, LSD,
session persistence, or seeding CLI option in AI-BT1. Tracker/DHT queries and
peer protocol traffic are still network traffic. Opt-in seeding and LAN sharing
belong to AI-BT2.

Two upstream limitations remain explicit:

* librqbit 9.0.1 implements the v1 peer protocol. V2-only `.torrent` files and
  `btmh` magnets with cached/HTTP metadata work through web seeds; v2-only swarm
  fallback and DHT metadata resolution return an unsupported error. Hybrids can
  fall back through their v1 identity. No v2 file is exposed without verification.
* librqbit's streaming lookahead is fixed at 32 MiB and is not configurable in
  its public API. `--readahead` controls our HTTP window, but cannot reduce that
  internal swarm window to zero. The dependency may retain those downloaded
  pieces in its scratch storage until unmount.

## Whole-file hashes and Pirate Face findings

A file's bencoded `sha256` extension (32 raw bytes or 64 hex digits) supplies an
expected whole-file checksum. For pinned Hugging Face web seeds matching
`https://huggingface.co/[datasets/|spaces/]<owner>/<repo>/resolve/<commit>/<path>`,
the backend also reuses the `hf://` tree API, token rules and tree cache to read
`lfs.oid` / `lfs.sha256`. Mutable branch URLs are not treated as a pinned source
identity. Missing independent hashes leave piece verification active, but do
not claim Hub whole-file verification.

Read-only inspection on 2026-10-16 found this concrete Pirate Face format:

* [`/s/qwen`](https://pirateface.co/s/qwen) supplied a v1 magnet for
  `Qwen/Qwen3.8-27B`, infohash
  `d394d1807bc3d6407b6bbb04da24094d69277f86`, with UDP/HTTP tracker parameters
  and `ws=https://pirateface.co/api/ws/Qwen/Qwen3.8-27B/1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0/`.
  This is a proxy web-seed base, not a direct Hub URL or metadata endpoint.
* [`/api/torrents?repo=Qwen/Qwen3.8-27B`](https://pirateface.co/api/torrents?repo=Qwen%2FQwen3.8-27B)
  returned `repoId`, `revision`, `infohash`, `magnet` and
  `files: [{ "path": "…", "sha256": "…" }]`. The response included hashes for
  small files as well as weights. The backend recognizes the proxy's pinned
  repository identity and, when the Hub has no LFS hash, accepts this API's
  checksums only when repository, revision and an explicit torrent infohash all match.
* No public swarm was joined and no weight payload was downloaded for this
  inspection. The public API does not establish that every metainfo file embeds
  a SHA-256 extension, nor that Pirate Face supplies v2 torrents. The verified
  checksum source here is the API manifest, rather than an assumed torrent
  comment or sidecar convention.

Pirate Face's [current explanation](https://pirateface.co/how-it-works) qualifies
hash and web-seed availability; the roadmap's blanket claim that every torrent
has both is not relied upon. Its [client source](https://github.com/pirateface/pirateface_hub/blob/main/src/pirateface/client/api.py)
uses the same read-only torrent lookup endpoint.

Coverage is tracked across seeks and concurrent handles. A background worker
incrementally hashes verified pieces produced in file order, retaining a streaming
hasher and next offset. Out-of-order coverage, or pieces evicted before the worker
can observe them, triggers a background pass through the cache/verified HTTP path.
Hashing, API lookups and refetching never hold the reader's verification mutex.
Readers do not wait for whole-file SHA-256 verification. A detected mismatch logs
an error, marks the file bad for the mount lifetime, and makes later reads fail
with EIO. Already returned bytes passed piece verification but cannot be retracted.

Hub tree and Pirate Face hash discovery runs in the background from mount time;
verification can complete after the checksum arrives. Independent checksums are
cached by **infohash, source repository and pinned revision**, and partial caches
are refilled. Legacy per-infohash `.sha256.json` entries are ignored because they
lack source provenance. Pirate manifests require an explicit matching infohash, including
v2-only torrents; a missing identity never matches. Missing hashes do not disable
piece verification or claim whole-file verification.

`TorrentMountSource::verified_file_sha256(path)` is the AI-BT2 publication hook:
it returns a digest only after the full-file check succeeds. Publishing completed
torrent files into the Hub cache remains AI-BT2 work. The existing `hf://` and
`hf-cache://` sharing support is independent of this torrent hook.

## Nested archives and indexes

With `-r`, TAR shards and the existing nested archive formats open through
seekable torrent readers and the normal session machinery. An uncompressed
`shard.tar.index.ptr` names `shard.tar.index.<sha256>.sqlite`; a well-known
`shard.tar.index.sqlite` is the fallback. Sibling SQLite blobs are spooled under
the platform cache’s `torrent-v1/indexes/` and kept until SQLite closes. The pointer's digest and the index's
archive size/content fingerprint must match before a TAR sidecar is reused.
Only the SQLite metadata is materialized. Missing or invalid sidecars fall back
to the existing nested parser. Automatic sibling-index reuse currently covers
uncompressed TAR; other nested formats retain their existing index behavior.

## Testing

Normal tests use loopback HTTP and two in-process librqbit sessions with DHT,
trackers and LSD disabled. Only the loopback test fixture session uploads; the
production downloader always disables uploads. No public tracker or swarm is
used by the default test suite.

```sh
cargo test -p ratarmount-remote --features bittorrent --lib torrent
cargo test -p ratarmount-session --features bittorrent --lib regression_torrent
cargo test -p ratarmount-session --lib regression_built_without_bittorrent
cargo test -p ratarmount-remote --lib regression_torrent_remote_dispatch
cargo test -p ratarmount --features bittorrent --bin ratarmount torrent_policy_tests
cargo test -p ratarmount --bin ratarmount torrent_policy_tests
./packaging/test-bittorrent-features.sh
```

The ignored `live_pirate_face_magnet` test additionally requires
`RATARMOUNT_TEST_MAGNET`. Running it against a public swarm requires the user's
explicit approval; it is not part of routine validation.

On Linux x86-64 with rustc 1.98.0, the same release profile and `export-parquet`
feature produced these sizes (2026-10-16). NFSv4/russh package features are outside
this comparison. Stripping used `strip --strip-all` on copies of each binary.

| Build | Unstripped bytes | Stripped bytes |
|-------|-----------------:|---------------:|
| Without `bittorrent` | 45,698,264 | 36,132,304 |
| With `bittorrent` | 58,184,128 | 45,062,968 |
| Increase | 12,485,864 (27.32%) | 8,930,664 (24.72%; 8.52 MiB) |
