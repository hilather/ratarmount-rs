# BitTorrent sources

The `bittorrent` feature mounts `magnet:?xt=…`, local `.torrent` files, and
HTTP(S) URLs whose path ends in `.torrent`. Quote magnets so the shell does
not interpret `&`. The feature is enabled in the CLI and Linux/macOS package
builds; `ratarmount-remote` and `ratarmount-session` require an explicit opt-in.

```sh
ratarmount ./dataset.torrent mnt/
ratarmount -r --readahead 8M 'https://example.org/dataset.torrent' mnt/
ratarmount 'magnet:?xt=urn:btih:…&tr=…&ws=…' mnt/
cargo build -p ratarmount --no-default-features       # no BitTorrent dependency
cargo build -p ratarmount-session --features bittorrent
```

Check the company network policy before running BitTorrent at work. Firewalls
may block or flag the protocol regardless of the content being transferred.

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
its tree offline. Payload reads offline still need the verified pieces.

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
Supplied layers that fail validation are always rejected.

BEP 19 HTTP(S) web seeds are tried in order through the shared HTTP connection
pool. Multi-file paths are `base/name/path`, with each path component URL
encoded; a single-file URL can identify the file directly. The HTTP transport
cache is disabled for this path. Only after SHA-1 (v1) or the SHA-256 Merkle
check (v2) succeeds does the torrent layer publish bytes into `range-v1`, under
`TorrentPiece { infohash, file, piece, size }`. Cache hits are checked again
against the torrent hashes. A corrupt piece is never returned or published;
the next seed, then the swarm, is tried instead.

`--readahead` reaches the torrent backend through `OpenOptions.readahead_bytes`.
One background worker per source fetches following pieces, bounded to 64 MiB;
seeks cancel the previous window between pieces. The demanded piece is fetched
before that window is scheduled. The range cache shares the existing
`RATARMOUNT_PAYLOAD_CACHE_BYTES` budget with other remote/payload reads; `0`
disables persistent pieces and HTTP prefetch. A reader still holds at most one
recent piece in the source's small memory cache.

## Swarm behavior and current limits

librqbit 9.0.1 runs on a dedicated thread with a private Tokio runtime and a
bounded request channel. It is created for metadata exchange or on the first
failed/absent web seed, not for a successful web-seed-only read. No files are
selected for background downloading; active file streams request pieces. The
bridge registers a stream while paused before starting peers, and retains the
current stream between pieces. This avoids rqbit's idle-peer reconnect race
when uploads are disabled and no files are selected.
Unverified protocol blocks use a temporary scratch directory under
`torrent-v1/scratch/`, separate from the verified range cache, removed on normal
shutdown. A crash can leave that scratch directory; it is safe to remove when
no torrent mount is running. Reader-capable nested formats, including TAR,
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
  checksums only when repository, revision and v1 infohash all match.
* No public swarm was joined and no weight payload was downloaded for this
  inspection. The public API does not establish that every metainfo file embeds
  a SHA-256 extension, nor that Pirate Face supplies v2 torrents. The verified
  checksum source here is the API manifest, rather than an assumed torrent
  comment or sidecar convention.

Pirate Face's [current explanation](https://pirateface.co/how-it-works) qualifies
hash and web-seed availability; the roadmap's blanket claim that every torrent
has both is not relied upon. Its [client source](https://github.com/pirateface/pirateface_hub/blob/main/src/pirateface/client/api.py)
uses the same read-only torrent lookup endpoint.

Coverage is tracked across seeks and concurrent handles. When all file bytes
have been read, a bounded piece-by-piece pass computes SHA-256. The completing
read fails with EIO on mismatch, the file is marked bad for the mount lifetime,
subsequent reads fail, and an error is logged. Earlier partial reads cannot be
retracted; they already passed piece verification. This final pass can refetch
pieces if caching is disabled or pieces have been evicted. Independent checksum
observations are cached next to metainfo for offline remounts.

`TorrentMountSource::verified_file_sha256(path)` is the AI-BT2 publication hook:
it returns a digest only after the full-file check succeeds. AI-BT1 does not
publish Hub blobs or claim that `hf://` already shares completed files.

## Nested archives and indexes

With `-r`, TAR shards and the existing nested archive formats open through
seekable torrent readers and the normal session machinery. An uncompressed
`shard.tar.index.ptr` names `shard.tar.index.<sha256>.sqlite`; a well-known
`shard.tar.index.sqlite` is the fallback. The pointer's digest and the index's
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
| Without `bittorrent` | 44,031,248 | 34,903,376 |
| With `bittorrent` | 56,395,904 | 43,734,712 |
| Increase | 12,364,656 (28.08%) | 8,831,336 (25.30%; 8.42 MiB) |
