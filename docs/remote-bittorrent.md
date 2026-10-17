# BitTorrent sources

The `bittorrent` feature mounts `magnet:?xt=…`, local `.torrent` files, and
HTTP(S) URLs whose path ends in `.torrent`. Quote magnets so the shell does
not interpret `&`. The feature is enabled in the three Linux/macOS release scripts listed in
[packaging](packaging.md). Cargo builds of the CLI
and library crates require `--features bittorrent`; default CI does not build librqbit.
With the feature off, local `.torrent` files and HTTP URLs keep their ordinary
file/HTTP behavior. Directories named `*.torrent` are always directories.

```sh
# Default (--torrent-swarm never): reads are served only from the cache and the torrent's web seeds (url-list).
ratarmount ./dataset.torrent mnt/
ratarmount -r --readahead 8M 'https://example.org/dataset.torrent' mnt/
ratarmount 'magnet:?xt=urn:btih:…&xs=https://example.org/dataset.torrent' mnt/
# No web seed, or a magnet with only tr=/ws=: opt in to peers.
ratarmount --torrent-swarm auto ./peers-only.torrent mnt/
ratarmount --torrent-swarm auto 'magnet:?xt=urn:btih:…&tr=…&ws=…' mnt/
cargo build -p ratarmount                           # no BitTorrent dependency
cargo build -p ratarmount --features bittorrent
cargo build -p ratarmount-session --features bittorrent
```

Check the company network policy before running BitTorrent at work. Firewalls
may block or flag the protocol regardless of the content being transferred.

**Network policy: `--torrent-swarm never|auto|lan|always` defaults to `never`.**
Package builds compile BitTorrent, but a mount contacts no peers, trackers, DHT
or LSD unless you pass `auto`, `lan` or `always`.

* `never` (default) allows the cache, `xs`/metainfo over HTTP(S), and web seeds
  only; no peer socket is opened. Missing metadata or a piece that cannot be
  obtained and verified fails with a `--torrent-swarm never` error that names
  the opt-in (`pass --torrent-swarm lan or auto to allow peers`). A magnet with
  no cached metadata and no `xs` URL therefore fails at mount.
* `auto` (opt-in; **joins public DHT/trackers** on fallback) starts the swarm
  only if metadata cannot be obtained from the cache, `xs` or metainfo file, or
  if no web seed can supply a verified requested piece.
  Available metadata plus a working web seed means **no DHT socket, tracker
  announce, LSD multicast, or peer connection**. After web seeds fail, an LSD-enabled
  mount gives LAN peers a three-second first attempt before public discovery.
  Checksum discovery can still use HTTPS APIs. `--seed` explicitly activates a session.
* `always` creates the swarm runtime at mount time, including DHT when enabled.
  Torrent peer streaming and tracker requests begin when the swarm is used.
* `lan` creates a session with **no DHT and no tracker requests**, and tries local
  peers before web seeds. Its peer allowlist also blocks public addresses learned
  through peer exchange or incoming connections. Private IPv4, IPv4 link-local,
  loopback, IPv6 ULA and IPv6 link-local addresses are allowed; a LAN using only
  globally routed addresses needs a private/link-local address for this mode.
  CGNAT `100.64.0.0/10` (including Tailscale IPv4 addresses) is not treated as LAN;
  there is currently no CIDR override. With a web seed available, a LAN attempt
  gets at most two seconds, then failed discovery backs off for 60 seconds.
  Other pieces can use the web seed while that attempt is pending. With no web
  seed, absent peers still time out after two seconds, but an established peer
  transfer gets the normal transfer timeout (30 seconds by default).
  HTTPS metadata, checksum APIs and web seeds remain permitted; `lan` limits peer
  discovery, rather than making every request offline.

At first public swarm activation per mount, an info-level log says:
`BitTorrent swarm enabled for <infohash>: your IP is visible to trackers/DHT peers`.
It uses normal log filtering; it does not bypass quiet logging. Disabling uploads
or TCP listening does **not** prevent tracker announcements or IP disclosure.
On Unix the DHT uses librqbit's interface binding on the kernel-selected IPv4
route interface (determined without sending a packet); failure to determine or
bind that interface fails swarm startup. On non-Unix platforms this build cannot
determine the default interface: librqbit binds DHT on all interfaces. Use `never`
if that is unacceptable. UPnP port mapping remains disabled.

`--torrent-lsd on|off` defaults to `on`, and only takes effect while a swarm
session exists, so under the default `never` policy it sends nothing. BEP 14
multicasts stay on the local network. `auto` with working web seeds and `never`
create no LSD socket; `lan` multicasts the infohash at mount time. Public `auto`/`always` downloader
sessions never accept incoming TCP connections. LAN-only sessions can use an
ephemeral protocol listener bound to a private local address to solicit prompt
LSD replies; payload uploads still require `--seed`. LAN activation logs explicitly state that
DHT and trackers are disabled. `--torrent-lsd off` disables multicast; library
users can still provide explicit private peer addresses.

```sh
ratarmount ./dataset.torrent mnt/                     # never: cache + web seeds only
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
using the magnet's policy-permitted discovery methods. Under the default `never`
policy there is no metadata exchange: a magnet that misses the cache and has no
working `xs` URL fails with `metadata unavailable` and the opt-in hint. LAN metadata exchange
actively solicits a BEP 14 reply from an existing donor and retains that donor's
address for the subsequent payload session. Auto gives this local attempt a
three-second grace period before starting public discovery. Swarm operations time out after 30 seconds
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
When a magnet supplies both `btih` and `btmh`, the v2 cache entry is preferred.
A layer-less hybrid cache entry remains a v1 fallback while other cache/`xs`
sources are tried for full v2 metadata. V1 metadata exchange omits external v2
piece layers; a hybrid received this way uses authenticated v1 piece hashes until
full metainfo is supplied.
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
verified pieces / 256 MiB; concurrent misses for a piece share one fetch. Torrent-specific piece buffers are not currently charged to `--memory-budget`.
Active readers and in-flight requests may
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

## Opt-in seeding and two-Dell LAN setup

`--seed` is off by default. It activates the selected swarm policy immediately,
accepts incoming IPv4 and IPv6 connections on `--torrent-listen-port` (default `0`,
which selects an available port for each mount), and logs **BITTORRENT SEEDING ENABLED**, the listener
and upload cap. `--seed` needs an explicit `--torrent-swarm lan|auto|always`:
with the default `never` (or an explicit `never`) it is an error. `--seed` also requires
a build with `--features bittorrent`. Use `--torrent-swarm lan` on both machines
to share without announcing to internet trackers or DHT peers. With `auto` or
`always`, **`--seed` joins public DHT/trackers at mount time**, including when
all requested reads can be served by cache or web seeds. Each session permits
at most 32 connected peers. An explicit occupied listen port remains an error;
use the random default for multiple concurrent mounts.

`--seed-upload-limit BYTES/s` defaults to **1048576** (1 MiB/s). It accepts decimal
integer byte rates from 16384 through 1000000000. The minimum is one 16 KiB
protocol block: librqbit's limiter refuses a block larger than its capacity.
Rates are rounded down to the limiter's nanosecond clock resolution, retaining
capacity for one protocol block; the activation log shows the effective cap.
Larger values are rejected because the dependency would create a zero refill
interval. The cap applies across the session's peers and permits an initial
one-second burst. Protocol/metadata overhead is outside this payload rate. Ordinary downloads
continue to set `disable_upload: true`; the dependency's `disable-upload` feature
makes this runtime switch available rather than preventing opt-in uploads.

The upload session reads verified range-cache pieces and complete Hub blobs,
then rqbit rehashes them before advertising HAVE. It has no selected downloads or
file streams. If the mount also needs peer downloads, a separate session keeps
uploads disabled and uses the quota-limited protocol scratch store. Only complete
pieces that pass the torrent layer's check enter the upload session's cache view.
Cache reads recheck their torrent hash; a corrupted/evicted cached piece fails an
upload rather than returning zero-filled scratch holes. Scratch fallback is
independently rehashed as well: a HAVE bit that authenticated a cached overlay
cannot authorize different speculative blocks underneath it after eviction.
No cache miss performs HTTP or swarm fetching on an upload thread.
The seed starts with an empty availability bitmap and inspects cache slots once.
Missing slots are not hashed as zero-filled files. Newly verified HTTP/cache
pieces enter an incremental queue: rqbit verifies only that piece, updates HAVE,
and announces it over existing peer connections. It never deletes/re-adds the
torrent for refreshes or rehashes previously advertised pieces. A small vendored
rqbit patch provides this API; its provenance and changes are recorded in
`vendor/librqbit/RATARMOUNT.md`.
Unmount cancels listeners, discovery and uploads even if a read is still timing out.

For two Dells on the same private LAN, place the same `.torrent` metadata file on
both machines (or use a magnet with a reachable `xs=.torrent` URL). On the first
Dell, warm the model's verified Hub cache through `hf://` or an existing Hub
client, with the same pinned repository/revision and LFS SHA-256. Hub cache sharing
is automatic when its directory exists; `RATARMOUNT_HF_SHARE_CACHE=1` also enables
creation of a new cache. Then run:

```sh
# First Dell: serve verified pieces, at up to 100 MiB/s.
ratarmount --torrent-swarm lan --seed --seed-upload-limit 104857600 \
  --torrent-listen-port 4240 ./model.torrent donor/

# Second Dell: discover the donor with BEP 14, before trying HTTPS.
ratarmount --torrent-swarm lan --torrent-scratch-limit 400GiB \
  ./model.torrent model/
# Read model/model.safetensors normally. Stop sharing by unmounting donor/.
```

Allow local UDP multicast port 6771 and the donor's incoming TCP port through
the LAN firewall. BEP 14 requires multicast connectivity; a direct ConnectX link
needs private addresses and multicast routing on that link. Keep the donor mounted
while reading on the second machine. The default scratch quota remains 2 GiB;
a swarm-only 300 GB sequential download needs a larger quota, as above, and enough
local disk. Wait for **BITTORRENT SEEDING READY** on the donor before starting
the second mount: the first inspection and verification of a very large warm
cache can take minutes. Already inspected pieces can be served during that work.
Scratch is temporary and separate from the shared persistent cache.
The default range-cache budget is also independent of that quota. A first Dell
with only partially cached pieces can serve those pieces; other requested pieces
need another local donor or the configured web seed. Hardware throughput on the
Dell/ConnectX setup has not been measured here.

Other upstream limitations:

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
the backend uses the `hf://` tree API and token rules to read fresh `lfs.oid`
values for the exact pinned commit. Non-LFS files use the Hub's Git blob `oid`. Mutable branch URLs are not treated as a pinned source
identity. Missing independent hashes leave piece verification active, but do
not claim Hub whole-file verification.

Read-only inspection on 2026-10-16 found this concrete Pirate Face format:

* [`/s/qwen`](https://pirateface.co/s/qwen) supplied a v1 magnet for
  `Qwen/Qwen3.8-27B`, infohash
  `d394d1807bc3d6407b6bbb04da24094d69277f86`, with UDP/HTTP tracker parameters
  and `ws=https://pirateface.co/api/ws/Qwen/Qwen3.8-27B/1d4bf0f2ff6012fd82039f2fa52739d0dd7c60c0/`.
  This is a proxy web-seed base, not a direct Hub URL or metadata endpoint, so
  under the default `never` policy such a magnet needs cached metadata, an `xs`
  URL, or an explicit `--torrent-swarm auto`.
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

`TorrentMountSource::verified_file_sha256(path)` returns a digest only after the
full-file check succeeds. For one unambiguous pinned Hub/Pirate Face repository
identity, only a fresh, authenticated Hub tree response for that exact commit
authorizes publication into the shared Hub cache. LFS files use the Hub's
`lfs.oid` SHA-256; non-LFS files are verified and installed only under the Hub's
Git blob SHA-1 `oid`. Metainfo extensions, Pirate Face manifests, on-disk torrent
checksum records and cached tree responses never authorize new snapshot entries.
Manifest hashes only add integrity checks that can make reads fail with EIO.
Offline, gated, rate-limited or failed Hub lookups leave publication disabled.
Conflicting identities or independent hashes fail closed.

Publication streams into AI-HF3's existing installer: the same
`$HF_HUB_CACHE/models--owner--repo/blobs/<Hub-oid>`, snapshot symlink, file lock,
atomic rename, digest check and `0666 & ~umask` permissions used by `hf://`.
It creates no second completed-file spool. Torrent publication never replaces an
existing `snapshots/<commit>/<path>` entry, including dangling symlinks and entries
created concurrently. A conflicting entry is preserved and logged even when the
new blob already exists. Busy blob locks and transient failed installs
are retried by the background verifier at idle five-second intervals, without
requiring another read; dropping the source stops further publication work. Once publication succeeds, redundant
torrent range pieces are removed (cross-file v1 pieces wait for all their spans).
Before fetching a file, its known SHA-256 is looked up in that repository's Hub
cache and verified, including when `RATARMOUNT_HF_CACHE_VERIFY=0`. Hits serve
locally without payload traffic or peer activation. An existing pinned Hub
snapshot can supply the independent digest itself (including Python-populated
caches), so a first torrent mount does not need a prior torrent checksum cache.
When all files are available this also avoids checksum API traffic; a complete
source-bound checksum observation plus cached blobs has the same effect. `hf://`
and `hf-cache://` can read a blob installed by a torrent; partial or failed whole-file
checks never publish a blob. For small non-LFS files whose Pirate Face digest is
SHA-256 but whose Hub blob ID is Git SHA-1, the pinned snapshot can reuse either
blob name after verifying the requested digest, without creating a duplicate. Transient protocol scratch remains until unmount.

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

Normal tests use loopback HTTP and two in-process librqbit sessions, including
opt-in production seeding, partial/corrupt cache bitfields, an enforced rate cap,
listener shutdown and HF cache sharing in both directions. Direct loopback peers
substitute for multicast discovery in deterministic tests; one auto-policy test
also enables local LSD. No public tracker or swarm is used by the default suite.
The real two-session multicast tests are gated by `RATARMOUNT_TEST_LSD=1` and still
disable public discovery; they cover both `.torrent` payload reads and a bare
magnet resolving metadata from an already-running donor. It needs a host/network namespace that supports multicast.

```sh
cargo test -p ratarmount-core --lib regression_torrent_swarm_default_never
cargo test -p ratarmount-remote --features bittorrent --lib torrent
cargo test -p ratarmount-session --features bittorrent --lib regression_torrent
cargo test -p ratarmount-session --lib regression_built_without_bittorrent
cargo test -p ratarmount-remote --lib regression_torrent_remote_dispatch
cargo test -p ratarmount --features bittorrent --bin ratarmount torrent_policy_tests
cargo test -p ratarmount --bin ratarmount torrent_policy_tests
./packaging/test-bittorrent-features.sh
RATARMOUNT_TEST_LSD=1 cargo test -p ratarmount-remote --features bittorrent \
  --lib regression_real_lsd_ -- --nocapture
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
