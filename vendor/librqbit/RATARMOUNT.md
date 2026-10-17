# ratarmount seed-cache patch

Source: crates.io `librqbit` 9.0.1 (Apache-2.0), upstream commit
`a499d2f243d124e144aef137afe7cb304a6e3f36`, `crates/librqbit`. Upstream source, license,
features and dependencies are retained. This copy is excluded from the workspace;
`ratarmount-remote` uses it only with the optional `bittorrent` feature.

The complete source delta is [RATARMOUNT.patch](RATARMOUNT.patch).

Changes from the published source:

- `TorrentStorage::externally_populated()` defaults to false. Cache seed storage
  opts in. Initialization requires no selected downloads and begins with an empty
  HAVE bitmap, without reading/hash-checking the entire logical torrent.
- `TorrentStateLive::recheck_external_piece(index)` verifies one piece through
  storage before setting HAVE, updating file accounting, and broadcasting HAVE.
  Repeated calls for an advertised piece perform no disk read. Existing peer
  connections remain active. Normal downloading and storage retain upstream behavior.

The cache adapter independently verifies every served piece and refuses missing,
corrupt or failed whole-file data even if a peer still holds an older HAVE bitmap.
No external caller can set HAVE without rqbit's piece hash check. This API is for
read-only external seed storage with no selected downloads; it is not a general
concurrent downloader mutation API.

Regression coverage lives in `ratarmount-remote/src/torrent/tests.rs`:
`regression_seed_incremental_have_keeps_peer_without_rescanning`,
`regression_seed_advertises_only_verified_cache_pieces_and_refuses_eviction`,
`regression_seed_upload_limit_and_unmount_stop_listener`, and the loopback/LSD
transfer tests. Remove this copy when an upstream release offers the same API.

Workspace/native builds use the path dependency. Before publishing the BitTorrent
feature to crates.io, this API needs an upstream release or a published fork;
Cargo registry packages cannot retain a dependency on this unpublished local patch.
