# Changelog

## Unreleased

- BitTorrent (`bittorrent` feature, built into the deb/rpm/portable packages): `--torrent-swarm` now defaults to `never`, so a mount reads only from the cache, `xs=` metainfo and web seeds and never contacts public trackers, DHT or LAN peer discovery unless asked. A magnet with no cached metadata and no `xs=` source, or a piece no web seed can serve, now fails with an error naming `--torrent-swarm lan` / `--torrent-swarm auto`; pass `--torrent-swarm auto` for the old behaviour. `--seed` now needs an explicit `--torrent-swarm lan`, `auto` or `always`.
- FUSE `-w`: a file that is unlinked or replaced while the kernel still holds it keeps returning its old bytes and attributes (`nlink` 0) until the last reference is dropped. A write handle opened before that keeps writing the orphan (discarded at commit). A new write open or an fh-less setattr on that nodeid returns `EACCES`.
- FUSE now returns the real errno (ENOTDIR, EISDIR, EXDEV, ELOOP, ENOTEMPTY, ENOSPC, EMFILE, ENFILE, …) instead of EIO for unmapped I/O errors.
- FUSE foreground (`-f`): an `ECONNABORTED` from the session read at unmount is now a clean exit (exit 0), like `ENODEV`, and is logged at info; it used to exit 1 when `FORGET`s raced the unmount.
