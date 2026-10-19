# Changelog

## Unreleased

### Changes

- FUSE unmount: `ratarmount -u`, the control socket `unmount` command and the in-mount `.ratarmount-control/unmount` file retry `fusermount3 -u` every 50 ms for about a second while the mount is briefly busy (desktop mount watchers such as gvfsd-trash and gvfs-udisks2-volume-monitor probe every new mount), instead of failing on the first `Device or resource busy`. A mount that serves a `:temp:` overlay or live commit and receives SIGTERM falls back to a logged lazy unmount (`fusermount3 -u -z`) if it is still busy after the retries; SIGINT only retries. The control-file `unmount` used to always fail because it unmounted inside the FUSE request that opened it; it now unmounts on its own thread, logs a failure and can be tried again. The control socket answers `error: …` and stays available when the unmount fails. If both the retries and the SIGTERM lazy unmount fail, the daemon logs an error and keeps serving. (#136)
- FUSE unmount follow-ups to #136: `fusermount3` on musl (Alpine) reports EBUSY as `Resource busy`, which is now retried too. A SIGTERM lazy detach logs once that it is waiting for open files to close, and the signal watcher keeps running after a failed lazy unmount so a later signal retries. Plain read-only and plain `-w` mounts (not only `:temp:` and live-commit ones), in the foreground, daemonized or with an export, now unmount on SIGTERM and SIGINT instead of leaving a dead (`ENOTCONN`) mount. With a file held open, SIGTERM takes about 1 s (the retry window) before the lazy detach. The control socket `unmount` answers `ok unmounted` reliably, and a daemonized mount serves the socket at all. The lazy-unmount log names the real flags and no longer claims a retry. (#137)
- `ratarmount-csi` and `ratarmount-volume-plugin`: publishing the owner-only socket no longer replaces a socket that is already listening. Two concurrent starts on one path used to both succeed and leave the first daemon listening on an unlinked inode; the second now fails with `socket already in use`, as a plain bind did. Uses `renameat2(RENAME_NOREPLACE)`, so a filesystem or seccomp profile without it fails closed. (#117)

## 0.1.35

### Changes

- BitTorrent (`bittorrent` feature, built into the deb, rpm, and portable packages and the macOS tarballs): `--torrent-swarm` now defaults to `never`, so a mount reads only from the cache, `xs=` metainfo and web seeds and never contacts public trackers, DHT or LAN peer discovery unless asked. A magnet with no cached metadata and no `xs=` source, or a piece no web seed can serve, now fails with an error that says to pass `--torrent-swarm lan or auto`; pass `--torrent-swarm auto` for the old behaviour. `--seed` now needs an explicit `--torrent-swarm lan`, `auto` or `always`. (#110)
- FUSE `-w`: a file that is unlinked or replaced while the kernel still holds it keeps returning its old bytes and attributes (`nlink` 0) until the last reference is dropped. A write handle opened before that keeps writing the orphan (discarded at commit). A new write open or an fh-less setattr on that nodeid returns `EACCES`. (#104, fixes #88)
- FUSE now returns the real errno (ENOTDIR, EISDIR, EXDEV, ELOOP, ENOTEMPTY, ENOSPC, EMFILE, ENFILE, …) instead of EIO for unmapped I/O errors. (#103)
- FUSE foreground (`-f`): an `ECONNABORTED` from the session read at unmount is now a clean exit (exit 0), like `ENODEV`, and is logged at info; it used to exit 1 when `FORGET`s raced the unmount. (#104, #105)
- FUSE `-w` copy-on-write no longer publishes a short file. The copy is written to a `.ratarmount.overlay.cow-*` temp, `fsync`'d, then renamed. A short read, or a source whose length changed during the copy, fails the copy; FUSE returns `EIO` and the temp is removed. A crash mid-copy leaves the temp, which list, lookup, and `--commit-overlay` ignore. The next open removes leftover temps it can reach; a directory that cannot be read is logged and skipped and does not fail the open. A second open of the same overlay database is refused while the first holds it, so it cannot delete an in-progress temp. An archive member whose name starts with `.ratarmount.overlay.cow-` (ASCII case ignored) is hidden from the mount. `--commit-overlay` drops only tombstoned or overlay-replaced paths. A cow-prefixed archive member is neither, so it stays in the archive unchanged. (#129, fixes #126)
- ISO indexes are `rock-ridge-joliet-v4`. An older sidecar (`rock-ridge-joliet-v1` through `v3`, or any other `isoMetadataVersion`) is rebuilt on open. (#127, #123)
- `--passthrough` defaults to `auto` (Linux ≥ 6.9, ABI ≥ 7.40): passthrough is used only for a read-only mount when the process has `CAP_SYS_ADMIN` in the initial user namespace and the source is a write overlay or exposes backing extents; otherwise reads stay in the daemon. `--passthrough on` errors if the kernel has no `FUSE_PASSTHROUGH`. `--direct-io` disables passthrough. Member copy stays off unless `--passthrough-copy` and a non-zero `--passthrough-copy-max`. (#110)
- Mounts are `exec` by default. With the default owner-only access and `auto_unmount`, the kernel mount gets `allow_other`, but ratarmount still answers only the mounting user unless `-o allow_other` or `allow_root` is given. (#110)
- `export-parquet` is a default feature of the `ratarmount` binary. `bittorrent` is not a default Cargo feature; the deb, rpm, and portable packages and the macOS tarballs enable it. (#110)

### Features

- `hf://` reads a commit-pinned Hugging Face repo; `--publish-index` can upload the sidecar to the Hub, S3, GCS, or Azure; `-w` can commit the archive back to the Hub as one commit. Cached Hub snapshots can be shared with `huggingface_hub` and mounted offline. (#110)
- Mount a `.torrent` or magnet. With the default `--torrent-swarm never`, bytes come from the cache, `xs=` metainfo, and web seeds. `lan`, `auto`, and `always` are opt-in. `--seed` uploads only with one of those policies. (#110)
- Agent sandboxes: `--sandbox`, read-only overlay globs, byte and file quotas, `overlay-stats`, a sandbox daemon (`sandbox` / `new` / `list` / `destroy`), and a RAM overlay. Owner, group, and umask can be mapped. `ratarmount diff` writes a patch of the overlay against the base. (#110)
- Python package `ratarmount-rs` (PyO3/maturin) over the session API, plus fsspec, torch, and WebDataset extras, `mount()`, and index publish. Its version comes from the workspace Cargo version (maturin `dynamic` version; no separate pin). (#110)
- Safetensors and GGUF mount as a tree of tensor files (raw bytes, plus JSON sidecars). Parent directories of tensor names are listed. Nested checkpoints open without a temp spool. (#110)
- Git: `--git`, `--git-ref`, `repo@REV`, `--git-prefix`. A bad explicit ref errors instead of falling back to HEAD. `--git-synthetic-head` adds a history-free `.git` so `git status` / `diff` work. `--bind` mounts a source at a subpath; a corpus list mounts many repos as one tree. (#110)
- `ratarmount shard` and `ratarmount export-index` for dataset shards. `ratarmount snapshot` wraps restic. `--roll-every` rolls a write-mounted archive by size or time. `--memory-budget` caps buffers, decode windows, and caches. User xattrs survive the write overlay and commit manifests. (#110)
- Docker/Podman volume plugin and a Kubernetes CSI node driver mount volumes with ratarmount. Their sockets are created mode 0600. (#110)
- HTTP(S) keeps a process-wide connection pool, Bearer auth, a redirect cache that does not send credentials to the redirect host, and a bounded parallel range prefetch. (#110)
- Seekable zstd can decode ahead. (#110)
- `--direct-io` sets `FOPEN_DIRECT_IO` on archive members (overlay files keep normal caching), forces passthrough off, and requests `FUSE_DIRECT_IO_ALLOW_MMAP` when the kernel offers it. It turns kernel readahead off. (#110)
- Linux kernels that advertise `FUSE_MAX_PAGES` (4.20+) get a 256-page request ceiling (1 MiB with 4 KiB pages); older Linux kernels, FreeBSD and other non-macOS targets stay at 32 pages; macOS keeps fuser's defaults. This is independent of `--direct-io`, and direct I/O does not turn a 128 KiB `cat` into a 1 MiB read. (#110)

### Fixes

- Joliet fallback no longer binds a Rock Ridge symlink-target directory (an `SL` directory) to a Joliet directory through a child match, and a run of those directories under a plain parent is one hop. Those bugs dropped or misplaced the directory's children. File type comes from the ISO directory flag; Rock Ridge `PX` supplies permission bits only, so a file is no longer shown as a directory. Devices, FIFOs, and sockets are regular files. (#127, #123, #119)
- FUSE `-w` implements `rename`, including rename over another name, without unlinking the target first. A cached destination name is not `INVAL_ENTRY`'d. Attribute cache on `-w` tracks what the kernel was told. (#87, #103, #91, #92, #84, fixes #86, #88)
- The overlay database is not recreated when it cannot be read or is missing its marker (unlinked members would reappear). The open error names the database path. A locked database says it is in use. `.ratarmount.overlay.sqlite*` and both marker names are hidden and not mutable through the mount. (#89, #94, #97, #99)
- Concurrent readers of one TAR or ZIP no longer share a file cursor (a read could return another member's bytes). ZIP Stored and zip-crate path opens are positional. Interrupted Windows range reads are retried. ZIP DOS timestamps are converted in Rust, so the zip and tar crates pass `cargo check` on the Windows CI job. That job does not run the servers or mount anything. (#111, #112, #121, #128)
- ZIP DOS timestamps: an invalid DOS date or a time in a spring-forward DST gap now gives mtime 0 instead of the current time or a normalized time, and a time in an autumn fold may differ by the zone's DST offset (usually an hour). (#128)
- VHDX images whose metadata items are packed at small offsets inside the metadata region (as qemu-img 11 writes them) now open; they were rejected because every item had to be 64 KiB aligned. The File Parameters and Logical Sector Size GUIDs were wrong and now follow MS-VHDX, and a logical sector size other than 512 or 4096 is rejected. (#108, #113)
- 9P and SMB clear `O_NONBLOCK` inherited from the listening socket (macOS/BSD was cutting large replies short). Accept treats `WouldBlock` and `Interrupted` as a poll, not a fatal error. (#114, #125)
- A closed stdout or stderr pipe after startup no longer panics the process (exit 101). This covers index status lines, the `ratarmount` binary, overlay commit and create-if-missing lines, and format-crate progress. (#95, #98, #100, #106, fixes #93, #102)
- `chmod` and timestamp updates on `-w` apply to the overlay file, so a program created in the overlay can be executed. (#110)
- Remote folder mounts use a published sibling index instead of scanning every nested archive. Remote TAR indexing coalesces member-header reads. A bzip2 block boundary no longer truncates a TAR listing. (#110)
- Docs and `hf://` examples use the Hugging Face owner `RealMattBrewer`. (#122)
- README, format, and benchmark guides were rewritten around local-model workflows. (#116)

### Packaging and build

- Workspace MSRV is Rust 1.90. CI has an `msrv` job. The crates.io dry-run reads `rust-version` from `Cargo.toml`. (#85, #109, #113)
- The portable glibc 2.31 tarball vendors OpenSSL statically. Releases through 0.1.34 linked bullseye `libssl.so.1.1` and failed to start on Arch, Ubuntu 22.04+, and current Fedora. Host `libarchive` and `libfuse3` are still dynamic. A shipped tarball gets OpenSSL fixes only when that tarball is rebuilt. (#107)

### Known issues

- Deb, rpm, and portable packages and the macOS tarballs enable `bittorrent` (vendored librqbit) and do not ship third-party license notices. The macOS staging copy of `LICENSE` is the project license only. (#110)
- Reported on [#110](https://github.com/hilather/ratarmount-rs/pull/110#issuecomment-6236724875):
  - `--commit-overlay` and live/interval/rolling commits can leave the archive mode 0600 (pre-existing; #110 added more commit paths that do this).
  - A `SIGKILL` during write churn can leave the mount hung until `echo 1 > /sys/fs/fuse/connections/<n>/abort` (pre-existing).
  - After a `kill -9` during live `.tar.zst` interval commits, an immediate `-w` remount can return intermittent `EIO` for files committed in the killed session; the archive is intact (seen on 0.1.34 too).
