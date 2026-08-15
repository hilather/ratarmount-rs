# NFSv3 userspace export (and optional NFSv4.1)

Status: **NFSv3 v1 + overlay writes** (default). **NFSv4.1** via `--nfs --nfs-vers 4` is compiled into **Linux release packages** (deb/rpm/portable/AppImage) and **macOS tarballs** (`packaging/build-*-packages.sh` / `build-appimage.sh` / `build-macos-tarball.sh` pass `--features nfsv4`; rustc ≥ 1.88). Source builds without the feature: `--nfs --nfs-vers 4` exits 2. RO without `-w`; **`-w` overlay writes** (create/write/mkdir/remove/setattr-size) match v3. Reader slots idle **90s** are dropped (lease approximation, **not** a CLOSE hook). **Linux kernel client verified** on loopback (privileged Docker, 2026-08-15: `./test-harness/nfs-docker/run.sh` — `vers=3` and `vers=4.1,sec=sys` `ls`/`cat` matched fixture files). Default unprivileged CI does **not** run that driver. Residuals: Kerberos / LAN / Windows / no mux / idle-TTL-not-CLOSE. Design: [nfsv3-export-design.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/nfsv3-export-design.md), [nfsv4-roadmap-design.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/nfsv4-roadmap-design.md).

`ratarmount --nfs` serves the same `MountSource` tree as FUSE over **in-process NFSv3** (`nfsserve` 0.11) by default. `--nfs-vers 4` selects **NFSv4.1** (`embednfs` 0.4.1, no MOUNT/portmap). No kernel `nfsd`, no FUSE mount, no extra system library. There is **no v3/v4 mux** on one port.

## Quick start

```bash
# NFS only — does not create a FUSE stem directory
ratarmount --nfs archive.tar.gz

# Optional bind (IPv4 only; default 127.0.0.1:20490)
ratarmount --nfs --nfs-bind 127.0.0.1:20490 archive.tar.gz

# FUSE + NFS (explicit mountpoint)
ratarmount --nfs -f archive.tar.gz mnt/

# Writable overlay (same `-w` / `:temp:` as FUSE) — NFSv3 and NFSv4.1
ratarmount --nfs -w :temp: archive.tar.gz
ratarmount --nfs --nfs-vers 4 -w :temp: archive.tar.gz

# Live commit into an uncompressed TAR (not :temp:, not .tar.gz/.zip)
ratarmount --nfs -w /var/lib/ratarmount/ov --commit-overlay-on-exit archive.tar
ratarmount --nfs -w /var/lib/ratarmount/ov --commit-overlay-interval 15m archive.tar

# NFSv4.1 (opt-in; Linux packages already enable nfsv4)
ratarmount --nfs --nfs-vers 4 archive.tar.gz

# Privileged well-known port (needs root or CAP_NET_BIND_SERVICE)
# ratarmount --nfs --nfs-bind 2049 archive.tar.gz
# ratarmount --nfs --nfs-vers 4 --nfs-bind 2049 archive.tar.gz
```

Linux client (loopback; kernel client verified in privileged Docker):

```bash
mount -t nfs -o vers=3,tcp,nolock,port=20490,mountport=20490 127.0.0.1:/ /mnt
# or:
mount.nfs -o user,noacl,nolock,vers=3,tcp,rsize=131072,port=20490,mountport=20490 127.0.0.1:/ mnt
```

Live overlay commit (uncompressed TAR only):

```bash
# Durable overlay required. gzip/bzip2/xz TAR and ZIP are rejected (use offline --commit-overlay).
ratarmount --nfs -w /var/lib/ratarmount/ov --commit-overlay-on-exit archive.tar
ratarmount --nfs -w /var/lib/ratarmount/ov --commit-overlay-interval 15m archive.tar
```

Interval commit is in-process: sibling copy of the archive, GNU `tar --delete`/`--append`, atomic replace, reopen the TAR, then clear overlay files so a later tick cannot duplicate members. On-exit commits on SIGINT/SIGTERM or when NFS/FUSE returns (no overlay reset). `:temp:` is rejected.

Privileged kernel-client check (not default CI):

```bash
./test-harness/nfs-docker/run.sh        # NFSv3 then NFSv4.1
./test-harness/nfs-docker/run.sh 3
./test-harness/nfs-docker/run.sh 4
```

The driver starts the **shipped** `ratarmount` (`--nfs` / `--nfs --nfs-vers 4`) and uses real `mount -t nfs` inside one privileged Ubuntu 24.04 container (`nfs-common`). Fixture member bytes are written to a file, packed into a tar, then `cmp`'d after `cat` — expected bytes are never hard-coded independently. **Skip** (exit 0) when docker is missing, the daemon is unusable, `/proc/filesystems` has no `nfs`/`nfs4`, or `mount` reports “must be superuser”. A mount that succeeds with empty or wrong member bytes is a **fail** (exit 1).

macOS (documented, not CI):

```bash
mount_nfs -o nolocks,vers=3,tcp,rsize=131072,port=20490,mountport=20490 127.0.0.1:/ mnt
```

## What v1 is

| Item | Behavior |
|------|----------|
| Protocol | NFSv3 + MOUNT + portmap on **one TCP port** |
| Access | Read-only by default (`NFS3ERR_ROFS`). With `-w` / `--write-overlay` (`:temp:` ok), create / write / mkdir / remove / size-setattr / rename / symlink persist on the overlay. |
| Default bind | `127.0.0.1:20490` (unprivileged) |
| Auth | AUTH_SYS (not verified). Localhost is the security boundary. |
| Locks | None — clients must pass `nolock` / `nolocks` |
| IPv6 | Not supported (`NFSTcpListener::bind` splits on first `:`) |
| `--nfs-allow` | Not shipped (no accept hook in nfsserve 0.11) |
| Filehandles | Invalid after process restart (generation = start time) |
| `--control-interface` | Requires a FUSE mountpoint; NFS-only → exit 2 |
| `--no-mount` | Incompatible with `--nfs` (exit 2) |

Non-loopback bind (`0.0.0.0`, LAN IP) prints a warning. There is no IP allowlist.

## Residuals (not v1 acceptance)

- **Windows** `mount.exe` / `dir`: nfsserve `READDIR` is unimplemented (Linux/macOS use `READDIRPLUS`). Default client port is often 2049, not 20490.
- Overlay **rename** / **symlink** work with `-w` on NFSv3 and NFSv4.1 (same overlay folder as FUSE). Without `-w` they stay `NFS3ERR_ROFS` / `NFS4ERR_ROFS`.
- Live `--commit-overlay-on-exit` / `--commit-overlay-interval` apply only to **uncompressed TAR** (copy + GNU `tar --delete`/`--append` + replace). gzip/bzip2/xz TAR and ZIP stay the offline `ratarmount --commit-overlay` path (full rewrite). `:temp:` is rejected. There is no NFS RPC to trigger commit.
- Linux NFSv4.1 `cp`/`cat` **close** can return `Remote I/O error` after a successful write (bytes still match on `cmp`). The adapter implements embednfs `COMMIT`; this is a residual, not silent data loss.
- Kerberos / RPCSEC_GSS / ACLs / delegations / NLM. NFSv4.1 is opt-in (`--nfs-vers 4`). Overlay create/write/mkdir/remove/setattr-size/rename/symlink work with `-w`.
- **LAN share** and **Windows** NFSv4 clients (embednfs is macOS-first over localhost; “does not guarantee correct behavior for non-macOS clients”).
- **No v3/v4 mux** on one port (see below). `mount -t nfs` without `vers=` may try v4 first — that is client policy.
- Idle TTL is **not** CLOSE (embednfs 0.4.1 `FileSystem` has no OPEN/CLOSE hook).
- NFS-only daemonize (v1 NFS-only stays in the foreground).
- `--nfs-vers` without `--nfs` is ignored (must not fail FUSE-only mounts).
- `--nfs-export-name` is a v3 MOUNT name; warned and ignored on v4.

## NFSv4.1 (`--nfs --nfs-vers 4`)

Status: **RO + `-w` overlay adapter shipped**. Optional feature `nfsv4` on `ratarmount-nfs` (forwarded from `ratarmount`) compiles [embednfs 0.4.1](https://docs.rs/embednfs/0.4.1/embednfs/) (`rust-version = "1.88"`, edition 2024). Workspace MSRV stays **1.74**; default `cargo test` / CI does **not** compile embednfs (same pattern as `gzip-rapidgzip`). `--nfs` without `--nfs-vers` remains NFSv3.

```bash
# Release packages (deb/rpm/portable/AppImage/macOS tarball) already compile nfsv4.
# Source without the feature: `--nfs --nfs-vers 4` exits 2:
#   rebuild with --features nfsv4 (rustc >= 1.88)
# Workspace MSRV stays 1.74; default `cargo test` / CI check does not compile embednfs.
cargo run --features nfsv4 -- --nfs --nfs-vers 4 archive.tar.gz
# Accepts `4` or `4.1`. Rejects `4.0` (macOS `vers=4` is NFSv4.0).
```

Linux client recipe (loopback kernel mount **verified** 2026-08-15 via `./test-harness/nfs-docker/run.sh 4`; unprivileged CI still cannot `mount -t nfs`):

```bash
mount -t nfs -o vers=4.1,tcp,port=20490,sec=sys 127.0.0.1:/ /mnt
# Remount after server restart may also need nosharecache.
```

| Option | Why |
|--------|-----|
| `vers=4.1` | embednfs is NFSv4.1 only. macOS `vers=4` is 4.0 and is rejected. |
| `tcp` | Userspace TCP listener (no UDP). |
| `port=` | High-port bind (default 20490); no portmap / mountd. |
| `sec=sys` | Avoid nfsidmap / `nobody` hang. Idmap is **client config**, not a protocol kill. |
| `nosharecache` | Optional if remounting the same `server:port` after a restart. |

If localhost still maps `nobody` after `sec=sys`, try `nfs4_disable_idmapping=1` or `Domain = localdomain` in `/etc/idmapd.conf`.

Without `-w`, v4 mutators return `NFS4ERR_ROFS` (`FsError::ReadOnly`). With `-w` / `--write-overlay` (`:temp:` ok), create / write / mkdir / remove / size-setattr / rename / symlink persist on the same `WriteOverlay` as FUSE and NFSv3. Writes report `WriteStability::DataSync` (bytes reached the overlay file/page cache; no extra `fsync`). `--nfs-export-name` is ignored (no MOUNT). AUTH_SYS is accepted and **not** used for authorization (same localhost boundary as v3).

### Reader idle TTL (not a CLOSE hook)

embednfs 0.4.1 `FileSystem` has **no** `open` / `close` / `lease_expired` hooks. OPEN/CLOSE/clientid/leases live inside `NfsServer` / `StateManager` (`DEFAULT_LEASE_TIME_SECS = 90`). We do **not** receive CLOSE.

v4 therefore drops live `ArchiveRead` slots whose `last_used` is older than **90s** (`READER_IDLE_TTL`, same as embednfs’s lease). `serve_v4` sweeps at ~1 Hz; a new slot insert also evicts idle entries. This **approximates** NFSv4.1 lease expiry. A client that CLOSEs immediately still holds the decompressor until idle TTL (or the cap-64 LRU). Pinned solid-7z slots are also dropped after 90s idle — the next READ re-opens (prefix-from-0). Cap-pressure eviction still prefers cheap (unpinned) slots first.

### Spike / protocol (PR 2, still green)

Status: **PASSED** (2026-08-15, rustc 1.97.1).

| Check | Result |
|-------|--------|
| `embednfs = "0.4.1"` behind `--features nfsv4` | Compiles on rustc ≥ 1.88 |
| `TcpListener::bind("127.0.0.1:0")` + `NfsServer::new(MemFs::new()).serve` + `NfsStop` | Exits within 2s (`v4_bind_ipv4_high_port`) |
| `NfsServer::listen("127.0.0.1:0")` | Starts; stop returns (`v4_listen_string_ipv4`) |
| Unprivileged TCP COMPOUND `EXCHANGE_ID` (program 100003, version 4) | **NFS4_OK** (`v4_exchange_id_smoke`) |
| Live Linux `mount -t nfs` | **PASSED** (2026-08-15) privileged Docker `./test-harness/nfs-docker/run.sh` — NFSv3 `vers=3,tcp,nolock,port=,mountport=` and NFSv4.1 `vers=4.1,tcp,port=,sec=sys`; `ls`/`cat` matched fixture files. Unprivileged host `mount` still exits 32 (`must be superuser`). |

**Packaging (PR 6):** Linux `packaging/build-native-packages.sh` and `packaging/build-appimage.sh` pass `--features nfsv4` on the **cargo** line. macOS `packaging/build-macos-tarball.sh` does too (rustup **stable**, rustc ≥ 1.88 assumed). Editing only `.github/workflows/packages.yml` does **not** compile v4. `--nfs` remains NFSv3 unless `--nfs-vers 4` is passed to a `nfsv4` binary. Overlay writes on v4 require `-w` (same as v3). Idle reader drop is the 90s TTL above, not a real CLOSE.

### embednfs 0.4.1 API actually used

- `NfsServer::new(MemFs::new())`
- `NfsServer::serve(self, tokio::net::TcpListener) -> io::Result<()>` (docs say “returns the local address”; the signature is `Result<()>` — read `local_addr()` on the listener first)
- `NfsServer::listen(self, addr: &str) -> io::Result<()>` — `TcpListener::bind(addr)` then `serve`. `"127.0.0.1:0"` works.
- `NfsServerBuilder` only exposes `id_mapper` + `build`. No lease-time, bind-hook, or accept-filter.

### FileSystem / lease finding

Grep of `~/.cargo/registry/src/**/embednfs-0.4.1`: `FileSystem` has **no** `open` / `close` / `lease_expired` hooks. OPEN/CLOSE/leases live inside `NfsServer` / `StateManager` (`DEFAULT_LEASE_TIME_SECS = 90`). No hidden builder callback. **v1 contract:** 90s idle TTL (see above), not a CLOSE hook.

embednfs non-promises (do not advertise LAN / Windows / Kerberos): “does not guarantee correct or robust behavior over a real network”; “does not guarantee correct behavior for non-macOS clients.” Support target is **macOS over localhost**.

### Blockers

None for compile / bind / EXCHANGE_ID / Linux loopback kernel mount. Residual: Kerberos / LAN / Windows / no mux; default CI stays unprivileged (no `mount -t nfs` there).

Source builds of `--features nfsv4` need **rustc ≥ 1.88**. rustc &lt; 1.88 cannot compile embednfs; do not vendor an NFS4 codec.

## How it differs from FUSE-T / kernel re-export

[FUSE-T](https://www.fuse-t.org/) on macOS is a **local** NFS/SMB translation of FUSE — not a LAN export. Kernel `nfsd` re-export of a FUSE mount needs `fsid=`, `allow_other`, and is a double hop. This product path is an in-process server.

## Packaging

Userspace only. Deb/rpm/portable tarballs / AppImage do **not** need `nfs-kernel-server`. Default listen port is **20490** (unprivileged).

| Build | `nfsv4` compiled? |
|-------|-------------------|
| `cargo test --workspace` / default CI `fmt + clippy + test` | **No** (MSRV 1.74; same pattern as `gzip-rapidgzip`) |
| CI job `nfsv4 feature tests` (`ci.yml`) | **Yes** (rustup stable) |
| `packaging/build-native-packages.sh` (deb/rpm/portable) | **Yes** — `cargo build --release -p ratarmount --features nfsv4` |
| `packaging/build-appimage.sh` | **Yes** — same cargo line |
| `packaging/build-macos-tarball.sh` | **Yes** (rustup stable ≥ 1.88 assumed). If a macOS builder is ever pinned below 1.88, drop the feature and update this table. |
| `cargo build` / `make release` (no features) | `--nfs --nfs-vers 4` → exit 2 |

This is a **stronger** packaging commitment than `gzip-rapidgzip` (still off). Current package jobs install rustup **stable**. If a Rocky/portable builder is ever pinned below rustc 1.88, keep the feature off and document here.

`--print-features` prints `nfsv4: compiled` on packaged binaries. `--oss-attributions` lists **embednfs** (MIT) when the feature is compiled.

See [packaging.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/packaging.md).

## Privileged port 2049 (optional)

Default remains `127.0.0.1:20490`. `--nfs-bind 2049` already parses as `127.0.0.1:2049` (`parse_nfs_bind`). Binding 2049 needs **root** or `CAP_NET_BIND_SERVICE`. There is no special-case listen path.

```bash
# v3 (default)
sudo ratarmount --nfs --nfs-bind 2049 archive.tar.gz
# or: sudo setcap cap_net_bind_service=+ep /usr/bin/ratarmount
#     ratarmount --nfs --nfs-bind 2049 archive.tar.gz

# v4.1 (nfsv4-enabled binary)
sudo ratarmount --nfs --nfs-vers 4 --nfs-bind 2049 archive.tar.gz
```

Linux client on 2049 (v3 recipe unchanged except `port=` / `mountport=`):

```bash
# v3
mount -t nfs -o vers=3,tcp,nolock,port=2049,mountport=2049 127.0.0.1:/ /mnt
# v4.1 — same idmap / sec=sys notes as above
mount -t nfs -o vers=4.1,tcp,port=2049,sec=sys 127.0.0.1:/ /mnt
```

## No v3/v4 mux on one port

`--nfs` is either NFSv3 **or** NFSv4.1, never both on one socket. Try-v4-then-v3 is **not** implemented.

NFSv3 (RPC program 100003 + MOUNT 100005 + portmap on `nfsserve`’s `NFSTcpListener`) and NFSv4.1 (COMPOUND, no portmap, `embednfs::NfsServer`) cannot share an accepted TCP connection without a custom RPC dispatcher. Neither crate documents a detect-and-handoff API.

Linux `mount -t nfs` without `vers=` may try v4 first on modern kernels — that is **client** policy, not something this process muxes. Operators who want “try 4 then 3” run **two processes on two ports**, or pass `--nfs-vers` explicitly. Revisit only if embednfs (or a successor) grows a mux.
