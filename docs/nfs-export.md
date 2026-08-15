# NFSv3 userspace export (and NFSv4.1 spike)

Status: **NFSv3 v1 + overlay writes**. NFSv4.1: **spike PASSED** (bind + unprivileged EXCHANGE_ID; no CLI yet). Design: [nfsv3-export-design.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/nfsv3-export-design.md), [nfsv4-roadmap-design.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/nfsv4-roadmap-design.md).

`ratarmount --nfs` serves the same `MountSource` tree as FUSE over **in-process NFSv3** (`nfsserve` 0.11). No kernel `nfsd`, no FUSE mount, no extra system library.

## Quick start

```bash
# NFS only — does not create a FUSE stem directory
ratarmount --nfs archive.tar.gz

# Optional bind (IPv4 only; default 127.0.0.1:20490)
ratarmount --nfs --nfs-bind 127.0.0.1:20490 archive.tar.gz

# FUSE + NFS (explicit mountpoint)
ratarmount --nfs -f archive.tar.gz mnt/

# Writable overlay (same `-w` / `:temp:` as FUSE)
ratarmount --nfs -w :temp: archive.tar.gz
```

Linux client (v1 acceptance):

```bash
mount -t nfs -o vers=3,tcp,nolock,port=20490,mountport=20490 127.0.0.1:/ /mnt
# or:
mount.nfs -o user,noacl,nolock,vers=3,tcp,rsize=131072,port=20490,mountport=20490 127.0.0.1:/ mnt
```

macOS (documented, not CI):

```bash
mount_nfs -o nolocks,vers=3,tcp,rsize=131072,port=20490,mountport=20490 127.0.0.1:/ mnt
```

## What v1 is

| Item | Behavior |
|------|----------|
| Protocol | NFSv3 + MOUNT + portmap on **one TCP port** |
| Access | Read-only by default (`NFS3ERR_ROFS`). With `-w` / `--write-overlay` (`:temp:` ok), create / write / mkdir / remove / size-setattr persist on the overlay. Rename and symlink stay `NFS3ERR_ROFS`. |
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
- Overlay **rename** / **symlink** over NFS (FUSE overlay may support more; NFS leaves these `NFS3ERR_ROFS`).
- `--commit-overlay` over NFS (use the existing CLI; not a network op).
- Kerberos, ACLs, NLM. NFSv4.1 is a compile-gated spike (see below); there is no `--nfs-vers` CLI yet.
- NFS-only daemonize (v1 NFS-only stays in the foreground).

## NFSv4.1 spike (PR 2)

Status: **PASSED** (2026-08-15, rustc 1.97.1). Optional feature `nfsv4` on `ratarmount-nfs` (forwarded from `ratarmount`) compiles [embednfs 0.4.1](https://docs.rs/embednfs/0.4.1/embednfs/) (`rust-version = "1.88"`, edition 2024). Workspace MSRV stays **1.74**; default `cargo test` / CI does **not** compile embednfs (same pattern as `gzip-rapidgzip`).

| Check | Result |
|-------|--------|
| `embednfs = "0.4.1"` behind `--features nfsv4` | Compiles on rustc ≥ 1.88 |
| `TcpListener::bind("127.0.0.1:0")` + `NfsServer::new(MemFs::new()).serve` + `NfsStop` | Exits within 2s (`v4_bind_ipv4_high_port`) |
| `NfsServer::listen("127.0.0.1:0")` | Starts; stop returns (`v4_listen_string_ipv4`) |
| Unprivileged TCP COMPOUND `EXCHANGE_ID` (program 100003, version 4) | **NFS4_OK** (`v4_exchange_id_smoke`) |
| Live Linux `mount -t nfs` | **Linux kernel client unverified** — `mount` exits 32 (`must be superuser to use mount`) |

**Not shipped:** `--nfs-vers`, `FileSystem` on `MountSource`, packaging `--features nfsv4`. `--nfs` remains NFSv3.

### Minimal Linux kernel option set (product claim, not yet verified)

Until a privileged `vers=4.1,tcp,port=,sec=sys` mount succeeds, README must not say “usable on Linux.” The recipe to try:

```bash
# After a future `--nfs --nfs-vers 4` binary (not in this spike):
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

### embednfs 0.4.1 API actually used

- `NfsServer::new(MemFs::new())`
- `NfsServer::serve(self, tokio::net::TcpListener) -> io::Result<()>` (docs say “returns the local address”; the signature is `Result<()>` — read `local_addr()` on the listener first)
- `NfsServer::listen(self, addr: &str) -> io::Result<()>` — `TcpListener::bind(addr)` then `serve`. `"127.0.0.1:0"` works.
- `NfsServerBuilder` only exposes `id_mapper` + `build`. No lease-time, bind-hook, or accept-filter.

### FileSystem / lease finding (for later PRs)

Grep of `~/.cargo/registry/src/**/embednfs-0.4.1`: `FileSystem` has **no** `open` / `close` / `lease_expired` hooks. OPEN/CLOSE/leases live inside `NfsServer` / `StateManager` (`DEFAULT_LEASE_TIME_SECS = 90`). Idle-TTL approximation remains the v1 contract (roadmap PR 5).

embednfs non-promises (do not advertise LAN / Windows / Kerberos): “does not guarantee correct or robust behavior over a real network”; “does not guarantee correct behavior for non-macOS clients.” Support target is **macOS over localhost**.

### Blockers

None for compile / bind / EXCHANGE_ID. Residual: **Linux kernel client unverified** (unprivileged CI cannot `mount -t nfs`). That blocks the README Linux claim; it is **not** a from-scratch-stack trigger.

Source builds of `--features nfsv4` need **rustc ≥ 1.88**. rustc &lt; 1.88 cannot compile embednfs; do not vendor an NFS4 codec.

## How it differs from FUSE-T / kernel re-export

[FUSE-T](https://www.fuse-t.org/) on macOS is a **local** NFS/SMB translation of FUSE — not a LAN export. Kernel `nfsd` re-export of a FUSE mount needs `fsid=`, `allow_other`, and is a double hop. This product path is an in-process server.

## Packaging

Userspace only. Deb/rpm/portable tarballs do not need `nfs-kernel-server`. Binding port 2049 still requires capabilities or root; the default is 20490.
