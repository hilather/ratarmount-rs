# NFSv3 userspace export

Status: **v1 + overlay writes**. Design: [nfsv3-export-design.md](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/nfsv3-export-design.md).

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
- NFSv4, Kerberos, ACLs, NLM.
- NFS-only daemonize (v1 NFS-only stays in the foreground).

## How it differs from FUSE-T / kernel re-export

[FUSE-T](https://www.fuse-t.org/) on macOS is a **local** NFS/SMB translation of FUSE — not a LAN export. Kernel `nfsd` re-export of a FUSE mount needs `fsid=`, `allow_other`, and is a double hop. This product path is an in-process server.

## Packaging

Userspace only. Deb/rpm/portable tarballs do not need `nfs-kernel-server`. Binding port 2049 still requires capabilities or root; the default is 20490.
