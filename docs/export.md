# Userspace exports besides NFS (HTTP, WebDAV, SMB, 9P, SFTP)

Status: **boolean flags shipped** (`--http` / `--webdav` / `--smb` / `--ninep` / `--sftp` / `--sftp-subsystem`) on the same `MountSource` tree as FUSE and NFS. Bind default **127.0.0.1** + unprivileged high ports. Auth is localhost unless an env password/user is set (same boundary as NFS AUTH_SYS-not-verified when unset). Overlay writes need `-w` where the protocol includes them; **HTTP GET/HEAD is read-only**.

NFS stays in [`nfs-export.md`](nfs-export.md). This page is the sibling adapters (`ratarmount-http`, `ratarmount-smb`, `ratarmount-9p`, `ratarmount-sftp`) plus shared bind/stop helpers in `ratarmount-export-core`. Roadmap: [`tasks/beyond-parity-roadmap.md`](tasks/beyond-parity-roadmap.md) P-5 / P-6 / P-2 / P-7 / P-10 / G-1.

There is **no** `ratarmount serve` subcommand. Combine flags on the existing CLI:

```bash
ratarmount --nfs --http archive.tar.gz
ratarmount --http archive.tar.gz            # HTTP-only (no FUSE mountpoint)
ratarmount --http --webdav --smb a.tar      # several exports, one process
```

`--http --no-mount` (and the same for the other export flags) **exits 2**. `--control-interface` still requires a FUSE mountpoint.

## Bind table

IPv4 only. Bare port → localhost. `[::1]` is rejected. Non-loopback prints a warning; there is no IP allowlist.

| Flag | Bind flag | Default | Well-known residual |
|------|-----------|---------|---------------------|
| `--nfs` | `--nfs-bind` | `127.0.0.1:20490` | 2049 |
| `--http` | `--http-bind` | `127.0.0.1:20491` | 80 / 8080 |
| `--webdav` | `--webdav-bind` | `127.0.0.1:20492` | 80 |
| `--ninep` | `--ninep-bind` | `127.0.0.1:20493` | 564 |
| `--sftp` | `--sftp-bind` | `127.0.0.1:20222` | 22 |
| `--smb` | `--smb-bind` | `127.0.0.1:20445` | 445 |

Bind flags take a **required value** (`num_args = 1`) so they cannot steal the archive path. Canonical 9P flag is **`--ninep`** (not `--9p`).

## HTTP GET/HEAD (`--http`) — P-5 `done`

Reverse of the HTTP Range client. One `source.open` + `fill_read` per request (gzip short `Read::read` is not EOF). Directories return `text/html` listings from `list_dirents`.

```bash
ratarmount --http archive.tar.gz
curl -I http://127.0.0.1:20491/member
curl -r 0-1023 http://127.0.0.1:20491/member
```

| Item | Behavior |
|------|----------|
| GET `/path` | 200 or 206; URL-decoded; `..` after decode → 400 |
| HEAD | `Content-Length`, `Accept-Ranges: bytes`, `Last-Modified` when mtime is finite |
| Range | Single `bytes=start-end` → 206 + `Content-Range`. Multiple ranges: first only or 200 full. Unsatisfiable → 416 |
| Auth | None (localhost) |
| Writes | Out of v1 (use `--webdav -w`) |

## WebDAV (`--webdav`) — P-6 `done`

Separate port from HTTP (v1 does not mux). PROPFIND Depth 0/1; Depth infinity / missing Depth → 403. GET/HEAD reuse the HTTP handler. OPTIONS `DAV: 1,2`.

```bash
ratarmount --webdav -w :temp: archive.tar.gz
# Finder / cadaver / cadaver-less:
curl -X PROPFIND -H 'Depth: 1' http://127.0.0.1:20492/
```

| Item | Behavior |
|------|----------|
| PROPFIND | `multistatus` with `getcontentlength`, `getlastmodified`, `resourcetype` |
| PUT / DELETE / MKCOL / MOVE | Overlay only (`-w`); without overlay → 403 |
| LOCK / UNLOCK | Exclusive write, in-memory (cap 1024; TTL 600 s). PUT/DELETE/MKCOL/PROPPATCH need `If` with the dest token (423 otherwise). COPY of a locked **source** onto an unlocked dest is allowed |
| COPY | Overlay only; Depth 0 file / Depth 1 immediate file children; nested collection child → 403 |
| PROPPATCH | 207 Multi-Status; live props no-op; dead props 403 per-prop |
| Basic | `RATARMOUNT_WEBDAV_USER` / `RATARMOUNT_WEBDAV_PASSWORD` when user is set; else none (localhost). Missing/wrong → 401 |
| Residual | Same-port HTTP+WebDAV mux; Finder/Explorer not in CI |

## SMB 2.0.2 (`--smb`) — P-2 `partial`

Userspace dialect subset. Share name `--smb-share` (default `ratarmount`). Guest `smbclient -N` `ls`/`get` on localhost is the **unsigned** v1 bar. Password env requires signing.

```bash
ratarmount --smb archive.tar.gz
smbclient //127.0.0.1/ratarmount -p 20445 -N -c ls
smbclient //127.0.0.1/ratarmount -p 20445 -N -c 'get member -'
```

| Item | Behavior |
|------|----------|
| Ops | NEGOTIATE, SESSION_SETUP (guest or `RATARMOUNT_SMB_USER`/`RATARMOUNT_SMB_PASSWORD`), TREE_CONNECT, CREATE, READ, QUERY_DIRECTORY, CLOSE, QUERY_INFO |
| Writes | CREATE-mkdir / WRITE / SET_INFO / DELETE only with `-w` |
| Guest | Password unset: unsigned; `smbclient -N` is the bar. Username match only if `RATARMOUNT_SMB_USER` is set |
| Password / signing | `RATARMOUNT_SMB_PASSWORD` set: NTLMv2 NT proof required; `SIGNING_REQUIRED`; HMAC-SHA256 on every request after SESSION_SETUP. Guest `-N` is off |
| Encryption / SMB 3.1.1 | **Residual** |
| Finder / Explorer | **Residual** (leases, create contexts; not a CI bar) |

## 9P2000.L TCP (`--ninep`) — P-7 `done`

```bash
ratarmount --ninep archive.tar.gz
mount -t 9p -o trans=tcp,port=20493,version=9p2000.L 127.0.0.1 /mnt
```

Writes (`Tlcreate` / `Twrite` / `Tmkdir` / `Tunlinkat` / `Trenameat` / `Tsymlink`) need `-w` else `EROFS`. **Residual:** virtio-9p / vhost-user-9p.

## SFTP (`--sftp`) — P-10 `done`

TCP listener `--sftp` / `--sftp-bind` (port 22 is `--sftp-bind 22`). Stdio OpenSSH `Subsystem sftp`: `--sftp-subsystem` (SFTP v3; no SSH-2). Needs **`--features sftp-russh`** (russh MSRV 1.85 > workspace 1.74 — **feature note**, not a protocol leftover). Linux/macOS packages enable it. Source builds without the feature: `--sftp` / `--sftp-subsystem` **exit 2** with a rebuild hint. Default CI does not compile russh.

```bash
# Packaged binary (sftp-russh compiled):
ratarmount --sftp archive.tar.gz
sftp -P 20222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null 127.0.0.1
# Stdio (sshd already authenticated):
#   Subsystem sftp /path/to/ratarmount --sftp-subsystem archive.tar
```

| Item | Behavior |
|------|----------|
| Auth (TCP) | Public-key from `--sftp-authorized-keys` or `RATARMOUNT_SFTP_AUTHORIZED_KEYS`, and/or password from `RATARMOUNT_SFTP_USER` / `RATARMOUNT_SFTP_PASSWORD`. Loopback defaults to `~/.ssh/authorized_keys`. **Non-loopback needs an explicit keys file or password env** (else exit 2; does not expose `$HOME` keys on `0.0.0.0`) |
| Host key | `RATARMOUNT_SFTP_HOST_KEY` or ephemeral ed25519 |
| Protocol | SFTP v3 REALPATH, STAT/LSTAT, OPENDIR/READDIR, OPEN/READ/CLOSE, READLINK. With `-w`: MKDIR, REMOVE, RMDIR, RENAME, OPEN-write, SETSTAT size |
| `--sftp-subsystem` | Stdio SFTP v3; exclusive with `--sftp`; ignores bind/keys; no SSH auth |

`--print-features` prints `sftp-russh: compiled` on packaged binaries.

## Shared rules (every export)

- **Fill-loop** every READ/GET. A short `Read::read` from gzip/7z is not EOF (same class as NFS `fill_read_for_nfs`).
- Overlay writes only with `-w` / `--write-overlay`. HTTP has no writes in v1.
- SIGINT / SIGTERM stops every export in the process (plus NFS).
- Credentials never appear in `debug!` / `Debug`.
- IPv6 is not supported (same split-on-first-`:` bind parser as NFS).

## Packaging

HTTP / WebDAV / SMB / 9P are always-on (MSRV 1.74). SFTP is **`sftp-russh`** on the same cargo line as `nfsv4`:

```text
cargo build --release -p ratarmount --features nfsv4,sftp-russh
```

Scripts: `packaging/build-native-packages.sh`, `build-appimage.sh`, `build-macos-tarball.sh`. Editing only `.github/workflows/packages.yml` does **not** compile either feature. Check: `./packaging/test-nfsv4-features.sh`.

See [packaging.md](packaging.md).
