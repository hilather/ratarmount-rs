# Userspace exports besides NFS (HTTP, WebDAV, SMB, 9P, SFTP)

Status: **boolean flags shipped** (`--http` / `--webdav` / `--smb` / `--ninep` / `--sftp`) on the same `MountSource` tree as FUSE and NFS. Bind default **127.0.0.1** + unprivileged high ports. Auth is localhost (same boundary as NFS AUTH_SYS-not-verified). Overlay writes need `-w` where the protocol includes them; **HTTP GET/HEAD is read-only**.

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

## WebDAV (`--webdav`) — P-6 `partial`

Separate port from HTTP (v1 does not mux). PROPFIND Depth 0/1; Depth infinity / missing Depth → 403. GET/HEAD reuse the HTTP handler.

```bash
ratarmount --webdav -w :temp: archive.tar.gz
# Finder / cadaver / cadaver-less:
curl -X PROPFIND -H 'Depth: 1' http://127.0.0.1:20492/
```

| Item | Behavior |
|------|----------|
| PROPFIND | `multistatus` with `getcontentlength`, `getlastmodified`, `resourcetype` |
| PUT / DELETE / MKCOL / MOVE | Overlay only (`-w`); without overlay → 403 |
| LOCK / UNLOCK | **Residual** (Finder save-in-place) |
| COPY / PROPPATCH / Basic | Residual |

## SMB 2.0.2 (`--smb`) — P-2 `partial`

Userspace dialect subset. Share name `--smb-share` (default `ratarmount`). Guest `smbclient` `ls`/`get` on localhost is the v1 bar.

```bash
ratarmount --smb archive.tar.gz
smbclient //127.0.0.1/ratarmount -p 20445 -N -c ls
smbclient //127.0.0.1/ratarmount -p 20445 -N -c 'get member -'
```

| Item | Behavior |
|------|----------|
| Ops | NEGOTIATE, SESSION_SETUP (guest or `RATARMOUNT_SMB_USER`/`RATARMOUNT_SMB_PASSWORD`), TREE_CONNECT, CREATE, READ, QUERY_DIRECTORY, CLOSE, QUERY_INFO |
| Writes | CREATE-mkdir / WRITE / SET_INFO / DELETE only with `-w` |
| Signing / encryption / SMB3 | **Residual** |
| Finder / Explorer | **Residual** |
| NTLM | Username match only — NT response is not verified |

## 9P2000.L TCP (`--ninep`) — P-7 `done`

```bash
ratarmount --ninep archive.tar.gz
mount -t 9p -o trans=tcp,port=20493,version=9p2000.L 127.0.0.1 /mnt
```

Writes (`Tlcreate` / `Twrite` / `Tmkdir` / `Tunlinkat` / `Trenameat` / `Tsymlink`) need `-w` else `EROFS`. **Residual:** virtio-9p / vhost-user-9p.

## SFTP (`--sftp`) — P-10 `partial`

TCP listener (not stdio `sftp-server`). Needs **`--features sftp-russh`** (russh MSRV 1.85 > workspace 1.74). Linux/macOS packages enable it. Source builds without the feature: `--sftp` **exits 2** with a rebuild hint. Default CI does not compile russh.

```bash
# Packaged binary (sftp-russh compiled):
ratarmount --sftp archive.tar.gz
sftp -P 20222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null 127.0.0.1
```

| Item | Behavior |
|------|----------|
| Auth | `authorized_keys` subset from `--sftp-authorized-keys` or `RATARMOUNT_SFTP_AUTHORIZED_KEYS`. Loopback defaults to `~/.ssh/authorized_keys`. **Non-loopback without an explicit keys file exits 2** (does not expose `$HOME` keys on `0.0.0.0`) |
| Host key | `RATARMOUNT_SFTP_HOST_KEY` or ephemeral ed25519 |
| Protocol | SFTP v3 REALPATH, STAT/LSTAT, OPENDIR/READDIR, OPEN/READ/CLOSE, READLINK. With `-w`: MKDIR, REMOVE, RMDIR, RENAME, OPEN-write, SETSTAT size |
| Password | Residual |
| `--sftp-subsystem` | Residual (TCP is v1) |

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
