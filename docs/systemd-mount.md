# systemd `.mount`, fstab, and autofs (G-5)

Status: **v1 RO helper shipped.** `Type=fuse.ratarmount` uses [`packaging/mount.fuse.ratarmount`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/mount.fuse.ratarmount) (installed as `/usr/sbin/mount.fuse.ratarmount` in `.deb`/`.rpm`). Kubernetes CSI is **spec-only** in this repo — see [`csi.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/csi.md). Residual: `-w` overlay units / StorageClass (needs F-7 write-through), SELinux / AppArmor policy, Windows.

FUSE needs a mountpoint. `--no-mount` is export-only (NFS/HTTP/…). Do **not** ship a `ratarmount@.service` with `ExecStart=ratarmount -f --no-mount` as a substitute for this helper.

Roadmap: [`tasks/beyond-parity-roadmap.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/beyond-parity-roadmap.md) G-5.

## Helper

`mount(8)` looks up `mount.fuse.TYPE` when the filesystem type is `fuse.ratarmount`:

```text
mount.fuse.ratarmount WHAT WHERE [-o OPTIONS]
```

Defaults: `allow_other,ro`. fstab-only tokens (`_netdev`, `noauto`, `x-systemd.*`, …) are stripped before they reach libfuse. The helper **daemonizes** via the normal `ratarmount` parent/child path (no `-f`).

**Credentials stay in the environment.** Never put `AWS_*`, `RESTIC_*`, or passwords on `What=`, `Options=`, or the autofs map line. Use `EnvironmentFile=` (mode `0600`) or the process environment.

```bash
# After a distro package (helper already in /usr/sbin):
sudo mkdir -p /mnt/archives/dataset
sudo mount -t fuse.ratarmount s3://bucket/dataset.tar.zst /mnt/archives/dataset \
  -o ro,allow_other,_netdev
```

From a source tree / portable tarball, install the helper next to `mount(8)`'s search path:

```bash
sudo install -m 755 packaging/mount.fuse.ratarmount /usr/sbin/mount.fuse.ratarmount
```

## fstab

```fstab
s3://bucket/dataset.tar.zst  /mnt/archives/dataset  fuse.ratarmount  ro,allow_other,_netdev  0  0
```

`_netdev` tells systemd to wait for the network. Local archives can omit it.

HPC home-quota: sidecar downloads still use `$XDG_CACHE_HOME/ratarmount/meta-v3/` — point `XDG_CACHE_HOME` at scratch if `$HOME` is small ([`phase10-remote.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/phase10-remote.md)).

## systemd `.mount`

Example unit: [`packaging/systemd/mnt-archives-dataset.mount`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/systemd/mnt-archives-dataset.mount). The **filename must be** `systemd-escape -p` of `Where=` (`/mnt/archives/dataset` → `mnt-archives-dataset.mount`).

```ini
[Unit]
Description=ratarmount RO archive (s3 dataset)
After=network-online.target
Wants=network-online.target

[Mount]
What=s3://bucket/dataset.tar.zst
Where=/mnt/archives/dataset
Type=fuse.ratarmount
Options=ro,allow_other,_netdev
TimeoutSec=0
# EnvironmentFile=-/etc/ratarmount/s3.env

[Install]
WantedBy=multi-user.target
```

`TimeoutSec=0` disables the mount timeout so a cold index of a large archive is not killed. `EnvironmentFile=-/etc/ratarmount/s3.env` (create with mode `0600`) is the supported way to pass `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_ENDPOINT_URL`.

```bash
sudo install -m 644 packaging/systemd/mnt-archives-dataset.mount \
  /etc/systemd/system/mnt-archives-dataset.mount
# edit What=/Where=/EnvironmentFile=
sudo mkdir -p /mnt/archives/dataset
sudo systemctl daemon-reload
sudo systemctl enable --now mnt-archives-dataset.mount
```

Check: `systemctl status mnt-archives-dataset.mount` and `findmnt /mnt/archives/dataset`.

## autofs

Example map: [`packaging/autofs/auto.ratarmount`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/autofs/auto.ratarmount).

```text
# /etc/auto.master.d/ratarmount.autofs
/mnt/archives  /etc/auto.ratarmount  --timeout=300

# /etc/auto.ratarmount
dataset -fstype=fuse.ratarmount,ro,allow_other :s3://bucket/dataset.tar.zst
```

Access `/mnt/archives/dataset` to mount on demand. Credentials inherit the autofs service environment (`systemctl edit autofs`, `EnvironmentFile=`).

## Tests

```bash
./packaging/test-systemd-unit.sh
```

Skip: `systemd-analyze` if systemd is missing; `kubeconform` if the CSI linter is missing. Always asserts the helper argv has **no** secrets (env only) and `Type=fuse.ratarmount`.

## Residual

| Item | Status |
|------|--------|
| RO fstab / systemd `.mount` / autofs | **v1** |
| Helper argv secrets | Forbidden (env / `EnvironmentFile=` only) |
| `-w` overlay `.mount` / live commit on `s3://` | Later (F-7) |
| `ratarmount@.service` + `--no-mount` | **Not** v1 |
| CSI driver | Spec-only ([`csi.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/csi.md)); separate repo |
| SELinux / AppArmor | Residual |
