# An image rootfs with a private repository

The [`scripts/rootfs-union.sh`](scripts/rootfs-union.sh) smoke accepts
`REPO_SOURCE=/path/to/repo.git@<commit>` and `ROOTFS_IMAGE=docker://...`, then
mounts the union and runs `git status` inside bubblewrap or systemd-nspawn when
available. It reports a mount skip without `/dev/fuse`.

Combine an OCI image at `/` with a committed Git tree at `/repo`. No Docker
daemon is needed; image layers are read through the registry backend. Use an
image digest and a full commit SHA for reproducible attempts. Run these examples
on Linux with FUSE available. Replace the image and repository revision with
ones containing the runtime and source you need.

```sh
mkdir -p mnt
ratarmount --git-synthetic-head -w attempt-overlay \
  --bind /repo=/srv/repos/project.git@0123456789abcdef0123456789abcdef01234567 \
  docker://ubuntu:24.04 mnt
```

The synthetic repository is at `mnt/repo/.git`; it contains one history-free
commit. The overlay covers both the image and repository. Use a fresh overlay
for each attempt. See [Git mounts](../git-mounts.md) for the object isolation
and cache requirements, and [sandbox controls](../sandbox.md) for read-only
path rules and quotas.

With bubblewrap installed, bind the assembled root and enter it:

```sh
bwrap --bind "$PWD/mnt" / --proc /proc --dev /dev --tmpfs /tmp \
  --unshare-pid --unshare-uts --unshare-ipc --unshare-net \
  --chdir /repo /bin/sh
```

The image must contain `/bin/sh` and the programs used by the task. Bubblewrap
needs the host's user-namespace support or its supported privileged setup.
The writable FUSE mount remains owned by the daemon's user; align the sandbox
user with it. The example supplies no host source repository or cache paths.

Alternatively, with systemd-nspawn installed and the required privileges:

```sh
sudo systemd-nspawn -D "$PWD/mnt" --chdir=/repo /bin/sh
```

A process running as a different uid needs appropriate FUSE access and Git
ownership configuration; see [Git mounts](../git-mounts.md). Configure nspawn's
network and namespace policy for the workload.

For a microVM, export the same tree through virtio-9p plumbing or an NFS client
instead of mounting FUSE on the host:

```sh
ratarmount serve --ninep --ninep-bind 127.0.0.1:5640 -w vm-overlay \
  --bind /repo=/srv/repos/project.git@0123456789abcdef0123456789abcdef01234567 \
  docker://ubuntu:24.04
# Or choose NFS (the guest must be able to reach this host address):
ratarmount serve --nfs --nfs-bind 127.0.0.1:20490 -w vm-overlay-nfs \
  --bind /repo=/srv/repos/project.git@0123456789abcdef0123456789abcdef01234567 \
  docker://ubuntu:24.04
```

These commands start network exports. Connect them using the VMM's supported
9P transport or the guest NFS client; they do not launch a VM or turn a TCP
9P listener directly into a virtio device. See [exports](../export.md) and
[NFS export](../nfs-export.md) for transport/client setup. Expose listeners only
on trusted interfaces. Finish with `ratarmount -u mnt` for the FUSE example.
