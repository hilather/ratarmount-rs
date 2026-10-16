# Apple silicon and Linux VMs

Library mode (`ratarmount_rs`) avoids a host FUSE mount and is the first path
to measure for Python/MLX loaders. Install a matching macOS arm64 wheel in a
venv, then run `samples.py` there. Host filesystem mounts require a compatible
ratarmount macOS build and macFUSE or FUSE-T. FUSE-T's
[developer FAQ](https://github.com/macos-fuse-t/fuse-t/wiki) says its runtime
installation does not automatically replace the macFUSE library: confirm the
binary was built/linked for the selected runtime. No M5 or macOS VM was available
for this task; all M5 results are **needs hardware**.

The current sandbox supervisor is Linux-only; the sandbox setup/build
comparisons skip on a native Mac. Run them and the `/proc` RSS measurement in
a Linux VM and label those results separately from native library reads.

The following distinguishes upstream documentation from interoperability that
still needs a real VM test (sources checked 2026-10-16).

| Path | What is established | What remains to test |
|---|---|---|
| macFUSE host mount | Other users are denied by default; `allow_other` removes that blanket restriction but keeps ordinary permissions. Upstream restricts the option to root or its admin group. | Whether the particular VM's sharing service can traverse and read the host FUSE mount. |
| FUSE-T host mount | Userspace implementation with NFS/SMB and FSKit backends; its mount architecture differs from macFUSE. | Exact `allow_other` handling for the installed backend/version and access through Lume/OrbStack. No supported guarantee found in the cited runtime documentation. |
| Lume shared directory | `lume run VM --shared-dir /absolute/path:ro` is documented. | Sharing a host FUSE mount rather than an ordinary directory, visibility after mounting, uid mapping and read correctness. |
| OrbStack shared directory | Linux sees Mac files through `/mnt/mac`; container file sharing uses VirtioFS. | Re-export of a nested host FUSE mount, mount timing and permissions for guest users/containers. |
| Direct NFS or 9P export into a Linux VM | Ratarmount serves the logical tree directly; the guest mounts a network filesystem. | Throughput/latency, guest kernel support, UID behavior, and VM-network reachability for the installed runtime. |

Sources: [macFUSE mount options](https://github.com/macfuse/macfuse/wiki/Mount-Options),
[FUSE-T architecture](https://github.com/macos-fuse-t/fuse-t),
[Lume CLI](https://cua.ai/docs/lume/reference/cli/vms),
[OrbStack Linux sharing](https://docs.orbstack.dev/machines/file-sharing), and
[OrbStack container sharing](https://docs.orbstack.dev/docker/file-sharing).

Do not infer Linux's `/etc/fuse.conf` semantics for macOS. Check the runtime's
own options and host privacy permissions; FUSE-T documents Network Volumes
access as a possible requirement. `allow_other` changes access on the host. It
does not by itself arrange a VM share or make a nested mount visible in a guest.
Mount the dataset first, then start the VM/share and verify a known checksum as
the actual guest user. Repeat after remount and VM restart before relying on it.

For an existing Lume Linux VM, try the documented share syntax:

```bash
# On the host, after mounting the dataset:
lume run ai-linux --shared-dir "$HOME/datasets/train:ro" --display none
```

The share location depends on the guest setup. In an OrbStack Linux machine,
try `/mnt/mac/Users/<user>/datasets/train`; use the real host username. Check
`stat`, directory listing and a full `shasum -a 256` on one known member inside
the guest and again inside its container. Compare with the host hash. These are
validation steps, not a claim that either runtime supports nested FUSE shares.

If sharing the host mount fails, compare direct exports. On the Mac host:

```bash
# Use an IP reachable from this VM. Keep it on a private VM-only network.
ratarmount --nfs --nfs-vers 4 --nfs-bind "$HOST_VM_IP:20490" /path/train.tar.zst
# Alternative, in a separate terminal/run:
ratarmount --ninep --ninep-bind "$HOST_VM_IP:5640" /path/train.tar.zst
```

In the Linux guest (root or `CAP_SYS_ADMIN`; NFS/9P client support required):

```bash
sudo mkdir -p /mnt/train
sudo mount -t nfs -o vers=4.1,tcp,port=20490,sec=sys,ro "$HOST_VM_IP:/" /mnt/train
# After unmounting NFS, compare 9P in a separate run:
sudo umount /mnt/train
sudo mount -t 9p -o trans=tcp,port=5640,version=9p2000.L,msize=1048576,ro \
  "$HOST_VM_IP" /mnt/train
sudo umount /mnt/train
```

Use a build with `nfsv4` for NFSv4.1. The direct export avoids the host-FUSE plus
VM-share stack; expecting fewer layers is an inference, not a measured win.
NFS has a broadly available Linux client; 9P depends on guest kernel configuration.
Neither command configures transport encryption. Bind to a private reachable
interface and use read-only data. The [NFS helper](two-box-nfs.md) measures the
NFS path plus a local-copy baseline from inside the VM; then compare 9P using
the same file, checksum and cache conditions. No universal winner is established.

FUSE passthrough is Linux-only. macOS keeps daemon reads; a Linux VM can use its
own Linux mount subject to its kernel and privileges. `--direct-io` also changes
cache/mmap behavior, so retain cached mode for mmap-dependent loaders and compare
it separately. The RSS benchmark reads Linux `/proc`, so run it inside the VM
and label that result as a VM measurement. Run the other scripts natively on the
M5 to avoid conflating host library performance with a guest network path.
