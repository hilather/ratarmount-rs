# Kubernetes CSI node plugin

`ratarmount-csi` is an in-repository Linux CSI node plugin. It serves Identity
and Node RPCs on `unix:///csi/csi.sock` and runs the packaged `ratarmount` CLI
in the foreground for each publish target. It has no Kubernetes client and
no controller, attach, staging, provisioning, snapshot, expansion, or stats
service. Static PVs are supported. Driver name:
`ratarmount.csi.hilather.github.io`.

The vendored [CSI v1.11.0 protocol](https://github.com/container-storage-interface/spec/blob/v1.11.0/csi.proto)
is compiled with pinned tonic 0.12.3, prost 0.13.5 and protox 0.7.2; no system
`protoc` is needed. The crate inherits workspace version and MSRV (Rust 1.90).
It is a workspace member, so workspace checks include it, but no other crate
depends on it. Default Cargo builds and existing package scripts still build
only `ratarmount`. This driver and its container are separate opt-in builds.

## Build and deploy

```bash
cargo build --release -p ratarmount-csi
# Builds both binaries inside Debian using the workspace MSRV:
docker build -f packaging/csi/Dockerfile -t ratarmount-csi:local .
# Load that image onto each node, or change the manifest to your registry tag.
kubectl apply -f packaging/csi/storageclass-readonly.yaml
kubectl apply -f packaging/csi/daemonset.yaml
# Edit source, volumeHandle, and Secret placeholders first:
kubectl apply -f packaging/csi/pv-static-readonly.yaml
```

The image is a build recipe, not a published image. The DaemonSet needs
`/dev/fuse`, privileged mount access / `SYS_ADMIN`, bidirectional propagation
on `/var/lib/kubelet/pods`, and persistent host directories for its socket and
journal. Its overlay root is host tmpfs `/dev/shm/ratarmount-csi`. The image
sets `user_allow_other` in `/etc/fuse.conf`. Adjust kubelet paths for clusters
using a nondefault root. Local sources must be visible at the same path in
the driver container on each eligible node; add a hostPath and node affinity
for node-local archives. Remote sources are usually simpler.

`CSIDriver` sets `attachRequired: false`, `fsGroupPolicy: None`, and persistent
volumes only. Ownership is set through `uid`/`gid`/`umask`, not recursive
fsGroup chown. The service account has no API permissions and its token is
not mounted. No RoleBinding is necessary: kubelet supplies Secret data with
each request, and the [node-driver-registrar needs no Kubernetes API RBAC](https://github.com/kubernetes-csi/node-driver-registrar/tree/v2.13.0#required-permissions).
StorageClasses use `kubernetes.io/no-provisioner`; they select static PVs.

For a standalone node test:

```bash
NODE_ID=test-node target/release/ratarmount-csi \
  --endpoint unix:///tmp/csi-test/csi.sock \
  --state-dir /tmp/csi-test/state \
  --target-root /tmp/csi-test/targets \
  --ratarmount /absolute/path/to/ratarmount
```

Other options are `--overlay-root` (default `/dev/shm/ratarmount-csi`) and
`--mount-timeout-seconds` (120). State and overlay roots must be private to
this driver instance, outside its target root, and writable only by the
operator. The socket is mode 0600. Requests must name absolute, normalized
targets below `--target-root`; symlink components are rejected.

## Volume attributes

| Key | Meaning |
|---|---|
| `source` | Required absolute local path or supported remote URL. No URL userinfo or query strings; use Secrets for credentials. |
| `overlay` | `none` (default): read-only mount. `tmpfs` or `tmpfs:SIZE`: private RAM write overlay for this target. |
| `readonlyGlobs` | Comma-separated protected root-relative globs, passed to `--overlay-readonly`; requires tmpfs. |
| `quota` | Logical overlay byte cap including COW; bytes or integer K/M/G/T suffix. The smaller of this and `tmpfs:SIZE` applies. |
| `uid`, `gid`, `umask` | Numeric ownership and octal permissions, passed through FUSE `-o`. |
| `recursive` | `true` or `false` (default): recurse into nested archives. |
| `gitSyntheticHead` | `true` or `false` (default): synthetic writable Git state; requires tmpfs. |
| `passthrough` | `auto`, `on`, or `off`; forwarded to the CLI, which negotiates kernel support. |

Unknown keys are rejected except the standard kubelet pod-info keys. Arbitrary
mount flags, filesystem types, block volumes, and `volume_mount_group` are
unsupported. This interface intentionally exposes no raw CLI flags, bind
sources, durable overlay directories, or commit operations.

`ReadOnlyMany` maps to CSI `MULTI_NODE_READER_ONLY`; reader-only capabilities
stay read-only even if the request omits `readonly`. A request with
`readonly=true` always adds `ro`, including with an overlay. Writer modes
require a tmpfs overlay unless the request itself is read-only.

[`pv-static-overlay.yaml`](../packaging/csi/pv-static-overlay.yaml) shows the
RL use case: an immutable shared base plus a separate RAM overlay for each
pod's publish target. Kubernetes must advertise `ReadWriteMany` for writable
pod mounts; a `ReadOnlyMany` PVC cannot be turned into a writable volume by
this driver. **Writes are private, not shared between pods.** This is useful
for disposable training/agent workspaces, not a general shared filesystem.
Containers sharing one pod volume share that target's overlay.

The driver creates a 0700 directory on verified tmpfs and passes it as `-w`,
with the logical quota equivalent to `--overlay-tmpfs=SIZE`. Named directories
let recovery remove overlays left by killed processes. Limits are logical
bytes, not a reserved RAM allocation. Node RAM/tmpfs capacity is still a
shared limit. Base archives are never committed or modified.

## Secrets

Use `spec.csi.nodePublishSecretRef` on the PV. Secret keys are exact child
environment variable names:

- `HF_TOKEN`
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
  `AWS_REGION`, `AWS_DEFAULT_REGION`
- `RESTIC_PASSWORD`
- `RATARMOUNT_HTTP_USER`, `RATARMOUNT_HTTP_PASSWORD`, `RATARMOUNT_HTTP_COOKIE`

The allowlist is exact; arbitrary `AWS_*` / `RATARMOUNT_*` configuration,
file-path credential variables, `PATH`, and `LD_PRELOAD` are rejected. Values
never enter argv, the journal, or driver logs. The child environment is
cleared before these values and fixed PATH/HOME are added. Child stdout and
stderr are suppressed because errors from a remote backend can contain
credentials. Driver logs report exit status and lifecycle failures without
printing requests. Encrypted archive passwords that require CLI flags are
not exposed. Token rotation takes effect at the next new mount; an identical
already-published target succeeds without remounting on a secret change.

## Lifecycle and restart behavior

Publish validates first, serializes operations, fsyncs an intent journal,
creates an empty target if needed, then starts a foreground child. Success
requires a live child and an exact `/proc/self/mountinfo` target. A repeat
with the same volume, target, access mode and normalized options is a no-op.
Different parameters at an occupied target return `ALREADY_EXISTS`. The same
volume may be published at multiple targets. Unknown mounts are never
adopted or removed.

Unpublish runs bounded `fusermount3 -u`, falling back to lazy `-u -z`, waits
for the owned child to exit (kills it after five seconds), removes its private
overlay and any target directory the driver created, and fsyncs journal
removal. Repeated unpublish succeeds. Errors retain ownership in the journal
for retry. A cancelled gRPC request does not interrupt a journaled operation.
A file lock prevents two processes from managing the same state directory.

A driver restart **cleans up all journaled mounts** before becoming ready;
it does not re-adopt them. Linux parent-death signaling kills foreground
children if the driver dies. Recovery never signals a journaled PID, avoiding
PID reuse hazards. Corrupt journals or failed unmounts fail startup closed.
SIGTERM/SIGINT drain the gRPC server and clean up mounts as well.

A crashed child is logged and is **not restarted automatically**. Kubelet
must explicitly republish, or the workload must be recreated. Kubelet may
not republish a volume in an already-running pod just because the plugin
restarted; operators should recreate affected pods. Overlays are ephemeral
and **lost on unpublish, child replacement, or driver restart**. `Probe`
reports driver readiness, not individual volume health.

## Tests

```bash
cargo fmt --all -- --check
cargo clippy -p ratarmount-csi --all-targets -- -D warnings
cargo test -p ratarmount-csi
./packaging/csi/test-manifests.sh
# Outside the sandbox, with /dev/fuse and allow_other configured:
RATARMOUNT_BIN=/absolute/path/to/ratarmount cargo test -p ratarmount-csi --test fuse -- --nocapture
# Isolated running plugin; requires kubernetes-csi/csi-test v5 csi-sanity:
CSI_ENDPOINT=unix:///tmp/csi-test/csi.sock ./packaging/csi/test-csi-sanity.sh
# Build the container image above first; creates/removes its own kind cluster:
RUN_CSI_KIND=1 ./packaging/csi/test-kind.sh
```

Pure tests cover validation, credentials, idempotency, failure recovery,
corrupt journals, process supervision and generated gRPC clients over a Unix
socket. Real FUSE tests check bytes, read-only writes and independent overlays.
The kind test checks those properties through PV/PVC/pod mounts, then checks
fresh overlays on replacement pods and empty journals after unpublish.

Scripts print explicit skips for unavailable tools. `csi-sanity` runs
Identity cases. In upstream csi-test v5.3.1 even Node setup unconditionally
calls `ControllerGetCapabilities`, and positive mount tests call `CreateVolume`;
neither RPC exists on this node-only plugin. Node validation is covered by
the Rust generated-client tests, and real static-volume lifecycle coverage
is supplied by the Rust FUSE and kind tests.
These privileged scripts are not in default CI. Manifest schema validation
uses `kubeconform -strict` when installed.

Residuals: dynamic provisioning, staging, snapshots, expansion, volume health
RPCs, automatic child restart, durable/shared writes, Windows CSI, and
cluster-specific SELinux/AppArmor policy. Pod-private overlay semantics are
an explicit application contract, not coherent ReadWriteMany storage.
