# Kubernetes CSI (G-5 spec)

Status: **spec-only in this repository.** There is **no** `ratarmount-csi` crate, no `k8s-openapi` dependency, and no in-tree kube client. v1 of G-5 is the FUSE mount helper + systemd / autofs ([`systemd-mount.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/systemd-mount.md)). A CSI driver, if shipped, lives in a **separate repo** and **execs the packaged `ratarmount` binary** (or `mount.fuse.ratarmount`) inside the node plugin.

Roadmap: [`tasks/beyond-parity-roadmap.md`](https://github.com/hilather/ratarmount-rs/blob/main/docs/tasks/beyond-parity-roadmap.md) G-5 `partial`. Example YAML: [`packaging/csi/`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/csi/).

## Why not an in-tree crate

FUSE needs a mountpoint on the **node**. `--no-mount` is export-only and cannot implement `NodePublishVolume`. Pulling `k8s-openapi` / controller-runtime into this workspace would threaten MSRV 1.74 and default CI. Exec of the already-packaged binary keeps CSI out of `cargo test --workspace`.

## v1 bar (RO)

| Item | Spec |
|------|------|
| Access mode | **ReadOnlyMany** only |
| Volume | One archive or remote URL (`s3://bucket/dataset.tar.zst`, `https://…`, local hostPath residual) |
| Publish | `NodePublishVolume` → `mount.fuse.ratarmount WHAT TARGET -o ro,allow_other` (or `ratarmount -o allow_other,ro -- WHAT TARGET`) |
| Unpublish | `ratarmount -u TARGET` / `fusermount3 -u` |
| Controller | Optional. Static PV is enough for v1. Dynamic provisioning residual |
| Attach | `attachRequired: false` (no block attach) |
| Privileges | Node plugin needs `/dev/fuse` and typically `SYS_ADMIN` (or a fuse device plugin). Not a default unprivileged pod |
| Credentials | Kubernetes **Secret** → env of the node plugin (`nodePublishSecretRef`). **Never** StorageClass `parameters` or PV `volumeAttributes` |

`-w` overlay / ReadWriteMany is a **later StorageClass** (needs F-7 write-through to `s3://`). Do not document a writable class in v1 YAML.

## Driver identity (example)

```text
driver:     ratarmount.csi.example
provisioner: ratarmount.csi.example
```

Rename to a real domain when the separate repo exists. Do not register this name in-cluster until that driver exists.

## NodePublishVolume (sketch)

```text
1. Validate capability = mount + ReadOnlyMany.
2. Read volumeAttributes["archive"] (URL or path). Reject if missing.
3. Load nodePublishSecretRef into the environment (AWS_*, RESTIC_*, …).
   Do not argv-expand secret values.
4. mkdir -p TARGET
5. exec mount.fuse.ratarmount ARCHIVE TARGET -o ro,allow_other
   (helper daemonizes; wait until findmnt TARGET succeeds)
6. Fail closed if the mount is empty when the archive is known-nonempty.
```

`NodeUnpublishVolume`: unmount, then remove the target directory if the plugin created it.

Container image: distroless-or-debian **plus** the GitHub Release portable/deb binary, `fuse3`, and the helper at `/usr/sbin/mount.fuse.ratarmount`. No rustc in the image.

## YAML (copy from `packaging/csi/`)

StorageClass + CSIDriver: [`packaging/csi/storageclass-readonly.yaml`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/csi/storageclass-readonly.yaml)

Static PV + PVC + Secret placeholders: [`packaging/csi/pv-static-readonly.yaml`](https://github.com/hilather/ratarmount-rs/blob/main/packaging/csi/pv-static-readonly.yaml)

`stringData` values are `REPLACE_ME`. Operators must use `kubectl create secret` / sealed-secrets / CSI secret store — do not commit real keys.

## kind / minikube (manual, not default CI)

```bash
# After a driver image exists in the separate repo:
kind create cluster
# install driver DaemonSet (privileged, /dev/fuse)
kubectl apply -f packaging/csi/storageclass-readonly.yaml
kubectl apply -f packaging/csi/pv-static-readonly.yaml   # after editing the Secret
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: ratar-reader
spec:
  containers:
    - name: reader
      image: busybox
      command: ["sleep", "3600"]
      volumeMounts:
        - name: dataset
          mountPath: /data
          readOnly: true
  volumes:
    - name: dataset
      persistentVolumeClaim:
        claimName: ratarmount-dataset
        readOnly: true
EOF
kubectl exec ratar-reader -- ls /data
```

Skip this path when docker/kind is missing. Empty or wrong member bytes after a successful mount is a **fail**. Default GitHub Actions CI does **not** run kind.

Lint (skip if the tool is missing):

```bash
kubeconform -strict -ignore-missing-schemas packaging/csi/*.yaml
./packaging/test-systemd-unit.sh
```

## Residual

| Item | Status |
|------|--------|
| Spec + example YAML | **this repo** |
| Node plugin that execs `ratarmount` | **separate repo** (capacity) |
| In-tree kube crate | **Not planned** |
| `-w` / ReadWriteMany StorageClass | Later (F-7) |
| Dynamic provisioning / snapshotter | Residual |
| Windows CSI / CSI-proxy | Residual |
| SELinux / AppArmor pod policy | Residual |
