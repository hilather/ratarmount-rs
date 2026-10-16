#!/usr/bin/env bash
# Privileged, opt-in: creates and removes its own isolated kind cluster.
set -euo pipefail
for tool in kind docker kubectl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "skip: $tool unavailable"
        exit 0
    fi
done
if [[ ${RUN_CSI_KIND:-0} != 1 ]]; then
    echo 'skip: set RUN_CSI_KIND=1 to create a privileged test cluster'
    exit 0
fi
if [[ ! -e /dev/fuse ]] || ! docker info >/dev/null 2>&1; then
    echo 'skip: /dev/fuse or Docker daemon unavailable'
    exit 0
fi
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
image=${CSI_TEST_IMAGE:-ratarmount-csi:local}
docker image inspect "$image" >/dev/null
work=$(mktemp -d)
cluster="ratar-csi-$$"
cleanup() {
    kind delete cluster --name "$cluster" || true
    rm -rf "$work"
}
trap cleanup EXIT
export KUBECONFIG="$work/kubeconfig"
python3 - "$work" <<'PY'
import io, json, pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
(root / 'fixtures').mkdir()
with tarfile.open(root / 'fixtures/data.tar', 'w') as tar:
    data = b'CSI fixture bytes\n'
    info = tarfile.TarInfo('payload.txt'); info.size = len(data); info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))
config = {'kind': 'Cluster', 'apiVersion': 'kind.x-k8s.io/v1alpha4', 'nodes': [
    {'role': 'control-plane', 'extraMounts': [
        {'hostPath': str(root / 'fixtures'), 'containerPath': '/fixtures', 'readOnly': True},
        {'hostPath': '/dev/fuse', 'containerPath': '/dev/fuse'}]}]}
(root / 'kind.json').write_text(json.dumps(config))
PY
kind create cluster --name "$cluster" --config "$work/kind.json" --wait 120s
kind load docker-image "$image" --name "$cluster"
kubectl apply -f "$root/packaging/csi/storageclass-readonly.yaml"
# Render the checked-in manifest plus the local fixture mount without PyYAML.
kubectl create --dry-run=client -f "$root/packaging/csi/daemonset.yaml" -o json > "$work/driver.json"
python3 - "$work/driver.json" "$image" <<'PY'
import json, sys
p = sys.argv[1]; doc = json.load(open(p))
items = doc.get('items', [doc])
for obj in items:
    if obj['kind'] != 'DaemonSet': continue
    spec = obj['spec']['template']['spec']
    spec['containers'][0]['image'] = sys.argv[2]
    spec['containers'][0]['volumeMounts'].append({'name': 'fixtures', 'mountPath': '/fixtures', 'readOnly': True})
    spec['volumes'].append({'name': 'fixtures', 'hostPath': {'path': '/fixtures', 'type': 'Directory'}})
open(p, 'w').write(json.dumps(doc))
PY
kubectl apply -f "$work/driver.json"
kubectl -n kube-system rollout status ds/ratarmount-csi-node --timeout=180s
python3 - "$work/workloads.json" <<'PY'
import json, sys
items = []
for name, mode, overlay in [('ro', 'ReadOnlyMany', 'none'), ('rw', 'ReadWriteMany', 'tmpfs:8M')]:
    items += [{'apiVersion': 'v1', 'kind': 'PersistentVolume', 'metadata': {'name': 'csi-test-'+name}, 'spec': {
        'capacity': {'storage': '8Mi'}, 'accessModes': [mode], 'storageClassName': '',
        'persistentVolumeReclaimPolicy': 'Retain', 'csi': {
            'driver': 'ratarmount.csi.hilather.github.io', 'volumeHandle': 'fixture-'+name, 'readOnly': name == 'ro',
            'volumeAttributes': {'source': '/fixtures/data.tar', 'overlay': overlay}}}},
        {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'metadata': {'name': 'csi-test-'+name}, 'spec': {
            'accessModes': [mode], 'storageClassName': '', 'volumeName': 'csi-test-'+name,
            'resources': {'requests': {'storage': '8Mi'}}}}]
for name, claim in [('reader', 'ro'), ('writer-a', 'rw'), ('writer-b', 'rw')]:
    items.append({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'labels': {'csi-test': 'true'}}, 'spec': {
        'containers': [{'name': 'test', 'image': 'busybox:1.37', 'command': ['sleep', '3600'],
                        'volumeMounts': [{'name': 'data', 'mountPath': '/data', 'readOnly': claim == 'ro'}]}],
        'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'csi-test-'+claim, 'readOnly': claim == 'ro'}}]}})
open(sys.argv[1], 'w').write(json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': items}))
PY
kubectl apply -f "$work/workloads.json"
kubectl wait --for=condition=Ready pod -l csi-test=true --timeout=180s
for pod in reader writer-a writer-b; do
    [[ $(kubectl exec "$pod" -- cat /data/payload.txt) == 'CSI fixture bytes' ]]
done
if kubectl exec reader -- sh -c 'echo forbidden > /data/new'; then
    echo 'FAIL: read-only mount accepted a write' >&2
    exit 1
fi
kubectl exec writer-a -- sh -c 'echo private-a > /data/private; echo changed > /data/payload.txt'
kubectl exec writer-b -- test ! -e /data/private
[[ $(kubectl exec writer-b -- cat /data/payload.txt) == 'CSI fixture bytes' ]]
kubectl delete pod -l csi-test=true --wait=true --timeout=120s
# A fresh pod sees the immutable base, not the previous pod's overlay.
kubectl apply -f "$work/workloads.json"
kubectl wait --for=condition=Ready pod -l csi-test=true --timeout=180s
[[ $(kubectl exec writer-a -- cat /data/payload.txt) == 'CSI fixture bytes' ]]
kubectl exec writer-a -- test ! -e /data/private
kubectl delete pod -l csi-test=true --wait=true --timeout=120s
# Check the journal eventually empties after kubelet unpublishes all targets.
for attempt in $(seq 1 30); do
    journal=$(kubectl -n kube-system exec ds/ratarmount-csi-node -c driver -- cat /var/lib/ratarmount-csi/journal.json)
    [[ $journal == '{}' ]] && break
    sleep 1
done
[[ $journal == '{}' ]]
echo 'PASS: kind read-only bytes, per-pod isolation, unpublish and fresh overlays'
