#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
if command -v kubeconform >/dev/null 2>&1; then
    kubeconform -strict -summary "$root"/packaging/csi/*.yaml
else
    echo 'skip: kubeconform not installed'
fi
# Always-on checks also run without schema tooling.
python3 - "$root" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
cargo = (root / 'Cargo.toml').read_text()
assert '"ratarmount-csi",' in cargo
assert 'default-members = ["ratarmount"]' in cargo
for path in root.glob('ratarmount*/Cargo.toml'):
    if path.parent.name != 'ratarmount-csi':
        assert 'ratarmount-csi' not in path.read_text(), path
for name in ['build-native-packages.sh', 'build-macos-tarball.sh', 'build-appimage.sh']:
    text = (root / 'packaging' / name).read_text()
    assert 'cargo build --release -p ratarmount ' in text
    assert '--workspace' not in text and 'ratarmount-csi' not in text
text = (root / 'packaging/csi/storageclass-readonly.yaml').read_text()
assert 'attachRequired: false' in text and 'fsGroupPolicy: None' in text
assert 'provisioner: kubernetes.io/no-provisioner' in text
daemon = (root / 'packaging/csi/daemonset.yaml').read_text()
for required in ['mountPropagation: Bidirectional', 'mountPath: /dev/fuse', 'SYS_ADMIN', 'name: NODE_ID', 'automountServiceAccountToken: false']:
    assert required in daemon, required
for path in (root / 'packaging/csi').glob('*.yaml'):
    assert 'ratarmount.csi.example' not in path.read_text(), path
print('PASS: CSI packaging isolation and manifest invariants')
PY
