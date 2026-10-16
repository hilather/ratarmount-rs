#!/usr/bin/env bash
# Regression: package feature lists omitted the lazy torrent backend.
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v python3 >/dev/null 2>&1; then
    echo "skip: python3 is unavailable"
    exit 0
fi
python3 - <<'PY'
from pathlib import Path
import re
for name in ['build-native-packages.sh', 'build-appimage.sh', 'build-macos-tarball.sh']:
    path = Path('packaging') / name
    lines = re.findall(r'^\s*cargo build --release -p ratarmount --features ([^\s]+)', path.read_text(), re.M)
    assert lines and all('bittorrent' in line.split(',') for line in lines), path
for crate in ['ratarmount', 'ratarmount-session', 'ratarmount-remote']:
    text = (Path(crate) / 'Cargo.toml').read_text()
    features = text.split('[features]', 1)[1].split('\n[', 1)[0]
    assert re.search(r'^bittorrent\s*=', features, re.M)
    defaults = re.search(r'^default\s*=\s*\[([^]]*)\]', features, re.M)
    assert defaults
    assert ('"bittorrent"' in defaults.group(1)) == (crate == 'ratarmount')
print('PASS: bittorrent enabled in CLI/packages and opt-in for libraries')
PY
