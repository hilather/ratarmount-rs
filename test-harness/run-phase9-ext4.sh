#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"

if ! command -v debugfs >/dev/null 2>&1 && [[ ! -x /usr/sbin/debugfs ]]; then
    echo "skip phase9 ext4: debugfs (e2fsprogs) not found"
    exit 0
fi

exec "$SCRIPT_DIR/run-codec-allowlist.sh" "$SCRIPT_DIR/phase9-ext4.txt" "Phase 9 ext4"
