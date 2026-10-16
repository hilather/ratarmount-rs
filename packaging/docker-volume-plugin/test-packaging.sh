#!/usr/bin/env bash
# Regression: namespace isolation or a mismatched activation socket hides plugin mounts.
set -euo pipefail
plugin_dir=$(cd "$(dirname "$0")" && pwd)
service="$plugin_dir/ratarmount-volume-plugin.service"
socket="$plugin_dir/ratarmount-volume-plugin.socket"
grep -Eq '^PrivateMounts=no$' "$service"
if grep -Eq '^(PrivateTmp|ProtectSystem|PrivateMounts)=yes$' "$service"; then
  echo 'FAIL: service hides FUSE mounts in a private namespace' >&2
  exit 1
fi
grep -Eq '^KillMode=mixed$' "$service"
grep -Eq '^ListenStream=/run/docker/plugins/ratarmount.sock$' "$socket"
grep -Eq '^SocketMode=0600$' "$socket"
bash -n "$plugin_dir/test-docker.sh"
if command -v systemd-analyze >/dev/null 2>&1; then
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' EXIT
  # Verify unit semantics before installing binaries into /usr/bin.
  sed 's|^ExecStart=.*|ExecStart=/bin/true|' "$service" > "$scratch/ratarmount-volume-plugin.service"
  cp "$socket" "$scratch/ratarmount-volume-plugin.socket"
  systemd-analyze verify "$scratch/ratarmount-volume-plugin.service" "$scratch/ratarmount-volume-plugin.socket"
else
  echo 'skip: systemd-analyze unavailable; static unit checks passed' >&2
fi
echo 'Volume plugin packaging checks passed'
