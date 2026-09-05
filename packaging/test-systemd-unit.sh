#!/usr/bin/env bash
# Regression: mount.fuse.ratarmount helper must not put credentials on argv;
# systemd unit Type=fuse.ratarmount. systemd-analyze verify skip-if-no-systemd.
# kubeconform on packaging/csi/*.yaml skip-if-missing.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER="$ROOT/packaging/mount.fuse.ratarmount"
UNIT="$ROOT/packaging/systemd/mnt-archives-dataset.mount"
MAP="$ROOT/packaging/autofs/auto.ratarmount"
NFPM="$ROOT/packaging/nfpm.yaml.tmpl"
CSI_DIR="$ROOT/packaging/csi"

fail=0
pass() { echo "PASS: $*"; }
fail_msg() { echo "FAIL: $*" >&2; fail=1; }

[[ -f "$HELPER" ]] || { echo "FAIL: missing $HELPER" >&2; exit 1; }
[[ -f "$UNIT" ]] || { echo "FAIL: missing $UNIT" >&2; exit 1; }
[[ -f "$MAP" ]] || { echo "FAIL: missing $MAP" >&2; exit 1; }

# --- helper: static ---
if head -n1 "$HELPER" | grep -qx '#!/bin/sh'; then
    pass "helper is POSIX sh"
else
    fail_msg "helper shebang must be #!/bin/sh"
fi

if grep -E '\$\{?(AWS_|RESTIC_|RATARMOUNT_[A-Z0-9_]*PASSWORD|AWS_SECRET|AWS_ACCESS)' "$HELPER" >/dev/null; then
    fail_msg "helper interpolates secret env vars (must inherit only)"
else
    pass "helper does not interpolate secret env vars"
fi

if grep -E 'exec[[:space:]]+"\$bin"' "$HELPER" >/dev/null \
    && grep -F 'allow_other,ro' "$HELPER" >/dev/null; then
    pass "helper execs ratarmount with default allow_other,ro"
else
    fail_msg "helper must exec ratarmount -o allow_other,ro"
fi

# --- helper: live argv (stub ratarmount) ---
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat >"$TMP/ratarmount" <<'EOF'
#!/bin/sh
printf '%s\0' "$@" >"${RATARMOUNT_ARGV_FILE:?}"
# Prove env is inherited, not copied onto argv.
if [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; then
    printf 'inherited_secret\n' >"${RATARMOUNT_ENV_FILE:?}"
fi
exit 0
EOF
chmod +x "$TMP/ratarmount" "$HELPER"

run_helper() {
    local out=$1
    shift
    RATARMOUNT_ARGV_FILE="$out" \
        RATARMOUNT_ENV_FILE="$TMP/env" \
        AWS_ACCESS_KEY_ID=AKIAEXAMPLE \
        AWS_SECRET_ACCESS_KEY=supersecret \
        RESTIC_PASSWORD=resticsecret \
        RATARMOUNT_SMB_PASSWORD=smbsecret \
        PATH="$TMP:$PATH" \
        "$HELPER" "$@"
}

check_argv_no_secrets() {
    local out=$1
    if grep -aE 'supersecret|resticsecret|smbsecret|AKIAEXAMPLE' "$out" >/dev/null; then
        fail_msg "helper argv leaked a secret: $(tr '\0' ' ' <"$out")"
        return
    fi
    pass "helper argv has no secrets ($2)"
}

run_helper "$TMP/argv1" 's3://bucket/dataset.tar.zst' /mnt/archives/dataset -o 'ro,allow_other,_netdev'
check_argv_no_secrets "$TMP/argv1" "WHAT WHERE -o"
argv1=$(tr '\0' '\n' <"$TMP/argv1")
printf '%s\n' "$argv1" | grep -qx -- '-o' || fail_msg "argv missing -o"
printf '%s\n' "$argv1" | grep -q 'allow_other' || fail_msg "argv missing allow_other"
printf '%s\n' "$argv1" | grep -q '\bro\b' || fail_msg "argv missing ro"
if printf '%s\n' "$argv1" | grep -F '_netdev' >/dev/null; then
    fail_msg "argv still has _netdev (fstab token): $(tr '\0' ' ' <"$TMP/argv1")"
else
    pass "helper strips _netdev"
fi
printf '%s\n' "$argv1" | grep -qx 's3://bucket/dataset.tar.zst' || fail_msg "argv missing WHAT"
printf '%s\n' "$argv1" | grep -qx '/mnt/archives/dataset' || fail_msg "argv missing WHERE"
[[ -f "$TMP/env" ]] && grep -qx inherited_secret "$TMP/env" \
    && pass "helper inherits AWS_* environment" \
    || fail_msg "stub did not see inherited AWS_SECRET_ACCESS_KEY"

run_helper "$TMP/argv2" -o 'ro,allow_other,_netdev' 's3://bucket/dataset.tar.zst' /mnt/x
check_argv_no_secrets "$TMP/argv2" "-o WHAT WHERE"
tr '\0' '\n' <"$TMP/argv2" | grep -qx 's3://bucket/dataset.tar.zst' \
    || fail_msg "option-first form lost WHAT"

# --- unit file ---
grep -qx 'Type=fuse.ratarmount' "$UNIT" && pass "unit Type=fuse.ratarmount" \
    || fail_msg "unit Type= must be fuse.ratarmount"
if grep -E '^ExecStart=' "$UNIT" >/dev/null; then
    fail_msg "unit must not use ExecStart= (not a .service / --no-mount)"
else
    pass "unit has no ExecStart="
fi
if grep -E -- '--no-mount' "$UNIT" | grep -vE '^#' >/dev/null; then
    fail_msg "unit must not pass --no-mount"
else
    pass "unit has no --no-mount"
fi
grep -E '^TimeoutSec=0$' "$UNIT" >/dev/null && pass "unit TimeoutSec=0" \
    || fail_msg "unit should set TimeoutSec=0 (cold index can be long)"
grep -E '^Where=/mnt/archives/dataset$' "$UNIT" >/dev/null \
    || fail_msg "example Where= must be /mnt/archives/dataset"
base=$(basename "$UNIT")
[[ "$base" == "mnt-archives-dataset.mount" ]] && pass "unit filename matches Where=" \
    || fail_msg "unit filename $base does not match Where=/mnt/archives/dataset"

if grep -E 'AWS_|RESTIC_|PASSWORD=' "$UNIT" | grep -vE '^#|EnvironmentFile' >/dev/null; then
    fail_msg "unit must not put secrets on What=/Options="
else
    pass "unit has no secrets on What=/Options="
fi

# --- autofs ---
grep -F 'fuse.ratarmount' "$MAP" >/dev/null && pass "autofs fstype=fuse.ratarmount" \
    || fail_msg "autofs map must use fuse.ratarmount"
if grep -E 'PASSWORD|AWS_|RESTIC_|secret=' "$MAP" | grep -v '^#' >/dev/null; then
    fail_msg "autofs map must not embed credentials"
else
    pass "autofs map has no embedded credentials"
fi

# --- nfpm installs helper ---
if [[ -f "$NFPM" ]] && grep -F 'packaging/mount.fuse.ratarmount' "$NFPM" >/dev/null \
    && grep -F '/usr/sbin/mount.fuse.ratarmount' "$NFPM" >/dev/null; then
    pass "nfpm installs helper to /usr/sbin/mount.fuse.ratarmount"
else
    fail_msg "nfpm.yaml.tmpl must install mount.fuse.ratarmount to /usr/sbin"
fi

# --- systemd-analyze verify (skip if missing) ---
if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze verify "$UNIT"; then
        pass "systemd-analyze verify $UNIT"
    else
        fail_msg "systemd-analyze verify failed"
    fi
else
    echo "skip: systemd-analyze not found"
fi

# --- kubeconform (skip if missing) ---
if command -v kubeconform >/dev/null 2>&1; then
    if kubeconform -strict -ignore-missing-schemas "$CSI_DIR"/*.yaml; then
        pass "kubeconform packaging/csi"
    else
        fail_msg "kubeconform failed on packaging/csi"
    fi
else
    echo "skip: kubeconform not found"
fi

if grep -ERi 'AKIA[0-9A-Z]{16}|BEGIN RSA PRIVATE KEY' "$CSI_DIR" >/dev/null 2>&1; then
    fail_msg "CSI YAML looks like it contains real credentials"
else
    pass "CSI YAML has no real-looking credentials"
fi

[[ "$fail" -eq 0 ]] || exit 1
echo "OK: systemd/autofs helper + unit + CSI spec ($ROOT)"
