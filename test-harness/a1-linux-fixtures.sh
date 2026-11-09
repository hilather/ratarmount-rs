#!/usr/bin/env bash
# Future approved GitHub CI only. Native provisioning remains HELD locally.
# Sourcing defines functions for mock contracts and performs no provisioning.

runner_context() {
    runner_uid=$(id -u)
    runner_gid=$(id -g)
    [[ $runner_uid -ne 0 && $runner_gid -ne 0 ]] || {
        echo 'A1_SETUP_FAILURE: unprivileged runner UID/GID required' >&2; return 1;
    }
    [[ ${GITHUB_ACTIONS:-} == true && ${CI:-} == true && ${RUNNER_OS:-} == Linux &&
       ${RUNNER_ENVIRONMENT:-} == github-hosted && ${RRS_A1_APPROVED_NATIVE_CI:-} == 1 &&
       ${GITHUB_RUN_ID:-} =~ ^[0-9]+$ && -n ${RUNNER_TEMP:-} && -n ${GITHUB_WORKSPACE:-} ]] || {
        echo 'A1_SETUP_FAILURE: Linux provisioning requires approved GitHub hosted CI' >&2; return 1;
    }
    case ${GITHUB_JOB:-} in check|checked-open-aarch64) ;; *) return 1 ;; esac
    [[ $(realpath -e -- "$GITHUB_WORKSPACE") == "$repository" &&
       $(stat -c %u -- "$RUNNER_TEMP") == "$runner_uid" && -d $RUNNER_TEMP && ! -L $RUNNER_TEMP ]] || return 1
    . /etc/os-release
    [[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || {
        echo "A1_SETUP_FAILURE: Ubuntu 24.04 required, observed $ID $VERSION_ID" >&2; return 1;
    }
    case $(uname -m):${RUNNER_ARCH:-} in x86_64:X64|aarch64:ARM64) ;;
        *) echo 'A1_SETUP_FAILURE: unaudited Linux ABI' >&2; return 1 ;;
    esac
}

verify_mount() {
    local target=$1 source=$2 kind=$3
    mountpoint -q -- "$target" &&
        [[ $(findmnt -rn -M "$target" -o TARGET) == "$target" &&
           $(findmnt -rn -M "$target" -o SOURCE) == "$source" &&
           $(findmnt -rn -M "$target" -o FSTYPE) == "$kind" &&
           $(findmnt -Rrn -M "$target" -o TARGET) == "$target" ]]
}

# Only these mounts/loop/image are ours. Any mismatch leaves resources intact.
cleanup_owned() {
    local cleanup_status=0 mounted kind target source attached
    for kind in tmpfs ext4; do
        if [[ $kind == tmpfs ]]; then target=$tmp_mount; source=$tmp_source
        else target=$ext_mount; source=$loop_device; fi
        if mountpoint -q -- "$target"; then
            if [[ -n $source ]] && verify_mount "$target" "$source" "$kind"; then
                sudo -n umount -- "$target" || cleanup_status=1
                mountpoint -q -- "$target" && cleanup_status=1
            else
                echo "A1_CLEANUP_FAILURE: refusing foreign/stacked $kind unmount" >&2
                cleanup_status=1
            fi
        fi
    done
    if [[ -n $loop_device ]]; then
        mounted=$(findmnt -rn -S "$loop_device" -o TARGET) || {
            # findmnt's no-match status is 1. Other failures are not absence.
            [[ $? -eq 1 ]] || cleanup_status=1
        }
        if [[ $cleanup_status -eq 0 && -z $mounted ]] &&
           [[ $(sudo -n losetup -ln -O BACK-FILE "$loop_device") == "$image" ]]; then
            sudo -n losetup -d "$loop_device" || cleanup_status=1
            attached=$(sudo -n losetup -ln -O BACK-FILE "$loop_device") || {
                [[ $? -eq 1 ]] || cleanup_status=1
            }
            [[ -z $attached ]] || cleanup_status=1
        else
            echo 'A1_CLEANUP_FAILURE: refusing foreign/in-use loop detach' >&2
            cleanup_status=1
        fi
    fi
    if [[ $cleanup_status -eq 0 ]]; then
        attached=$(sudo -n losetup -j "$image") || cleanup_status=1
        [[ -z $attached ]] || cleanup_status=1
    fi
    if [[ $cleanup_status -eq 0 ]]; then
        rm -f -- "$image" || cleanup_status=1
        rmdir -- "$ext_mount" "$tmp_mount" "$base" || cleanup_status=1
        [[ ! -e $image && ! -e $base ]] || cleanup_status=1
    fi
    printf '%s\n' "$cleanup_status" > "$attempt_output/cleanup.exit-code" || cleanup_status=1
    printf 'A1_CLEANUP original=%s cleanup_status=%s probe_complete=%s\n' \
        "$original" "$cleanup_status" "$fixture_probe_complete"
    return "$cleanup_status"
}

cleanup() {
    original=$?
    trap - EXIT INT TERM
    set +e
    cleanup_owned
    cleanup_status=$?
    printf '%s\n' "$original" > "$attempt_output/original.exit-code" || cleanup_status=1
    if [[ $cleanup_status -ne 0 ]]; then original=1; fi
    printf '%s\n' "$original" > "$attempt_output/fixture.exit-code" || original=1
    exit "$original"
}

fixture_probe() {
    verify_mount "$ext_mount" "$loop_device" ext4
    verify_mount "$tmp_mount" "$tmp_source" tmpfs
    python3 -I test-harness/a1-evidence.py linux-fixture --root "$ext_mount/owned" \
        --mount "$ext_mount" --source "$loop_device" --kind ext4 > "$attempt_output/ext4-owner.json"
    python3 -I test-harness/a1-evidence.py linux-fixture --root "$tmp_mount/owned" \
        --mount "$tmp_mount" --source "$tmp_source" --kind tmpfs > "$attempt_output/tmpfs-owner.json"
    fixture_probe_complete=1
    printf '%s\n' 1 > "$attempt_output/probe.complete"
}

finish_attempt() {
    local mode=$1
    [[ $fixture_probe_complete -eq 1 ]] || return 1
    if [[ $mode == forced ]]; then
        # Forced 73 occurs only after real mount, ownership, traversal/create/use.
        exit 73
    fi
    [[ $mode == normal ]] || return 1
    python3 -I test-harness/a1-evidence.py root-controls --engines "$engines" \
        --tmpfs-root "$RRS_A1_TMPFS_ROOT" --scratch-root "$RRS_A1_EXT4_ROOT" \
        --output-dir "$attempt_output/root-controls"
    python3 -I test-harness/a1-evidence.py run-engines --output-dir "$engines"
    python3 -I test-harness/a1-evidence.py verify-engines --output-dir "$engines"
    python3 -I test-harness/a1-evidence.py engine-mutations --output-dir "$engines" \
        --mutations-dir "$attempt_output/engine-mutations"
}

mount_owned() {
    sudo -n mount -t ext4 -o nodev,nosuid -- "$loop_device" "$ext_mount"
    sudo -n mount -t tmpfs -o nodev,nosuid,uid=0,gid=0,mode=0700,size=256m "$tmp_source" "$tmp_mount"
    verify_mount "$ext_mount" "$loop_device" ext4
    verify_mount "$tmp_mount" "$tmp_source" tmpfs
}

assign_runner_roots() {
    # tmpfs ignores uid/gid/mode on remount; install -d sets the existing root.
    verify_mount "$tmp_mount" "$tmp_source" tmpfs
    sudo -n install -d -m 700 -o "$runner_uid" -g "$runner_gid" -- "$tmp_mount" "$ext_mount/owned" "$tmp_mount/owned"
    export RRS_A1_EXT4_ROOT="$ext_mount/owned" RRS_A1_TMPFS_ROOT="$tmp_mount/owned"
    export RRS_A1_REQUIRE_FIXTURES=1 TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 CARGO_TERM_COLOR=never
    unset RRS_A1_LOCK_CHILD RRS_A1_LOCK_ROLE
    verify_mount "$tmp_mount" "$tmp_source" tmpfs
    [[ $(stat -c '%u:%g:%a' -- "$tmp_mount") == "$runner_uid:$runner_gid:700" ]]
    [[ $(stat -c '%u:%g:%a' -- "$tmp_mount/owned") == "$runner_uid:$runner_gid:700" ]]
}

fixture_attempt() (
    set -euo pipefail
    local attempt_output=$1 mode=$2 engines=$3
    mkdir -m 700 -- "$attempt_output"
    local base image ext_mount tmp_mount tmp_source loop_device= fixture_probe_complete=0 original=0
    base=$(mktemp -d "$RUNNER_TEMP/rrs-a1-linux.XXXXXXXX")
    base=$(cd -- "$base" && pwd -P)
    image="$base/ext4.img"
    ext_mount="$base/ext4"
    tmp_mount="$base/tmpfs"
    tmp_source="rrs-a1-$(basename -- "$base")"
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir -m 700 -- "$ext_mount" "$tmp_mount"
    truncate -s 512M -- "$image"
    mkfs.ext4 -F -O casefold -E encoding=utf8 "$image"
    loop_device=$(sudo -n losetup --find --show -- "$image")
    [[ -n $loop_device && $(sudo -n losetup -ln -O BACK-FILE "$loop_device") == "$image" ]]
    mount_owned
    # Original broken root-owned fixture is an expected negative with stock's
    # already verified index executable. A build failure cannot satisfy it.
    if [[ $mode == normal ]]; then
        python3 -I test-harness/a1-evidence.py old-root-control --output-dir "$engines" \
            --root "$tmp_mount" > "$attempt_output/old-root.json"
    fi
    assign_runner_roots
    fixture_probe
    finish_attempt "$mode"
)

assert_attempt_status() {
    local normal=$1 forced=$2
    [[ $normal -eq 0 && $forced -eq 73 &&
       $(cat -- "$output/normal/fixture.exit-code") == 0 &&
       $(cat -- "$output/forced/fixture.exit-code") == 73 &&
       $(cat -- "$output/forced/original.exit-code") == 73 &&
       $(cat -- "$output/normal/cleanup.exit-code") == 0 &&
       $(cat -- "$output/forced/cleanup.exit-code") == 0 &&
       $(cat -- "$output/normal/probe.complete") == 1 &&
       $(cat -- "$output/forced/probe.complete") == 1 ]]
}

main() {
    set -euo pipefail
    umask 077
    [[ $# -eq 1 ]] || { echo "usage: bash $0 OUTPUT_DIRECTORY" >&2; return 2; }
    repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
    cd -- "$repository"
    runner_context
    output=$(realpath -m -- "$1")
    [[ $output == "$(realpath -e -- "$RUNNER_TEMP")/"* && $output != "$repository/"* ]] || return 1
    mkdir -p -- "$output"
    [[ $(stat -c %u -- "$output") == "$runner_uid" && ! -L $output ]] || return 1
    for tool in sudo mkfs.ext4 losetup mount umount mountpoint findmnt python3 flock cargo rustc; do
        command -v "$tool" >/dev/null || { echo "A1_SETUP_FAILURE: missing $tool" >&2; return 1; }
    done
    # All builds are unprivileged, unique per engine, and finish before setup.
    python3 -I test-harness/a1-evidence.py build-engines --output-dir "$output/engines"
    sudo -n true
    local normal forced
    # Do not call fixture_attempt in `if`/`||`: Bash would disable errexit in
    # its body. Its own subshell explicitly enables it before any setup.
    set +e
    fixture_attempt "$output/normal" normal "$output/engines"
    normal=$?
    fixture_attempt "$output/forced" forced "$output/engines"
    forced=$?
    set -e
    assert_attempt_status "$normal" "$forced"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
