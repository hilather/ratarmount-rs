#!/usr/bin/env bash
# Run the tests that once depended on the developer's umask under umask 0002
# (common where each user has a private group). Under 0002 a default
# temporary directory is group-writable (0775) and a new file is 0664, so a
# fixture that hands one to a private-directory check (sandbox socket parent,
# synthetic Git cache, range cache) or compares it with a 0644 overlay file
# fails there and passes under 022. Fixtures set explicit modes instead.
#
# CI runs everything under 022, so this script is the guard. Extra arguments
# are passed to every `cargo test` (e.g. `--release`). Set CARGO to override
# the cargo command.
#
# Not here yet: overlay_changes regression_cow_lower_view_lists_base_and_build_edits,
# overlay_import regression_cow_git_import_hash_roundtrip_base_and_lower and
# fuse_cow_agreement supervisor_finalized_layer fail under 0002 because an
# implicit copy-on-write parent directory takes the mounting process's umask
# instead of the lower view's mode (a product bug, not a fixture problem).
set -euo pipefail

cd "$(dirname "$0")/.."
umask 0002
if [ "$(umask)" != "0002" ]; then
    echo "FAIL: could not set umask 0002 (got $(umask))" >&2
    exit 1
fi

cargo_cmd=(${CARGO:-cargo})
status=0
run() {
    echo "+ umask 0002; cargo test $*" >&2
    if ! "${cargo_cmd[@]}" test "$@"; then
        status=1
    fi
}

run -p ratarmount-index --lib range_cache "${@}"
run -p ratarmount-formats-git --lib secure_cache "${@}"
run -p ratarmount-compositing --lib regression_cow_changes_match_rowed_edits "${@}"
run -p ratarmount-compositing --lib regression_hash_excluded_edits_do_not_contribute "${@}"
run -p ratarmount --bin ratarmount overlay_pack "${@}"
run -p ratarmount --test diff "${@}"
# The mount tests print `skip:` without /dev/fuse or fusermount3; the daemon
# binds its socket (the check that refused under 0002) before any mount.
run -p ratarmount --test sandbox "${@}"

if [ "$status" -ne 0 ]; then
    echo "FAIL: a test failed under umask 0002" >&2
fi
exit "$status"
