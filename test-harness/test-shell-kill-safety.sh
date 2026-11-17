#!/usr/bin/env bash
# Regression: harness cleanup signalled recorded PIDs absent from its running
# jobs. Exercise real handlers without build, FUSE, Docker or Python fixtures.
set -eEuo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
# Bash 3.2 can lose errexit failures in subshells. Check every block and setup
# explicitly, including inside functions called from an ||/if context.
here=${BASH_SOURCE[0]%/*}
here=$(cd "$here" && pwd) || fail "cannot locate test directory"
root=$(cd "$here/.." && pwd) || fail "cannot locate repository"
export RATARMOUNT_ALLOW_NO_PY=1 RATARMOUNT_CMD=true RATARMOUNT_ENV_QUIET=1
source "$here/env.sh" || fail "cannot source env.sh"
# Logs must survive make-overlay removing WORK.
scratch=$(mktemp -d) || fail "cannot create scratch directory"
logs=$(mktemp -d) || { rm -rf "$scratch"; fail "cannot create log directory"; }
helper=''
job=''
# Independent of the guard under test, including during mutation failures.
# Poll both running and stopped jobs before wait, so a stopped child cannot hang
# this test. rc retains wait's status; a polling timeout is a separate failure.
wait_owned() {
    local pid=$1 attempt=0 running stopped
    while :; do
        running=" $(jobs -pr | tr '\n' ' ') " || return 1
        stopped=" $(jobs -ps | tr '\n' ' ') " || return 1
        [[ "$running$stopped" == *" $pid "* ]] || break
        [[ $attempt -lt 100 ]] || return 1
        sleep 0.05 || return 1
        attempt=$((attempt + 1))
    done
    rc=0
    wait "$pid" 2>/dev/null || rc=$?
}
reap_owned() {
    local pid running stopped
    running=" $(jobs -pr | tr '\n' ' ') " || return 1
    stopped=" $(jobs -ps | tr '\n' ' ') " || return 1
    for pid in "$@"; do
        if [[ -n "$pid" && "$running$stopped" == *" $pid "* ]]; then
            builtin kill -CONT "$pid" 2>/dev/null || true
            builtin kill "$pid" 2>/dev/null || true
        fi
        [[ -z "$pid" ]] || wait_owned "$pid" || return 1
    done
}
cleanup_test() {
    local status=$?
    reap_owned "$helper" "$job" || status=1
    exec 4>&- || status=1
    rm -rf "$scratch" "$logs" || status=1
    return "$status"
}
trap cleanup_test EXIT
trap 'exit 143' TERM

# The foreign child belongs to this helper. Arm TERM before publishing readiness.
# In reaped mode kill is strictly log-only, including with the trap guard removed.
helper_code=$(cat <<'CHILD'
set -uo pipefail
fail() { echo "FAIL: helper: $*" >&2; exit 1; }
mode=$1 fifo=$2 hold=$3 log=$4
forward=''
kill() {
    local running
    printf '%s\n' "$*" >> "$log" || fail "cannot log signal"
    running=" $(jobs -pr | tr '\n' ' ') " || fail "cannot list helper jobs"
    if [[ -n "$forward" && $# -eq 1 && $1 == "$forward" &&
          "$running" == *" $forward "* ]]; then
        forward=''
        builtin kill "$@" || fail "cannot signal owned child"
    fi
}
exec 3<> "$hold" || fail "cannot open hold FIFO"
if [[ "$mode" == live ]]; then sleep 60 & else true & fi
s=$!
terminate_helper() {
    local running
    running=" $(jobs -pr | tr '\n' ' ') " || fail "cannot list TERM-trap jobs"
    if [[ "$running" == *" $s "* ]]; then
        kill "$s" 2>/dev/null || fail "helper TERM signal failed"
    fi
    rc=0
    wait "$s" 2>/dev/null || rc=$?
    exec 3>&- || fail "cannot close TERM-trap FIFO"
    exit "$rc"
}
trap terminate_helper TERM
if [[ "$mode" == reaped ]]; then wait "$s" || fail "reaped child failed"; else forward=$s; fi
printf '%s\n' "$s" > "$fifo" || fail "cannot publish readiness"
if [[ "$mode" == live ]]; then
    rc=0
    wait "$s" || rc=$?
else
    read -r -t 20 -u 3 ignored || fail "hold FIFO timed out"
    rc=0
fi
exec 3>&- || fail "cannot close hold FIFO"
exit "$rc"
CHILD
) || fail "cannot construct helper"
start_helper() {
    local mode=$1 fifo="$scratch/$1.ready" hold="$scratch/$1.hold"
    helper_log="$logs/$mode.helper.kill"
    : > "$helper_log" || fail "cannot create helper log"
    mkfifo "$fifo" "$hold" || fail "cannot create helper FIFOs"
    # Fixed descriptors work on Bash 3.2; close the inherited copy in the child.
    exec 4<> "$fifo" || fail "cannot open helper FIFO"
    "$BASH" -c "$helper_code" _ "$mode" "$fifo" "$hold" "$helper_log" 4>&- &
    helper=$!
    read -r -t 10 unrelated <&4 || fail "$mode helper never became ready"
    exec 4>&- || fail "cannot close readiness descriptor"
    [[ "$unrelated" =~ ^[0-9]+$ && "$unrelated" -gt 1 ]] || fail "invalid helper child PID"
}

# Regression: shared guard rejects reaped and non-child PIDs without any signal
# attempt. A1: every rejected case uses a log-only stub, even under mutation.
start_helper live || fail "live helper setup failed"
(
    kill_log="$logs/shared.log-only"
    : > "$kill_log" || fail "cannot create kill log"
    kill() { printf '%s\n' "$*" >> "$kill_log" || fail "cannot log signal"; }
    true &
    exited=$!
    wait "$exited" || fail "short-lived job failed"
    kill_running_jobs "$unrelated" "$exited" "" 0 1 -1 invalid || fail "shared cleanup failed"
    [[ ! -s "$kill_log" ]] || fail "shared guard reached log-only kill: $(cat "$kill_log")"
) || fail "shared guard block failed"
builtin kill -0 "$unrelated" 2>/dev/null || fail "foreign child was signalled"

# Regression: a running simple job still receives SIGTERM (143). Readiness
# avoids signalling Bash between fork and its fresh shell/exec setup.
ready="$scratch/job.ready"
mkfifo "$ready" || fail "cannot create job FIFO"
exec 4<> "$ready" || fail "cannot open job FIFO"
# Noninteractive Bash tracks stopped status only with job control enabled.
set -m
"$BASH" -c 'printf "ready\n" > "$1" || exit 1; exec sleep 60' _ "$ready" 4>&- &
job=$!
read -r -t 10 message <&4 || fail "shared job never became ready"
exec 4>&- || fail "cannot close job FIFO"
[[ "$message" == ready ]] || fail "unexpected shared job readiness"
# Regression: stopped jobs must be excluded by jobs -pr. Even a jobs -p
# mutation reaches only this log-only stub. Observe the stop with a deadline.
builtin kill -STOP "$job" || fail "cannot stop owned job"
attempt=0
while :; do
    stopped=" $(jobs -ps | tr '\n' ' ') " || fail "cannot list stopped jobs"
    [[ "$stopped" != *" $job "* ]] || break
    [[ $attempt -lt 100 ]] || fail "owned job never stopped"
    sleep 0.05 || fail "stop polling failed"
    attempt=$((attempt + 1))
done
# Keep this call in the owning shell: (...) would discard its job table.
kill_log="$logs/stopped.log-only"
: > "$kill_log" || fail "cannot create stopped-job log"
kill() { printf '%s\n' "$*" >> "$kill_log" || fail "cannot log signal"; }
kill_running_jobs "$job" || fail "stopped-job cleanup failed"
[[ ! -s "$kill_log" ]] || fail "stopped job reached log-only kill: $(cat "$kill_log")"
unset -f kill || fail "cannot remove stopped-job signal stub"
builtin kill -CONT "$job" || fail "cannot resume owned job"
attempt=0
while :; do
    running=" $(jobs -pr | tr '\n' ' ') " || fail "cannot list running jobs"
    [[ "$running" != *" $job "* ]] || break
    [[ $attempt -lt 100 ]] || fail "owned job never resumed"
    sleep 0.05 || fail "resume polling failed"
    attempt=$((attempt + 1))
done
kill_running_jobs "$job" || fail "running-job cleanup failed"
wait_owned "$job" || fail "running job did not exit within five seconds"
set +m
job=''
[[ $rc -eq 143 ]] || fail "running job exited with $rc, want 143 (SIGTERM)"

# Regression: empty input, unsafe targets and partial numeric matches cannot
# pass a controlled job list. No signal in this block is ever forwarded.
(
    kill_log="$logs/controls.log-only"
    : > "$kill_log" || fail "cannot create kill log"
    jobs() { [[ $# -eq 1 && $1 == -pr ]] || return 1; printf '424242\n'; }
    kill() { printf '%s\n' "$*" >> "$kill_log" || fail "cannot log signal"; }
    kill_running_jobs || fail "empty cleanup failed"
    kill_running_jobs "" 0 1 -1 -424242 invalid 42424 24242 x424242 424242x || fail "PID controls cleanup failed"
    [[ ! -s "$kill_log" ]] || fail "PID controls reached log-only kill: $(cat "$kill_log")"
    # A4/A11 residual: a stale number reused by another running job of this
    # same shell passes the numeric guard. This deliberately records that limit.
    kill_running_jobs 424242 || fail "same-shell residual cleanup failed"
    contents=$(cat "$kill_log") || fail "cannot read controls log"
    [[ "$contents" == 424242 ]] || fail "same-shell PID reuse residual changed"
) || fail "PID controls block failed"

# Regression: no-job and failed-signal cleanup returns success under strict
# errexit/ERR handling and does not skip subsequent cleanup.
# A new process keeps errexit/ERR active even though its launch is checked with
# ||. Checking a (...) block with || would disable the behavior being tested.
"$BASH" -eEuo pipefail -c '
    fail() { echo "FAIL: $*" >&2; exit 1; }
    source "$1" || fail "cannot source strict-mode helper"
    logs=$2
    trap "fail \"unexpected ERR during guarded cleanup\"" ERR
    jobs() { [[ $# -eq 1 && $1 == -pr ]] || return 1; printf "%s" "$listed"; }
    kill() { printf "%s\n" "$*" >> "$logs/failed-signal" || fail "cannot log failed signal"; return 1; }
    listed=""
    # Deliberately unguarded: the parent checks this process status as well as
    # the continuation marker, rather than relying on Bash 3.2 subshell -e.
    kill_running_jobs "" 424242
    [[ ! -e "$logs/failed-signal" ]] || fail "no-job cleanup attempted a signal"
    listed=424242
    kill_running_jobs 424242
    contents=$(cat "$logs/failed-signal") || fail "cannot read failed-signal log"
    [[ "$contents" == 424242 ]] || fail "failed signal not exercised"
    printf "continued\n" > "$logs/continued" || fail "cannot write continuation marker"
' _ "$here/env.sh" "$logs" || fail "strict cleanup process failed"
[[ -f "$logs/continued" ]] || fail "guard skipped later cleanup"

# Extract the actual standalone handler without running its fixture/mount setup.
extract_cleanup() {
    local body
    body=$(awk '/^cleanup\(\) \{/ { found = 1 } found { print } found && /^}/ { exit }' "$1") || fail "cannot read cleanup from $1"
    [[ "$body" == 'cleanup() {'*$'\n}' ]] || fail "cannot extract cleanup from $1"
    printf '%s\n' "$body" || fail "cannot emit cleanup from $1"
}
for script in "$here/make-overlay-v0.1.35.sh" "$here/nfs-docker/inside.sh"; do
    body=$(extract_cleanup "$script") || fail "cleanup extraction failed for $script"
    for state in live reaped; do
        (
            WORK=$(mktemp -d "$scratch/work.XXXXXX") || fail "cannot create handler workspace"
            MNT="$WORK/mnt"
            mkdir -p "$MNT" || fail "cannot create handler mountpoint"
            kill_log="$logs/${script##*/}.$state.kill"
            : > "$kill_log" || fail "cannot create kill log"
            fusermount3() { :; }
            umount() { :; }
            mountpoint() { :; }
            forward=''
            kill() {
                local running
                printf '%s\n' "$*" >> "$kill_log" || fail "cannot log handler signal"
                running=" $(jobs -pr | tr '\n' ' ') " || fail "cannot list handler jobs"
                if [[ -n "$forward" && $# -eq 1 && $1 == "$forward" &&
                      "$running" == *" $forward "* ]]; then
                    forward=''
                    builtin kill "$@" || fail "cannot signal owned job"
                fi
            }
            eval "$body" || fail "cannot define cleanup from $script"
            PID=''
            trap 'status=$?; reap_owned "$PID" || status=1; exec 5>&- || status=1; rm -rf "$WORK" || status=1; exit "$status"' EXIT
            if [[ "$state" == live ]]; then
                ready="$WORK/ready"
                mkfifo "$ready" || fail "cannot create handler FIFO"
                exec 5<> "$ready" || fail "cannot open handler FIFO"
                "$BASH" -c 'printf "ready\n" > "$1" || exit 1; exec sleep 60' _ "$ready" 5>&- &
                PID=$!
                forward=$PID
                read -r -t 10 message <&5 || fail "$script job never became ready"
                exec 5>&- || fail "cannot close handler FIFO"
                [[ "$message" == ready ]] || fail "$script unexpected readiness"
            else
                true &
                PID=$!
                wait "$PID" || fail "short-lived handler job failed"
            fi
            cleanup || fail "$script cleanup failed"
            # inside.sh disables errexit; every assertion below is explicit.
            [[ -f "$kill_log" ]] || fail "$script removed its kill log"
            if [[ "$state" == live ]]; then
                contents=$(cat "$kill_log") || fail "cannot read handler log"
                [[ "$contents" == "$PID" ]] || fail "$script did not signal its running job once"
                wait_owned "$PID" || fail "$script job did not exit within five seconds"
                [[ $rc -eq 143 ]] || fail "$script job exited with $rc, want 143 (SIGTERM)"
            else
                [[ ! -s "$kill_log" ]] || fail "$script reached reaped log-only kill: $(cat "$kill_log")"
            fi
            PID=''
        ) || fail "$script $state handler block failed"
        builtin kill -0 "$unrelated" 2>/dev/null || fail "$script signalled the foreign child"
    done
done

# Regression: the helper TERM trap kills/reaps its live child but emits no call
# through its log-only reaped-child stub. Both variants terminate and are reaped.
kill_running_jobs "$helper" || fail "helper cleanup failed"
wait_owned "$helper" || fail "helper did not exit within five seconds"
helper=''
[[ $rc -eq 143 ]] || fail "live helper exited with $rc, want 143 (child SIGTERM)"
[[ -f "$helper_log" ]] || fail "live helper kill log missing"
contents=$(cat "$helper_log") || fail "cannot read live helper log"
[[ "$contents" == "$unrelated" ]] || fail "helper did not signal its live child once"
start_helper reaped || fail "reaped helper setup failed"
kill_running_jobs "$helper" || fail "helper cleanup failed"
wait_owned "$helper" || fail "helper did not exit within five seconds"
helper=''
[[ $rc -eq 0 ]] || fail "reaped-child helper exited with $rc, want 0"
[[ -f "$helper_log" ]] || fail "reaped-child helper kill log missing"
[[ ! -s "$helper_log" ]] || fail "helper reached reaped log-only kill: $(cat "$helper_log")"

# S1's explicit cohort: assert every file exists, sources env.sh and is inspected.
callers=(run-codec-allowlist run-index-interop run-phase2-allowlist run-phase3-gzip run-phase7-nested)
inspected=' '
for name in "${callers[@]}"; do
    f="$here/$name.sh"
    contents=$(cat "$f") || fail "cannot read caller: $name"
    [[ -f "$f" && "$contents" == *'/env.sh"'* ]] || fail "caller not inspected: $name"
    n=0
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        [[ ! $line =~ ^[[:space:]]*# ]] || continue
        if [[ $line =~ (^|[^[:alnum:]_-])kill[[:space:]]+([^-[:space:]]|-[^0]) ]]; then
            fail "${f#"$root"/}:$n: signals a pid without kill_running_jobs: $line"
        fi
    done < "$f" || fail "cannot scan caller: $name"
    inspected="$inspected$name "
done
for name in "${callers[@]}"; do
    [[ "$inspected" == *" $name "* ]] || fail "caller not inspected: $name"
done
echo "ok: shell kill safety (${#callers[@]} S1 callers inspected)" || fail "cannot report success"
