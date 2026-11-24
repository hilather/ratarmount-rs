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
finished=''
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
reap_signal() { builtin kill "$@"; }
reap_owned() {
    local pid owned
    # Exclude finished jobs; without job control, stopped children remain in -pr.
    owned=" $(jobs -pr | tr '\n' ' ') " || return 1
    for pid in "$@"; do
        if [[ -n "$pid" && "$owned" == *" $pid "* ]]; then
            reap_signal -CONT "$pid" 2>/dev/null || true
            reap_signal "$pid" 2>/dev/null || true
        fi
        [[ -z "$pid" ]] || wait_owned "$pid" || return 1
    done
}
cleanup_test() {
    local status=$?
    # The finished-job discriminator is wait-only, including on failure: its
    # recorded PID must never reach reap_owned's signalling cleanup.
    if [[ -n "$finished" ]]; then
        wait "$finished" 2>/dev/null || status=1
    fi
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
"$BASH" -c 'printf "ready\n" > "$1" || exit 1; exec sleep 60' _ "$ready" 4>&- &
job=$!
read -r -t 10 message <&4 || fail "shared job never became ready"
exec 4>&- || fail "cannot close job FIFO"
[[ "$message" == ready ]] || fail "unexpected shared job readiness"
# Non-fatal diagnostics for both owning-shell job-state cases below.
fail_owned_job() {
    local pid=$1
    shift || fail "missing diagnostic PID"
    {
        printf '%s\n' 'jobs -l:' || true
        jobs -l || true
        printf '%s\n' 'jobs -ps:' || true
        jobs -ps || true
        printf '%s\n' 'jobs -pr:' || true
        jobs -pr || true
        printf '%s\n' "ps -o pid,stat,command -p $pid:" || true
        ps -o pid,stat,command -p "$pid" || true
    } >&2
    fail "$@"
}
# Stop an owned readiness job and observe the stop independently of Bash's
# job-state filters. Readiness is printed before exec, and on macOS (XNU) execve
# continues in a new proc and task: a SIGSTOP that lands mid-exec stops only the
# discarded image and kill still succeeds. So first wait, bounded, until the PID
# runs sleep, then repeat the idempotent SIGSTOP until ps reports T.
stop_owned_job() {
    local pid=$1 label=$2 attempt=0 comm stat
    while :; do
        comm=$(ps -o comm= -p "$pid") || fail_owned_job "$pid" "cannot inspect $label image"
        comm=${comm#"${comm%%[![:space:]]*}"}
        comm=${comm%"${comm##*[![:space:]]}"}
        if [[ "$comm" == sleep || "$comm" == */sleep ]]; then break; fi
        [[ $attempt -lt 100 ]] || fail_owned_job "$pid" "$label never started sleep (image: $comm)"
        sleep 0.05 || fail_owned_job "$pid" "$label exec polling failed"
        attempt=$((attempt + 1))
    done
    attempt=0
    while :; do
        builtin kill -STOP "$pid" || fail_owned_job "$pid" "cannot stop $label"
        stat=$(ps -o stat= -p "$pid") || fail_owned_job "$pid" "cannot inspect stopped $label"
        stat=${stat#"${stat%%[![:space:]]*}"}
        if [[ "$stat" == T* ]]; then return 0; fi
        [[ $attempt -lt 100 ]] || fail_owned_job "$pid" "$label never stopped"
        sleep 0.05 || fail_owned_job "$pid" "$label stop polling failed"
        attempt=$((attempt + 1))
    done
}
# Regression: without job control, jobs -pr still selects a stopped owned job.
stop_owned_job "$job" "owned job" || fail_owned_job "$job" "owned job stop failed"
# Keep this call in the owning shell: (...) would discard its job table.
kill_log="$logs/stopped.log-only"
: > "$kill_log" || fail_owned_job "$job" "cannot create stopped-job log"
# Preserve stderr for logging failures even though the guard silences kill.
kill() { printf '%s\n' "$*" >> "$kill_log" || fail_owned_job "$job" "cannot log signal" 2>&6; }
kill_running_jobs "$job" "$unrelated" 6>&2 || fail_owned_job "$job" "stopped-job cleanup failed"
# Compare the file including its final newline, so extra blank calls also fail.
printf '%s\n' "$job" > "$logs/stopped.expected" || fail_owned_job "$job" "cannot create stopped-job expectation"
cmp -s "$kill_log" "$logs/stopped.expected" || fail_owned_job "$job" "stopped owned job was not signalled exactly once"
unset -f kill || fail_owned_job "$job" "cannot remove stopped-job signal stub"
builtin kill -CONT "$job" || fail_owned_job "$job" "cannot resume owned job"
attempt=0
while :; do
    stat=$(ps -o stat= -p "$job") || fail_owned_job "$job" "cannot inspect resumed job"
    stat=${stat#"${stat%%[![:space:]]*}"}
    if [[ -n "$stat" && "$stat" != T* ]]; then break; fi
    [[ $attempt -lt 100 ]] || fail_owned_job "$job" "owned job never resumed"
    sleep 0.05 || fail_owned_job "$job" "resume polling failed"
    attempt=$((attempt + 1))
done
kill_running_jobs "$job" || fail_owned_job "$job" "running-job cleanup failed"
wait_owned "$job" || fail_owned_job "$job" "running job did not exit within five seconds"
[[ $rc -eq 143 ]] || fail_owned_job "$job" "running job exited with $rc, want 143 (SIGTERM)"
job=''

# Regression: jobs -pr rejects a finished, un-waited job still listed by jobs -p.
# Keep this in the owning script shell: Bash 3.2 loses the entry in a -c shell.
true &
finished=$!
attempt=0
while :; do
    running=" $(jobs -pr | tr '\n' ' ') " || fail_owned_job "$finished" "cannot list running jobs for finished case"
    [[ "$running" == *" $finished "* ]] || break
    [[ $attempt -lt 100 ]] || fail_owned_job "$finished" "finished job never left jobs -pr"
    sleep 0.05 || fail_owned_job "$finished" "finished-job polling failed"
    attempt=$((attempt + 1))
done
owned=" $(jobs -p | tr '\n' ' ') " || fail_owned_job "$finished" "cannot list owned jobs for finished case"
[[ "$owned" == *" $finished "* ]] || fail_owned_job "$finished" "finished job missing from jobs -p; discriminator is not live"
kill_log="$logs/finished.log-only"
: > "$kill_log" || fail_owned_job "$finished" "cannot create finished-job log"
kill() { printf '%s\n' "$*" >> "$kill_log" || fail_owned_job "$finished" "cannot log signal" 2>&6; }
kill_running_jobs "$finished" 6>&2 || fail_owned_job "$finished" "finished-job cleanup failed"
contents=$(cat "$kill_log") || fail_owned_job "$finished" "cannot read finished-job log"
[[ ! -s "$kill_log" ]] || fail_owned_job "$finished" "finished job reached log-only kill: $contents"
unset -f kill || fail_owned_job "$finished" "cannot remove finished-job signal stub"
wait "$finished" || fail_owned_job "$finished" "finished job wait failed"
finished=''

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

# Regression: reap_owned must only wait for a completed, un-waited owned job.
# All earlier helpers are reaped before replacing the cleanup signal function.
# Keep the job in this owning shell, and intercept both signals even in mutants.
true &
finished=$!
attempt=0
while :; do
    running=" $(jobs -pr | tr '\n' ' ') " || fail_owned_job "$finished" "cannot list running jobs for reap case"
    [[ "$running" == *" $finished "* ]] || break
    [[ $attempt -lt 100 ]] || fail_owned_job "$finished" "reap job never left jobs -pr"
    sleep 0.05 || fail_owned_job "$finished" "reap-job polling failed"
    attempt=$((attempt + 1))
done
owned=" $(jobs -p | tr '\n' ' ') " || fail_owned_job "$finished" "cannot list owned jobs for reap case"
[[ "$owned" == *" $finished "* ]] || fail_owned_job "$finished" "reap job missing from jobs -p; discriminator is not live"
reap_log="$logs/reap.log-only"
: > "$reap_log" || fail_owned_job "$finished" "cannot create reap log"
reap_signal() {
    # Log targets only, so any erroneous CONT call also gives decimal PID evidence.
    if [[ $1 == -CONT ]]; then shift || fail_owned_job "$finished" "cannot parse reap signal" 2>&6; fi
    printf '%s\n' "$@" >> "$reap_log" || fail_owned_job "$finished" "cannot log reap signal" 2>&6
}
reap_owned "$finished" 6>&2 || fail_owned_job "$finished" "completed-job reap failed"
reap_signal() { builtin kill "$@"; }
[[ $rc -eq 0 ]] || fail_owned_job "$finished" "completed reap job exited with $rc, want 0"
owned=" $(jobs -p | tr '\n' ' ') " || fail_owned_job "$finished" "cannot list jobs after reap"
[[ "$owned" != *" $finished "* ]] || fail_owned_job "$finished" "completed job was not reaped"
contents=$(cat "$reap_log") || fail_owned_job "$finished" "cannot read reap log"
[[ ! -s "$reap_log" ]] || fail_owned_job "$finished" "reap cleanup reached log-only kill: $contents"
finished=''

# Regression: reap_owned resumes, terminates and boundedly reaps a stopped child.
ready="$scratch/reap.ready"
mkfifo "$ready" || fail "cannot create reap-job FIFO"
exec 4<> "$ready" || fail "cannot open reap-job FIFO"
"$BASH" -c 'printf "ready\n" > "$1" || exit 1; exec sleep 60' _ "$ready" 4>&- &
job=$!
read -r -t 10 message <&4 || fail_owned_job "$job" "reap job never became ready"
exec 4>&- || fail_owned_job "$job" "cannot close reap-job FIFO"
[[ "$message" == ready ]] || fail_owned_job "$job" "unexpected reap-job readiness"
stop_owned_job "$job" "reap job" || fail_owned_job "$job" "reap job stop failed"
reap_owned "$job" || fail_owned_job "$job" "stopped reap job did not exit within five seconds"
[[ $rc -eq 143 ]] || fail_owned_job "$job" "stopped reap job exited with $rc, want 143 (SIGTERM)"
job=''

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
