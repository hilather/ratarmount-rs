#!/usr/bin/env bash
# Regression: harness and benchmark cleanup signalled stale pids. Exit traps
# sent SIGTERM to every pid they had recorded, including mounts that had exited
# long before (bash reaps a job as soon as it exits, so such a pid may already
# belong to an unrelated process), and `pkill -f "ratarmount.*$WORKDIR"` also
# matched a concurrent run whose work directory extends this one's
# (`...-1234` vs `...-12345`). Needs no build, FUSE or Python checkout.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/.." && pwd)
export RATARMOUNT_ALLOW_NO_PY=1 RATARMOUNT_CMD=true RATARMOUNT_ENV_QUIET=1
source "$here/env.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# 1. kill_running_jobs signals running jobs of this shell and nothing else.
# Not a job of this shell: stands in for whatever process reused a recorded pid.
unrelated=$(bash -c 'sleep 60 >/dev/null 2>&1 & echo $!')
trap 'kill "$unrelated" 2>/dev/null || true' EXIT
sleep 60 &
job=$!
true &
exited=$!
wait "$exited"
kill_running_jobs "$unrelated" "$exited" "" "$job"
rc=0
wait "$job" || rc=$?
[[ $rc -eq 143 ]] || fail "running job exited with $rc, want 143 (SIGTERM)"
kill -0 "$unrelated" 2>/dev/null || fail "signalled $unrelated, which is not a job of this shell"

# 2. The pkill pattern ends the work directory at a path boundary. pkill and
# bash's =~ both use POSIX extended regular expressions.
WORKDIR=/tmp/ratarmount-compare-1234
pattern="ratarmount.*${WORKDIR}(/| |\$)"
[[ "ratarmount -f $WORKDIR/a.tar $WORKDIR/mnt" =~ $pattern ]] || fail "pattern misses its own run"
[[ "ratarmount --index-folders $WORKDIR" =~ $pattern ]] || fail "pattern misses a bare work directory"
[[ ! "ratarmount -f ${WORKDIR}5/a.tar ${WORKDIR}5/mnt" =~ $pattern ]] || fail "pattern matches a sibling run"

# 3. Scripts that source env.sh signal recorded pids only through
# kill_running_jobs, and every pkill uses the pattern checked above.
want_pkill='pkill -f "ratarmount.*${WORKDIR}(/| |\$)"'
checked=0
for f in "$root"/test-harness/*.sh "$root"/benchmarks/*.sh; do
    [[ $f != "$here/test-shell-kill-safety.sh" && $(<"$f") == *'/env.sh"'* ]] || continue
    checked=$((checked + 1))
    n=0
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        [[ ! $line =~ ^[[:space:]]*# ]] || continue
        if [[ $line =~ (^|[^[:alnum:]_-])kill[[:space:]]+([^-[:space:]]|-[^0]) ]]; then
            fail "${f#"$root"/}:$n: signals a pid without kill_running_jobs: $line"
        fi
        if [[ $line =~ (^|[^[:alnum:]_])pkill([^[:alnum:]_]|$) && $line != *"$want_pkill"* ]]; then
            fail "${f#"$root"/}:$n: pkill without the anchored work directory: $line"
        fi
    done <"$f"
done
((checked > 10)) || fail "only $checked scripts source env.sh; is the lint looking in the right place?"
echo "ok: shell kill safety ($checked scripts linted)"
