#!/usr/bin/env bash
# Minimal docker/podman stand-in. Each command gets a process group so timeout
# and crash recovery kill descendants as well as the shell running the command.
# The state file records the group leader's pid and start time: kill and rm
# signal the group only while that leader still runs, so a stale state file
# never signals a group whose pid was reused.
set -eu
state=${RATARMOUNT_STUB_STATE:?set RATARMOUNT_STUB_STATE}
mkdir -p "$state"
# Start time (field 22 of /proc/PID/stat) of a live process; empty when PID is
# gone or a zombie. comm (field 2) may contain spaces and ')'.
start_time() {
  local stat fields
  { read -r stat < "/proc/$1/stat"; } 2>/dev/null || return 0
  fields=(${stat##*) })
  [[ ${fields[0]-} == Z ]] || printf '%s\n' "${fields[19]-}"
}
verb=$1
shift
case "$verb" in
  run)
    name= mount= envs=() argv=("$@")
    while (($#)); do
      case "$1" in
        --rm) shift ;;
        --name) name=$2; shift 2 ;;
        -v) mount=${2%:*}; shift 2 ;;
        -e) envs+=("$2"); shift 2 ;;
        -w|--network|--cpus|--memory|--user|--cap-drop|--cap-add|--security-opt|--pids-limit) shift 2 ;;
        *) shift; break ;; # image
      esac
    done
    [[ -n "$name" && -n "$mount" ]]
    # Kept after the run so tests can read the full runtime argv, one per line.
    printf "%s\n" "${argv[@]}" > "$state/$name.argv"
    setsid env "${envs[@]}" bash -c '
      state=$1; name=$2; mount=$3; shift 3
      read -r stat < "/proc/$$/stat"
      fields=(${stat##*) })
      printf "%s %s\n" "$$" "${fields[19]}" > "$state/$name.tmp"
      mv "$state/$name.tmp" "$state/$name"
      cd "$mount"; exec "$@"
    ' _ "$state" "$name" "$mount" "$@" &
    pid=$!
    result=0
    wait "$pid" || result=$?
    rm -f "$state/$name"
    exit "$result"
    ;;
  kill|rm)
    [[ ${1:-} != -f ]] || shift
    if [[ -f "$state/$1" ]]; then
      pid= start=
      read -r pid start < "$state/$1" || true
      # Never 0 or 1: `kill -- -1` signals every process this user may signal.
      if [[ $pid =~ ^[1-9][0-9]*$ && $pid != 1 && -n $start \
        && $(start_time "$pid") == "$start" ]]; then
        kill -KILL -- "-$pid" 2>/dev/null || true
      fi
      rm -f "$state/$1"
    fi
    ;;
  *) echo "unsupported stub verb: $verb" >&2; exit 2 ;;
esac
