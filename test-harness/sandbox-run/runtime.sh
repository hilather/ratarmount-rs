#!/usr/bin/env bash
# Minimal docker/podman stand-in. Each command gets a process group so timeout
# and crash recovery can kill descendants after the command's leader exits.
# The state file records the leader's pid and start time. kill/rm signal a
# matching live leader's group, or re-verify surviving members individually.
# run and kill/rm retain valid state until the group has no live members;
# cleanup times out with an error and keeps state if members survive.
# These test-only start-time checks narrow but do not close PID reuse races.
set -eu
state=${RATARMOUNT_STUB_STATE:?set RATARMOUNT_STUB_STATE}
mkdir -p "$state"
# Set proc_group (field 5) and proc_start (field 22) for a live process.
# Gone processes and zombies are not live group members.
live_stat() {
  local stat= fields
  proc_group= proc_start=
  # Whole file: comm (field 2) may embed newlines, spaces, and ')'.
  # read -d '' reads through EOF, returning nonzero even on a successful read.
  { IFS= read -r -d '' stat < "/proc/$1/stat"; } 2>/dev/null || [[ -n $stat ]] || return 1
  fields=(${stat##*) })
  [[ ${fields[0]-} != Z && ${fields[0]-} != X \
    && ${fields[2]-} =~ ^[1-9][0-9]*$ && ${fields[19]-} =~ ^[0-9]+$ ]] || return 1
  proc_group=${fields[2]}
  proc_start=${fields[19]}
}
group_members() {
  local path member
  for path in /proc/[0-9]*/stat; do
    member=${path#/proc/}
    member=${member%/stat}
    if live_stat "$member" && [[ $proc_group == "$1" ]]; then
      printf '%s %s\n' "$member" "$proc_start"
    fi
  done
}
stop_group() {
  local pid=$1 start=$2 deadline=$((SECONDS + 5)) members member member_start
  while :; do
    if live_stat "$pid"; then
      # Linux cannot reuse a PID while it is still a process group's id.
      # A live replacement therefore proves that the original group is empty.
      [[ $proc_start == "$start" ]] || return 0
      kill -KILL -- "-$pid" 2>/dev/null || true
    fi
    members=$(group_members "$pid")
    [[ -n $members ]] || return 0
    if ((SECONDS >= deadline)); then
      echo "stub $verb: process group $pid still has live members; keeping state" >&2
      return 1
    fi
    while read -r member member_start; do
      # With no reused leader, pgid PID still belongs to our leader's
      # descendants. Require each survivor to start no earlier than the leader,
      # then re-read both group and start time immediately before signalling.
      # Never signal a negative, zero, or PID 1 target on this survivor path.
      [[ $member =~ ^[1-9][0-9]*$ && $member != 1 \
        && $member_start =~ ^[0-9]+$ ]] || continue
      # Compare canonical decimal strings without overflowing shell integers.
      [[ ${#member_start} -gt ${#start} \
        || ( ${#member_start} -eq ${#start} && ! $member_start < $start ) ]] || continue
      if live_stat "$pid" && [[ $proc_start != "$start" ]]; then
        return 0
      fi
      if live_stat "$member" && [[ $proc_group == "$pid" && $proc_start == "$member_start" ]]; then
        kill -KILL -- "$member" 2>/dev/null || true
      fi
    done <<< "$members"
    sleep 0.05
  done
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
      # Whole /proc/$$/stat: same newline-in-comm rule as live_stat.
      stat=$(cat "/proc/$$/stat")
      fields=(${stat##*) })
      printf "%s %s\n" "$$" "${fields[19]}" > "$state/$name.tmp"
      mv "$state/$name.tmp" "$state/$name"
      cd "$mount"; exec "$@"
    ' _ "$state" "$name" "$mount" "$@" &
    pid=$!
    result=0
    wait "$pid" || result=$?
    # A command can exit before its descendants. Preserve their recovery record.
    if [[ -z $(group_members "$pid") ]]; then
      rm -f "$state/$name"
    fi
    exit "$result"
    ;;
  kill|rm)
    [[ ${1:-} != -f ]] || shift
    if [[ -f "$state/$1" ]]; then
      pid= start=
      read -r pid start < "$state/$1" || true
      # Never 0 or 1: `kill -- -1` signals every process this user may signal.
      if [[ $pid =~ ^[1-9][0-9]*$ && $pid != 1 && $start =~ ^(0|[1-9][0-9]*)$ ]]; then
        stop_group "$pid" "$start" || exit 1
      fi
      # Legacy/malformed records cannot establish ownership. Keep the existing
      # no-signal removal rather than guess and risk killing another group.
      rm -f "$state/$1"
    fi
    ;;
  *) echo "unsupported stub verb: $verb" >&2; exit 2 ;;
esac
