#!/usr/bin/env bash
# Minimal docker/podman stand-in. Each command gets a process group so timeout
# and crash recovery kill descendants as well as the shell running the command.
set -eu
state=${RATARMOUNT_STUB_STATE:?set RATARMOUNT_STUB_STATE}
mkdir -p "$state"
verb=$1
shift
case "$verb" in
  run)
    name= mount= envs=()
    while (($#)); do
      case "$1" in
        --rm) shift ;;
        --name) name=$2; shift 2 ;;
        -v) mount=${2%:*}; shift 2 ;;
        -e) envs+=("$2"); shift 2 ;;
        -w|--network|--cpus|--memory|--user) shift 2 ;;
        *) shift; break ;; # image
      esac
    done
    [[ -n "$name" && -n "$mount" ]]
    setsid env "${envs[@]}" bash -c '
      state=$1; name=$2; mount=$3; shift 3
      printf "%s\n" "$$" > "$state/$name.tmp"
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
      read -r pid < "$state/$1"
      kill -KILL -- "-$pid" 2>/dev/null || true
      rm -f "$state/$1"
    fi
    ;;
  *) echo "unsupported stub verb: $verb" >&2; exit 2 ;;
esac
