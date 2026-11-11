#!/usr/bin/env bash
# Separate Docker-compatible native benchmark fixture. Faults belong only here.
set -euo pipefail
state=${BENCH_STUB_STATE:?stub state directory required}
printf '%q ' "$@" >> "$state/calls"
printf '\n' >> "$state/calls"
verb=$1
shift
case "$verb" in
  image)
    [[ $1 == inspect && $2 == --format && $3 == '{{json .}}' ]]
    [[ ! -f $state/inspect-fail ]] || exit 19
    image=$4
    [[ ! -f $state/identity-mismatch ]] || image=wrong
    arch=amd64
    [[ $(uname -m) != aarch64 ]] || arch=arm64
    printf '{"RepoDigests":["%s"],"Os":"linux","Architecture":"%s"}\n' "$image" "$arch"
    ;;
  run)
    [[ $1 == -d && $2 == --init && $3 == --pull=never && $4 == --name ]]
    name=$5
    shift 5
    [[ $1 == -v && $3 == -w && $4 == /repo ]]
    tree=${2%:/repo}
    shift 4
    [[ $1 == --network && $2 == none && $3 == --cap-drop && $4 == ALL ]]
    [[ $5 == --security-opt && $6 == no-new-privileges && $7 == --pids-limit ]]
    [[ $9 == --user && ${11} == --cpus && ${13} == --memory ]]
    [[ ${16} == sleep && ${17} == infinity && $# == 17 ]]
    [[ -d $tree && -f $tree/source.txt && ! -e $tree/changed ]]
    [[ ! -f $state/many-directories || -d $tree/directory-1099 ]]
    if [[ -f $state/archive-modes ]]; then
      [[ $(stat -c %a "$tree/archive-zero") == 0 && $(stat -c %a "$tree/archive-write") == 300 ]]
    fi
    printf '%s\n' "$tree" >> "$state/trees"
    touch "$state/starting"
    if [[ -f $state/late ]]; then sleep 0.3; fi
    if [[ -f $state/run-hang ]]; then while :; do sleep 0.05; done; fi
    printf '%s\n' "$tree" > "$state/container.$name"
    printf '%s\n' "$name"
    [[ ! -f $state/run-fail ]] || exit 17
    ;;
  exec)
    while [[ $1 == -e ]]; do shift 2; done
    name=$1
    phase=$2
    tree=$(cat "$state/container.$name")
    [[ -d $tree ]]
    printf '%s\n' "$phase" >> "$state/phases"
    touch "$tree/changed"
    if [[ -f $state/mode-000 && ! -d $tree/runtime-zero ]]; then mkdir -m 000 "$tree/runtime-zero"; fi
    if [[ -f $state/mode-0500 && ! -d $tree/runtime-readonly ]]; then mkdir -p "$tree/runtime-readonly/child"; chmod 0500 "$tree/runtime-readonly"; fi
    if [[ -f $state/depth-257 && ! -d $tree/deep ]]; then
      path=$tree/deep
      for ((i=0; i<257; i++)); do mkdir "$path"; path=$path/d; done
    fi
    if [[ -f $state/exec-hang ]]; then
      touch "$state/executing"
      while [[ -f $state/container.$name ]]; do sleep 0.02; done
      exit 23
    fi
    printf '%s output\n' "$phase"
    printf '%s diagnostic\n' "$phase" >&2
    [[ ! -f $state/fail-$phase ]] || exit 7
    ;;
  kill|rm)
    [[ ${1:-} != -f ]] || shift
    name=$1
    [[ ! -f $state/stop-fail ]] || { printf 'injected stop failure\n' >&2; exit 9; }
    if [[ ! -f $state/container.$name ]]; then printf 'No such container\n' >&2; exit 1; fi
    tree=$(cat "$state/container.$name")
    [[ -d $tree ]] # Cleanup must not have started while a runtime is still owned.
    printf '%s\n' "$verb" >> "$state/stops"
    if [[ $verb == rm ]]; then
      rm -- "$state/container.$name"
      if [[ -f $state/interrupt-after-stop ]]; then kill -INT "$PPID"; fi
    fi
    ;;
  inspect)
    [[ -f $state/container.$1 ]]
    printf '{"State":{"Running":true}}\n'
    ;;
  *) printf 'unsupported fixture operation: %s\n' "$verb" >&2; exit 2 ;;
esac
