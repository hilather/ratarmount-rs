# SWE-bench / mini-swe-agent attempts

Register a task's base once, request N writable paths, run an agent in each,
collect patches, then destroy the attempts. Each mount shares the immutable
source's index and has an independent overlay. Use the benchmark's
`base_commit`, never the fix commit or a moving branch. The synthetic Git tree
contains a single parentless commit and no original repository history.

This recipe requires Linux FUSE, the built `ratarmount` binary, Python 3.9+,
and a container runtime. Containers supply process/network isolation; overlay
policies supply filesystem protection. Read [sandbox API](../sandbox.md#sandbox-supervisor-api)
for state recovery, quotas, protocol errors and permissions. Non-root mounts
with `allow_other` need `user_allow_other` enabled in `/etc/fuse.conf`. The
example maps ownership to the host caller and runs the container as that UID;
adapt the mapping if using user namespaces.

For a minimal local end-to-end smoke with a temporary Git repository, run
[`scripts/swe-bench-sandbox.sh`](scripts/swe-bench-sandbox.sh). It pins the
base commit, enables `--git-synthetic-head`, protects `tests/**`, writes one
attempt result, and exports a patch with `ratarmount diff --git`. It reports a
mount skip without `/dev/fuse`.

Start the daemon in a separate terminal:

```sh
export SANDBOX_SOCKET="${XDG_RUNTIME_DIR:?}/ratarmount-sandbox.sock"
mkdir -m 700 -p "$HOME/.local/state/swe-sandboxes"
ratarmount sandbox daemon --socket "$SANDBOX_SOCKET" \
  --state-dir "$HOME/.local/state/swe-sandboxes" --max-attempts 256
```

Set the task and the container environment. `AGENT_IMAGE` should contain the
repository's dependencies and mini-swe-agent (or another agent command). The
agent/model configuration can live in that image or be passed using the
container runtime's environment/secret options. No model or benchmark download
is needed for the default smoke command below.

```sh
export REPO=/srv/repos/project.git        # bare repo on the host
export BASE_COMMIT=0123456789abcdef0123456789abcdef01234567
export TASK_ID=example-task
export ATTEMPTS=8
export AGENT_IMAGE=your-prepared-swe-image
# Smoke test, or replace with your configured mini-swe-agent invocation:
export AGENT_COMMAND='git status --porcelain; printf "attempt change\n" > agent-result.txt'
export PYTHONPATH="$PWD/clients/python${PYTHONPATH:+:$PYTHONPATH}"
python3 - <<'PY'
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess

from ratarmount_sandbox import RatarmountSandbox

socket = os.environ['SANDBOX_SOCKET']
task = os.environ['TASK_ID']
source = str(Path(os.environ['REPO']).resolve()) + '@' + os.environ['BASE_COMMIT']
output = Path('attempt-patches') / task
output.mkdir(parents=True, exist_ok=True)
uid, gid = os.getuid(), os.getgid()

with RatarmountSandbox(socket) as api:
    # Use a fresh task name for changed source/options. Reusing the same name
    # is safe only when the harness knows the registered definition is identical.
    api.create_base(task, source, git_synthetic_head=True,
                    readonly_globs=['tests/**'], quota=2 * 1024**3,
                    uid=uid, gid=gid, umask='022', allow_other=True)
    attempts = api.new(task, count=int(os.environ.get('ATTEMPTS', '8')),
                       overlay='disk')  # 'tmpfs' for RAM-backed attempts

    def run_agent(attempt):
        command = [
            'docker', 'run', '--rm', '--user', f'{uid}:{gid}',
            '-v', f'{attempt.path}:/repo:rw', '-w', '/repo',
            os.environ['AGENT_IMAGE'], 'sh', '-lc',
            os.environ['AGENT_COMMAND'],
        ]
        # The container exits before collecting the patch: no concurrent writers.
        result = subprocess.run(command, capture_output=True, text=True)
        (output / f'{attempt.id}.log').write_text(result.stdout + result.stderr)
        return attempt, result.returncode

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(attempts)) as pool:
        results = list(pool.map(run_agent, attempts))
    for attempt, returncode in results:
        (output / f'{attempt.id}.patch').write_text(attempt.diff(git=True))
        (output / f'{attempt.id}.json').write_text(json.dumps({
            'returncode': returncode, 'stats': attempt.stats(),
        }, indent=2))
# Context exit unmounts and deletes these attempts. Registered base/cache remain.
PY
```

For mini-swe-agent, set `AGENT_COMMAND` to the invocation supported by the
prepared image, with that task's problem statement/configuration. Keep model
credentials in the runtime's environment or secret mount, outside source URLs.
Feed the resulting Git patch to the SWE-bench evaluation harness against the
same base commit. Synthetic `.git` content is excluded from API patches, so
Git's writable index and agent commits do not leak into the submission. The
read-only `tests/**` policy rejects writes, deletes and renames affecting the
protected paths; choose the benchmark's actual test paths if they differ.

For an OCI rootfs plus repository, register the image as `source` and set
`binds=['/repo=' + source]` with `git_synthetic_head=True`. Mount
`attempt.path + '/repo'` into the agent container and protect `repo/tests/**`.
The API patch then has `repo/` prefixes because it describes the entire composed
base; strip that component when applying to a plain repository (for example,
`git apply -p2`). Use an image with an empty `/repo` to avoid inherited files
merging into the worktree. See [rootfs composition](sandbox-rootfs.md).

Clean up remaining attempts after a harness transport failure:

```sh
ratarmount sandbox list --socket "$SANDBOX_SOCKET" --base "$TASK_ID"
ratarmount sandbox destroy --socket "$SANDBOX_SOCKET" --base "$TASK_ID"
# Once every task's patches have been collected:
ratarmount sandbox shutdown --socket "$SANDBOX_SOCKET"
```

A supervisor restart discards all attempts. It retains bases and warmed
indexes. For large teacher passes (for example, 12,000 attempts), process tasks
in bounded batches and destroy each batch after collecting its patches; the
attempt limit includes crashed mounts. Do not blindly repeat `new` after a
client timeout: list and reconcile first.
